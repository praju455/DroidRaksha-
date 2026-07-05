"""
Celery tasks — run_analysis_task runs the full static analysis pipeline
and publishes granular progress events to Redis Pub/Sub so the WebSocket
endpoint can stream them to the browser in real time.

Progress events format (JSON published to channel "progress:{job_id}"):
  {"stage": "manifest",  "pct": 15, "msg": "Parsing AndroidManifest.xml..."}
  {"stage": "complete",  "pct": 100, "analysis_id": "<uuid>"}
  {"stage": "error",     "pct": 0,   "msg": "Analysis failed: ..."}
"""
from __future__ import annotations
import asyncio
import json
import os
import hashlib

import redis as sync_redis

from backend.worker.celery_app import celery_app

# Synchronous Redis client for Pub/Sub (Celery tasks are sync)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis = sync_redis.from_url(REDIS_URL, decode_responses=True)


def _publish(job_id: str, payload: dict) -> None:
    """
    Publish a progress event to the job's Redis channel AND append to a
    buffered list so late WebSocket connections can replay missed events.
    """
    data = json.dumps(payload)
    # Pub/Sub for live subscribers
    _redis.publish(f"progress:{job_id}", data)
    # Buffered list for late-joining WebSockets (replayed on connect)
    _redis.rpush(f"progress_log:{job_id}", data)
    _redis.expire(f"progress_log:{job_id}", 600)  # 10 min TTL


_worker_loop = None

def _run_async(coro):
    """Run an async coroutine from a sync Celery task context."""
    global _worker_loop
    if _worker_loop is None or _worker_loop.is_closed():
        _worker_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_worker_loop)
    return _worker_loop.run_until_complete(coro)


@celery_app.task(
    bind=True,
    name="backend.worker.tasks.run_analysis_task",
    max_retries=2,
    soft_time_limit=1800,
    time_limit=1920,
)
def run_analysis_task(self, apk_path: str, filename: str, job_id: str) -> dict:
    """
    Full static analysis pipeline as a Celery task.
    Publishes granular progress (0–100%) to Redis channel 'progress:{job_id}'.
    """
    from backend.engines import (
        manifest_parser,
        string_extractor,
        cert_analyzer,
        yara_scanner,
        obfuscation,
    )
    from backend.intel import india_ioc, virustotal, abuseipdb, asn_lookup, otx
    from backend.scoring import risk_scorer
    from backend.ai import narrative as ai_narrative_module
    from backend.ai import (
        classifier as family_classifier,
        mitre_full,
        xgboost_classifier,
        anomaly_detector,
        malbert_classifier,
        langchain_agent,
    )
    from backend.db import database

    try:
        # ── Stage 1: Hashing (5%) ─────────────────────────────────────────
        _publish(job_id, {"stage": "hashing", "pct": 5, "msg": "Computing file hashes..."})
        
        # S3 Fallback: If running on a remote worker without a shared volume, download from S3
        if not os.path.exists(apk_path):
            _publish(job_id, {"stage": "download", "pct": 6, "msg": "Downloading from S3/R2..."})
            from backend.storage.s3 import download_file as s3_download
            os.makedirs(os.path.dirname(apk_path), exist_ok=True)
            # We assume filename in S3 is apks/{sha256}.apk but we don't have sha256 yet...
            # Actually, apk_path is uploads/sha256.apk, so we can extract the basename
            object_name = f"apks/{os.path.basename(apk_path)}"
            success = _run_async(s3_download(object_name, apk_path))
            if not success:
                raise FileNotFoundError(f"APK not found locally and failed to download from S3: {apk_path}")

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
        hashes = {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
            "file_size": os.path.getsize(apk_path),
        }

        # ── Stage 2: Manifest (20%) ───────────────────────────────────────
        _publish(job_id, {"stage": "manifest", "pct": 20, "msg": "Parsing AndroidManifest.xml..."})
        manifest = manifest_parser.analyze(apk_path)

        # ── Stage 3: Strings (35%) ────────────────────────────────────────
        _publish(job_id, {"stage": "strings", "pct": 35, "msg": "Extracting strings & IOCs..."})
        strings = string_extractor.analyze(apk_path)

        # ── Stage 4: Certificate (45%) ────────────────────────────────────
        _publish(job_id, {"stage": "certificate", "pct": 45, "msg": "Analysing signing certificate..."})
        cert = cert_analyzer.analyze(apk_path)

        # ── Stage 5: YARA (58%) ───────────────────────────────────────────
        _publish(job_id, {"stage": "yara", "pct": 58, "msg": "Running 50 YARA rules..."})
        yara = yara_scanner.analyze(apk_path)

        # ── Stage 6: Obfuscation (65%) ────────────────────────────────────
        _publish(job_id, {"stage": "obfuscation", "pct": 65, "msg": "Detecting obfuscation & packers..."})
        obf = obfuscation.analyze(apk_path)

        # ── Stage 7: India IOC (72%) ──────────────────────────────────────
        _publish(job_id, {"stage": "india_ioc", "pct": 72, "msg": "Checking India threat intelligence..."})
        ioc = india_ioc.analyze(apk_path, manifest, strings)

        # ── Stage 8: Threat Intel (80%) ───────────────────────────────────
        _publish(job_id, {"stage": "threat_intel", "pct": 80, "msg": "Querying VirusTotal & AbuseIPDB..."})
        vt = _run_async(virustotal.analyze(apk_path))
        ip_list = [item["value"] for item in strings.get("ips", [])]
        abuse = _run_async(abuseipdb.analyze(ip_list))
        domains = []
        for item in strings.get("urls", []):
            value = item.get("value", "")
            if value:
                domains.append(value)
        asn = _run_async(asn_lookup.analyze(ip_list))
        otx_result = _run_async(otx.analyze(ip_list, domains))

        # ── Stage 9: Risk Score (82%) ────────────────────────────────────
        _publish(job_id, {"stage": "risk_score", "pct": 82, "msg": "Calculating risk score..."})
        risk = risk_scorer.calculate(manifest, strings, cert, yara, obf, vt, abuse, ioc)

        # ── Stage 10: Rule-Based Family Classifier (85%) ────────────────────
        _publish(job_id, {"stage": "classify", "pct": 85, "msg": "Classifying malware family..."})
        family_result = family_classifier.classify(manifest, strings, yara, obf, ioc, vt)

        # ── Stage 11: XGBoost + SHAP (88%) ───────────────────────────────
        _publish(job_id, {"stage": "xgboost", "pct": 88, "msg": "Running XGBoost classifier (MalDroid 2020)..."})
        xgb_result = xgboost_classifier.classify(manifest, strings, yara, obf, ioc)

        # ── Stage 12: Isolation Forest / Zero-Day (91%) ───────────────────
        _publish(job_id, {"stage": "anomaly", "pct": 91, "msg": "Running Isolation Forest zero-day detection..."})
        anomaly_result = anomaly_detector.detect(manifest, strings, yara, obf, ioc)

        # ── Stage 13: MalBERT Zero-Shot (94%) ───────────────────────────
        _publish(job_id, {"stage": "malbert", "pct": 94, "msg": "MalBERT zero-shot classification..."})
        malbert_result = malbert_classifier.classify(manifest, yara, obf, strings)

        # ── Stage 14: MITRE ATT&CK Full (90%) ──────────────────────────
        _publish(job_id, {"stage": "mitre", "pct": 90, "msg": "Mapping 40+ MITRE ATT&CK techniques..."})
        mitre = mitre_full.get_mitre_tactics(manifest, obf, yara, strings)

        # ── Stage 15: LangChain Agent Verdict (93%) ──────────────────────
        _publish(job_id, {"stage": "agent", "pct": 93, "msg": "LangChain Agent generating court-grade verdict..."})
        agent_verdict = langchain_agent.run_agent(
            manifest=manifest, strings=strings, yara=yara,
            obfuscation=obf, india_ioc=ioc, risk=risk,
            xgboost_result=xgb_result, malbert_result=malbert_result,
            family_result=family_result, anomaly_result=anomaly_result,
        )

        # ── Stage 16: Frida Offline Sandbox (96%) ────────────────────────
        _publish(job_id, {"stage": "sandbox", "pct": 96, "msg": "Running Docker sandbox (Frida offline analysis)..."})
        from backend.engines import sandbox_engine
        try:
            sandbox_result = sandbox_engine.run(apk_path)
        except Exception as sandbox_err:
            sandbox_result = {"sandbox_available": False, "error": str(sandbox_err)}

        # ── Stage 17: MobSF Static API (98%) ─────────────────────────────
        _publish(job_id, {"stage": "mobsf", "pct": 98, "msg": "MobSF static deep-scan..."})
        from backend.engines import mobsf_client
        try:
            import asyncio as _asyncio
            mobsf_result = _run_async(mobsf_client.analyze(apk_path))
        except Exception as mobsf_err:
            mobsf_result = {"available": False, "error": str(mobsf_err)}

        # ── Stage 18: Correlation Engine ─────────────────────────────────
        _publish(job_id, {"stage": "correlation", "pct": 99, "msg": "Correlating static and dynamic indicators..."})
        from backend.engines import correlation_engine, dga_detector, investigator
        correlation = correlation_engine.correlate(
            manifest=manifest,
            strings=strings,
            dynamic=sandbox_result,
            network={},
            india_ioc=ioc,
            mobsf=mobsf_result,
            threat_intel={"virustotal": vt, "abuseipdb": abuse, "asn": asn, "otx": otx_result},
        )
        dga_static = dga_detector.analyze_domains(domains)

        # ── Stage 19: Investigative Evidence Report ────────────────────────────────
        _publish(job_id, {"stage": "evidence", "pct": 99, "msg": "Generating investigative evidence report..."})
        evidence_report = investigator.analyze(apk_path, manifest, strings)

        # Use agent court narrative as primary AI narrative
        ai_text = agent_verdict.get("court_narrative", "")
        recommendations = agent_verdict.get("recommendations", [])
        if not ai_text:
            # Fallback to old narrative generator
            ai_text, recommendations = _run_async(
                ai_narrative_module.generate_narrative(manifest, risk, yara, ioc, cert, obf)
            )

        import uuid
        from datetime import datetime, timezone
        analysis_id = str(uuid.uuid4())
        result = {
            "id": analysis_id,
            "status": "complete",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hashes": hashes,
            "filename": filename,
            "manifest": manifest,
            "strings": strings,
            "certificate": cert,
            "yara": yara,
            "obfuscation": obf,
            "virustotal": vt,
            "abuseipdb": abuse,
            "asn": asn,
            "otx": otx_result,
            "dga_static": dga_static,
            "india_ioc": ioc,
            "risk": risk,
            "mitre": mitre,
            # ── ML Intelligence Layer ─────────────────────────────────────────
            "ml_classification": family_result,
            "xgboost": xgb_result,
            "malbert": malbert_result,
            "anomaly": anomaly_result,
            "agent_verdict": agent_verdict,
            # ── AI Narrative ───────────────────────────────────────────────
            "ai_narrative": ai_text,
            "ai_recommendations": recommendations,
            # ── Dynamic Sandbox ────────────────────────────────────────────
            "dynamic": sandbox_result,
            "mobsf": mobsf_result,
            "correlation": correlation,
            # ── Investigative Evidence Report ───────────────────────────────
            "evidence_report": evidence_report,
        }

        # ── Save to DB (99%) ──────────────────────────────────────────────
        _publish(job_id, {"stage": "saving", "pct": 99, "msg": "Saving results to database..."})
        _run_async(database.save_analysis(result))

        # ── Index IOCs to Elasticsearch (99.5%) ───────────────────────────
        _publish(job_id, {"stage": "indexing", "pct": 99, "msg": "Indexing IOCs to Elasticsearch..."})
        from backend.db import elastic
        _run_async(elastic.index_analysis(result))

        # ── Done (100%) ───────────────────────────────────────────────────
        _publish(job_id, {
            "stage": "complete",
            "pct": 100,
            "msg": f"Analysis complete — {risk['risk_level']} ({risk['score']}/100)",
            "analysis_id": analysis_id,
            "risk_level": risk["risk_level"],
            "risk_score": risk["score"],
        })
        return result

    except Exception as exc:
        _publish(job_id, {"stage": "error", "pct": 0, "msg": f"Analysis failed: {str(exc)}"})
        raise self.retry(exc=exc, countdown=5)
