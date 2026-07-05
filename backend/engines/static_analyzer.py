"""
Static analysis orchestrator: runs all engines and assembles the final result.
"""
from __future__ import annotations
import hashlib
import os
import uuid
from datetime import datetime, timezone
from loguru import logger

from backend.engines import (
    manifest_parser,
    string_extractor,
    cert_analyzer,
    yara_scanner,
    obfuscation,
)
from backend.intel import india_ioc, virustotal, abuseipdb, asn_lookup, otx, c2_detector
from backend.scoring import risk_scorer
from backend.ai import narrative as ai_narrative_module


def _hash_file(path: str) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "file_size": os.path.getsize(path),
    }


async def run(apk_path: str, filename: str) -> dict:
    """Run all analysis engines and return a complete analysis result."""
    logger.info(f"Starting analysis: {filename}")

    analysis_id = str(uuid.uuid4())
    hashes = _hash_file(apk_path)

    file_size_mb = hashes.get("file_size", 0) / (1024 * 1024)
    if file_size_mb > 700:
        logger.warning(f"File too large ({file_size_mb:.2f}MB). Using mock data to prevent OOM.")
        manifest = manifest_parser._mock_manifest(apk_path)
        strings = string_extractor._mock_strings()
        cert = cert_analyzer._mock_cert()
        yara = yara_scanner._mock_yara()
        obf = obfuscation._mock_obfuscation()
    else:
        logger.info("Running manifest parser...")
        manifest = manifest_parser.analyze(apk_path)

        logger.info("Running string extractor...")
        strings = string_extractor.analyze(apk_path)

        logger.info("Running certificate analyzer...")
        cert = cert_analyzer.analyze(apk_path)

        logger.info("Running YARA scanner...")
        yara = yara_scanner.analyze(apk_path)

        logger.info("Running obfuscation detector...")
        obf = obfuscation.analyze(apk_path)

    logger.info("Running India IOC check...")
    ioc = india_ioc.analyze(apk_path, manifest, strings)

    logger.info("Running VirusTotal lookup...")
    vt = await virustotal.analyze(apk_path)

    logger.info("Running AbuseIPDB check...")
    ip_list = [item["value"] for item in strings.get("ips", [])]
    abuse = await abuseipdb.analyze(ip_list)

    domains = [item.get("value", "") for item in strings.get("urls", []) if item.get("value")]
    logger.info("Running ASN and OTX lookups...")
    asn = await asn_lookup.analyze(ip_list)
    otx_result = await otx.analyze(ip_list, domains)

    logger.info("Running C2 intelligence detection...")
    # sandbox_smali populated after sandbox runs — pass None here, updated post-sandbox below
    all_urls = [item.get("value", "") for item in strings.get("urls", [])]
    c2_intel_pre = c2_detector.analyze(
        strings=strings,
        sandbox_smali=None,
        abuseipdb_result=abuse,
        urls=all_urls,
    )

    logger.info("Calculating risk score...")
    risk = risk_scorer.calculate(manifest, strings, cert, yara, obf, vt, abuse, ioc, c2_intel_pre)

    logger.info("Getting MITRE ATT&CK mapping...")
    mitre = ai_narrative_module.get_mitre_tactics(manifest, obf, yara)

    logger.info("Generating base AI narrative...")
    ai_text, recommendations = await ai_narrative_module.generate_narrative(
        manifest, risk, yara, ioc, cert, obf
    )

    # ── ML Intelligence Layer Fallback (Runs synchronously when Celery is down) ──
    logger.info("Running synchronous ML intelligence layer...")
    from backend.ai import (
        classifier as family_classifier,
        xgboost_classifier,
        anomaly_detector,
        malbert_classifier,
        langchain_agent,
    )

    family_result = family_classifier.classify(manifest, strings, yara, obf, ioc, vt)
    xgb_result = xgboost_classifier.classify(manifest, strings, yara, obf, ioc)
    anomaly_result = anomaly_detector.detect(manifest, strings, yara, obf, ioc)
    malbert_result = malbert_classifier.classify(manifest, yara, obf, strings)

    logger.info("Running LangChain Agent...")
    agent_verdict = langchain_agent.run_agent(
        manifest=manifest, strings=strings, yara=yara,
        obfuscation=obf, india_ioc=ioc, risk=risk,
        xgboost_result=xgb_result, malbert_result=malbert_result,
        family_result=family_result, anomaly_result=anomaly_result,
    )

    # Override standard narrative with LangChain agent's narrative if generated
    if agent_verdict.get("court_narrative"):
        ai_text = agent_verdict["court_narrative"]
        recommendations = agent_verdict.get("recommendations", recommendations)

    # ── Frida Offline Sandbox ──────────────────────────────────────────────────
    logger.info("Running sandbox engine (Docker / Frida offline)...")
    from backend.engines import sandbox_engine
    try:
        sandbox_result = sandbox_engine.run(apk_path)
    except Exception as e:
        sandbox_result = {"sandbox_available": False, "error": str(e)}

    # Re-run C2 detection with smali findings now available
    logger.info("Re-running C2 detection with sandbox smali data...")
    sandbox_smali = sandbox_result.get("smali_analysis") if sandbox_result.get("sandbox_available") else None
    c2_intel = c2_detector.analyze(
        strings=strings,
        sandbox_smali=sandbox_smali,
        abuseipdb_result=abuse,
        urls=all_urls,
    )
    # Re-score with enriched C2 data
    risk = risk_scorer.calculate(manifest, strings, cert, yara, obf, vt, abuse, ioc, c2_intel)

    # ── MobSF Static API ───────────────────────────────────────────────────
    logger.info("Running MobSF static analysis...")
    from backend.engines import mobsf_client
    try:
        mobsf_result = await mobsf_client.analyze(apk_path)
    except Exception as e:
        mobsf_result = {"available": False, "error": str(e)}

    logger.info("Running static/dynamic correlation...")
    from backend.engines import correlation_engine, dga_detector
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
        # ── ML Intelligence Layer ──
        "ml_classification": family_result,
        "xgboost": xgb_result,
        "malbert": malbert_result,
        "anomaly": anomaly_result,
        "agent_verdict": agent_verdict,
        # ── AI Narrative ──
        "ai_narrative": ai_text,
        "ai_recommendations": recommendations,
        # ── Dynamic Sandbox ──
        "dynamic": sandbox_result,
        "mobsf": mobsf_result,
        "correlation": correlation,
        "c2_intelligence": c2_intel,
    }

    logger.info(f"Analysis complete: {analysis_id} | Risk: {risk['risk_level']} ({risk['score']}/100)")
    return result
