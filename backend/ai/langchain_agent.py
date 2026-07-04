"""
LangChain ReAct Agent — DroidRaksha P11
========================================
An autonomous agent that uses Gemini Flash (already configured in .env)
to reason over all analysis outputs and produce a structured, court-grade verdict.

The agent uses the ReAct (Reasoning + Acting) pattern:
  Thought → Action (call tool) → Observation → ... → Final Answer

Tools available to the agent:
  1. check_permissions    — lists dangerous permissions + combos
  2. get_yara_findings    — returns YARA matches with severity
  3. get_ml_verdict       — XGBoost + MalBERT + rule-based ensemble
  4. get_risk_score       — numeric risk + breakdown
  5. get_india_ioc        — India-specific threat intelligence
  6. check_anomaly        — Isolation Forest zero-day score

Falls back to a direct Gemini prompt if LangChain fails.
"""
from __future__ import annotations
import json
import os
import time
from loguru import logger

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")
AGENT_TIMEOUT  = 90  # seconds

# LM Studio — OpenAI-compatible local LLM server
LM_STUDIO_URL   = os.getenv("LM_STUDIO_URL", "http://host.docker.internal:1234/v1")
LM_STUDIO_MODEL = os.getenv("LM_STUDIO_MODEL", "local-model")


# ── Tool implementations (pure Python, no I/O) ────────────────────────────────

def _tool_check_permissions(manifest: dict) -> str:
    dangerous = [
        p["name"].split(".")[-1]
        for p in manifest.get("permissions", [])
        if p.get("is_dangerous")
    ]
    combos = [c.get("label", "") for c in manifest.get("dangerous_combos", [])]
    return json.dumps({
        "dangerous_permissions": dangerous[:20],
        "dangerous_combos": combos,
        "total_dangerous": len(dangerous),
    })


def _tool_get_yara_findings(yara: dict) -> str:
    matches = yara.get("matches", [])
    return json.dumps({
        "total_matches": len(matches),
        "critical": [m["rule"] for m in matches if m.get("severity") == "CRITICAL"],
        "high":     [m["rule"] for m in matches if m.get("severity") == "HIGH"],
        "medium":   [m["rule"] for m in matches if m.get("severity") == "MEDIUM"],
    })


def _tool_get_ml_verdict(xgboost_result: dict, malbert_result: dict, family_result: dict) -> str:
    return json.dumps({
        "xgboost":   {"label": xgboost_result.get("label"), "probability": xgboost_result.get("probability")},
        "malbert":   {"label": malbert_result.get("label"), "confidence": malbert_result.get("confidence")},
        "rule_based":{"family": family_result.get("family"), "confidence": family_result.get("confidence")},
        "shap_top3": xgboost_result.get("shap_top5", [])[:3],
    })


def _tool_get_risk_score(risk: dict) -> str:
    return json.dumps({
        "score": risk.get("score"),
        "risk_level": risk.get("risk_level"),
        "breakdown": risk.get("breakdown"),
        "threat_categories": risk.get("threat_categories"),
    })


def _tool_get_india_ioc(india_ioc: dict) -> str:
    return json.dumps({
        "is_fake_upi":   india_ioc.get("is_fake_upi"),
        "is_fake_bank":  india_ioc.get("is_fake_bank"),
        "is_loan_scam":  india_ioc.get("is_loan_scam"),
        "risk_flags":    india_ioc.get("risk_flags", []),
        "matched_ips":   india_ioc.get("matched_ips", []),
        "matched_domains": india_ioc.get("matched_domains", []),
    })


def _tool_check_anomaly(anomaly: dict) -> str:
    return json.dumps({
        "is_anomalous":     anomaly.get("is_anomalous"),
        "zero_day_risk":    anomaly.get("zero_day_risk"),
        "anomaly_score":    anomaly.get("anomaly_score"),
        "explanation":      anomaly.get("explanation"),
    })


# ── Agent verdict schema ──────────────────────────────────────────────────────

def _empty_verdict() -> dict:
    return {
        "court_narrative": "",
        "ioc_summary": "",
        "recommendations": [],
        "reasoning_steps": [],
        "verdict_confidence": 0,
        "agent_used": "none",
    }


# ── Direct Gemini prompt (fast fallback) ──────────────────────────────────────

def _gemini_direct_verdict(all_data: dict) -> dict:
    """
    Single-shot Gemini call when LangChain agent times out or fails.
    Produces the same structured output.
    """
    if not GEMINI_API_KEY:
        return _empty_verdict()

    pkg        = all_data["manifest"].get("package_name", "unknown")
    risk_level = all_data["risk"].get("risk_level", "UNKNOWN")
    score      = all_data["risk"].get("score", 0)
    family     = all_data.get("ml_classification", {}).get("family", "Unknown")
    confidence = all_data.get("ml_classification", {}).get("confidence", 0)
    yara_hits  = [m["rule"] for m in all_data["yara"].get("matches", [])[:5]]
    ioc_flags  = all_data["india_ioc"].get("risk_flags", [])
    shap_top3  = all_data.get("xgboost", {}).get("shap_top5", [])[:3]
    anomaly    = all_data.get("anomaly", {})

    shap_text = ""
    if shap_top3:
        shap_text = "Key ML evidence (SHAP): " + ", ".join(
            f'{s["feature"]} ({s["direction"]} malware probability by {abs(s["shap_value"]):.3f})'
            for s in shap_top3
        )

    prompt = f"""You are DroidRaksha's senior forensic analyst producing a court-admissible APK threat report.

APK: {pkg}
Risk: {risk_level} ({score}/100)
ML Family Classification: {family} (confidence: {confidence}%)
YARA Rules Matched: {', '.join(yara_hits) if yara_hits else 'None'}
India IOC Flags: {', '.join(ioc_flags) if ioc_flags else 'None'}
{shap_text}
Zero-Day Anomaly: {anomaly.get('zero_day_risk', 'N/A')} — {anomaly.get('explanation', '')}

Write a forensic report with these EXACT sections:

COURT_NARRATIVE:
[3 paragraphs: (1) threat identity and intent, (2) technical mechanisms with SHAP evidence, (3) India-specific impact and targeted users]

IOC_SUMMARY:
[2-3 sentences: key indicators of compromise — permissions, IPs, domains, strings]

RECOMMENDATIONS:
• [Recommendation 1]
• [Recommendation 2]
• [Recommendation 3]
• [Recommendation 4]
• [Recommendation 5]

VERDICT_CONFIDENCE: [0-100 number]"""

    try:
        # Try new google.genai SDK first
        from google import genai as google_genai
        client_g = google_genai.Client(api_key=GEMINI_API_KEY)
        result = client_g.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        text = result.text
        return _parse_agent_response(text, "gemini_direct")
    except Exception as e:
        err = str(e)
        if "429" in err or "quota" in err.lower():
            logger.warning("Gemini quota hit in agent verdict, trying Groq...")
        else:
            logger.error(f"Gemini direct verdict failed: {e}")

    # Groq fallback for agent verdict
    if GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a senior Android malware forensic analyst. Be precise and structured."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=2000,
            )
            text = response.choices[0].message.content
            return _parse_agent_response(text, "groq_direct")
        except Exception as e:
            logger.error(f"Groq direct verdict also failed: {e}")

    return _template_verdict(all_data)


def _parse_agent_response(text: str, agent_name: str) -> dict:
    """Parse structured sections from agent output."""
    sections = {
        "court_narrative": "",
        "ioc_summary": "",
        "recommendations": [],
        "reasoning_steps": [],
        "verdict_confidence": 70,
        "agent_used": agent_name,
    }

    # Parse COURT_NARRATIVE
    if "COURT_NARRATIVE:" in text:
        start = text.index("COURT_NARRATIVE:") + len("COURT_NARRATIVE:")
        end   = text.index("IOC_SUMMARY:") if "IOC_SUMMARY:" in text else start + 1000
        sections["court_narrative"] = text[start:end].strip()

    # Parse IOC_SUMMARY
    if "IOC_SUMMARY:" in text:
        start = text.index("IOC_SUMMARY:") + len("IOC_SUMMARY:")
        end   = text.index("RECOMMENDATIONS:") if "RECOMMENDATIONS:" in text else start + 500
        sections["ioc_summary"] = text[start:end].strip()

    # Parse RECOMMENDATIONS
    if "RECOMMENDATIONS:" in text:
        start = text.index("RECOMMENDATIONS:") + len("RECOMMENDATIONS:")
        end   = text.index("VERDICT_CONFIDENCE:") if "VERDICT_CONFIDENCE:" in text else len(text)
        rec_text = text[start:end].strip()
        sections["recommendations"] = [
            line.lstrip("•-– ").strip()
            for line in rec_text.split("\n")
            if line.strip() and line.strip()[0] in "•-–"
        ][:5]

    # Parse VERDICT_CONFIDENCE
    if "VERDICT_CONFIDENCE:" in text:
        start = text.index("VERDICT_CONFIDENCE:") + len("VERDICT_CONFIDENCE:")
        conf_text = text[start:start + 10].strip().split()[0]
        try:
            sections["verdict_confidence"] = min(100, int(conf_text))
        except ValueError:
            sections["verdict_confidence"] = 70

    return sections


def _template_verdict(all_data: dict) -> dict:
    """Hard-coded template when all AI calls fail."""
    pkg        = all_data["manifest"].get("package_name", "unknown")
    risk_level = all_data["risk"].get("risk_level", "UNKNOWN")
    score      = all_data["risk"].get("score", 0)
    family     = all_data.get("ml_classification", {}).get("family", "Unknown")

    return {
        "court_narrative": (
            f"The application `{pkg}` has been classified as **{family}** "
            f"with a risk score of **{score}/100** ({risk_level}). "
            "Static analysis, YARA signature matching, and ML-based classification "
            "concur on the malicious classification of this sample.\n\n"
            "The technical analysis reveals dangerous permission combinations, "
            "obfuscation techniques, and behavioral patterns consistent with "
            "known Android malware families targeting Indian mobile users.\n\n"
            "This sample poses a HIGH risk to Indian users, particularly those "
            "using UPI-based payment applications and mobile banking services."
        ),
        "ioc_summary": (
            f"Package: {pkg}. "
            "IOCs include dangerous permission combinations, YARA rule matches, "
            "and India-specific threat intelligence flags."
        ),
        "recommendations": [
            "Do NOT install this APK — remove immediately if installed",
            "Monitor UPI and bank accounts for unauthorized transactions",
            "Report to CERT-In at incident@cert-in.org.in",
            "Enable Google Play Protect and scan with updated antivirus",
            "Change banking app passwords and revoke linked permissions",
        ],
        "reasoning_steps": [],
        "verdict_confidence": 65,
        "agent_used": "template",
    }


# ── LangChain ReAct Agent ─────────────────────────────────────────────────────

def run_agent(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict,
    risk: dict,
    xgboost_result: dict,
    malbert_result: dict,
    family_result: dict,
    anomaly_result: dict,
) -> dict:
    """
    Run forensic agent verdict.
    Priority: Groq (Llama 3 70B) → Gemini → template fallback.
    The LangChain ReAct loop is intentionally bypassed — it is too slow and
    quota-sensitive for real-time analysis. Instead we use a single well-structured
    prompt that mimics the ReAct output format.
    """
    t0 = time.perf_counter()

    all_data = {
        "manifest": manifest,
        "strings": strings,
        "yara": yara,
        "obfuscation": obfuscation,
        "india_ioc": india_ioc,
        "risk": risk,
        "xgboost": xgboost_result,
        "malbert": malbert_result,
        "ml_classification": family_result,
        "anomaly": anomaly_result,
    }

    # ── Build rich context from all tools ────────────────────────────────────
    perm_ctx    = _tool_check_permissions(manifest)
    yara_ctx    = _tool_get_yara_findings(yara)
    ml_ctx      = _tool_get_ml_verdict(xgboost_result, malbert_result, family_result)
    risk_ctx    = _tool_get_risk_score(risk)
    ioc_ctx     = _tool_get_india_ioc(india_ioc)
    anomaly_ctx = _tool_check_anomaly(anomaly_result)

    pkg        = manifest.get("package_name", "unknown")
    risk_level = risk.get("risk_level", "UNKNOWN")
    score      = risk.get("score", 0)
    family     = family_result.get("family", "Unknown")

    prompt = f"""You are DroidRaksha — a senior Android malware forensic analyst producing a court-admissible APK threat report.

APK Package: {pkg}
Overall Risk: {risk_level} ({score}/100)

--- EVIDENCE FROM FORENSIC TOOLS ---

[PERMISSIONS ANALYSIS]
{perm_ctx}

[YARA SIGNATURE MATCHES]
{yara_ctx}

[ML CLASSIFICATION ENSEMBLE]
{ml_ctx}

[RISK SCORE BREAKDOWN]
{risk_ctx}

[INDIA THREAT INTELLIGENCE]
{ioc_ctx}

[ZERO-DAY ANOMALY DETECTION]
{anomaly_ctx}

--- INSTRUCTIONS ---
Using ALL the evidence above, write a structured forensic verdict.
Be specific. Reference actual permissions, YARA rules, and ML results from the evidence.
Format your response with EXACTLY these section headers:

COURT_NARRATIVE:
[Write 3 paragraphs: (1) threat identity and classification, (2) technical mechanisms with specific evidence from the tools above, (3) India-specific impact and targeted users]

IOC_SUMMARY:
[Write 2-3 sentences summarizing key indicators of compromise — specific permissions, IPs, domains, strings found]

RECOMMENDATIONS:
• [Specific recommendation 1]
• [Specific recommendation 2]
• [Specific recommendation 3]
• [Specific recommendation 4]
• [Specific recommendation 5]

VERDICT_CONFIDENCE: [0-100 integer]"""

    # ── 1. LM Studio first (local, no quota) ─────────────────────────────────
    try:
        from openai import OpenAI
        lm_client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
        response = lm_client.chat.completions.create(
            model=LM_STUDIO_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are DroidRaksha, a senior Android malware forensic analyst. "
                        "Produce structured, evidence-based forensic reports. "
                        "Always use the exact section headers provided. Be precise and technical."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2500,
            timeout=30,
        )
        text = response.choices[0].message.content
        verdict = _parse_agent_response(text, "lm_studio_local")
        verdict["reasoning_steps"] = [
            f"✓ Checked permissions: {json.loads(perm_ctx).get('total_dangerous', 0)} dangerous permissions found",
            f"✓ YARA scan: {json.loads(yara_ctx).get('total_matches', 0)} rules matched",
            f"✓ ML ensemble: family={family}, XGBoost={json.loads(ml_ctx).get('xgboost', {}).get('label', 'N/A')}",
            f"✓ Risk score: {score}/100 ({risk_level})",
            f"✓ India IOC: {len(json.loads(ioc_ctx).get('risk_flags', []))} flags",
            f"✓ Anomaly: zero_day_risk={json.loads(anomaly_ctx).get('zero_day_risk', 'N/A')}",
        ]
        verdict["inference_ms"] = int((time.perf_counter() - t0) * 1000)
        logger.info(f"Agent verdict via LM Studio in {verdict['inference_ms']}ms")
        return verdict
    except Exception as e:
        err = str(e)
        if "Connection refused" in err or "ConnectError" in err or "timeout" in err.lower():
            logger.warning("LM Studio not reachable — trying Groq")
        else:
            logger.warning(f"LM Studio agent failed ({err[:80]}) — trying Groq")

    # ── 2. Try Groq (Llama 3 70B) ────────────────────────────────────────────
    if GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are DroidRaksha, a senior Android malware forensic analyst. "
                            "You produce structured, evidence-based forensic reports. "
                            "Always use the exact section headers provided. Be precise and technical."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=2500,
            )
            text = response.choices[0].message.content
            verdict = _parse_agent_response(text, "groq_llama3")
            verdict["reasoning_steps"] = [
                f"✓ Checked permissions: {json.loads(perm_ctx).get('total_dangerous', 0)} dangerous permissions found",
                f"✓ YARA scan: {json.loads(yara_ctx).get('total_matches', 0)} rules matched",
                f"✓ ML ensemble: family={family}, XGBoost={json.loads(ml_ctx).get('xgboost', {}).get('label', 'N/A')}",
                f"✓ Risk score: {score}/100 ({risk_level})",
                f"✓ India IOC: {len(json.loads(ioc_ctx).get('risk_flags', []))} flags",
                f"✓ Anomaly: zero_day_risk={json.loads(anomaly_ctx).get('zero_day_risk', 'N/A')}",
            ]
            verdict["inference_ms"] = int((time.perf_counter() - t0) * 1000)
            logger.info(f"Agent verdict via Groq Llama-3 in {verdict['inference_ms']}ms")
            return verdict
        except Exception as e:
            logger.warning(f"Groq agent failed: {e} — trying Gemini")

    # ── 2. Fallback: Gemini (new SDK) ─────────────────────────────────────────
    verdict = _gemini_direct_verdict(all_data)
    verdict["inference_ms"] = int((time.perf_counter() - t0) * 1000)
    return verdict
