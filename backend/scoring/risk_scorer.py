"""
Risk scorer: aggregates results from all engines into a 0-100 risk score.
"""
from __future__ import annotations


SEVERITY_SCORES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
RISK_LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "SAFE"),
]


def calculate(
    manifest: dict,
    strings: dict,
    cert: dict,
    yara: dict,
    obfuscation: dict,
    virustotal: dict,
    abuseipdb: dict,
    india_ioc: dict,
    c2_intelligence: dict | None = None,
) -> dict:
    """Calculate overall risk score and return breakdown."""
    breakdown = {
        "permissions": 0,
        "yara": 0,
        "certificate": 0,
        "threat_intel": 0,
        "obfuscation": 0,
        "india_ioc": 0,
        "strings": 0,
        "c2_confidence": 0,
    }

    # ── Permissions ──────────────────────────────────────────
    dangerous_count = sum(
        1 for p in manifest.get("permissions", []) if p.get("is_dangerous")
    )
    combo_count = len(manifest.get("dangerous_combos", []))
    breakdown["permissions"] = min(10, dangerous_count * 1 + combo_count * 5)

    # ── YARA ──────────────────────────────────────────────────
    yara_score = 0
    for hit in yara.get("matches", []):
        yara_score += SEVERITY_SCORES.get(hit.get("severity", "MEDIUM"), 8)
    breakdown["yara"] = min(30, yara_score)

    # ── Certificate ───────────────────────────────────────────
    # Now using the richer cert_risk_score (0-100) from cert_analyzer.
    # Weighted at max 20 points in the overall risk score (was 5).
    raw_cert_score = cert.get("cert_risk_score", 0)
    trust = cert.get("trust_verdict", "UNVERIFIED")

    if trust == "VERIFIED":
        # Publisher confirmed: cert contributes 0 to risk even if slightly self-signed
        cert_score = 0
    elif trust == "UNTRUSTED":
        cert_score = 20  # max penalty
    elif trust == "EXPIRED":
        cert_score = 12
    elif trust == "PARTIAL":
        cert_score = int(raw_cert_score * 0.1)  # partial trust dampens penalty
    else:
        # UNVERIFIED / UNRECOGNIZED: scale 0-100 cert score down to 0-15
        cert_score = int(min(15, raw_cert_score * 0.15))

    breakdown["certificate"] = cert_score

    # ── Threat Intel ──────────────────────────────────────────
    ti_score = 0
    vt = virustotal
    if vt.get("found") and vt.get("detection_count", 0) > 0:
        ratio = vt["detection_count"] / max(vt["total_engines"], 1)
        ti_score += min(30, int(ratio * 50))
    if abuseipdb.get("max_confidence", 0) > 50:
        ti_score += 10
    breakdown["threat_intel"] = min(40, ti_score)

    # ── Obfuscation ───────────────────────────────────────────
    breakdown["obfuscation"] = min(5, int(obfuscation.get("score", 0) * 0.05))

    # ── India IOC ─────────────────────────────────────────────
    ioc_score = 0
    if india_ioc.get("is_fake_upi"):
        ioc_score += 20
    if india_ioc.get("is_fake_bank"):
        ioc_score += 20
    if india_ioc.get("is_loan_scam"):
        ioc_score += 15
    ioc_score += len(india_ioc.get("matched_ips", [])) * 5
    ioc_score += len(india_ioc.get("matched_domains", [])) * 5
    breakdown["india_ioc"] = min(30, ioc_score)

    # ── Strings ───────────────────────────────────────────────
    string_score = 0
    string_score += len(strings.get("ips", [])) * 1
    string_score += len([u for u in strings.get("urls", []) if u.get("risk") == "high"]) * 2
    string_score += len(strings.get("suspicious_strings", [])) * 1
    breakdown["strings"] = min(10, string_score)

    # ── C2 Intelligence ───────────────────────────────────────
    c2 = c2_intelligence or {}
    c2_score = 0
    if c2.get("c2_framework_detected"):
        frameworks = c2.get("frameworks_detected", [])
        critical_count = sum(1 for f in frameworks if f.get("severity") == "CRITICAL")
        high_count     = sum(1 for f in frameworks if f.get("severity") == "HIGH")
        c2_score += min(30, critical_count * 15 + high_count * 8)
    confirmed_ips = c2.get("confirmed_c2_ips", [])
    c2_score += min(20, len(confirmed_ips) * 5)
    if c2.get("tor_detected"):
        c2_score += 15
    if c2.get("india_c2_domains"):
        c2_score += min(15, len(c2["india_c2_domains"]) * 5)
    breakdown["c2_confidence"] = min(40, c2_score)

    # ── Total ─────────────────────────────────────────────────────
    primary_score = breakdown["yara"] + breakdown["threat_intel"] + breakdown["india_ioc"] + breakdown["c2_confidence"]
    secondary_score = breakdown["permissions"] + breakdown["certificate"] + breakdown["obfuscation"] + breakdown["strings"]
    
    # Cap total score carefully: Max 80 from Primary, Max 20 from Secondary
    total = min(80, primary_score) + min(20, secondary_score)
    total = min(100, total)

    # Map to risk level
    risk_level = "SAFE"
    for threshold, level in RISK_LEVELS:
        if total >= threshold:
            risk_level = level
            break

    # Threat categories
    categories = []
    if india_ioc.get("is_fake_upi") or india_ioc.get("is_fake_bank"):
        categories.append("Banking Trojan")
    if india_ioc.get("is_loan_scam"):
        categories.append("Loan Scam")
    if any("OTP" in h.get("rule", "") or "SMS" in h.get("rule", "") for h in yara.get("matches", [])):
        categories.append("OTP Interceptor")
    if any("Overlay" in h.get("rule", "") or "overlay" in h.get("tags", []) for h in yara.get("matches", [])):
        categories.append("Overlay Attack")
    if obfuscation.get("has_dex_classloader"):
        categories.append("Dropper/Loader")
    if abuseipdb.get("flagged_ips"):
        categories.append("C2 Communication")
    if virustotal.get("malware_families"):
        categories += virustotal["malware_families"][:2]

    return {
        "score": total,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "threat_categories": list(dict.fromkeys(categories)),
    }
