"""
C2 Intelligence Engine — DroidRaksha
=====================================
Detects Command & Control infrastructure indicators from static APK analysis.

Combines:
  - C2 framework fingerprinting (Cobalt Strike, Metasploit, AndroRAT, SpyNote, etc.)
  - Beacon pattern detection (periodic HTTP call proximity in smali)
  - Tor / dark-web routing detection
  - Fast-flux / multi-IP domain indicators
  - IP geolocation risk scoring (datacenter hosting, high-risk ASNs)
  - India-specific C2 patterns (RBI/UPI lookalike C2 domains)
"""
from __future__ import annotations

import re
import math
from collections import Counter
from urllib.parse import urlparse
from loguru import logger


# ── C2 Framework Signatures ───────────────────────────────────────────────────
# Strings found in smali bytecode that indicate known RAT / C2 frameworks

C2_FRAMEWORKS: dict[str, dict] = {
    "AndroRAT": {
        "severity": "CRITICAL",
        "description": "Open-source Android Remote Access Trojan. Full device control.",
        "patterns": [
            r"androrat", r"rat\.apk", r"com\.androrat", r"myServer\.start",
            r"AudioCapture", r"FileManager.*send", r"getGPS.*interval",
        ],
    },
    "AhMyth": {
        "severity": "CRITICAL",
        "description": "AhMyth RAT — camera, microphone, SMS, file exfiltration.",
        "patterns": [
            r"ahmyth", r"AhMyth", r"io\.github\.sangrobot",
            r"socket\.connect.*myip", r"FileManager.*socket",
        ],
    },
    "SpyNote": {
        "severity": "CRITICAL",
        "description": "SpyNote RAT — keylogger, screen capture, live streaming.",
        "patterns": [
            r"spynote", r"SpyNote", r"com\.craxsrat", r"CRAXSRAT",
            r"KeyLog.*socket", r"ScreenCapture.*stream",
        ],
    },
    "DarkComet": {
        "severity": "CRITICAL",
        "description": "DarkComet RAT — widely used in targeted attacks.",
        "patterns": [
            r"DarkComet", r"darkcomet", r"DARK_COMET",
            r"DC2\.Ping", r"SuspendSvc",
        ],
    },
    "Metasploit": {
        "severity": "CRITICAL",
        "description": "Metasploit Meterpreter stager detected.",
        "patterns": [
            r"meterpreter", r"Meterpreter", r"metasploit",
            r"stageless.*payload", r"reverse_tcp", r"reverse_https",
            r"com/metasploit",
        ],
    },
    "Cobalt Strike": {
        "severity": "CRITICAL",
        "description": "Cobalt Strike beacon implant. Used by APT groups.",
        "patterns": [
            r"cobaltstrike", r"CobaltStrike", r"beacon\.dll",
            r"ReflectiveDll", r"MalleableC2", r"sleep.*jitter",
            r"checksum8",
        ],
    },
    "njRAT": {
        "severity": "CRITICAL",
        "description": "njRAT — common in Middle East / South Asia attacks.",
        "patterns": [
            r"njrat", r"njRAT", r"bladabindi",
            r"LimeRAT", r"nj-rat",
        ],
    },
    "Cerberus / Alien": {
        "severity": "CRITICAL",
        "description": "Cerberus banking trojan / Alien successor. Targets Indian banking apps.",
        "patterns": [
            r"cerberus", r"Cerberus", r"alien\.apk",
            r"grabber.*clipboard", r"injectView.*overlay",
            r"AccessibilityService.*bank",
        ],
    },
    "Anubis": {
        "severity": "CRITICAL",
        "description": "Anubis banking trojan. Active in India targeting UPI apps.",
        "patterns": [
            r"anubis", r"Anubis", r"anubisnetworks",
            r"overlay.*paytm", r"overlay.*phonepe", r"overlay.*gpay",
        ],
    },
    "Generic_HTTP_Beacon": {
        "severity": "HIGH",
        "description": "Generic HTTP C2 beacon pattern (periodic HTTP call near sleep()).",
        "patterns": [
            r"Thread\.sleep.*\d{4,}.*HttpURLConnection",
            r"HttpURLConnection.*Thread\.sleep.*\d{4,}",
            r"Timer.*HttpPost",
            r"ScheduledExecutorService.*HttpClient",
        ],
    },
    "DNS_Tunneling": {
        "severity": "HIGH",
        "description": "DNS tunneling C2 channel — data exfil over DNS TXT/MX queries.",
        "patterns": [
            r"DnsResolver.*TXT", r"TYPE_TXT", r"queryType.*txt",
            r"base64.*dns", r"dns.*exfil",
            r"iodine", r"dnscat",
        ],
    },
}

# ── Tor / Dark Web Indicators ─────────────────────────────────────────────────
TOR_PATTERNS = [
    r"\.onion",
    r"orbot", r"Orbot",
    r"torproject",
    r"SOCKS5.*127\.0\.0\.1.*9050",
    r"Socks5Proxy.*9150",
]

# ── High-Risk Hosting ASNs (known C2/bulletproof hosters) ────────────────────
HIGH_RISK_ASNS = {
    "AS9009":  "M247 Europe (bulletproof hoster)",
    "AS59253": "Leaseweb Asia (frequent C2 host)",
    "AS62282": "FranTech Solutions (bulletproof)",
    "AS174":   "Cogent (frequent C2 upstream)",
    "AS3223":  "Voxility (DDoS botnet hosting)",
    "AS8075":  "Microsoft Azure (common attacker infra)",
    "AS16509": "Amazon AWS (common attacker infra)",
    "AS15169": "Google Cloud (common attacker infra)",
}

# ── High-Risk Country Codes for C2 hosting ───────────────────────────────────
HIGH_RISK_COUNTRIES = {
    "RU": ("Russia", 90),
    "KP": ("North Korea", 95),
    "CN": ("China", 70),
    "IR": ("Iran", 85),
    "NG": ("Nigeria", 60),
    "RO": ("Romania", 50),
}

# ── India-specific C2 domain patterns ────────────────────────────────────────
INDIA_C2_DOMAINS = [
    r"rbi-verify\.", r"paytm-secure\.", r"upi-alert\.",
    r"aadhaar-update\.", r"sbi-kyc\.", r"hdfc-otp\.",
    r"icici-verify\.", r"axis-bank-alert\.",
    r"gov\.in\.[a-z0-9-]+\.", r"india-cert\.",
]


# ── Core Detection Functions ──────────────────────────────────────────────────

def _scan_content_for_frameworks(content: str) -> list[dict]:
    """Scan raw smali/string content for C2 framework signatures."""
    detected = []
    for framework, info in C2_FRAMEWORKS.items():
        for pattern in info["patterns"]:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                detected.append({
                    "framework": framework,
                    "severity":  info["severity"],
                    "description": info["description"],
                    "matched_pattern": pattern,
                })
                break  # one match per framework is enough
    return detected


def _detect_tor(content: str) -> bool:
    """Check for Tor routing indicators."""
    for pattern in TOR_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


def _detect_india_c2_domains(urls: list[str]) -> list[str]:
    """Find India-specific phishing/C2 domains in extracted URLs."""
    flagged = []
    for url in urls:
        for pattern in INDIA_C2_DOMAINS:
            if re.search(pattern, url, re.IGNORECASE):
                flagged.append(url)
                break
    return list(set(flagged))


def _score_ip_geo_risk(flagged_ips: list[dict]) -> list[dict]:
    """
    Add geo-risk scoring to AbuseIPDB flagged IPs.
    Enriches each IP dict with risk_reason and geo_risk_score.
    """
    enriched = []
    for ip_info in flagged_ips:
        country = ip_info.get("country", "??")
        usage   = ip_info.get("usage_type", "")
        isp     = ip_info.get("isp", "")

        geo_risk = 0
        reasons  = []

        if country in HIGH_RISK_COUNTRIES:
            name, score = HIGH_RISK_COUNTRIES[country]
            geo_risk += score
            reasons.append(f"High-risk country: {name}")

        if "Data Center" in usage or "Hosting" in usage or "VPN" in usage:
            geo_risk += 25
            reasons.append(f"Datacenter/hosting ASN ({usage})")

        for asn_id, asn_desc in HIGH_RISK_ASNS.items():
            if asn_id in isp or asn_desc.split()[0] in isp:
                geo_risk += 30
                reasons.append(f"Known bulletproof/attacker ASN: {asn_desc}")
                break

        enriched.append({
            **ip_info,
            "geo_risk_score": min(geo_risk, 100),
            "geo_risk_reasons": reasons,
            "c2_probability": "HIGH" if geo_risk >= 50 else "MEDIUM" if geo_risk >= 25 else "LOW",
        })
    return enriched


# ── Main Analyzer ─────────────────────────────────────────────────────────────

def analyze(
    strings: dict,
    sandbox_smali: dict | None,
    abuseipdb_result: dict,
    urls: list[str],
) -> dict:
    """
    Full C2 intelligence analysis.

    Args:
        strings:          Output from string_extractor (contains ips, urls, suspicious_strings)
        sandbox_smali:    Output from sandbox smali walker (critical_apis, network_endpoints, etc.)
        abuseipdb_result: Output from abuseipdb.analyze (flagged_ips)
        urls:             All URL strings extracted from the APK

    Returns:
        Structured C2 intelligence result dict
    """

    # Build combined content to scan
    all_text_parts = []

    # From string extractor
    for item in strings.get("suspicious_strings", []):
        all_text_parts.append(item.get("value", ""))
    for item in strings.get("urls", []):
        all_text_parts.append(item.get("value", ""))

    # From sandbox smali results
    if sandbox_smali:
        for api in sandbox_smali.get("critical_apis", []):
            all_text_parts.append(api.get("api", ""))
        for ep in sandbox_smali.get("network_endpoints", []):
            all_text_parts.append(str(ep))
        for dtype, items in sandbox_smali.get("sensitive_data", {}).items():
            for item in items:
                all_text_parts.append(item.get("snippet", ""))

    combined_content = "\n".join(all_text_parts)

    # ── Framework detection ──────────────────────────────────────────────────
    frameworks_detected = _scan_content_for_frameworks(combined_content)

    # ── Tor detection ────────────────────────────────────────────────────────
    tor_detected = _detect_tor(combined_content)

    # ── India C2 domain patterns ──────────────────────────────────────────────
    india_c2_domains = _detect_india_c2_domains(urls)

    # ── IP geo-risk enrichment ────────────────────────────────────────────────
    raw_flagged = abuseipdb_result.get("flagged_ips", [])
    enriched_ips = _score_ip_geo_risk(raw_flagged)

    # High-confidence C2 IPs (abuse confidence > 70 OR geo risk HIGH)
    confirmed_c2_ips = [
        ip for ip in enriched_ips
        if ip.get("confidence", 0) >= 70 or ip.get("c2_probability") == "HIGH"
    ]

    # ── Beacon pattern detection from smali ──────────────────────────────────
    beacon_patterns_found = []
    if sandbox_smali:
        anti = sandbox_smali.get("antianalysis", {})
        # If the APK checks for debuggers/emulators AND has network endpoints,
        # that's a classic C2 beacon pattern
        has_network = bool(sandbox_smali.get("network_endpoints"))
        has_timer_patterns = any(
            re.search(r"sleep|Timer|Executor|Handler.*postDelayed", api.get("api", ""), re.IGNORECASE)
            for api in sandbox_smali.get("high_apis", [])
        )
        if has_network and has_timer_patterns:
            beacon_patterns_found.append("Periodic network call pattern (timer + HTTP)")
        if anti.get("emulator_detect") and has_network:
            beacon_patterns_found.append("Emulator detection + network = evasive beacon")
        if anti.get("debugger_detect") and has_network:
            beacon_patterns_found.append("Anti-debug + network = C2 evasion pattern")

    # ── Overall C2 confidence score ──────────────────────────────────────────
    c2_score = 0
    c2_verdict = "NONE"

    # Framework hits are near-certain
    critical_frameworks = [f for f in frameworks_detected if f["severity"] == "CRITICAL"]
    high_frameworks     = [f for f in frameworks_detected if f["severity"] == "HIGH"]
    c2_score += len(critical_frameworks) * 40
    c2_score += len(high_frameworks) * 20

    # Confirmed C2 IPs
    c2_score += len(confirmed_c2_ips) * 15

    # Tor
    if tor_detected:
        c2_score += 30

    # India phishing domains
    c2_score += len(india_c2_domains) * 10

    # Beacon patterns
    c2_score += len(beacon_patterns_found) * 10

    c2_score = min(c2_score, 100)

    if c2_score >= 70:
        c2_verdict = "CONFIRMED"
    elif c2_score >= 40:
        c2_verdict = "LIKELY"
    elif c2_score >= 15:
        c2_verdict = "SUSPECTED"
    else:
        c2_verdict = "NONE"

    result = {
        "c2_verdict":          c2_verdict,
        "c2_confidence_score": c2_score,
        "frameworks_detected": frameworks_detected,
        "c2_framework_detected": bool(frameworks_detected),
        "confirmed_c2_ips":    confirmed_c2_ips,
        "all_flagged_ips":     enriched_ips,
        "beacon_patterns":     beacon_patterns_found,
        "tor_detected":        tor_detected,
        "india_c2_domains":    india_c2_domains,
        "summary": _build_summary(c2_verdict, frameworks_detected, confirmed_c2_ips, tor_detected),
    }

    logger.info(
        f"C2 detection complete: verdict={c2_verdict} score={c2_score} "
        f"frameworks={len(frameworks_detected)} c2_ips={len(confirmed_c2_ips)}"
    )
    return result


def _build_summary(
    verdict: str,
    frameworks: list[dict],
    c2_ips: list[dict],
    tor: bool,
) -> str:
    if verdict == "NONE":
        return "No C2 infrastructure indicators detected."

    parts = []
    if frameworks:
        names = list({f["framework"] for f in frameworks})
        parts.append(f"C2 framework(s) detected: {', '.join(names)}")
    if c2_ips:
        parts.append(f"{len(c2_ips)} confirmed C2 IP(s) found")
    if tor:
        parts.append("Tor/anonymous routing detected")
    return f"[{verdict}] " + ". ".join(parts) + "."
