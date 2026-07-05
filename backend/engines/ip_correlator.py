"""
IP Correlator — DroidRaksha Phase: Live Interception Correlation

Compares two IP sets:
  - static_ips : IPs found hardcoded in the APK (from string_extractor)
  - live_flows : Real-time intercepted flows (from intercept_engine)

Returns a CorrelationResult with:
  confirmed_c2   : IPs that are BOTH hardcoded AND calling home → CRITICAL
  static_only    : Hardcoded but not yet seen in live traffic → SUSPICIOUS
  live_only      : Live traffic to IPs not in APK code → UNKNOWN EXTERNAL
  risk           : Overall risk verdict
"""
from __future__ import annotations
from typing import Any


def correlate(static_ips: list[dict], live_flows: list[dict]) -> dict[str, Any]:
    """
    Correlate static IPs (from APK string extraction) with live intercepted flows.

    Args:
        static_ips:  List of {value: str, risk: str, type: str} from string_extractor
        live_flows:  List of {dst_ip: str, host: str, url: str, method: str, ...} from intercept_engine

    Returns correlation dict.
    """
    # Build sets
    static_set: set[str] = {
        item["value"].strip()
        for item in static_ips
        if item.get("value") and _is_valid_ip(item["value"].strip())
    }

    # Live IP set — use dst_ip if available, else skip
    live_ip_set: set[str] = {
        flow["dst_ip"].strip()
        for flow in live_flows
        if flow.get("dst_ip") and _is_valid_ip(flow["dst_ip"].strip())
    }

    # Live host set (for URL matching)
    live_hosts: set[str] = {
        flow["host"].strip().lower()
        for flow in live_flows
        if flow.get("host")
    }

    # ── Correlation sets ──────────────────────────────────────────────────────
    confirmed  = static_set & live_ip_set          # CRITICAL
    static_only = static_set - live_ip_set         # Hardcoded but not seen live
    live_only  = live_ip_set - static_set          # Live but not in APK

    # ── Build detail objects ──────────────────────────────────────────────────
    confirmed_details = []
    for ip in sorted(confirmed):
        static_entry = _find_static(ip, static_ips)
        live_entries = [f for f in live_flows if f.get("dst_ip") == ip]
        confirmed_details.append({
            "ip":           ip,
            "verdict":      "CONFIRMED_C2",
            "risk":         "CRITICAL",
            "label":        "Encoded in APK + Live Traffic Detected",
            "static_risk":  static_entry.get("risk", "high") if static_entry else "high",
            "live_calls":   len(live_entries),
            "methods":      list({f["method"] for f in live_entries if f.get("method")}),
            "hosts":        list({f["host"] for f in live_entries if f.get("host")}),
            "urls":         [f["url"] for f in live_entries[:3] if f.get("url")],
            "tls":          any(f.get("tls") for f in live_entries),
            "first_seen":   min((f["ts"] for f in live_entries if f.get("ts")), default=0),
        })

    static_only_details = []
    for ip in sorted(static_only):
        static_entry = _find_static(ip, static_ips)
        static_only_details.append({
            "ip":       ip,
            "verdict":  "STATIC_ONLY",
            "risk":     static_entry.get("risk", "medium") if static_entry else "medium",
            "label":    "Hardcoded in APK — not seen in live traffic yet",
        })

    live_only_details = []
    for ip in sorted(live_only):
        live_entries = [f for f in live_flows if f.get("dst_ip") == ip]
        live_only_details.append({
            "ip":       ip,
            "verdict":  "LIVE_ONLY",
            "risk":     "high",
            "label":    "Live traffic destination — not hardcoded in APK",
            "live_calls": len(live_entries),
            "hosts":    list({f["host"] for f in live_entries if f.get("host")}),
            "urls":     [f["url"] for f in live_entries[:2] if f.get("url")],
            "tls":      any(f.get("tls") for f in live_entries),
        })

    # ── Overall risk ──────────────────────────────────────────────────────────
    if confirmed:
        risk = "CRITICAL"
    elif live_only:
        risk = "HIGH"
    elif static_only:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # ── Unique live hosts (for display) ──────────────────────────────────────
    live_host_list = []
    seen_hosts: set[str] = set()
    for f in live_flows:
        h = f.get("host", "")
        if h and h not in seen_hosts:
            seen_hosts.add(h)
            live_host_list.append({
                "host":   h,
                "ip":     f.get("dst_ip", ""),
                "tls":    f.get("tls", False),
                "method": f.get("method", ""),
                "status": f.get("status", 0),
                "confirmed": f.get("dst_ip", "") in confirmed,
            })

    return {
        "risk":               risk,
        "total_static_ips":   len(static_set),
        "total_live_ips":     len(live_ip_set),
        "confirmed_c2":       confirmed_details,
        "static_only":        static_only_details,
        "live_only":          live_only_details,
        "live_hosts":         live_host_list[:50],
        "match_count":        len(confirmed),
        "total_live_flows":   len(live_flows),
        "summary": (
            f"CRITICAL: {len(confirmed)} IPs hardcoded in APK AND actively calling home. "
            if confirmed else
            f"{len(live_only)} unknown external IPs contacted during session. "
            if live_only else
            f"No live traffic correlated with static IPs. {len(static_only)} encoded IPs not yet seen."
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_valid_ip(ip: str) -> bool:
    """Basic IPv4 validation — also skip private/loopback."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        vals = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= v <= 255 for v in vals):
        return False
    # Skip private / loopback / link-local
    if vals[0] in (10, 127):
        return False
    if vals[0] == 172 and 16 <= vals[1] <= 31:
        return False
    if vals[0] == 192 and vals[1] == 168:
        return False
    if vals[0] == 169 and vals[1] == 254:
        return False
    if vals[0] == 0:
        return False
    return True


def _find_static(ip: str, static_ips: list[dict]) -> dict | None:
    for item in static_ips:
        if item.get("value", "").strip() == ip:
            return item
    return None
