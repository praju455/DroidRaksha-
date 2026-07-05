"""
PCAP Analyzer Engine
Parses .pcap files and extracts:
  - DNS queries and responses
  - HTTP/S host headers and IPs
  - All unique remote IP/port connections
  - C2 beaconing heuristics (repetitive request intervals)
  - India IOC cross-reference (IPs, domains)

Uses dpkt for fast packet iteration — no tshark required.
"""
from __future__ import annotations
import math
import socket
import struct
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from loguru import logger

from backend.engines import beacon_detector, dga_detector

try:
    import dpkt
    DPKT_OK = True
except ImportError:
    DPKT_OK = False
    logger.warning("dpkt not installed — PCAP analysis unavailable")

# ── India IOC lists (lazy-imported so engine is standalone) ──────────────────
INDIA_SUSPICIOUS_DOMAINS = {
    "bhim-upi.xyz", "sbi-alert.net", "phonepe-kyc.com",
    "paytm-reward.club", "npci-verify.co", "aadhaar-update.xyz",
    "hdfc-netbanking.tk", "icici-secure.ml", "axis-otp.ga",
    "google-lotto.cf", "amazon-rewards.gq",
}

INDIA_SUSPICIOUS_IPS = {
    "45.128.232.0/24",   # Known APT-C-23 range
    "185.220.101.0/24",  # Tor exit often abused
}

# ── Beaconing detection parameters ───────────────────────────────────────────
BEACON_MIN_PACKETS   = 5     # Minimum contacts to analyse
BEACON_JITTER_CV     = 0.25  # Coefficient of variation threshold (low = regular)
BEACON_MAX_INTERVAL  = 600   # Max seconds between contacts to be considered

# ── DGA heuristics ───────────────────────────────────────────────────────────
DGA_ENTROPY_THRESHOLD   = 3.8   # High entropy → likely DGA
DGA_MIN_LABEL_LEN       = 12    # Long random subdomain
KNOWN_LEGIT_TLDS = {".com", ".net", ".org", ".in", ".co.in", ".io"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy of a string (bits per char)."""
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _is_private(ip_str: str) -> bool:
    """Quick RFC-1918 / loopback / link-local check."""
    try:
        parts = list(map(int, ip_str.split(".")))
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True
    except Exception:
        pass
    return False


def _coeff_variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return (variance ** 0.5) / mean


def _detect_beaconing(ip_timestamps: dict[str, list[float]]) -> list[dict]:
    """
    For each remote IP that appears ≥ BEACON_MIN_PACKETS times,
    compute inter-arrival intervals and flag those with low jitter.
    """
    alerts = []
    for ip, ts_list in ip_timestamps.items():
        if _is_private(ip):
            continue
        ts_sorted = sorted(ts_list)
        if len(ts_sorted) < BEACON_MIN_PACKETS:
            continue
        intervals = [
            ts_sorted[i + 1] - ts_sorted[i]
            for i in range(len(ts_sorted) - 1)
            if ts_sorted[i + 1] - ts_sorted[i] <= BEACON_MAX_INTERVAL
        ]
        if len(intervals) < BEACON_MIN_PACKETS - 1:
            continue
        cv = _coeff_variation(intervals)
        if cv < BEACON_JITTER_CV:
            avg_interval = sum(intervals) / len(intervals)
            alerts.append({
                "ip": ip,
                "contact_count": len(ts_list),
                "avg_interval_sec": round(avg_interval, 1),
                "jitter_cv": round(cv, 3),
                "confidence": "HIGH" if cv < 0.10 else "MEDIUM",
                "description": (
                    f"Possible C2 beacon — contacted {len(ts_list)}× "
                    f"every {avg_interval:.0f}s (jitter CV={cv:.2f})"
                ),
            })
    detector_result = beacon_detector.analyze_timestamps(ip_timestamps)
    return detector_result.get("alerts") or alerts


def _is_dga(domain: str) -> bool:
    """Simple heuristic DGA detection via entropy + label length."""
    try:
        labels = domain.rstrip(".").split(".")
        if len(labels) < 2:
            return False
        subdomain = labels[0]
        if len(subdomain) < DGA_MIN_LABEL_LEN:
            return False
        return dga_detector.score_domain(domain).get("is_dga", False)
    except Exception:
        return False


# ── Main analyzer ──────────────────────────────────────────────────────────────

def analyze(pcap_path: str | Path, india_ioc_data: Optional[dict] = None, static_endpoints: Optional[list] = None) -> dict:
    """
    Parse a PCAP file and return a structured network report.

    Args:
        pcap_path:      Path to the .pcap file.
        india_ioc_data: Optional pre-computed India IOC data to cross-reference.
        static_endpoints: Optional list of {"url": string, "file": string} extracted from static analysis.

    Returns dict with keys:
        dns_queries, http_hosts, remote_ips, beaconing_alerts,
        dga_suspects, india_ioc_hits, summary, available
    """
    if not DPKT_OK:
        return {"available": False, "error": "dpkt not installed"}

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        return {"available": False, "error": f"PCAP file not found: {pcap_path}"}

    dns_queries: dict[str, int] = {}           # domain → count
    dns_responses: dict[str, list[str]] = {}   # domain → [resolved IPs]
    http_hosts: dict[str, int] = {}            # host → count
    http_uris: list[dict] = []                  # {host, uri, method}
    remote_ips: dict[str, dict] = {}           # ip → {count, ports, first_seen}
    ip_timestamps: dict[str, list[float]] = defaultdict(list)
    tls_sni_hosts: list[str] = []

    packet_count = 0
    parse_errors  = 0

    try:
        with open(pcap_path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)

            for ts, buf in pcap:
                packet_count += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    parse_errors += 1
                    continue

                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                ip_pkt = eth.data
                try:
                    src_ip = socket.inet_ntoa(ip_pkt.src)
                    dst_ip = socket.inet_ntoa(ip_pkt.dst)
                except Exception:
                    try:
                        src_ip = socket.inet_ntop(socket.AF_INET6, ip_pkt.src)
                        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_pkt.dst)
                    except Exception:
                        continue

                # Track remote IPs
                for ip in (src_ip, dst_ip):
                    if not _is_private(ip):
                        if ip not in remote_ips:
                            remote_ips[ip] = {
                                "count": 0, "ports": set(),
                                "first_seen": datetime.utcfromtimestamp(ts).isoformat(),
                            }
                        remote_ips[ip]["count"] += 1
                        ip_timestamps[ip].append(float(ts))

                transport = ip_pkt.data

                # ── DNS ───────────────────────────────────────────────────────
                if isinstance(transport, dpkt.udp.UDP) and (
                    transport.dport == 53 or transport.sport == 53
                ):
                    try:
                        dns = dpkt.dns.DNS(transport.data)
                        for q in dns.qd:
                            domain = q.name.lower().rstrip(".")
                            dns_queries[domain] = dns_queries.get(domain, 0) + 1
                        for ans in dns.an:
                            if ans.type == dpkt.dns.DNS_A:
                                try:
                                    resolved = socket.inet_ntoa(ans.rdata)
                                    dns_responses.setdefault(ans.name.lower().rstrip("."), []).append(resolved)
                                except Exception:
                                    pass
                    except Exception:
                        pass

                # ── HTTP ──────────────────────────────────────────────────────
                if isinstance(transport, dpkt.tcp.TCP):
                    dst_port = transport.dport
                    src_port = transport.sport
                    # Track ports for remote IPs
                    for ip, port in [(dst_ip, dst_port), (src_ip, src_port)]:
                        if not _is_private(ip) and ip in remote_ips:
                            remote_ips[ip]["ports"].add(port)

                    if dst_port == 80 and len(transport.data) > 0:
                        try:
                            req = dpkt.http.Request(transport.data)
                            host = req.headers.get("host", dst_ip)
                            http_hosts[host] = http_hosts.get(host, 0) + 1
                            if len(http_uris) < 200:
                                http_uris.append({
                                    "host": host,
                                    "method": req.method,
                                    "uri": req.uri[:200],
                                })
                        except Exception:
                            pass

                    # TLS SNI extraction (ClientHello)
                    if dst_port == 443 and len(transport.data) > 5:
                        try:
                            raw = bytes(transport.data)
                            if raw[0] == 0x16 and raw[5] == 0x01:  # TLS ClientHello
                                # Walk extensions to find SNI (type 0x0000)
                                pos = 43
                                if pos < len(raw):
                                    session_len = raw[pos]
                                    pos += 1 + session_len
                                    if pos + 2 <= len(raw):
                                        cs_len = struct.unpack("!H", raw[pos:pos+2])[0]
                                        pos += 2 + cs_len + 1 + raw[pos + 2 + cs_len]
                                        pos += 2  # skip extensions length
                                        while pos + 4 <= len(raw):
                                            ext_type = struct.unpack("!H", raw[pos:pos+2])[0]
                                            ext_len  = struct.unpack("!H", raw[pos+2:pos+4])[0]
                                            if ext_type == 0:  # SNI
                                                name_start = pos + 9
                                                name_end   = name_start + struct.unpack("!H", raw[pos+7:pos+9])[0]
                                                sni = raw[name_start:name_end].decode("ascii", errors="ignore")
                                                if sni and sni not in tls_sni_hosts:
                                                    tls_sni_hosts.append(sni)
                                                    http_hosts[sni] = http_hosts.get(sni, 0) + 1
                                                break
                                            pos += 4 + ext_len
                        except Exception:
                            pass

    except Exception as exc:
        logger.error(f"PCAP parse failed: {exc}")
        return {"available": False, "error": str(exc)}

    # ── Post-processing ───────────────────────────────────────────────────────

    # Convert ports sets to sorted lists for JSON serialisation
    # and perform static-to-dynamic correlation
    for ip, ip_data in remote_ips.items():
        ip_data["ports"] = sorted(ip_data["ports"])
        
        # Correlate with static analysis endpoints if available
        static_files = set()
        if static_endpoints:
            for ep in static_endpoints:
                # If the IP is present anywhere in the static URL/IP string
                if ip in str(ep.get("url", "")):
                    static_files.add(ep.get("file"))
        
        ip_data["static_files"] = sorted(list(static_files))

    # C2 beaconing detection
    beaconing_alerts = _detect_beaconing(ip_timestamps)

    # DGA detection
    dga_suspects = [
        dga_detector.score_domain(d, c)
        for d, c in dns_queries.items()
        if _is_dga(d)
    ]

    # India IOC cross-reference
    india_hits: list[dict] = []
    all_domains = set(dns_queries.keys()) | set(http_hosts.keys()) | set(tls_sni_hosts)
    all_ips     = set(remote_ips.keys())

    # Check against hardcoded India suspicious list
    for domain in all_domains:
        for suspect in INDIA_SUSPICIOUS_DOMAINS:
            if suspect in domain:
                india_hits.append({
                    "type": "domain",
                    "value": domain,
                    "reason": f"Matches India suspicious pattern: {suspect}",
                    "severity": "HIGH",
                })

    # Optionally cross-reference passed-in India IOC data
    if india_ioc_data:
        for domain in india_ioc_data.get("matched_domains", []):
            if domain in all_domains:
                india_hits.append({
                    "type": "domain", "value": domain,
                    "reason": "In India IOC database", "severity": "HIGH",
                })
        for ip in india_ioc_data.get("matched_ips", []):
            if ip in all_ips:
                india_hits.append({
                    "type": "ip", "value": ip,
                    "reason": "In India IOC database", "severity": "CRITICAL",
                })

    # Deduplicate India hits
    seen_vals = set()
    unique_india_hits = []
    for h in india_hits:
        if h["value"] not in seen_vals:
            seen_vals.add(h["value"])
            unique_india_hits.append(h)

    # Top remote IPs (by packet count)
    top_ips = sorted(
        [{"ip": ip, **data} for ip, data in remote_ips.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:50]

    # Top DNS queries
    top_dns = sorted(
        [{"domain": d, "count": c} for d, c in dns_queries.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:100]

    # Risk assessment
    pcap_risk = "LOW"
    if len(beaconing_alerts) > 0:
        pcap_risk = "CRITICAL" if any(a["confidence"] == "HIGH" for a in beaconing_alerts) else "HIGH"
    elif len(unique_india_hits) > 0 or len(dga_suspects) > 0:
        pcap_risk = "HIGH"
    elif len(top_ips) > 20:
        pcap_risk = "MEDIUM"

    return {
        "available": True,
        "pcap_risk": pcap_risk,
        "summary": {
            "total_packets": packet_count,
            "parse_errors": parse_errors,
            "unique_remote_ips": len(remote_ips),
            "dns_query_count": len(dns_queries),
            "http_host_count": len(http_hosts),
            "tls_sni_count": len(tls_sni_hosts),
            "beaconing_alerts": len(beaconing_alerts),
            "dga_suspects": len(dga_suspects),
            "india_hits": len(unique_india_hits),
        },
        "dns_queries": top_dns,
        "http_hosts": sorted(
            [{"host": h, "count": c} for h, c in http_hosts.items()],
            key=lambda x: x["count"], reverse=True
        )[:50],
        "http_requests": http_uris[:100],
        "tls_sni": tls_sni_hosts[:50],
        "remote_ips": top_ips,
        "beaconing_alerts": beaconing_alerts,
        "dga_suspects": dga_suspects,
        "india_ioc_hits": unique_india_hits,
    }
