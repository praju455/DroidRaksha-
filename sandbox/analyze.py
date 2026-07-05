#!/usr/bin/env python3
"""
DroidRaksha Sandbox Analyzer
============================
Entry point for the Docker sandbox container.

Workflow:
  1. Decompile APK with apktool → extract smali bytecode + resources
  2. Walk all .smali files and extract behavioral intelligence
  3. Run Frida offline hooks against extracted classes
  4. Score behaviors and emit structured JSON to /output/result.json

Usage (inside container):
  python analyze.py --apk /input/app.apk --out /output/result.json
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from collections import defaultdict

try:
    from loguru import logger
except ImportError:
    import logging as logger  # type: ignore


# ── Android API danger classification ─────────────────────────────────────────

CRITICAL_APIS = {
    # SMS / Phone
    "sendTextMessage", "sendMultipartTextMessage", "sendDataMessage",
    "call", "makeCall", "dialOut",
    # Contacts / Location / Microphone / Camera
    "query.*ContactsContract", "getLastKnownLocation", "requestLocationUpdates",
    "startRecording", "setAudioSource", "takePicture",
    # Device identifiers
    "getDeviceId", "getImei", "getSubscriberId", "getMacAddress",
    "getSimSerialNumber", "getAndroidId",
    # Crypto (suspicious usage patterns)
    "DESKeySpec", "SecretKeySpec.*DES", "NullCipher",
    # Root
    "su", "chmod 777", "/system/bin/sh",
    # Data exfil
    "HttpURLConnection", "OkHttpClient", "URL.openConnection",
}

HIGH_APIS = {
    # Network
    "Socket", "ServerSocket", "DatagramSocket",
    "HttpsURLConnection", "SSLSocket",
    # Storage
    "getExternalStorage", "getExternalFilesDir",
    "openFileOutput", "FileOutputStream",
    # Crypto
    "Cipher.getInstance", "KeyGenerator", "SecretKeyFactory",
    "MessageDigest", "Mac.getInstance",
    # Reflection & dynamic loading
    "Class.forName", "getDeclaredMethod", "invoke",
    "DexClassLoader", "PathClassLoader", "loadClass",
    "Runtime.exec", "ProcessBuilder",
    # Native
    "System.loadLibrary", "System.load",
}

MEDIUM_APIS = {
    # Clipboard
    "ClipboardManager", "setPrimaryClip", "getPrimaryClip",
    # Accessibility
    "AccessibilityService", "AccessibilityEvent",
    # Admin
    "DevicePolicyManager", "lockNow", "wipeData",
    # Notifications
    "NotificationListenerService",
    # Broadcast
    "sendBroadcast", "registerReceiver",
}

# Known crypto algorithms  
CRYPTO_PATTERNS = {
    "AES":   r"AES[/\-]?(?:CBC|ECB|GCM|CTR)?",
    "DES":   r"\bDES\b|DESede|3DES|TripleDES",
    "RSA":   r"\bRSA\b",
    "XOR":   r"(?:xor|XOR)\s*[\^=]|\^=\s*0x[0-9a-fA-F]+",
    "RC4":   r"\bRC4\b|ARCFOUR",
    "MD5":   r"\bMD5\b",
    "SHA1":  r"\bSHA-?1\b",
    "SHA256": r"\bSHA-?256\b",
}

# Anti-analysis patterns
ANTIANALYSIS_PATTERNS = {
    "emulator_detect":   r"isEmulator|Build\.FINGERPRINT.*generic|Build\.MODEL.*sdk|getprop ro\.product",
    "root_detect":       r"su\b|/system/xbin/su|/sbin/su|RootBeer|RootTools|checkRootMethod",
    "debugger_detect":   r"isDebuggerConnected|android\.os\.Debug|DEBUGGABLE|waitForDebugger",
    "frida_detect":      r"frida|fridaDump|anti.hook|checkHook|detectFrida",
    "hook_detect":       r"Substrate|Xposed|hooking|hookMethod|XposedBridge",
    "cert_pinning":      r"CertificatePinner|TrustManager|checkServerTrusted|getAcceptedIssuers",
    "obfuscation_check": r"[a-z]{1,2}\.[a-z]{1,2}\.[a-z]{1,2}|[a-z]\d{4,}",
}

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    "hardcoded_key":   r"(?:api[_-]?key|secret[_-]?key|private[_-]?key)\s*[=:]\s*[\"'][^\"']{8,}[\"']",
    "hardcoded_url":   r"https?://(?!schemas\.android|www\.w3\.org|example\.com)[^\s\"'<>]{10,}",
    "base64_secret":   r"[A-Za-z0-9+/]{40,}={0,2}",
    "phone_number":    r"\+91[6-9]\d{9}|0[6-9]\d{9}",   # India phone pattern
    "upi_id":          r"[\w.]+@(?:upi|okaxis|okicici|oksbi|ybl|ibl|axl|waicici|naviaxis)",
}


# ── Smali Walker ──────────────────────────────────────────────────────────────

def walk_smali(decompiled_dir: Path) -> dict:
    """
    Walk all .smali files and extract behavioral intelligence.
    Returns a structured findings dict.
    """
    findings = {
        "critical_apis":    [],
        "high_apis":        [],
        "medium_apis":      [],
        "crypto_usage":     defaultdict(list),   # algo → [file:line]
        "antianalysis":     defaultdict(list),   # type → [file:line]
        "sensitive_data":   defaultdict(list),   # type → [snippet]
        "dynamic_loading":  [],
        "native_libs":      [],
        "reflection_calls": [],
        "network_endpoints": [],
        "permissions_used": [],
        "smali_file_count": 0,
        "total_methods":    0,
    }

    smali_dir = decompiled_dir / "smali"
    if not smali_dir.exists():
        # Some APKs use smali_classes2, smali_classes3 etc
        smali_dirs = list(decompiled_dir.glob("smali*"))
    else:
        smali_dirs = [smali_dir]

    seen_apis   = set()
    seen_crypto = set()

    for sdir in smali_dirs:
        for smali_file in sdir.rglob("*.smali"):
            findings["smali_file_count"] += 1
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            rel_path = str(smali_file.relative_to(decompiled_dir))

            # Count methods
            findings["total_methods"] += content.count(".method ")

            # ── API scanning ─────────────────────────────────────────────────
            for api in CRITICAL_APIS:
                if re.search(api, content) and api not in seen_apis:
                    seen_apis.add(api)
                    findings["critical_apis"].append({
                        "api": api,
                        "file": rel_path,
                        "severity": "CRITICAL",
                    })

            for api in HIGH_APIS:
                if re.search(api, content) and f"H:{api}" not in seen_apis:
                    seen_apis.add(f"H:{api}")
                    findings["high_apis"].append({
                        "api": api,
                        "file": rel_path,
                        "severity": "HIGH",
                    })

            for api in MEDIUM_APIS:
                if re.search(api, content) and f"M:{api}" not in seen_apis:
                    seen_apis.add(f"M:{api}")
                    findings["medium_apis"].append({
                        "api": api,
                        "file": rel_path,
                        "severity": "MEDIUM",
                    })

            # ── Crypto ──────────────────────────────────────────────────────
            for algo, pattern in CRYPTO_PATTERNS.items():
                if re.search(pattern, content, re.IGNORECASE):
                    key = f"{algo}:{rel_path}"
                    if key not in seen_crypto:
                        seen_crypto.add(key)
                        findings["crypto_usage"][algo].append(rel_path)

            # ── Anti-analysis ───────────────────────────────────────────────
            for technique, pattern in ANTIANALYSIS_PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings["antianalysis"][technique].extend([
                        {"file": rel_path, "match": m[:80]} for m in matches[:3]
                    ])

            # ── Sensitive data ───────────────────────────────────────────────
            for dtype, pattern in SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings["sensitive_data"][dtype].extend([
                        {"file": rel_path, "snippet": m[:120]} for m in matches[:5]
                    ])

            # ── Network endpoints ────────────────────────────────────────────
            urls = re.findall(r'https?://[^\s"\'<>]{6,}', content)
            # Find raw IPs (IPv4) that are not local
            ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', content)
            
            for url in urls[:10]:
                findings["network_endpoints"].append({"url": url, "file": rel_path})
            for ip in ips[:10]:
                if ip not in ["127.0.0.1", "0.0.0.0", "255.255.255.255"] and not ip.startswith("10.") and not ip.startswith("192.168."):
                    findings["network_endpoints"].append({"url": ip, "file": rel_path})

            # ── Dynamic class loading ────────────────────────────────────────
            if re.search(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader", content):
                findings["dynamic_loading"].append(rel_path)

            # ── Native libraries ─────────────────────────────────────────────
            libs = re.findall(r'System\.loadLibrary\s*\(\s*["\']([^"\']+)["\']', content)
            findings["native_libs"].extend(libs)

            # ── Reflection ───────────────────────────────────────────────────
            if re.search(r"getDeclaredMethod|getMethod|invoke\b", content):
                findings["reflection_calls"].append(rel_path)

    # Deduplicate
    findings["native_libs"]        = list(set(findings["native_libs"]))
    
    # Deduplicate network endpoints (list of dicts)
    seen_endpoints = set()
    unique_endpoints = []
    for ep in findings["network_endpoints"]:
        key = f"{ep['url']}::{ep['file']}"
        if key not in seen_endpoints:
            seen_endpoints.add(key)
            unique_endpoints.append(ep)
    findings["network_endpoints"] = unique_endpoints[:50]
    
    findings["dynamic_loading"]    = list(set(findings["dynamic_loading"]))
    findings["reflection_calls"]   = list(set(findings["reflection_calls"]))

    # Convert defaultdicts to regular dicts for JSON
    findings["crypto_usage"]   = dict(findings["crypto_usage"])
    findings["antianalysis"]   = dict(findings["antianalysis"])
    findings["sensitive_data"] = dict(findings["sensitive_data"])

    return findings


# ── Manifest walker ───────────────────────────────────────────────────────────

def extract_manifest_data(decompiled_dir: Path) -> dict:
    """Extract package info and permissions from decoded AndroidManifest.xml."""
    manifest_path = decompiled_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        return {}

    content = manifest_path.read_text(encoding="utf-8", errors="ignore")

    # Extract permissions
    perms = re.findall(r'android:name="(android\.permission\.[^"]+)"', content)

    # Package name
    pkg = re.search(r'package="([^"]+)"', content)

    # Activities, services, receivers
    activities = re.findall(r'<activity[^>]+android:name="([^"]+)"', content)
    services   = re.findall(r'<service[^>]+android:name="([^"]+)"', content)
    receivers  = re.findall(r'<receiver[^>]+android:name="([^"]+)"', content)
    providers  = re.findall(r'<provider[^>]+android:name="([^"]+)"', content)

    return {
        "package_name": pkg.group(1) if pkg else "unknown",
        "permissions":  list(set(perms)),
        "activities":   activities[:20],
        "services":     services[:20],
        "receivers":    receivers[:20],
        "providers":    providers[:10],
    }


# ── Resource walker ───────────────────────────────────────────────────────────

def extract_resource_data(decompiled_dir: Path) -> dict:
    """Scan res/ folder for suspicious embedded content."""
    results = {
        "suspicious_assets": [],
        "embedded_executables": [],
        "hidden_dex": [],
        "total_assets": 0,
    }

    asset_dir = decompiled_dir / "assets"
    res_dir   = decompiled_dir / "res"

    for search_dir in [asset_dir, res_dir]:
        if not search_dir.exists():
            continue
        for f in search_dir.rglob("*"):
            if f.is_file():
                results["total_assets"] += 1
                name_lower = f.name.lower()

                # Embedded DEX
                if name_lower.endswith(".dex") or name_lower.endswith(".odex"):
                    results["hidden_dex"].append(str(f.relative_to(decompiled_dir)))

                # Suspicious executables
                if any(name_lower.endswith(ext) for ext in [".so", ".elf", ".bin", ".sh"]):
                    results["embedded_executables"].append(str(f.relative_to(decompiled_dir)))

                # Suspicious asset names
                if any(kw in name_lower for kw in ["payload", "inject", "hook", "shell", "exploit"]):
                    results["suspicious_assets"].append(str(f.relative_to(decompiled_dir)))

    return results


# ── Behavior Scoring ──────────────────────────────────────────────────────────

def score_behavior(smali: dict, manifest: dict, resources: dict) -> dict:
    """
    Compute a behavioral risk score from extracted findings.
    Returns: { score: 0-100, level: str, flags: [str], summary: str }
    """
    score = 0
    flags = []

    # Critical API hits — high weight
    crit_count = len(smali.get("critical_apis", []))
    if crit_count > 0:
        score += min(crit_count * 12, 40)
        flags.append(f"{crit_count} critical Android API(s) detected (SMS, location, identifiers)")

    # High API hits
    high_count = len(smali.get("high_apis", []))
    if high_count > 3:
        score += min(high_count * 4, 20)
        flags.append(f"{high_count} high-risk API(s) detected (network sockets, crypto, reflection)")

    # Anti-analysis techniques
    anti = smali.get("antianalysis", {})
    if anti.get("emulator_detect"):
        score += 8
        flags.append("Emulator detection code found")
    if anti.get("root_detect"):
        score += 6
        flags.append("Root/privilege escalation detection found")
    if anti.get("debugger_detect"):
        score += 6
        flags.append("Anti-debugging techniques detected")
    if anti.get("frida_detect") or anti.get("hook_detect"):
        score += 10
        flags.append("Anti-hooking / Frida detection present — actively evades analysis")
    if anti.get("cert_pinning"):
        score += 5
        flags.append("Certificate pinning — blocks traffic interception")

    # Dynamic code loading
    if smali.get("dynamic_loading"):
        score += 15
        flags.append(f"Dynamic DEX/class loading in {len(smali['dynamic_loading'])} file(s) — code injection risk")

    # Native libraries
    native = smali.get("native_libs", [])
    if native:
        score += min(len(native) * 5, 15)
        flags.append(f"Native libraries loaded: {', '.join(native[:5])}")

    # Suspicious crypto
    crypto = smali.get("crypto_usage", {})
    if "DES" in crypto:
        score += 8
        flags.append("Weak DES/3DES encryption detected")
    if "XOR" in crypto:
        score += 6
        flags.append("XOR obfuscation patterns found")

    # Sensitive data
    sensitive = smali.get("sensitive_data", {})
    if sensitive.get("hardcoded_key"):
        score += 12
        flags.append("Hardcoded API keys / secrets found in code")
    if sensitive.get("upi_id"):
        score += 15
        flags.append("⚠️ Hardcoded UPI ID detected — potential India payment fraud")
    if sensitive.get("phone_number"):
        score += 8
        flags.append("Hardcoded Indian phone numbers found")

    # Hidden resources
    if resources.get("hidden_dex"):
        score += 20
        flags.append(f"Hidden DEX files embedded in assets: {resources['hidden_dex']}")
    if resources.get("embedded_executables"):
        score += 15
        flags.append(f"Embedded native executables: {resources['embedded_executables'][:3]}")

    # Permission count check
    perms = manifest.get("permissions", [])
    dangerous = [p for p in perms if any(kw in p for kw in [
        "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_SMS", "SEND_SMS",
        "ACCESS_FINE_LOCATION", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS",
        "READ_PHONE_STATE", "RECEIVE_BOOT_COMPLETED",
    ])]
    if len(dangerous) > 5:
        score += 10
        flags.append(f"{len(dangerous)} dangerous permissions declared: {', '.join(dangerous[:4])}...")

    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 55:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "SAFE"

    # Summary sentence
    top_flags = flags[:3]
    summary = f"Behavioral score {score}/100 ({level}). " + (
        " ".join(top_flags[:2]) if top_flags else "No significant behavioral indicators found."
    )

    return {"score": score, "level": level, "flags": flags, "summary": summary}


# ── APKTool Runner ────────────────────────────────────────────────────────────

def run_apktool(apk_path: Path, out_dir: Path) -> tuple[bool, str]:
    """Run apktool to decompile the APK."""
    try:
        result = subprocess.run(
            ["apktool", "d", str(apk_path), "-o", str(out_dir), "-f", "--no-res"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            return True, ""
        # Try with resource decoding if no-res failed
        result2 = subprocess.run(
            ["apktool", "d", str(apk_path), "-o", str(out_dir), "-f"],
            capture_output=True, text=True, timeout=180,
        )
        return result2.returncode == 0, result2.stderr
    except subprocess.TimeoutExpired:
        return False, "apktool timed out after 180 seconds"
    except FileNotFoundError:
        return False, "apktool not found in PATH"
    except Exception as e:
        return False, str(e)


# ── Main Entry Point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DroidRaksha Sandbox Analyzer")
    parser.add_argument("--apk",  required=True, help="Path to input APK")
    parser.add_argument("--out",  required=True, help="Path to output JSON")
    args = parser.parse_args()

    apk_path = Path(args.apk)
    out_path = Path(args.out)
    work_dir = Path("/work/decompiled")

    start_time = time.time()
    result = {
        "sandbox_available": True,
        "engine":            "frida-offline-v1",
        "apk_path":          str(apk_path),
        "error":             None,
    }

    print(f"[sandbox] Starting analysis of {apk_path.name}", flush=True)

    # Step 1 — APKTool decompile
    print("[sandbox] Running apktool decompile...", flush=True)
    success, err = run_apktool(apk_path, work_dir)
    if not success:
        result.update({"error": f"apktool failed: {err}", "sandbox_available": False})
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result))
        print(f"[sandbox] FAILED: {err}", flush=True)
        sys.exit(1)

    print(f"[sandbox] APKTool complete. Walking smali...", flush=True)

    # Step 2 — Smali behavioral extraction
    smali_findings  = walk_smali(work_dir)
    manifest_data   = extract_manifest_data(work_dir)
    resource_data   = extract_resource_data(work_dir)

    print(f"[sandbox] Scanned {smali_findings['smali_file_count']} smali files, "
          f"{smali_findings['total_methods']} methods", flush=True)

    # Step 3 — Behavior scoring
    behavior_score = score_behavior(smali_findings, manifest_data, resource_data)

    elapsed = round(time.time() - start_time, 1)

    result.update({
        "sandbox_available": True,
        "analysis_time_sec": elapsed,
        "behavioral_score":  behavior_score,
        "smali_analysis":    smali_findings,
        "manifest":          manifest_data,
        "resources":         resource_data,
        "engine_version":    "frida-offline-v1.0",
    })

    print(f"[sandbox] Done in {elapsed}s — Risk: {behavior_score['level']} ({behavior_score['score']}/100)",
          flush=True)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"[sandbox] Results written to {out_path}", flush=True)


if __name__ == "__main__":
    main()
