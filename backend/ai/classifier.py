"""
Malware Family Classifier — DroidRaksha P11
-------------------------------------------
Rule-based classifier that determines the most likely malware family and
a confidence score (0–100) based on static analysis signals.

Families supported:
  BankingTrojan  — OTP stealing + overlay attacks on banking apps
  RAT            — Remote Access Trojan: mic, cam, location, file access
  Spyware        — Background surveillance without C2 interaction
  Ransomware     — File encryption, ransom demand strings
  Adware         — Aggressive ad-loading, click fraud
  Dropper        — Downloads + executes secondary payload
  SMSStealer     — Primarily harvests SMS for OTP / 2FA bypass
  FakeApp        — Impersonates a legitimate app (IRCTC, CoWIN, bank…)
  CryptoMiner    — XMRig / Monero mining in background
  Stalkerware    — Covert tracking without victim awareness
  ClipboardHijacker — Swaps crypto wallet addresses
  Unknown        — Cannot be confidently classified
"""
from __future__ import annotations
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FamilyScore:
    family: str
    score: int = 0
    evidence: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.evidence.append(reason)


# ---------------------------------------------------------------------------
# Signal extractors (pure functions on analysis dicts)
# ---------------------------------------------------------------------------

def _permissions(manifest: dict) -> set[str]:
    return {
        p.get("name", "").split(".")[-1]
        for p in manifest.get("permissions", [])
    }


def _yara_rules(yara: dict) -> set[str]:
    return {h.get("rule", "") for h in yara.get("matches", [])}


def _yara_tags(yara: dict) -> set[str]:
    tags: set[str] = set()
    for h in yara.get("matches", []):
        tags.update(h.get("tags", []))
    return tags


def _string_values(strings: dict) -> set[str]:
    vals: set[str] = set()
    for key in ("suspicious_strings", "urls"):
        for item in strings.get(key, []):
            vals.add(item.get("value", "").lower())
    return vals


def _india_flags(ioc: dict) -> set[str]:
    return {
        *(["fake_upi"] if ioc.get("is_fake_upi") else []),
        *(["fake_bank"] if ioc.get("is_fake_bank") else []),
        *(["loan_scam"] if ioc.get("is_loan_scam") else []),
        *[f.lower().replace(" ", "_") for f in ioc.get("risk_flags", [])],
    }


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

def classify(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict,
    virustotal: dict,
) -> dict:
    """
    Returns:
        {
          "family": "BankingTrojan",
          "confidence": 87,
          "evidence": ["READ_SMS + SYSTEM_ALERT_WINDOW (OTP overlay)", ...],
          "secondary_families": ["SMSStealer"],
          "is_india_targeted": True,
        }
    """
    perms = _permissions(manifest)
    rules = _yara_rules(yara)
    tags  = _yara_tags(yara)
    strs  = _string_values(strings)
    ioc   = _india_flags(india_ioc)
    combos = {c.get("label", "") for c in manifest.get("dangerous_combos", [])}

    # ── Build a score per family ─────────────────────────────────────────────
    families: dict[str, FamilyScore] = {
        f: FamilyScore(f) for f in [
            "BankingTrojan", "RAT", "Spyware", "Ransomware",
            "Adware", "Dropper", "SMSStealer", "FakeApp",
            "CryptoMiner", "Stalkerware", "ClipboardHijacker",
        ]
    }

    bt  = families["BankingTrojan"]
    rat = families["RAT"]
    spy = families["Spyware"]
    ran = families["Ransomware"]
    adw = families["Adware"]
    drp = families["Dropper"]
    sms = families["SMSStealer"]
    fak = families["FakeApp"]
    min_ = families["CryptoMiner"]
    stk = families["Stalkerware"]
    clip = families["ClipboardHijacker"]

    # ── Banking Trojan signals ───────────────────────────────────────────────
    if {"READ_SMS", "RECEIVE_SMS"} & perms and "SYSTEM_ALERT_WINDOW" in perms:
        bt.add(30, "READ_SMS + SYSTEM_ALERT_WINDOW → OTP intercept + overlay")
    if "BIND_ACCESSIBILITY_SERVICE" in perms:
        bt.add(20, "Accessibility Service → keylogging / auto-fill stealing")
    if any("banking" in r.lower() or "overlay" in r.lower() or "trojan" in r.lower() for r in rules):
        bt.add(25, "YARA: banking trojan / overlay rule matched")
    if "fake_bank" in ioc or "fake_upi" in ioc:
        bt.add(20, "India IOC: fake banking / UPI app identified")
    if any("sbi" in s or "hdfc" in s or "icici" in s or "npci" in s or "bhim" in s or "phonepe" in s for s in strs):
        bt.add(15, "Strings: Indian banking brand impersonation")
    if "OTP Interceptor + Overlay" in combos or "SMS + Accessibility" in combos:
        bt.add(20, "Dangerous combo: OTP interception + overlay attack")

    # ── RAT signals ─────────────────────────────────────────────────────────
    if "RECORD_AUDIO" in perms and "CAMERA" in perms:
        rat.add(25, "RECORD_AUDIO + CAMERA → surveillance RAT")
    if "ACCESS_FINE_LOCATION" in perms and "RECEIVE_BOOT_COMPLETED" in perms:
        rat.add(15, "Location + boot persistence → persistent tracker")
    if any("rat" in r.lower() or "remote_access" in r.lower() or "c2" in r.lower() for r in rules):
        rat.add(30, "YARA: RAT / C2 beacon rule matched")
    if any("screen_recorder" in r.lower() or "screenshot" in r.lower() for r in rules):
        rat.add(20, "YARA: screen recorder detected")
    if "c2" in tags or "beacon" in tags:
        rat.add(15, "YARA tag: C2 beaconing behavior")

    # ── Spyware signals ──────────────────────────────────────────────────────
    if "ACCESS_FINE_LOCATION" in perms and len(perms & {"READ_CONTACTS", "READ_CALL_LOG", "READ_SMS"}) >= 2:
        spy.add(25, "GPS + contacts + call log: covert data collection")
    if any("stalker" in r.lower() or "spyware" in r.lower() or "gps_tracker" in r.lower() for r in rules):
        spy.add(30, "YARA: spyware / stalkerware rule matched")
    if any("stalkerware" in s or "spouse" in s or "cheating" in s for s in strs):
        spy.add(20, "Strings: stalkerware marketing language")

    # ── Stalkerware signals ──────────────────────────────────────────────────
    if all(p in perms for p in ["ACCESS_FINE_LOCATION", "READ_SMS", "READ_CONTACTS"]) and \
            "REQUEST_INSTALL_PACKAGES" not in perms:
        stk.add(25, "Location + SMS + contacts without install → stalkerware profile")
    if any("stalkerware" in r.lower() or "indian_stalkerware" in r.lower() for r in rules):
        stk.add(30, "YARA: stalkerware rule matched")

    # ── Ransomware signals ───────────────────────────────────────────────────
    if any("ransom" in r.lower() or "encrypt" in r.lower() or "locker" in r.lower() for r in rules):
        ran.add(40, "YARA: ransomware / file encryption rule matched")
    if any("bitcoin" in s or "decrypt" in s or "your files" in s or "ransom" in s for s in strs):
        ran.add(25, "Strings: ransom demand language")
    if "MANAGE_EXTERNAL_STORAGE" in perms or "WRITE_EXTERNAL_STORAGE" in perms:
        if any("cipher" in s or "aes" in s for s in strs):
            ran.add(20, "Storage write + AES cipher strings → file encryption")

    # ── Dropper signals ──────────────────────────────────────────────────────
    if obfuscation.get("has_dex_classloader"):
        drp.add(30, "DexClassLoader: runtime payload download")
    if "REQUEST_INSTALL_PACKAGES" in perms:
        drp.add(20, "REQUEST_INSTALL_PACKAGES: silently installs 2nd stage")
    if any("dropper" in r.lower() or "packed_dex" in r.lower() or "native_dropper" in r.lower() for r in rules):
        drp.add(25, "YARA: dropper / packed DEX rule matched")
    if any("fake_system_update" in r.lower() for r in rules):
        drp.add(20, "YARA: fake system update dropper")

    # ── SMS Stealer signals ──────────────────────────────────────────────────
    if {"READ_SMS", "RECEIVE_SMS"} & perms:
        sms.add(20, "SMS read/receive permissions present")
    if any("sms_steal" in r.lower() or "whatsapp_steal" in r.lower() for r in rules):
        sms.add(30, "YARA: SMS / WhatsApp stealer rule matched")
    if any("otp" in s or "verification code" in s or "one-time" in s for s in strs):
        sms.add(20, "Strings: OTP interception keywords")

    # ── FakeApp signals ──────────────────────────────────────────────────────
    if any("fake_irctc" in r.lower() or "fake_cowin" in r.lower() or "fake_trai" in r.lower()
           or "fake_income_tax" in r.lower() or "fake_" in r.lower() for r in rules):
        fak.add(35, "YARA: fake Indian government / utility app")
    if "fake_bank" in ioc or "fake_upi" in ioc:
        fak.add(20, "India IOC: confirmed fake banking/payment app")
    if any("irctc" in s or "cowin" in s or "aarogya" in s or "uidai" in s or "digilocker" in s for s in strs):
        fak.add(25, "Strings: Indian govt service impersonation")

    # ── Crypto Miner signals ─────────────────────────────────────────────────
    if any("miner" in r.lower() or "xmrig" in r.lower() or "monero" in r.lower() for r in rules):
        min_.add(40, "YARA: XMRig / Monero miner detected")
    if any("xmr" in s or "mining" in s or "stratum" in s or "monero" in s for s in strs):
        min_.add(25, "Strings: mining pool / Monero references")

    # ── Clipboard Hijacker signals ───────────────────────────────────────────
    if any("clipboard" in s or "btc" in s or "eth" in s or "0x" in s[:4] for s in strs):
        clip.add(20, "Strings: clipboard / crypto wallet pattern")
    if "READ_CLIPBOARD" in perms or "BIND_INPUT_METHOD" in perms:
        clip.add(20, "Permission: clipboard or input method access")

    # ── Adware signals ───────────────────────────────────────────────────────
    if any("adview" in s or "admob" in s or "sdk.ad" in s for s in strs):
        adw.add(10, "Strings: ad SDK references")

    # ── VirusTotal family hints ──────────────────────────────────────────────
    for vt_family in virustotal.get("malware_families", []):
        vf = vt_family.lower()
        if any(k in vf for k in ["banker", "banking", "trojan.sms"]):
            bt.add(25, f"VirusTotal family: {vt_family}")
        elif any(k in vf for k in ["rat", "remote"]):
            rat.add(25, f"VirusTotal family: {vt_family}")
        elif any(k in vf for k in ["ransom"]):
            ran.add(30, f"VirusTotal family: {vt_family}")
        elif any(k in vf for k in ["spy", "stalker"]):
            spy.add(20, f"VirusTotal family: {vt_family}")
        elif any(k in vf for k in ["dropper", "downloader"]):
            drp.add(20, f"VirusTotal family: {vt_family}")
        elif any(k in vf for k in ["miner", "coin"]):
            min_.add(25, f"VirusTotal family: {vt_family}")

    # ── India-targeted bonus ─────────────────────────────────────────────────
    is_india_targeted = bool(ioc) or any(
        "india" in r.lower() or "indian" in r.lower() for r in rules
    )

    # ── Pick winner ──────────────────────────────────────────────────────────
    ranked = sorted(families.values(), key=lambda x: x.score, reverse=True)
    top = ranked[0]

    if top.score == 0:
        return {
            "family": "Unknown",
            "confidence": 0,
            "evidence": ["Insufficient signals for classification"],
            "secondary_families": [],
            "is_india_targeted": is_india_targeted,
        }

    # Confidence = score normalised to 0–100 (cap at 95)
    confidence = min(95, max(40, int((top.score / 120) * 100)))

    secondary = [
        r.family for r in ranked[1:4]
        if r.score > 10 and r.family != top.family
    ]

    return {
        "family": top.family,
        "confidence": confidence,
        "evidence": top.evidence[:6],
        "secondary_families": secondary,
        "is_india_targeted": is_india_targeted,
    }
