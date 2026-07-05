"""
Live Interception Engine — mitmproxy integration for DroidRaksha.

Manages a 60-second mitmdump session per analysis ID.
The inline addon writes captured flow data (IP, host, method, URL, status) to
a JSON-lines temp file which this engine tails and returns.

Architecture:
  start_session(analysis_id)  → spawns mitmdump on port 8080, writes addon script
  stop_session(analysis_id)   → kills process, freezes results
  get_flows(analysis_id)      → returns all captured flows + correlation
  is_running(analysis_id)     → True while mitmdump is alive

Emulator setup (rooted Google APIs, done once via ADB):
  adb shell settings put global http_proxy <HOST_IP>:8080
  adb push <mitmproxy-ca-cert.pem> /data/local/tmp/
  adb shell "su -c 'cp /data/local/tmp/mitmproxy-ca-cert.pem /system/etc/security/cacerts/c8750f0d.0'"
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from loguru import logger

# ── State Store (in-memory per backend lifetime) ─────────────────────────────
# { analysis_id: SessionState }
_sessions: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()

MITM_PORT = int(os.getenv("MITM_PORT", "8080"))
INTERCEPT_DURATION = int(os.getenv("INTERCEPT_DURATION", "60"))  # seconds


# ── mitmproxy addon script (written to disk at session start) ──────────────

_ADDON_TEMPLATE = """
import json
import time
import socket

OUTPUT_FILE = {output_file!r}

class DroidRakshaAddon:
    def response(self, flow):
        try:
            dst_host = flow.request.pretty_host
            dst_ip   = ""
            
            # Prefer mitmproxy's resolved peer IP (avoids blocking DNS lookup)
            if flow.server_conn and flow.server_conn.peername:
                dst_ip = flow.server_conn.peername[0]
            else:
                try:
                    dst_ip = socket.gethostbyname(dst_host)
                except Exception:
                    pass
                    
            record = {{
                "ts":      time.time(),
                "method":  flow.request.method,
                "host":    dst_host,
                "url":     flow.request.pretty_url[:300],
                "dst_ip":  dst_ip,
                "dst_port": flow.request.port,
                "status":  flow.response.status_code if flow.response else 0,
                "tls":     flow.request.scheme == "https",
            }}
            with open(OUTPUT_FILE, "a") as f:
                f.write(json.dumps(record) + "\\n")
        except Exception as e:
            pass

addons = [DroidRakshaAddon()]
"""


def _addon_path(analysis_id: str) -> Path:
    return Path(tempfile.gettempdir()) / f"dr_addon_{analysis_id[:8]}.py"


def _flows_path(analysis_id: str) -> Path:
    return Path(tempfile.gettempdir()) / f"dr_flows_{analysis_id[:8]}.jsonl"


# ── Public API ────────────────────────────────────────────────────────────────

def mitmproxy_available() -> dict:
    """Check if mitmdump is installed and on PATH."""
    try:
        result = subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            ver = result.stdout.strip().split("\n")[0]
            return {"available": True, "version": ver}
        return {"available": False, "error": result.stderr.strip()}
    except FileNotFoundError:
        return {
            "available": False,
            "error": "mitmdump not found. Run: pip install mitmproxy",
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def start_session(analysis_id: str) -> dict:
    """
    Start a 60-second mitmproxy capture session for this analysis.
    Returns immediately — capture runs in background thread.
    """
    with _lock:
        if analysis_id in _sessions and _sessions[analysis_id].get("running"):
            return {"status": "already_running", "analysis_id": analysis_id}

    flows_file = _flows_path(analysis_id)
    addon_file = _addon_path(analysis_id)

    # Clean up any previous session files
    flows_file.unlink(missing_ok=True)
    addon_file.unlink(missing_ok=True)

    # Write the addon script
    addon_script = _ADDON_TEMPLATE.format(output_file=str(flows_file))
    addon_file.write_text(addon_script, encoding="utf-8")

    # Spawn mitmdump
    cmd = [
        "mitmdump",
        "--listen-host", "0.0.0.0",
        "--listen-port", str(MITM_PORT),
        "--ssl-insecure",       # accept any cert from upstream
        "--quiet",
        "-s", str(addon_file),
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return {"status": "error", "error": "mitmdump not found. pip install mitmproxy"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

    started_at = time.time()

    with _lock:
        _sessions[analysis_id] = {
            "proc": proc,
            "flows_file": flows_file,
            "addon_file": addon_file,
            "started_at": started_at,
            "running": True,
            "flows": [],
        }

    # Auto-stop after INTERCEPT_DURATION seconds
    def _auto_stop():
        time.sleep(INTERCEPT_DURATION)
        stop_session(analysis_id)

    t = threading.Thread(target=_auto_stop, daemon=True)
    t.start()

    logger.info(f"Intercept session started for {analysis_id[:8]} on port {MITM_PORT}")
    return {
        "status": "started",
        "analysis_id": analysis_id,
        "port": MITM_PORT,
        "duration_sec": INTERCEPT_DURATION,
        "started_at": started_at,
    }


def stop_session(analysis_id: str) -> dict:
    """Stop the mitmproxy session and finalize captured flows."""
    with _lock:
        session = _sessions.get(analysis_id)
        if not session:
            return {"status": "not_found"}
        if not session.get("running"):
            return {"status": "already_stopped"}

        proc: subprocess.Popen = session["proc"]
        session["running"] = False
        session["stopped_at"] = time.time()

    # Kill the process
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    # Read all flows
    flows = _read_flows(session["flows_file"])
    with _lock:
        _sessions[analysis_id]["flows"] = flows

    # Cleanup temp files
    try:
        session["flows_file"].unlink(missing_ok=True)
        session["addon_file"].unlink(missing_ok=True)
    except Exception:
        pass

    logger.info(f"Intercept session stopped for {analysis_id[:8]} — {len(flows)} flows captured")
    return {"status": "stopped", "flow_count": len(flows)}


def is_running(analysis_id: str) -> bool:
    with _lock:
        s = _sessions.get(analysis_id)
        if not s:
            return False
        return s.get("running", False)


def get_flows(analysis_id: str) -> dict:
    """
    Return all captured flows for this session.
    If still running, reads the live file. If stopped, returns cached flows.
    """
    with _lock:
        session = _sessions.get(analysis_id)

    if not session:
        return {"available": False, "error": "No session found for this analysis"}

    running = session.get("running", False)
    started_at = session.get("started_at", 0)
    stopped_at = session.get("stopped_at", None)

    if running:
        # Live read from the JSONL file
        flows = _read_flows(session["flows_file"])
        elapsed = time.time() - started_at
        remaining = max(0, INTERCEPT_DURATION - elapsed)
    else:
        flows = session.get("flows", [])
        elapsed = (stopped_at or started_at) - started_at
        remaining = 0

    return {
        "available": True,
        "running": running,
        "flow_count": len(flows),
        "flows": flows,
        "elapsed_sec": round(elapsed, 1),
        "remaining_sec": round(remaining, 1),
        "duration_sec": INTERCEPT_DURATION,
        "started_at": started_at,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _read_flows(flows_file: Path) -> list[dict]:
    """Read all flow records from the JSONL output file."""
    flows = []
    try:
        if not flows_file.exists():
            return flows
        with flows_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        flows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        logger.warning(f"Error reading flows file: {e}")
    return flows
