"""
Live Interception REST + SSE API
==================================
Routes:
  GET  /api/intercept/status                    — check mitmproxy availability + ADB setup info
  POST /api/intercept/{analysis_id}/start       — start 60-second capture session
  POST /api/intercept/{analysis_id}/stop        — stop session early
  GET  /api/intercept/{analysis_id}             — get flows + correlation result
  GET  /api/intercept/{analysis_id}/stream      — SSE live stream of flows (polls every 2s)
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from loguru import logger

from backend.db import database
from backend.engines import intercept_engine, ip_correlator

router = APIRouter()

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")


# ── Helper: get static IPs for an analysis ───────────────────────────────────

async def _get_static_ips(analysis_id: str) -> list[dict]:
    """Pull hardcoded IPs from the saved analysis record (string_extractor output)."""
    try:
        result = await database.get_analysis(analysis_id)
        if not result:
            return []
        strings = result.get("strings", {})
        ips: list[dict] = strings.get("ips", [])
        return ips
    except Exception as e:
        logger.warning(f"Could not fetch static IPs for {analysis_id[:8]}: {e}")
        return []


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/intercept/status")
async def intercept_status():
    """Check if mitmproxy is installed and return ADB proxy setup instructions."""
    mitm_info = intercept_engine.mitmproxy_available()

    emulator_backend = os.getenv("EMULATOR_BACKEND", "genymotion").lower()
    
    if emulator_backend == "avd":
        host_ip = os.getenv("MITM_PROXY_HOST", "10.0.2.2")
        setup_commands = [
            f"adb shell settings put global http_proxy {host_ip}:{intercept_engine.MITM_PORT}",
            "# Push mitmproxy CA cert (rooted emulator):",
            f"adb push %USERPROFILE%\\.mitmproxy\\mitmproxy-ca-cert.pem /data/local/tmp/",
            "adb shell su -c 'cp /data/local/tmp/mitmproxy-ca-cert.pem /system/etc/security/cacerts/c8750f0d.0'",
            "adb shell su -c 'chmod 644 /system/etc/security/cacerts/c8750f0d.0'",
            "# Clear proxy after session:",
            "adb shell settings delete global http_proxy",
        ]
    else:
        # Genymotion default
        host_ip = os.getenv("MITM_PROXY_HOST", "10.0.3.2")
        genymotion_ip = os.getenv("GENYMOTION_DEVICE_IP", "192.168.55.101")
        setup_commands = [
            f"# Connect to Genymotion device (Update GENYMOTION_DEVICE_IP env var if IP differs)",
            f"adb connect {genymotion_ip}:5555",
            f"adb shell settings put global http_proxy {host_ip}:{intercept_engine.MITM_PORT}",
            "# Push mitmproxy CA cert (rooted emulator):",
            f"adb push %USERPROFILE%\\.mitmproxy\\mitmproxy-ca-cert.pem /data/local/tmp/",
            "adb shell su 0 cp /data/local/tmp/mitmproxy-ca-cert.pem /system/etc/security/cacerts/c8750f0d.0",
            "adb shell su 0 chmod 644 /system/etc/security/cacerts/c8750f0d.0",
            "# Clear proxy after session:",
            "adb shell settings delete global http_proxy",
        ]

    return {
        **mitm_info,
        "mitm_port": intercept_engine.MITM_PORT,
        "duration_sec": intercept_engine.INTERCEPT_DURATION,
        "host_ip": host_ip,
        "setup_commands": setup_commands,
    }


@router.post("/intercept/{analysis_id}/start")
async def start_intercept(analysis_id: str):
    """Start a 60-second mitmproxy capture session for this APK analysis."""
    # Verify analysis exists
    result = await database.get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    session_result = intercept_engine.start_session(analysis_id)

    if session_result.get("status") == "error":
        raise HTTPException(status_code=503, detail=session_result.get("error", "Failed to start mitmproxy"))

    return {
        "analysis_id": analysis_id,
        **session_result,
        "message": (
            f"Intercept session started on port {intercept_engine.MITM_PORT}. "
            f"Interact with the app in the emulator for {intercept_engine.INTERCEPT_DURATION} seconds. "
            "Session will auto-stop and generate correlation results."
        ),
    }


@router.post("/intercept/{analysis_id}/stop")
async def stop_intercept(analysis_id: str):
    """Stop the intercept session early and finalize results."""
    result = intercept_engine.stop_session(analysis_id)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail="No active session for this analysis")
        
    # After stopping, fetch the finalized flows and correlation to save to DB
    flows_data = intercept_engine.get_flows(analysis_id)
    if flows_data.get("available"):
        static_ips = await _get_static_ips(analysis_id)
        correlation = ip_correlator.correlate(static_ips, flows_data.get("flows", []))
        await database.save_live_intercept_result(analysis_id, {
            "flows": flows_data.get("flows", []),
            "correlation": correlation
        })
        
    return {"analysis_id": analysis_id, **result}


@router.get("/intercept/{analysis_id}")
async def get_intercept_result(analysis_id: str):
    """Get captured flows and IP correlation results for this analysis."""
    flows_data = intercept_engine.get_flows(analysis_id)

    if not flows_data.get("available"):
        # Fallback to MongoDB if session isn't in memory (e.g. after backend restart)
        saved_analysis = await database.get_analysis(analysis_id)
        if saved_analysis and "live_intercept" in saved_analysis:
            live_data = saved_analysis["live_intercept"]
            static_ips = await _get_static_ips(analysis_id)
            return {
                "analysis_id": analysis_id,
                "session_found": True,
                "running": False,
                "elapsed_sec": 60,
                "remaining_sec": 0,
                "duration_sec": 60,
                "flow_count": len(live_data.get("flows", [])),
                "flows": live_data.get("flows", []),
                "static_ips": static_ips,
                "correlation": live_data.get("correlation"),
            }

        return {
            "analysis_id":  analysis_id,
            "session_found": False,
            "message": "No intercept session found. Start one with POST /api/intercept/{id}/start",
        }

    # Fetch static IPs from the saved analysis
    static_ips = await _get_static_ips(analysis_id)

    # Run correlation
    correlation = ip_correlator.correlate(
        static_ips=static_ips,
        live_flows=flows_data.get("flows", []),
    )

    return {
        "analysis_id": analysis_id,
        "session_found": True,
        "running": flows_data.get("running"),
        "elapsed_sec": flows_data.get("elapsed_sec"),
        "remaining_sec": flows_data.get("remaining_sec"),
        "duration_sec": flows_data.get("duration_sec"),
        "flow_count": flows_data.get("flow_count"),
        "flows": flows_data.get("flows", []),
        "static_ips": static_ips,
        "correlation": correlation,
    }


@router.get("/intercept/{analysis_id}/stream")
async def stream_intercept(analysis_id: str):
    """
    SSE stream that pushes live flow events every 2 seconds.
    Client receives JSON events with the latest flows + session status.
    """
    async def event_generator():
        last_count = 0
        while True:
            flows_data = intercept_engine.get_flows(analysis_id)
            if not flows_data.get("available"):
                yield f"data: {json.dumps({'error': 'no_session', 'done': True})}\n\n"
                break

            current_flows = flows_data.get("flows", [])
            new_flows = current_flows[last_count:]
            last_count = len(current_flows)

            # Fetch static IPs for live correlation
            static_ips = await _get_static_ips(analysis_id)
            correlation = ip_correlator.correlate(static_ips, current_flows)

            payload = {
                "running":        flows_data.get("running"),
                "elapsed_sec":    flows_data.get("elapsed_sec"),
                "remaining_sec":  flows_data.get("remaining_sec"),
                "flow_count":     len(current_flows),
                "new_flows":      new_flows,
                "correlation":    correlation,
                "done":           not flows_data.get("running"),
            }
            yield f"data: {json.dumps(payload)}\n\n"

            if not flows_data.get("running"):
                # Save to DB before breaking
                await database.save_live_intercept_result(analysis_id, {
                    "flows": current_flows,
                    "correlation": correlation
                })
                break

            await asyncio.sleep(2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
