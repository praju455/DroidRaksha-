"""
WebSocket progress endpoint — streams real-time analysis progress to the browser.

Flow:
  1. Browser connects to ws://localhost:8000/api/ws/{job_id}
  2. Server first replays any buffered events from Redis List (race condition fix)
  3. Server subscribes to Redis Pub/Sub channel "progress:{job_id}"
  4. Live events are forwarded as JSON to the WebSocket client
  5. Connection closes when stage == "complete" or "error"
"""
from __future__ import annotations
import asyncio
import json
import os
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger
import redis.asyncio as aioredis

router = APIRouter()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


@router.websocket("/ws/{job_id}")
async def analysis_progress_ws(websocket: WebSocket, job_id: str):
    """
    Stream analysis progress events to browser.
    Replays buffered past events first (fixes race condition where
    Celery finishes before the WS connection is established).
    """
    await websocket.accept()
    logger.info(f"WS connected for job {job_id[:8]}...")

    redis = aioredis.from_url(REDIS_URL, decode_responses=True)

    try:
        # ── Step 1: Replay all buffered events (catch up on missed stages) ──
        buffered = await redis.lrange(f"progress_log:{job_id}", 0, -1)
        already_done = False

        for raw in buffered:
            try:
                event = json.loads(raw)
                await websocket.send_json(event)
                if event.get("stage") in ("complete", "error"):
                    already_done = True
            except Exception:
                continue

        # Job is already finished — no need to subscribe to live stream
        if already_done:
            logger.info(f"Job {job_id[:8]} already complete, sent buffered replay")
            return

        # ── Step 2: Subscribe for live events going forward ─────────────────
        await websocket.send_json({
            "stage": "queued",
            "pct": 0,
            "msg": "Analysis queued — waiting for worker...",
        })

        # Start background ping/keep-alive task to prevent connection timeouts during long tasks
        async def send_pings():
            try:
                while True:
                    await asyncio.sleep(20)
                    await websocket.send_json({"stage": "ping", "pct": 0, "msg": "keep-alive"})
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        logger.info(f"Subscribing to redis for {job_id[:8]}")
        pubsub = redis.pubsub()
        await pubsub.subscribe(f"progress:{job_id}")
        logger.info(f"Subscribed successfully for {job_id[:8]}")

        ping_task = asyncio.create_task(send_pings())

        try:
            # Wait up to 30 minutes for the job to complete (sandbox, mobsf, AI can take time)
            deadline = asyncio.get_event_loop().time() + 1800

            import redis.exceptions
            while True:
                if asyncio.get_event_loop().time() > deadline:
                    await websocket.send_json({"stage": "error", "pct": 0, "msg": "Analysis timed out"})
                    break

                try:
                    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                except redis.exceptions.TimeoutError:
                    continue
                except Exception as e:
                    # other redis errors
                    logger.warning(f"Redis pubsub error: {e}")
                    await asyncio.sleep(1)
                    continue

                if message is None:
                    await asyncio.sleep(0.1)
                    continue

                if message["type"] != "message":
                    continue

                try:
                    event = json.loads(message["data"])
                except (json.JSONDecodeError, TypeError):
                    continue

                await websocket.send_json(event)

                if event.get("stage") in ("complete", "error"):
                    break
        finally:
            ping_task.cancel()
            try:
                # Wrap unsubscribe to prevent it from masking WebSocketDisconnect if it times out
                await pubsub.unsubscribe(f"progress:{job_id}")
            except Exception as e:
                logger.warning(f"Error unsubscribing from redis: {e}")

    except WebSocketDisconnect:
        logger.info(f"WS disconnected for job {job_id[:8]}")
    except Exception as e:
        logger.error(f"WS error for job {job_id[:8]}: {e}")
        try:
            await websocket.send_json({"stage": "error", "pct": 0, "msg": str(e)})
        except Exception:
            pass
    finally:
        await redis.close()
        try:
            await websocket.close()
        except Exception:
            pass
        logger.info(f"WS closed for job {job_id[:8]}")
