"""
Stats route: returns dashboard statistics.
"""
from __future__ import annotations
import json
from fastapi import APIRouter
from backend.db import database

router = APIRouter()


@router.get("/stats")
async def get_stats():
    """Return aggregated statistics for the dashboard."""
    base = await database.get_stats()

    # ── Enrich with ML family breakdown ───────────────────────────────────────
    family_counts: dict[str, int] = {}
    india_targeted = 0
    pcap_count = 0

    async with database.async_session_factory() as session:
        from sqlalchemy import select
        
        # PCAP records
        try:
            pcap_rows = (await session.execute(select(database.PCAPRecord))).scalars().all()
            pcap_count = len(pcap_rows)
        except Exception:
            pass

    # ── Query MongoDB for family breakdown and India targeting ──
    try:
        from backend.db.mongo import db
        pipeline = [
            {"$group": {"_id": "$ml_classification.family", "count": {"$sum": 1}}}
        ]
        async for doc in db.analyses.aggregate(pipeline):
            family = doc.get("_id") or "Unknown"
            family_counts[family] = doc.get("count", 0)
            
        india_targeted = await db.analyses.count_documents({"ml_classification.is_india_targeted": True})
    except Exception as e:
        from loguru import logger
        logger.error(f"Failed to fetch stats from Mongo: {e}")

    base["family_breakdown"] = family_counts
    base["india_targeted"] = india_targeted
    base["pcap_scans"] = pcap_count
    return base
