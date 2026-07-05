"""
SQLite database setup and CRUD operations using SQLAlchemy async.
"""
import json
import os
from datetime import datetime, timezone
from typing import Optional, Union

from backend.db.mongo import save_raw_result, get_raw_result, save_pcap_raw, get_pcap_raw, save_live_intercept_result
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, Text, DateTime, select
from loguru import logger

# Default to PostgreSQL (Supabase) if no DATABASE_URL is provided in production
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@db.xxxx.supabase.co:5432/postgres")

engine = create_async_engine(DATABASE_URL, echo=False)
async_session_factory = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class AnalysisRecord(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    file_size: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(20))
    package_name: Mapped[str] = mapped_column(String(255), default="unknown")
    # result_json is now stored in MongoDB
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class PCAPRecord(Base):
    __tablename__ = "pcap_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    # Plain Column avoids Mapped[Optional[str]] issues on Python 3.14 + SQLAlchemy 2.x
    analysis_id = mapped_column(String(36), nullable=True, index=True, default=None)
    pcap_risk: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    # Satisfy SQLite NOT NULL constraint from an older schema migration
    result_json: Mapped[str] = mapped_column(String, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


async def init_db() -> None:
    """Create tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized")


async def save_analysis(result: dict) -> None:
    """Persist an analysis result to the database."""
    async with async_session_factory() as session:
        existing = await session.get(AnalysisRecord, result["id"])
        if existing:
            existing.filename = result.get("filename", "unknown.apk")
            existing.sha256 = result["hashes"]["sha256"]
            existing.file_size = result["hashes"]["file_size"]
            existing.risk_score = result["risk"]["score"]
            existing.risk_level = result["risk"]["risk_level"]
            existing.package_name = result.get("manifest", {}).get("package_name", "unknown")
        else:
            record = AnalysisRecord(
                id=result["id"],
                filename=result.get("filename", "unknown.apk"),
                sha256=result["hashes"]["sha256"],
                file_size=result["hashes"]["file_size"],
                risk_score=result["risk"]["score"],
                risk_level=result["risk"]["risk_level"],
                package_name=result.get("manifest", {}).get("package_name", "unknown"),
            )
            session.add(record)
        await session.commit()
        
    # Save the huge raw blob to MongoDB
    await save_raw_result(result["id"], result)
    logger.info(f"Saved analysis {result['id']} metadata to PG and raw to Mongo")


async def get_analysis(analysis_id: str) -> Optional[dict]:
    """Retrieve an analysis result by ID."""
    async with async_session_factory() as session:
        stmt = select(AnalysisRecord).where(AnalysisRecord.id == analysis_id)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row:
            # Try MongoDB first
            mongo_doc = await get_raw_result(analysis_id)
            if mongo_doc:
                # Remove MongoDB _id field
                mongo_doc.pop('_id', None)

                # Backfill c2_intelligence for analyses that predate the field
                if "c2_intelligence" not in mongo_doc:
                    try:
                        from backend.intel import c2_detector
                        strings = mongo_doc.get("strings", {})
                        abuseipdb_result = mongo_doc.get("abuseipdb", {})
                        all_urls = [
                            item.get("value", "")
                            for item in strings.get("urls", [])
                            if item.get("value")
                        ]
                        sandbox_smali = None
                        dynamic = mongo_doc.get("dynamic", {})
                        if dynamic and dynamic.get("sandbox_available"):
                            sandbox_smali = dynamic.get("smali_analysis")
                        mongo_doc["c2_intelligence"] = c2_detector.analyze(
                            strings=strings,
                            sandbox_smali=sandbox_smali,
                            abuseipdb_result=abuseipdb_result,
                            urls=all_urls,
                        )
                    except Exception as e:
                        logger.warning(f"C2 backfill failed for {analysis_id}: {e}")
                        mongo_doc["c2_intelligence"] = None

                return mongo_doc
        return None


async def get_analysis_by_hash(sha256: str) -> Optional[dict]:
    """Retrieve analysis by APK SHA256 (cache lookup)."""
    async with async_session_factory() as session:
        stmt = select(AnalysisRecord).where(AnalysisRecord.sha256 == sha256).order_by(
            AnalysisRecord.created_at.desc()
        )
        row = (await session.execute(stmt)).scalars().first()
        if row:
            mongo_doc = await get_raw_result(row.id)
            if mongo_doc:
                mongo_doc.pop('_id', None)
                return mongo_doc
        return None


async def get_stats() -> dict:
    """Return dashboard statistics."""
    async with async_session_factory() as session:
        all_records = (await session.execute(select(AnalysisRecord))).scalars().all()

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        for r in all_records:
            counts[r.risk_level] = counts.get(r.risk_level, 0) + 1

        recent = sorted(all_records, key=lambda r: r.created_at, reverse=True)[:10]
        recent_list = [
            {
                "id": r.id,
                "filename": r.filename,
                "package_name": r.package_name,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "created_at": r.created_at.isoformat(),
            }
            for r in recent
        ]

        return {
            "total_analyzed": len(all_records),
            "threats_detected": sum(
                1 for r in all_records if r.risk_level in ("CRITICAL", "HIGH")
            ),
            "india_threats": counts.get("CRITICAL", 0),
            "critical_count": counts.get("CRITICAL", 0),
            "high_count": counts.get("HIGH", 0),
            "medium_count": counts.get("MEDIUM", 0),
            "low_count": counts.get("LOW", 0),
            "safe_count": counts.get("SAFE", 0),
            "recent_analyses": recent_list,
        }
async def save_pcap_result(
    pcap_id: str,
    filename: str,
    analysis_id: Optional[str],
    network: dict,
) -> None:
    """Persist a PCAP analysis result."""
    async with async_session_factory() as session:
        record = PCAPRecord(
            id=pcap_id,
            filename=filename,
            analysis_id=analysis_id,
            pcap_risk=network.get("pcap_risk", "UNKNOWN"),
        )
        session.add(record)
        await session.commit()
        
    await save_pcap_raw(pcap_id, network)
    logger.info(f"Saved PCAP result {pcap_id} to DB and Mongo")


async def get_pcap_result(pcap_id: str) -> Optional[dict]:
    """Retrieve a PCAP analysis result by ID."""
    async with async_session_factory() as session:
        stmt = select(PCAPRecord).where(PCAPRecord.id == pcap_id)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row:
            mongo_doc = await get_pcap_raw(pcap_id)
            if mongo_doc:
                mongo_doc.pop('_id', None)
                return mongo_doc
        return None


async def get_pcap_results_for_analysis(analysis_id: str) -> list[dict]:
    """Get all PCAP results linked to a specific APK analysis."""
    async with async_session_factory() as session:
        stmt = select(PCAPRecord).where(PCAPRecord.analysis_id == analysis_id)
        rows = (await session.execute(stmt)).scalars().all()
        
        results = []
        for r in rows:
            mongo_doc = await get_pcap_raw(r.id)
            if mongo_doc:
                mongo_doc.pop('_id', None)
                results.append(mongo_doc)
        return results
