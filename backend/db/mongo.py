"""
MongoDB driver for storing raw JSON blobs.
Relational metadata remains in PostgreSQL (via database.py).
"""
import os
from loguru import logger
from motor.motor_asyncio import AsyncIOMotorClient

_client = None
_db = None

def get_mongo_db():
    global _client, _db
    # Read lazily so dotenv is guaranteed to have loaded first
    mongo_uri = os.getenv("MONGO_URI", "")
    if not mongo_uri:
        return None
        
    if _client is None:
        try:
            _client = AsyncIOMotorClient(mongo_uri)
            _db = _client.get_database("droidraksha")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            return None
    return _db

async def save_raw_result(analysis_id: str, result: dict) -> None:
    """Save or update the full raw analysis JSON in MongoDB."""
    db = get_mongo_db()
    if db is None:
        logger.warning(f"MongoDB not configured. Skipping raw save for {analysis_id}")
        return
        
    collection = db["raw_analyses"]
    # Upsert the document
    await collection.update_one(
        {"_id": analysis_id},
        {"$set": result},
        upsert=True
    )
    logger.info(f"Saved raw JSON to MongoDB for {analysis_id}")

async def get_raw_result(analysis_id: str) -> dict | None:
    """Retrieve the full raw analysis JSON from MongoDB."""
    db = get_mongo_db()
    if db is None:
        return None
        
    collection = db["raw_analyses"]
    doc = await collection.find_one({"_id": analysis_id})
    return doc

async def save_pcap_raw(pcap_id: str, network_data: dict) -> None:
    """Save full PCAP results to MongoDB."""
    db = get_mongo_db()
    if db is None:
        return
        
    collection = db["pcap_analyses"]
    await collection.update_one(
        {"_id": pcap_id},
        {"$set": network_data},
        upsert=True
    )

async def get_pcap_raw(pcap_id: str) -> dict | None:
    """Retrieve full PCAP result from MongoDB."""
    db = get_mongo_db()
    if db is None:
        return None
        
    collection = db["pcap_analyses"]
    return await collection.find_one({"_id": pcap_id})

async def save_live_intercept_result(analysis_id: str, intercept_data: dict) -> None:
    """Save live interception results to the existing raw analysis document."""
    db = get_mongo_db()
    if db is None:
        return
        
    collection = db["raw_analyses"]
    await collection.update_one(
        {"_id": analysis_id},
        {"$set": {"live_intercept": intercept_data}},
        upsert=True
    )
    logger.info(f"Saved live intercept data to MongoDB for {analysis_id}")
