"""
Migration: Move result_json from SQLite → MongoDB, then drop the column.
Run inside the backend container:
  docker exec droidraksha-backend python scripts/migrate_sqlite_to_mongo.py
"""
import asyncio
import json
import os
import sqlite3
import sys

# ── Motor (async MongoDB driver) ─────────────────────────────────────────────
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/droidraksha")
DB_PATH   = os.getenv("DB_PATH",   "/app/droidraksha.db")


async def migrate():
    # 1. Open SQLite synchronously (migration script, not a FastAPI request)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Check whether result_json column even exists
    cur.execute("PRAGMA table_info(analyses)")
    columns = [r["name"] for r in cur.fetchall()]
    if "result_json" not in columns:
        print("✅ result_json column already gone — nothing to do.")
        conn.close()
        return

    # 2. Fetch all rows that have result_json data
    cur.execute("SELECT id, result_json FROM analyses WHERE result_json IS NOT NULL")
    rows = cur.fetchall()
    print(f"Found {len(rows)} rows with result_json to migrate.")

    # 3. Write them to MongoDB
    client = AsyncIOMotorClient(MONGO_URI)
    db     = client.get_database("droidraksha")
    collection = db["raw_analyses"]

    migrated = 0
    skipped  = 0
    for row in rows:
        analysis_id  = row["id"]
        result_json  = row["result_json"]
        if not result_json:
            skipped += 1
            continue
        try:
            doc = json.loads(result_json)
        except json.JSONDecodeError as e:
            print(f"  ⚠️  Could not parse JSON for {analysis_id}: {e}")
            skipped += 1
            continue

        await collection.update_one(
            {"_id": analysis_id},
            {"$set": doc},
            upsert=True,
        )
        migrated += 1
        print(f"  ✅ Migrated {analysis_id}")

    client.close()
    print(f"\nMigrated {migrated}, skipped {skipped}.")

    # 4. Drop the result_json column from SQLite
    #    SQLite < 3.35 doesn't support DROP COLUMN, so we recreate the table.
    print("\nDropping result_json column from SQLite analyses table …")
    cur.execute("""
        CREATE TABLE analyses_new (
            id           TEXT    NOT NULL PRIMARY KEY,
            filename     TEXT    NOT NULL,
            sha256       TEXT    NOT NULL,
            file_size    INTEGER NOT NULL,
            risk_score   INTEGER NOT NULL,
            risk_level   TEXT    NOT NULL,
            package_name TEXT    NOT NULL DEFAULT 'unknown',
            created_at   TEXT    NOT NULL
        )
    """)
    cur.execute("""
        INSERT INTO analyses_new (id, filename, sha256, file_size, risk_score, risk_level, package_name, created_at)
        SELECT                    id, filename, sha256, file_size, risk_score, risk_level, package_name, created_at
        FROM analyses
    """)
    cur.execute("DROP TABLE analyses")
    cur.execute("ALTER TABLE analyses_new RENAME TO analyses")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_analyses_sha256 ON analyses (sha256)")
    conn.commit()
    conn.close()

    print("✅ SQLite schema updated — result_json column removed.")
    print("\nDone! Re-start the worker and backend containers to pick up the clean schema.")


if __name__ == "__main__":
    asyncio.run(migrate())
