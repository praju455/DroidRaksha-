"""
DroidRaksha — FastAPI Backend Entry Point
"""
from __future__ import annotations
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from loguru import logger

from backend.db.database import init_db
from backend.routes import upload, analysis, sandbox, stats, websocket, report, search, export, copilot, intercept
from backend.db.database import engine, Base
from backend.db import elastic

load_dotenv()

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Supabase / PostgreSQL database...")
    await init_db()
    
    logger.info("Initializing Bonsai Elasticsearch index...")
    await elastic.setup_index()

    logger.info("DroidRaksha Backend startup complete.")
    yield


app = FastAPI(
    title="DroidRaksha API",
    description="India's AI-powered APK Threat Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        "http://localhost:3000",
        "http://localhost:3001",
        "https://droid-raksha.vercel.app",
        "https://frontened-nu.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes — all under /api prefix
app.include_router(upload.router, prefix="/api", tags=["Upload"])
app.include_router(analysis.router, prefix="/api", tags=["Analysis"])
app.include_router(stats.router, prefix="/api/stats", tags=["Statistics"])
app.include_router(report.router, prefix="/api/report", tags=["PDF Report"])
app.include_router(export.router, prefix="/api/export", tags=["Intelligence Export"])
app.include_router(search.router, prefix="/api/search", tags=["Global Search"])
app.include_router(stats.router, prefix="/api", tags=["Dashboard"])
app.include_router(websocket.router, prefix="/api", tags=["WebSocket"])
app.include_router(sandbox.router, prefix="/api", tags=["Sandbox"])
app.include_router(intercept.router, prefix="/api", tags=["Live Intercept"])
app.include_router(copilot.router, prefix="/api", tags=["Threat Copilot"])


@app.get("/health")
async def health():
    return {"status": "ok", "service": "DroidRaksha API v1.0"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("BACKEND_PORT", "8000"))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=True, reload_dirs=["backend"])
