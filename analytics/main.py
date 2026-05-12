import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from analytics.routers import analytics, events, stats
from analytics.websocket_manager import websocket_manager
from collector.db import close_db, init_db
from intelligence.analyzer import IntelligenceAnalyzer

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    logger.info("Initializing IntelligenceAnalyzer...")
    app.state.analyzer = IntelligenceAnalyzer()
    yield
    await close_db()


app = FastAPI(
    title="ThreatScope Analytics API",
    description="Analytics and real-time dashboard API for adaptive honeypot events.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(stats.router, prefix="/api/stats", tags=["stats"])
app.include_router(analytics.router, prefix="/api/analytics", tags=["analytics"])


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
