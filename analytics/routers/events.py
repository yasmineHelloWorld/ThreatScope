import asyncio
import logging
from datetime import datetime, timezone
from typing import Any
import uuid
import re

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from analytics.services.event_service import EventFilters, EventService
from analytics.websocket_manager import websocket_manager
from collector.db import get_session
from collector.models import Event

logger = logging.getLogger(__name__)

router = APIRouter()


class IngestEventRequest(BaseModel):
    endpoint: str
    method: str = "GET"
    username: str | None = None
    password: str | None = None
    payload: Any = None
    userAgent: str | None = None
    referrer: str | None = None
    riskLevel: str = "low"
    ip: str | None = None
    timestamp: str | None = None


def _frontend_risk_floor(body: IngestEventRequest) -> tuple[int, str | None, bool]:
    level_floor = {
        "low": 10,
        "medium": 45,
        "high": 75,
    }.get((body.riskLevel or "low").lower(), 10)

    text = f"{body.endpoint} {body.method} {body.payload} {body.username or ''} {body.password or ''}"
    lowered = text.lower()

    if re.search(r"union\s+select|or\s+1=1|drop\s+table|sleep\s*\(", lowered):
        return max(level_floor, 90), "SQL Injection", True
    if re.search(r"<script|onerror=|javascript:|<img\s+src=", lowered):
        return max(level_floor, 85), "XSS", True
    if re.search(r"\.\./|/etc/passwd|whoami|cat\s+/|;|\|\||&&|\$\(", lowered):
        return max(level_floor, 88), "Command Injection", True

    return level_floor, None, False


def _serialize(event: Event) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "ip_address": str(event.ip_address),
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "service_type": event.service_type,
        "request_type": event.request_type,
        "username": event.username,
        "password": event.password,
        "payload": event.payload,
        "user_agent": event.user_agent,
        "endpoint": event.endpoint,
        "risk_score": event.risk_score or 0,
        "attack_type": event.attack_type,
        "is_attack": bool(event.is_attack),
        "session_id": str(event.session_id) if event.session_id else None,
        "response_sent": event.response_sent,
        "metadata": event.extra_data or {},
    }


@router.post("/ingest")
async def ingest_event(
    body: IngestEventRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    ip = body.ip or request.client.host if request.client else "127.0.0.1"

    event_data = {
        "ip_address": ip,
        "timestamp": body.timestamp or datetime.now(timezone.utc).isoformat(),
        "service_type": "web-admin",
        "request_type": body.method,
        "username": body.username,
        "password": body.password,
        "payload": str(body.payload) if body.payload is not None else None,
        "user_agent": body.userAgent,
        "endpoint": body.endpoint,
    }

    analyzer = getattr(request.app.state, "analyzer", None)
    risk_score = 0
    attack_type = None
    is_attack = False
    details = {}
    floor_score, hinted_attack, hinted_is_attack = _frontend_risk_floor(body)

    if analyzer:
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, analyzer.analyze_event, event_data)
            risk_score = result.risk_score
            attack_type = result.attack_type
            is_attack = result.is_attack
            details = {"detector_details": result.details} if result.details else {}
        except Exception as e:
            logger.error("Analyzer failed on ingested event: %s", e)

    # Keep analyzer output, but enforce floor from frontend risk level / payload hints.
    risk_score = max(risk_score, floor_score)
    if hinted_is_attack:
        is_attack = True
        if not attack_type:
            attack_type = hinted_attack

    event = Event(
        id=str(uuid.uuid4()),
        ip_address=ip,
        timestamp=datetime.now(timezone.utc),
        service_type="web-admin",
        request_type=body.method,
        username=body.username,
        password=body.password,
        payload=str(body.payload) if body.payload is not None else None,
        user_agent=body.userAgent,
        endpoint=body.endpoint,
        risk_score=risk_score,
        attack_type=attack_type,
        is_attack=is_attack,
        extra_data=details or None,
    )
    session.add(event)
    await session.commit()
    await session.refresh(event)

    try:
        serialized = _serialize(event)
        await websocket_manager.broadcast(serialized)
    except Exception as e:
        logger.warning("WebSocket broadcast failed: %s", e)

    logger.info(
        "Ingested event %s from %s (risk=%d, type=%s)",
        event.id, ip, risk_score, attack_type or "none",
    )

    return {
        "id": str(event.id),
        "risk_score": risk_score,
        "classification": (
            "Malicious" if risk_score >= 70
            else "Suspicious" if risk_score >= 40
            else "Benign"
        ),
        "attack_type": attack_type,
        "is_attack": is_attack,
    }


@router.get("")
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ip_address: str | None = None,
    service_type: str | None = None,
    attack_type: str | None = None,
    is_attack: bool | None = None,
    min_risk: int | None = Query(None, ge=0, le=100),
    max_risk: int | None = Query(None, ge=0, le=100),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    filters = EventFilters(
        ip_address=ip_address,
        service_type=service_type,
        attack_type=attack_type,
        is_attack=is_attack,
        min_risk=min_risk,
        max_risk=max_risk,
        start_time=start_time,
        end_time=end_time,
    )
    return await EventService(session).list_events(filters, limit, offset)
