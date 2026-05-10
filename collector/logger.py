import json
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from collector.models import Event, Session, AttackAlert
from collector.db import AsyncSessionLocal

logger = logging.getLogger(__name__)


async def log_event(
    ip_address: str,
    service_type: str,
    request_type: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    payload: Optional[str] = None,
    user_agent: Optional[str] = None,
    endpoint: Optional[str] = None,
    risk_score: int = 0,
    attack_type: Optional[str] = None,
    is_attack: bool = False,
    session_id: Optional[UUID] = None,
    response_sent: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> UUID:
    async with AsyncSessionLocal() as session:
        event = Event(
            id=uuid4(),
            ip_address=ip_address,
            timestamp=datetime.now(timezone.utc),
            service_type=service_type,
            request_type=request_type,
            username=username,
            password=password,
            payload=payload,
            user_agent=user_agent,
            endpoint=endpoint,
            risk_score=risk_score,
            attack_type=attack_type,
            is_attack=is_attack,
            session_id=session_id,
            response_sent=response_sent,
            metadata=metadata,
        )
        session.add(event)
        await session.commit()
        event_id = event.id
        logger.info("Logged event %s from %s on %s (risk=%d)", event_id, ip_address, service_type, risk_score)
        return event_id


async def create_session(ip_address: str) -> UUID:
    async with AsyncSessionLocal() as session:
        sess = Session(id=uuid4(), ip_address=ip_address)
        session.add(sess)
        await session.commit()
        return sess.id


async def update_session(session_id: UUID, risk_score: int):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Session).where(Session.id == session_id))
        sess = result.scalar_one_or_none()
        if sess:
            sess.event_count += 1
            sess.max_risk_score = max(sess.max_risk_score, risk_score)
            await session.commit()


async def create_attack_alert(
    ip_address: str,
    attack_type: str,
    confidence: float,
    details: Optional[dict] = None,
) -> UUID:
    async with AsyncSessionLocal() as session:
        alert = AttackAlert(
            id=uuid4(),
            ip_address=ip_address,
            attack_type=attack_type,
            confidence=confidence,
            details=details,
        )
        session.add(alert)
        await session.commit()
        return alert.id
