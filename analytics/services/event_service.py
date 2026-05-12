from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from collector.models import Event


@dataclass
class EventFilters:
    ip_address: str | None = None
    service_type: str | None = None
    attack_type: str | None = None
    is_attack: bool | None = None
    min_risk: int | None = None
    max_risk: int | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None


def serialize_event(event: Event) -> dict[str, Any]:
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
        "metadata": event.metadata or {},
    }


class EventService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_events(self, filters: EventFilters, limit: int, offset: int) -> dict:
        filtered = self._apply_filters(select(Event), filters)
        total_query = self._apply_filters(select(func.count()).select_from(Event), filters)

        total = (await self.session.execute(total_query)).scalar_one()
        rows = await self.session.execute(
            filtered.order_by(Event.timestamp.desc()).limit(limit).offset(offset)
        )

        return {
            "items": [serialize_event(event) for event in rows.scalars().all()],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def _apply_filters(self, query: Select, filters: EventFilters) -> Select:
        if filters.ip_address:
            query = query.where(Event.ip_address == filters.ip_address)
        if filters.service_type:
            query = query.where(Event.service_type == filters.service_type)
        if filters.attack_type:
            query = query.where(Event.attack_type == filters.attack_type)
        if filters.is_attack is not None:
            query = query.where(Event.is_attack.is_(filters.is_attack))
        if filters.min_risk is not None:
            query = query.where(Event.risk_score >= filters.min_risk)
        if filters.max_risk is not None:
            query = query.where(Event.risk_score <= filters.max_risk)
        if filters.start_time:
            query = query.where(Event.timestamp >= filters.start_time)
        if filters.end_time:
            query = query.where(Event.timestamp <= filters.end_time)
        return query
