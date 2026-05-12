from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from analytics.services.event_service import EventFilters, EventService
from collector.db import get_session

router = APIRouter()


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
