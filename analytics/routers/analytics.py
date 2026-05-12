from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from analytics.services.stats_service import StatsService
from collector.db import get_session

router = APIRouter()


@router.get("/timeline")
async def timeline(
    interval: str = Query("hour", pattern="^(minute|hour|day)$"),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    return await StatsService(session).timeline(interval, start_time, end_time)


@router.get("/attack-distribution")
async def attack_distribution(session: AsyncSession = Depends(get_session)) -> list[dict]:
    return await StatsService(session).attack_distribution()


@router.get("/top-ips")
async def top_ips(
    limit: int = Query(10, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    return await StatsService(session).top_ips(limit)


@router.get("/risk-timeline")
async def risk_timeline(
    ip_address: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    return await StatsService(session).risk_timeline(ip_address, limit)


@router.get("/service-distribution")
async def service_distribution(session: AsyncSession = Depends(get_session)) -> list[dict]:
    return await StatsService(session).service_distribution()
