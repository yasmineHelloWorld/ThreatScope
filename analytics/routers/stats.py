from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from analytics.services.stats_service import StatsService
from collector.db import get_session

router = APIRouter()


@router.get("")
async def get_stats(session: AsyncSession = Depends(get_session)) -> dict:
    return await StatsService(session).summary()
