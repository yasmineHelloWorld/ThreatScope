from datetime import datetime, timedelta, timezone

from sqlalchemy import case, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from analytics.services.event_service import serialize_event
from collector.models import AttackAlert, Event


class StatsService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def summary(self) -> dict:
        now = datetime.now(timezone.utc)
        last_24h = now - timedelta(hours=24)

        totals = (
            await self.session.execute(
                select(
                    func.count(Event.id),
                    func.coalesce(func.sum(case((Event.is_attack.is_(True), 1), else_=0)), 0),
                    func.count(func.distinct(Event.ip_address)),
                    func.coalesce(func.avg(Event.risk_score), 0),
                    func.coalesce(func.max(Event.risk_score), 0),
                )
            )
        ).one()

        attacks_24h = (
            await self.session.execute(
                select(func.count(Event.id)).where(
                    Event.is_attack.is_(True),
                    Event.timestamp >= last_24h,
                )
            )
        ).scalar_one()

        alert_rows = await self.session.execute(
            select(AttackAlert).order_by(AttackAlert.detected_at.desc()).limit(10)
        )

        return {
            "total_events": totals[0],
            "total_attacks": totals[1],
            "unique_ips": totals[2],
            "average_risk_score": round(float(totals[3]), 2),
            "max_risk_score": int(totals[4]),
            "attack_counts_by_type": await self._count_by(Event.attack_type, Event.is_attack.is_(True)),
            "events_by_service_type": await self._count_by(Event.service_type),
            "top_attacking_ips": await self.top_ips(10),
            "recent_high_risk_alerts": [
                {
                    "id": str(alert.id),
                    "ip_address": str(alert.ip_address),
                    "attack_type": alert.attack_type,
                    "confidence": float(alert.confidence or 0),
                    "detected_at": alert.detected_at.isoformat() if alert.detected_at else None,
                    "details": alert.details or {},
                }
                for alert in alert_rows.scalars().all()
            ],
            "attacks_last_24h": attacks_24h,
        }

    async def timeline(
        self,
        interval: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[dict]:
        bucket = func.date_trunc(interval, Event.timestamp).label("bucket")
        query = select(
            bucket,
            func.count(Event.id).label("event_count"),
            func.coalesce(func.sum(case((Event.is_attack.is_(True), 1), else_=0)), 0).label("attack_count"),
            func.coalesce(func.avg(Event.risk_score), 0).label("average_risk"),
        )
        if start_time:
            query = query.where(Event.timestamp >= start_time)
        if end_time:
            query = query.where(Event.timestamp <= end_time)

        rows = await self.session.execute(query.group_by(bucket).order_by(bucket))
        return [
            {
                "bucket": row.bucket.isoformat() if row.bucket else None,
                "event_count": row.event_count,
                "attack_count": row.attack_count,
                "average_risk": round(float(row.average_risk), 2),
            }
            for row in rows
        ]

    async def attack_distribution(self) -> list[dict]:
        counts = await self._count_by(Event.attack_type, Event.is_attack.is_(True))
        return [{"name": key, "value": value} for key, value in counts.items()]

    async def service_distribution(self) -> list[dict]:
        counts = await self._count_by(Event.service_type)
        return [{"name": key, "value": value} for key, value in counts.items()]

    async def top_ips(self, limit: int = 10) -> list[dict]:
        rows = await self.session.execute(
            select(
                Event.ip_address,
                func.count(Event.id).label("event_count"),
                func.coalesce(func.sum(case((Event.is_attack.is_(True), 1), else_=0)), 0).label("attack_count"),
                func.coalesce(func.max(Event.risk_score), 0).label("max_risk"),
            )
            .group_by(Event.ip_address)
            .order_by(desc("attack_count"), desc("event_count"), desc("max_risk"))
            .limit(limit)
        )
        return [
            {
                "ip_address": str(row.ip_address),
                "event_count": row.event_count,
                "attack_count": row.attack_count,
                "max_risk": row.max_risk,
            }
            for row in rows
        ]

    async def risk_timeline(self, ip_address: str | None = None, limit: int = 200) -> list[dict]:
        query = select(Event).order_by(Event.timestamp.desc()).limit(limit)
        if ip_address:
            query = query.where(Event.ip_address == ip_address)

        rows = await self.session.execute(query)
        events = list(reversed(rows.scalars().all()))
        return [
            {
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "ip_address": str(event.ip_address),
                "risk_score": event.risk_score or 0,
                "attack_type": event.attack_type,
                "is_attack": bool(event.is_attack),
            }
            for event in events
        ]

    async def recent_events(self, limit: int = 50) -> list[dict]:
        rows = await self.session.execute(
            select(Event).order_by(Event.timestamp.desc()).limit(limit)
        )
        return [serialize_event(event) for event in rows.scalars().all()]

    async def _count_by(self, column, *where_clauses) -> dict[str, int]:
        query = select(column, func.count(Event.id)).where(column.is_not(None))
        for clause in where_clauses:
            query = query.where(clause)
        rows = await self.session.execute(query.group_by(column).order_by(desc(func.count(Event.id))))
        return {str(key): count for key, count in rows}
