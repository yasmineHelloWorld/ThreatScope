import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, Index, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Event(Base):
    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address = Column(String(45), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    service_type = Column(String(20), nullable=False)
    request_type = Column(String(50))
    username = Column(String(255))
    password = Column(String(255))
    payload = Column(Text)
    user_agent = Column(Text)
    endpoint = Column(String(255))
    risk_score = Column(Integer, default=0)
    attack_type = Column(String(50))
    is_attack = Column(Boolean, default=False)
    session_id = Column(String(36))
    response_sent = Column(Text)
    extra_data = Column(JSON)

    __table_args__ = (
        Index("idx_events_ip", "ip_address"),
        Index("idx_events_timestamp", "timestamp"),
        Index("idx_events_attack_type", "attack_type"),
        Index("idx_events_risk_score", "risk_score"),
    )


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address = Column(String(45), nullable=False)
    start_time = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    end_time = Column(DateTime(timezone=True))
    event_count = Column(Integer, default=0)
    max_risk_score = Column(Integer, default=0)
    classification = Column(String(20))


class AttackAlert(Base):
    __tablename__ = "attack_alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address = Column(String(45), nullable=False)
    attack_type = Column(String(50), nullable=False)
    confidence = Column(Integer)
    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    details = Column(JSON)
