from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field


class EventSchema(BaseModel):
    id: UUID
    ip_address: str
    timestamp: datetime
    service_type: str
    request_type: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    payload: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    risk_score: int = 0
    attack_type: Optional[str] = None
    is_attack: bool = False
    session_id: Optional[UUID] = None
    response_sent: Optional[str] = None
    metadata: Optional[dict] = None


class SessionSchema(BaseModel):
    id: UUID
    ip_address: str
    start_time: datetime
    end_time: Optional[datetime] = None
    event_count: int = 0
    max_risk_score: int = 0
    classification: Optional[str] = None


class AttackAlertSchema(BaseModel):
    id: UUID
    ip_address: str
    attack_type: str
    confidence: float
    detected_at: datetime
    details: Optional[dict] = None
