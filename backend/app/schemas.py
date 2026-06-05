from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class RawLogBase(BaseModel):
    content: str
    format_type: str = Field(pattern="^(auth_log|nginx_access|json)$")


class RawLogCreate(RawLogBase):
    pass


class RawLogResponse(RawLogBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


class ParsedEventResponse(BaseModel):
    id: int
    log_id: int
    timestamp: datetime
    event_type: str
    source_ip: str
    username: Optional[str] = None
    status_code: Optional[int] = None
    request_path: Optional[str] = None
    user_agent: Optional[str] = None
    raw_message: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    country_code: Optional[str] = None

    class Config:
        from_attributes = True


class RuleResponse(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    threshold_window_seconds: int
    threshold_count: int
    enabled: bool

    class Config:
        from_attributes = True


class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    threshold_window_seconds: Optional[int] = None
    threshold_count: Optional[int] = None


class AlertResponse(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: str
    timestamp: datetime
    explanation: str
    recommended_action: str
    false_positive_notes: str

    class Config:
        from_attributes = True


class AlertDetailResponse(AlertResponse):
    events: List[ParsedEventResponse] = []

    class Config:
        from_attributes = True


class SeverityCount(BaseModel):
    severity: str
    count: int


class TopIp(BaseModel):
    source_ip: str
    count: int


class TopUsername(BaseModel):
    username: str
    count: int


class EventOverTime(BaseModel):
    time_bucket: str
    count: int


class DashboardStats(BaseModel):
    total_events: int
    severity_counts: List[SeverityCount]
    top_ips: List[TopIp]
    top_usernames: List[TopUsername]
    events_over_time: List[EventOverTime]
    recent_alerts: List[AlertResponse]
