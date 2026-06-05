from sqlalchemy import Table, Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from .database import Base

# Association table for Alert and ParsedEvent (Many-to-Many)
alert_events = Table(
    "alert_events",
    Base.metadata,
    Column("alert_id", Integer, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", Integer, ForeignKey("parsed_events.id", ondelete="CASCADE"), primary_key=True),
)

class RawLog(Base):
    __tablename__ = "raw_logs"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    format_type = Column(String, nullable=False)  # auth_log, nginx_access, json
    timestamp = Column(DateTime, nullable=False)

    parsed_events = relationship("ParsedEvent", back_populates="raw_log", cascade="all, delete-orphan")

class ParsedEvent(Base):
    __tablename__ = "parsed_events"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("raw_logs.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String, nullable=False)  # SSH_LOGIN, HTTP_REQUEST, GENERIC_JSON
    source_ip = Column(String, nullable=False)
    username = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)  # HTTP code or SSH success(1)/fail(0)
    request_path = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    raw_message = Column(Text, nullable=False)

    # Mock geolocation data for impossible travel
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    country_code = Column(String, nullable=True)

    raw_log = relationship("RawLog", back_populates="parsed_events")
    alerts = relationship("Alert", secondary=alert_events, back_populates="events")

class Rule(Base):
    __tablename__ = "rules"

    id = Column(String, primary_key=True, index=True)  # e.g., ssh_brute_force
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    threshold_window_seconds = Column(Integer, nullable=False)
    threshold_count = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, ForeignKey("rules.id", ondelete="CASCADE"), nullable=False)
    rule_name = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    explanation = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    false_positive_notes = Column(Text, nullable=False)

    events = relationship("ParsedEvent", secondary=alert_events, back_populates="alerts")
