import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

from app import models, detector
from app.database import Base

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    detector.init_rules(session)
    yield session
    session.close()

def test_ssh_brute_force(db_session):
    # Ingest 5 failures from same IP within 10 seconds
    ip = "192.0.2.10"
    raw_log = models.RawLog(content="syslog", format_type="auth_log", timestamp=datetime.utcnow())
    db_session.add(raw_log)
    db_session.commit()

    events = []
    base_time = datetime.utcnow()
    for i in range(5):
        event = models.ParsedEvent(
            log_id=raw_log.id,
            timestamp=base_time + timedelta(seconds=i),
            event_type="SSH_LOGIN",
            source_ip=ip,
            status_code=0,
            raw_message="failed SSH"
        )
        db_session.add(event)
        events.append(event)
    db_session.commit()

    detector.run_detections(db_session, events)

    alerts = db_session.query(models.Alert).filter(models.Alert.rule_id == "ssh_brute_force").all()
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert len(alerts[0].events) == 5

def test_ssh_login_after_fail(db_session):
    ip = "198.51.100.20"
    raw_log = models.RawLog(content="syslog", format_type="auth_log", timestamp=datetime.utcnow())
    db_session.add(raw_log)
    db_session.commit()

    events = []
    base_time = datetime.utcnow()
    # 3 failures
    for i in range(3):
        event = models.ParsedEvent(
            log_id=raw_log.id,
            timestamp=base_time + timedelta(seconds=i),
            event_type="SSH_LOGIN",
            source_ip=ip,
            status_code=0,
            raw_message="failed SSH"
        )
        db_session.add(event)
        events.append(event)
    
    # 1 success
    success_event = models.ParsedEvent(
        log_id=raw_log.id,
        timestamp=base_time + timedelta(seconds=4),
        event_type="SSH_LOGIN",
        source_ip=ip,
        status_code=1,
        username="root",
        raw_message="accepted SSH"
    )
    db_session.add(success_event)
    events.append(success_event)
    db_session.commit()

    detector.run_detections(db_session, [success_event])

    alerts = db_session.query(models.Alert).filter(models.Alert.rule_id == "ssh_login_after_fail").all()
    assert len(alerts) == 1
    # Check that events include the successful one
    assert success_event in alerts[0].events

def test_path_probing(db_session):
    raw_log = models.RawLog(content="nginx", format_type="nginx_access", timestamp=datetime.utcnow())
    db_session.add(raw_log)
    db_session.commit()

    probe_event = models.ParsedEvent(
        log_id=raw_log.id,
        timestamp=datetime.utcnow(),
        event_type="HTTP_REQUEST",
        source_ip="192.0.2.50",
        status_code=404,
        request_path="/.env",
        raw_message="probe"
    )
    db_session.add(probe_event)
    db_session.commit()

    detector.run_detections(db_session, [probe_event])

    alerts = db_session.query(models.Alert).filter(models.Alert.rule_id == "path_probing").all()
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"

def test_impossible_travel(db_session):
    raw_log = models.RawLog(content="syslog", format_type="auth_log", timestamp=datetime.utcnow())
    db_session.add(raw_log)
    db_session.commit()

    # Login 1: US New York (192.0.2.1)
    login1 = models.ParsedEvent(
        log_id=raw_log.id,
        timestamp=datetime.utcnow() - timedelta(minutes=10),
        event_type="SSH_LOGIN",
        source_ip="192.0.2.1",
        username="traveler",
        status_code=1,
        latitude=40.7128,
        longitude=-74.0060,
        country_code="US",
        raw_message="accepted SSH US"
    )
    db_session.add(login1)

    # Login 2: DE Frankfurt (198.51.100.1) 10 minutes later
    login2 = models.ParsedEvent(
        log_id=raw_log.id,
        timestamp=datetime.utcnow(),
        event_type="SSH_LOGIN",
        source_ip="198.51.100.1",
        username="traveler",
        status_code=1,
        latitude=50.1109,
        longitude=8.6821,
        country_code="DE",
        raw_message="accepted SSH DE"
    )
    db_session.add(login2)
    db_session.commit()

    detector.run_detections(db_session, [login2])

    alerts = db_session.query(models.Alert).filter(models.Alert.rule_id == "impossible_travel").all()
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"

def test_http_status_burst(db_session):
    ip = "203.0.113.30"
    raw_log = models.RawLog(content="nginx", format_type="nginx_access", timestamp=datetime.utcnow())
    db_session.add(raw_log)
    db_session.commit()

    events = []
    base_time = datetime.utcnow()
    for i in range(10):
        event = models.ParsedEvent(
            log_id=raw_log.id,
            timestamp=base_time + timedelta(seconds=i * 2),
            event_type="HTTP_REQUEST",
            source_ip=ip,
            status_code=404,
            request_path="/missing",
            user_agent="Mozilla/5.0",
            raw_message="404 request",
        )
        db_session.add(event)
        events.append(event)
    db_session.commit()

    detector.run_detections(db_session, events)

    alerts = db_session.query(models.Alert).filter(models.Alert.rule_id == "http_status_burst").all()
    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert len(alerts[0].events) == 10


def test_unusual_user_agent(db_session):
    raw_log = models.RawLog(content="nginx", format_type="nginx_access", timestamp=datetime.utcnow())
    db_session.add(raw_log)
    db_session.commit()

    event = models.ParsedEvent(
        log_id=raw_log.id,
        timestamp=datetime.utcnow(),
        event_type="HTTP_REQUEST",
        source_ip="192.0.2.60",
        status_code=200,
        request_path="/index.html",
        user_agent="sqlmap/1.8.2",
        raw_message="scanner user-agent",
    )
    db_session.add(event)
    db_session.commit()

    detector.run_detections(db_session, [event])

    alerts = db_session.query(models.Alert).filter(models.Alert.rule_id == "unusual_user_agent").all()
    assert len(alerts) == 1
    assert alerts[0].severity == "LOW"
