import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from . import detector, models, parser, schemas


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def ingest_raw_log(db: Session, content: str, format_type: str) -> models.RawLog:
    raw_log = models.RawLog(
        content=content,
        format_type=format_type,
        timestamp=datetime.utcnow(),
    )
    db.add(raw_log)
    db.commit()
    db.refresh(raw_log)

    event_dicts = parser.parse_log_content(content, format_type)
    db_events: List[models.ParsedEvent] = []
    for event_dict in event_dicts:
        event = models.ParsedEvent(log_id=raw_log.id, **event_dict)
        db.add(event)
        db_events.append(event)

    db.commit()
    for event in db_events:
        db.refresh(event)

    if db_events:
        detector.run_detections(db, db_events)

    return raw_log


def clear_security_data(db: Session) -> None:
    db.query(models.alert_events).delete()
    db.query(models.Alert).delete()
    db.query(models.ParsedEvent).delete()
    db.query(models.RawLog).delete()
    db.commit()


def _default_sample_logs_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "sample_logs"


def _replace_syslog_date(line: str, new_date_str: str) -> str:
    return re.sub(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}", new_date_str, line)


def _replace_nginx_date(line: str, new_date_str: str) -> str:
    return re.sub(
        r"\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[^\]]+\]",
        f"[{new_date_str}]",
        line,
    )


def load_demo_logs(db: Session, sample_logs_dir: Optional[str] = None) -> None:
    sample_dir = Path(sample_logs_dir) if sample_logs_dir else _default_sample_logs_dir()
    clear_security_data(db)
    detector.init_rules(db)

    now = datetime.utcnow()

    auth_log_path = sample_dir / "auth_ssh.log"
    if auth_log_path.exists():
        lines = auth_log_path.read_text(encoding="utf-8").strip().splitlines()
        adjusted_lines = []
        for i, line in enumerate(lines):
            event_time = now - timedelta(seconds=(len(lines) - 1 - i) * 15)
            adjusted_lines.append(_replace_syslog_date(line, event_time.strftime("%b %d %H:%M:%S")))
        ingest_raw_log(db, "\n".join(adjusted_lines), "auth_log")

    nginx_log_path = sample_dir / "nginx_access.log"
    if nginx_log_path.exists():
        lines = nginx_log_path.read_text(encoding="utf-8").strip().splitlines()
        adjusted_lines = []
        for i, line in enumerate(lines):
            event_time = now - timedelta(seconds=(len(lines) - 1 - i) * 5)
            adjusted_lines.append(_replace_nginx_date(line, event_time.strftime("%d/%b/%Y:%H:%M:%S +0000")))
        ingest_raw_log(db, "\n".join(adjusted_lines), "nginx_access")

    json_log_path = sample_dir / "generic_security.json"
    if json_log_path.exists():
        data = json.loads(json_log_path.read_text(encoding="utf-8"))
        adjusted_events = []
        for i, obj in enumerate(data):
            updated = dict(obj)
            event_time = now - timedelta(seconds=(len(data) - 1 - i) * 20)
            updated["timestamp"] = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            adjusted_events.append(updated)
        ingest_raw_log(db, json.dumps(adjusted_events), "json")


def get_dashboard_stats(db: Session) -> schemas.DashboardStats:
    total_events = db.query(models.ParsedEvent).count()

    counts_by_severity = {
        severity: count
        for severity, count in db.query(models.Alert.severity, func.count(models.Alert.id))
        .group_by(models.Alert.severity)
        .all()
    }
    severity_counts = [
        schemas.SeverityCount(severity=severity, count=counts_by_severity.get(severity, 0))
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ]

    top_ips = [
        schemas.TopIp(source_ip=source_ip, count=count)
        for source_ip, count in db.query(models.ParsedEvent.source_ip, func.count(models.ParsedEvent.id))
        .group_by(models.ParsedEvent.source_ip)
        .order_by(func.count(models.ParsedEvent.id).desc())
        .limit(5)
        .all()
    ]

    top_usernames = [
        schemas.TopUsername(username=username, count=count)
        for username, count in db.query(models.ParsedEvent.username, func.count(models.ParsedEvent.id))
        .filter(models.ParsedEvent.username.isnot(None))
        .group_by(models.ParsedEvent.username)
        .order_by(func.count(models.ParsedEvent.id).desc())
        .limit(5)
        .all()
    ]

    events_over_time = [
        schemas.EventOverTime(time_bucket=time_bucket, count=count)
        for time_bucket, count in db.query(
            func.strftime("%Y-%m-%d %H:00", models.ParsedEvent.timestamp).label("time_bucket"),
            func.count(models.ParsedEvent.id),
        )
        .group_by("time_bucket")
        .order_by("time_bucket")
        .all()
    ]

    recent_alerts = [
        schemas.AlertResponse.model_validate(alert)
        for alert in db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(10).all()
    ]

    return schemas.DashboardStats(
        total_events=total_events,
        severity_counts=severity_counts,
        top_ips=top_ips,
        top_usernames=top_usernames,
        events_over_time=events_over_time,
        recent_alerts=recent_alerts,
    )


def get_parsed_events(
    db: Session,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    search: Optional[str] = None,
) -> List[models.ParsedEvent]:
    query = db.query(models.ParsedEvent)
    if source_ip:
        query = query.filter(models.ParsedEvent.source_ip == source_ip)
    if username:
        query = query.filter(models.ParsedEvent.username == username)
    if start_time:
        query = query.filter(models.ParsedEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(models.ParsedEvent.timestamp <= end_time)
    if search:
        query = query.filter(models.ParsedEvent.raw_message.contains(search))
    return query.order_by(models.ParsedEvent.timestamp.desc()).limit(500).all()


def get_alerts(
    db: Session,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[models.Alert]:
    query = db.query(models.Alert)
    if severity:
        query = query.filter(models.Alert.severity == severity)
    if source_ip or username:
        query = query.join(models.Alert.events)
        if source_ip:
            query = query.filter(models.ParsedEvent.source_ip == source_ip)
        if username:
            query = query.filter(models.ParsedEvent.username == username)
    if start_time:
        query = query.filter(models.Alert.timestamp >= start_time)
    if end_time:
        query = query.filter(models.Alert.timestamp <= end_time)
    return query.options(selectinload(models.Alert.events)).order_by(models.Alert.timestamp.desc()).distinct().all()


def get_alert_detail(db: Session, alert_id: int) -> Optional[models.Alert]:
    return (
        db.query(models.Alert)
        .options(selectinload(models.Alert.events))
        .filter(models.Alert.id == alert_id)
        .first()
    )


def get_rules(db: Session) -> List[models.Rule]:
    return db.query(models.Rule).order_by(models.Rule.id).all()


def update_rule(db: Session, rule_id: str, rule_update: schemas.RuleUpdate) -> Optional[models.Rule]:
    rule = db.query(models.Rule).filter(models.Rule.id == rule_id).first()
    if not rule:
        return None
    if rule_update.enabled is not None:
        rule.enabled = rule_update.enabled
    if rule_update.threshold_window_seconds is not None:
        rule.threshold_window_seconds = max(0, rule_update.threshold_window_seconds)
    if rule_update.threshold_count is not None:
        rule.threshold_count = max(1, rule_update.threshold_count)
    db.commit()
    db.refresh(rule)
    return rule


def reset_rules(db: Session) -> List[models.Rule]:
    db.query(models.Rule).delete()
    db.commit()
    detector.init_rules(db)
    return get_rules(db)


def generate_report_markdown(db: Session) -> str:
    stats = get_dashboard_stats(db)
    alerts = db.query(models.Alert).options(selectinload(models.Alert.events)).all()
    alerts.sort(key=lambda a: (SEVERITY_ORDER.get(a.severity, 99), a.timestamp), reverse=False)

    report = [
        "# BlueWatch Lite - Incident Summary Report",
        f"Generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "",
        "## 1. Executive Summary",
        f"- **Total Security Events Parsed:** {stats.total_events}",
        f"- **Total Alerts Triggered:** {len(alerts)}",
        "",
        "### Alert Severity Breakdown",
    ]
    for severity_count in stats.severity_counts:
        report.append(f"- **{severity_count.severity}:** {severity_count.count}")

    report.extend(["", "## 2. Top Threat Indicators", "", "### Top Traffic Sources"])
    report.extend([f"- {item.source_ip} ({item.count} events)" for item in stats.top_ips] or ["- None"])

    report.extend(["", "### Top Usernames"])
    report.extend([f"- {item.username} ({item.count} events)" for item in stats.top_usernames] or ["- None"])

    report.extend(["", "## 3. Triggered Alert Details"])
    if not alerts:
        report.append("No alerts triggered in this reporting window.")
    for alert in alerts:
        report.extend(
            [
                "",
                f"### [{alert.severity}] {alert.rule_name} (Alert #{alert.id})",
                f"- **Timestamp:** {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC",
                f"- **Explanation:** {alert.explanation}",
                f"- **Recommended Defensive Action:** {alert.recommended_action}",
                f"- **False Positive Notes:** {alert.false_positive_notes}",
                f"- **Matched Events:** {len(alert.events)}",
            ]
        )

    report.extend(["", "## 4. Defensive Next Steps"])
    report.extend(
        [
            "- Validate whether the top source IPs are expected internal/test traffic.",
            "- Review high and critical alerts first.",
            "- Tune thresholds for your environment before using these detections operationally.",
            "- Keep this project local-only; do not point it at real networks without authorization.",
        ]
    )

    report.extend(["", "## 5. Rule Summary"])
    for rule in get_rules(db):
        status = "Enabled" if rule.enabled else "Disabled"
        report.append(
            f"- **{rule.name}** ({status}, severity {rule.severity}, threshold {rule.threshold_count}/{rule.threshold_window_seconds}s): {rule.description}"
        )

    return "\n".join(report)
