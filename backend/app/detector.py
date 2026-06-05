import math
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from . import models

# Haversine formula to calculate distance between two coordinates in km
def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0  # Earth's radius in km
    
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    return R * c

# Default rules config
DEFAULT_RULES = [
    {
        "id": "ssh_brute_force",
        "name": "SSH Brute Force",
        "description": "Multiple failed SSH logins from a single IP address in a short time frame.",
        "severity": "HIGH",
        "threshold_window_seconds": 60,
        "threshold_count": 5,
        "enabled": True
    },
    {
        "id": "ssh_login_after_fail",
        "name": "Successful Login After Failures",
        "description": "A successful SSH login is observed after multiple failures from the same source IP.",
        "severity": "HIGH",
        "threshold_window_seconds": 300,
        "threshold_count": 3,
        "enabled": True
    },
    {
        "id": "http_status_burst",
        "name": "HTTP Status Burst",
        "description": "A high number of client error responses (401/403/404) from a single IP.",
        "severity": "MEDIUM",
        "threshold_window_seconds": 60,
        "threshold_count": 10,
        "enabled": True
    },
    {
        "id": "path_probing",
        "name": "Possible Path Probing",
        "description": "An HTTP request targets known administrative, configuration, or backup paths.",
        "severity": "HIGH",
        "threshold_window_seconds": 0,
        "threshold_count": 1,
        "enabled": True
    },
    {
        "id": "unusual_user_agent",
        "name": "Unusual User Agent",
        "description": "An HTTP request features an empty or scanner-like User Agent (e.g. sqlmap, nmap).",
        "severity": "LOW",
        "threshold_window_seconds": 0,
        "threshold_count": 1,
        "enabled": True
    },
    {
        "id": "impossible_travel",
        "name": "Impossible Travel Simulation",
        "description": "A user logs in from two geographically distant locations within an impossible time window.",
        "severity": "CRITICAL",
        "threshold_window_seconds": 3600,
        "threshold_count": 1,
        "enabled": True
    }
]

def init_rules(db: Session):
    for r in DEFAULT_RULES:
        db_rule = db.query(models.Rule).filter(models.Rule.id == r["id"]).first()
        if not db_rule:
            db_rule = models.Rule(**r)
            db.add(db_rule)
    db.commit()

def run_detections(db: Session, new_events: List[models.ParsedEvent]):
    # Get all rules
    rules_dict = {rule.id: rule for rule in db.query(models.Rule).all()}
    
    # Process each new event
    for event in new_events:
        # 1. SSH Brute Force
        rule = rules_dict.get("ssh_brute_force")
        if rule and rule.enabled and event.event_type == "SSH_LOGIN" and event.status_code == 0:
            window_start = event.timestamp - timedelta(seconds=rule.threshold_window_seconds)
            failures = db.query(models.ParsedEvent).filter(
                models.ParsedEvent.event_type == "SSH_LOGIN",
                models.ParsedEvent.status_code == 0,
                models.ParsedEvent.source_ip == event.source_ip,
                models.ParsedEvent.timestamp >= window_start,
                models.ParsedEvent.timestamp <= event.timestamp
            ).all()
            
            if len(failures) >= rule.threshold_count:
                # Check for recent alert to avoid spam
                recent_alert = db.query(models.Alert).filter(
                    models.Alert.rule_id == rule.id,
                    models.Alert.timestamp >= event.timestamp - timedelta(seconds=rule.threshold_window_seconds)
                ).join(models.Alert.events).filter(models.ParsedEvent.source_ip == event.source_ip).first()
                
                if not recent_alert:
                    alert = models.Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=event.timestamp,
                        explanation=f"Detected {len(failures)} failed SSH login attempts from source IP {event.source_ip} in under {rule.threshold_window_seconds} seconds.",
                        recommended_action="Block the offending source IP at the firewall or configure hosts.allow/hosts.deny. Investigate if the targeted accounts have strong passwords.",
                        false_positive_notes="Legitimate user forgetting their password or an automated system with outdated credentials."
                    )
                    alert.events.extend(failures)
                    db.add(alert)
                    db.commit()

        # 2. SSH Successful Login After Failures
        rule = rules_dict.get("ssh_login_after_fail")
        if rule and rule.enabled and event.event_type == "SSH_LOGIN" and event.status_code == 1:
            window_start = event.timestamp - timedelta(seconds=rule.threshold_window_seconds)
            failures = db.query(models.ParsedEvent).filter(
                models.ParsedEvent.event_type == "SSH_LOGIN",
                models.ParsedEvent.status_code == 0,
                models.ParsedEvent.source_ip == event.source_ip,
                models.ParsedEvent.timestamp >= window_start,
                models.ParsedEvent.timestamp <= event.timestamp
            ).all()
            
            if len(failures) >= rule.threshold_count:
                recent_alert = db.query(models.Alert).filter(
                    models.Alert.rule_id == rule.id,
                    models.Alert.timestamp >= event.timestamp - timedelta(seconds=30)
                ).join(models.Alert.events).filter(models.ParsedEvent.source_ip == event.source_ip).first()
                
                if not recent_alert:
                    alert = models.Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=event.timestamp,
                        explanation=f"A successful login for user '{event.username}' from IP {event.source_ip} occurred after {len(failures)} failed attempts in the last {rule.threshold_window_seconds} seconds.",
                        recommended_action="Immediately audit user sessions. Confirm if this successful login was authorized. Check if there are other logins from the same user elsewhere.",
                        false_positive_notes="User finally remembered their password after several mistypes."
                    )
                    alert.events.extend(failures + [event])
                    db.add(alert)
                    db.commit()

        # 3. HTTP Status Burst
        rule = rules_dict.get("http_status_burst")
        if rule and rule.enabled and event.event_type == "HTTP_REQUEST" and event.status_code in [401, 403, 404]:
            window_start = event.timestamp - timedelta(seconds=rule.threshold_window_seconds)
            errors = db.query(models.ParsedEvent).filter(
                models.ParsedEvent.event_type == "HTTP_REQUEST",
                models.ParsedEvent.status_code.in_([401, 403, 404]),
                models.ParsedEvent.source_ip == event.source_ip,
                models.ParsedEvent.timestamp >= window_start,
                models.ParsedEvent.timestamp <= event.timestamp
            ).all()
            
            if len(errors) >= rule.threshold_count:
                recent_alert = db.query(models.Alert).filter(
                    models.Alert.rule_id == rule.id,
                    models.Alert.timestamp >= event.timestamp - timedelta(seconds=rule.threshold_window_seconds)
                ).join(models.Alert.events).filter(models.ParsedEvent.source_ip == event.source_ip).first()
                
                if not recent_alert:
                    alert = models.Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=event.timestamp,
                        explanation=f"Source IP {event.source_ip} triggered {len(errors)} HTTP error status responses (401/403/404) in under {rule.threshold_window_seconds} seconds.",
                        recommended_action="Evaluate if the traffic is automated (crawlers/scanners). Block or rate-limit the IP at the reverse proxy or web application firewall level.",
                        false_positive_notes="A broken link on the site causing legitimate users to request multiple missing assets rapidly."
                    )
                    alert.events.extend(errors)
                    db.add(alert)
                    db.commit()

        # 4. Path Probing
        rule = rules_dict.get("path_probing")
        if rule and rule.enabled and event.event_type == "HTTP_REQUEST" and event.request_path:
            probing_patterns = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/etc/passwd"]
            if any(pattern in event.request_path.lower() for pattern in probing_patterns):
                # Check recent path probing for same IP/path to avoid duplicate alerts
                recent_alert = db.query(models.Alert).filter(
                    models.Alert.rule_id == rule.id,
                    models.Alert.timestamp >= event.timestamp - timedelta(seconds=10)
                ).join(models.Alert.events).filter(
                    models.ParsedEvent.source_ip == event.source_ip,
                    models.ParsedEvent.request_path == event.request_path
                ).first()
                
                if not recent_alert:
                    alert = models.Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=event.timestamp,
                        explanation=f"Source IP {event.source_ip} requested a sensitive path: '{event.request_path}'. This indicates active folder/file probing.",
                        recommended_action="Block the IP. Make sure administrative routes are protected by robust IP restriction or multi-factor authentication.",
                        false_positive_notes="An administrator visiting the admin path, or a legacy script fetching an older configuration path."
                    )
                    alert.events.append(event)
                    db.add(alert)
                    db.commit()

        # 5. Unusual User Agent
        rule = rules_dict.get("unusual_user_agent")
        if rule and rule.enabled and event.event_type == "HTTP_REQUEST":
            is_suspicious = False
            ua = event.user_agent or ""
            if not ua.strip():
                is_suspicious = True
                reason = "User Agent header is empty."
            else:
                scanner_keywords = ["sqlmap", "nmap", "nikto", "masscan", "dirbuster", "gobuster", "scanner"]
                for kw in scanner_keywords:
                    if kw in ua.lower():
                        is_suspicious = True
                        reason = f"User Agent contains known scanner signature: '{kw}'."
                        break
            
            if is_suspicious:
                recent_alert = db.query(models.Alert).filter(
                    models.Alert.rule_id == rule.id,
                    models.Alert.timestamp >= event.timestamp - timedelta(seconds=10)
                ).join(models.Alert.events).filter(
                    models.ParsedEvent.source_ip == event.source_ip,
                    models.ParsedEvent.user_agent == event.user_agent
                ).first()
                
                if not recent_alert:
                    alert = models.Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=event.timestamp,
                        explanation=f"Source IP {event.source_ip} sent a request with an unusual User Agent. Reason: {reason}",
                        recommended_action="Block request or user-agent signatures. Set up browser verification (e.g. Cloudflare Turnstile) to weed out automated scanners.",
                        false_positive_notes="Custom API clients, system uptime monitoring scripts, or curl requests used by developers."
                    )
                    alert.events.append(event)
                    db.add(alert)
                    db.commit()

        # 6. Impossible Travel Simulation
        rule = rules_dict.get("impossible_travel")
        if rule and rule.enabled and event.event_type == "SSH_LOGIN" and event.status_code == 1 and event.username:
            if event.latitude is not None and event.longitude is not None:
                # Query other successful logins for the same username within 1 hour
                window_start = event.timestamp - timedelta(seconds=rule.threshold_window_seconds)
                window_end = event.timestamp + timedelta(seconds=rule.threshold_window_seconds)
                other_logins = db.query(models.ParsedEvent).filter(
                    models.ParsedEvent.event_type == "SSH_LOGIN",
                    models.ParsedEvent.status_code == 1,
                    models.ParsedEvent.username == event.username,
                    models.ParsedEvent.id != event.id,
                    models.ParsedEvent.latitude != None,
                    models.ParsedEvent.longitude != None,
                    models.ParsedEvent.timestamp >= window_start,
                    models.ParsedEvent.timestamp <= window_end
                ).all()
                
                for hist in other_logins:
                    if hist.source_ip == event.source_ip:
                        continue
                    
                    dist = haversine_distance(
                        event.latitude, event.longitude,
                        hist.latitude, hist.longitude
                    )
                    
                    time_diff_sec = abs((event.timestamp - hist.timestamp).total_seconds())
                    if time_diff_sec < 5:
                        time_diff_sec = 5  # Prevent division by zero or extremely high speeds due to clock jitter
                        
                    time_diff_hours = time_diff_sec / 3600.0
                    speed = dist / time_diff_hours
                    
                    if speed > 800.0:  # Distance divided by time exceeds 800 km/h
                        # Check duplicate
                        recent_alert = db.query(models.Alert).filter(
                            models.Alert.rule_id == rule.id,
                            models.Alert.timestamp >= event.timestamp - timedelta(seconds=300)
                        ).join(models.Alert.events).filter(models.ParsedEvent.username == event.username).first()
                        
                        if not recent_alert:
                            alert = models.Alert(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                timestamp=event.timestamp,
                                explanation=(
                                    f"User '{event.username}' logged in from {event.country_code} ({event.source_ip}) "
                                    f"and {hist.country_code} ({hist.source_ip}) within {time_diff_sec / 60:.1f} minutes. "
                                    f"Distance is {dist:.1f} km, which requires a travel speed of {speed:.1f} km/h."
                                ),
                                recommended_action="Mandatory credential revocation and session kill for the user. Force password reset and MFA enrollment.",
                                false_positive_notes="User accessing via a VPN or Tor network that routes traffic through different exit nodes rapidly."
                            )
                            alert.events.extend([event, hist])
                            db.add(alert)
                            db.commit()
                            break  # Trigger once per validation run to avoid duplicates
