import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# Mock Geolocation Map for RFC 5737 documentation/test IP prefixes only.
def get_mock_geo(ip: str) -> Tuple[Optional[float], Optional[float], Optional[str]]:
    if ip.startswith("192.0.2."):
        return 40.7128, -74.0060, "US"  # New York
    if ip.startswith("198.51.100."):
        return 50.1109, 8.6821, "DE"  # Frankfurt
    if ip.startswith("203.0.113."):
        return 1.3521, 103.8198, "SG"  # Singapore
    return None, None, None


def parse_auth_log_line(line: str) -> Optional[Dict[str, Any]]:
    ssh_pattern = re.compile(
        r"sshd\[\d+\]:\s+(Accepted|Failed)\s+password\s+for\s+"
        r"(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+\d+"
    )
    ts_pattern = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")

    ts_match = ts_pattern.match(line)
    if not ts_match:
        return None

    ts_str_clean = " ".join(ts_match.group(1).split())
    try:
        parsed_time = datetime.strptime(
            f"{datetime.utcnow().year} {ts_str_clean}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        parsed_time = datetime.utcnow()

    match = ssh_pattern.search(line)
    if not match:
        return None

    status_str, username, source_ip = match.groups()
    status_code = 1 if status_str == "Accepted" else 0
    lat, lon, country = get_mock_geo(source_ip)

    return {
        "timestamp": parsed_time,
        "event_type": "SSH_LOGIN",
        "source_ip": source_ip,
        "username": username,
        "status_code": status_code,
        "request_path": None,
        "user_agent": None,
        "raw_message": line.strip(),
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
    }


def parse_nginx_log_line(line: str) -> Optional[Dict[str, Any]]:
    nginx_pattern = re.compile(
        r'^(\S+)\s+-\s+-\s+\[(.*?)\]\s+"(\S+)\s+(\S+)\s+[^\"]*"\s+'
        r'(\d+)\s+(\d+)\s+"[^\"]*"\s+"([^\"]*)"'
    )
    match = nginx_pattern.match(line)
    if not match:
        return None

    source_ip = match.group(1)
    ts_str = match.group(2)
    request_path = match.group(4)
    status_code = int(match.group(5))
    user_agent = match.group(7)

    try:
        parsed_time = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        parsed_time = parsed_time.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        parsed_time = datetime.utcnow()

    lat, lon, country = get_mock_geo(source_ip)

    return {
        "timestamp": parsed_time,
        "event_type": "HTTP_REQUEST",
        "source_ip": source_ip,
        "username": None,
        "status_code": status_code,
        "request_path": request_path,
        "user_agent": user_agent if user_agent != "-" else "",
        "raw_message": line.strip(),
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
    }


def parse_json_object(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ts_str = obj.get("timestamp")
    source_ip = obj.get("source_ip")
    if not ts_str or not source_ip:
        return None

    try:
        ts_str_clean = str(ts_str).replace("Z", "+00:00")
        parsed_time = datetime.fromisoformat(ts_str_clean)
        if parsed_time.tzinfo is not None:
            parsed_time = parsed_time.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        parsed_time = datetime.utcnow()

    status_code = obj.get("status_code")
    if status_code is not None:
        try:
            status_code = int(status_code)
        except (TypeError, ValueError):
            status_code = None

    lat, lon, country = get_mock_geo(source_ip)

    return {
        "timestamp": parsed_time,
        "event_type": obj.get("event_type", "GENERIC_JSON"),
        "source_ip": source_ip,
        "username": obj.get("username"),
        "status_code": status_code,
        "request_path": obj.get("request_path"),
        "user_agent": obj.get("user_agent"),
        "raw_message": obj.get("message") or obj.get("raw_message") or json.dumps(obj),
        "latitude": lat,
        "longitude": lon,
        "country_code": country,
    }


def parse_json_log(content: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for obj in data:
                if isinstance(obj, dict):
                    parsed = parse_json_object(obj)
                    if parsed:
                        events.append(parsed)
            return events
        if isinstance(data, dict):
            parsed = parse_json_object(data)
            return [parsed] if parsed else []
    except json.JSONDecodeError:
        pass

    for line in content.strip().splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                parsed = parse_json_object(obj)
                if parsed:
                    events.append(parsed)
        except json.JSONDecodeError:
            continue
    return events


def parse_log_content(content: str, format_type: str) -> List[Dict[str, Any]]:
    if format_type == "auth_log":
        return [
            parsed
            for line in content.strip().splitlines()
            if line.strip()
            for parsed in [parse_auth_log_line(line)]
            if parsed
        ]
    if format_type == "nginx_access":
        return [
            parsed
            for line in content.strip().splitlines()
            if line.strip()
            for parsed in [parse_nginx_log_line(line)]
            if parsed
        ]
    if format_type == "json":
        return parse_json_log(content)
    return []
