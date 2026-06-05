from app.parser import parse_auth_log_line, parse_nginx_log_line, parse_json_log, get_mock_geo

def test_mock_geo():
    lat, lon, cc = get_mock_geo("192.0.2.5")
    assert cc == "US"
    assert lat == 40.7128
    assert lon == -74.0060

    lat, lon, cc = get_mock_geo("198.51.100.12")
    assert cc == "DE"

    lat, lon, cc = get_mock_geo("203.0.113.88")
    assert cc == "SG"

    lat, lon, cc = get_mock_geo("8.8.8.8")
    assert cc is None

def test_parse_auth_log_line():
    failed_line = "Jun  5 22:30:01 server sshd[1234]: Failed password for invalid user admin from 192.0.2.10 port 59123 ssh2"
    result = parse_auth_log_line(failed_line)
    assert result is not None
    assert result["event_type"] == "SSH_LOGIN"
    assert result["status_code"] == 0
    assert result["username"] == "admin"
    assert result["source_ip"] == "192.0.2.10"
    assert result["country_code"] == "US"

    accepted_line = "Jun  5 22:31:15 server sshd[1235]: Accepted password for root from 198.51.100.20 port 59203 ssh2"
    result = parse_auth_log_line(accepted_line)
    assert result is not None
    assert result["event_type"] == "SSH_LOGIN"
    assert result["status_code"] == 1
    assert result["username"] == "root"
    assert result["source_ip"] == "198.51.100.20"
    assert result["country_code"] == "DE"

def test_parse_nginx_log_line():
    line = '203.0.113.30 - - [05/Jun/2026:22:30:00 +0000] "GET /login HTTP/1.1" 401 530 "-" "Mozilla/5.0"'
    result = parse_nginx_log_line(line)
    assert result is not None
    assert result["event_type"] == "HTTP_REQUEST"
    assert result["status_code"] == 401
    assert result["request_path"] == "/login"
    assert result["source_ip"] == "203.0.113.30"
    assert result["country_code"] == "SG"
    assert result["user_agent"] == "Mozilla/5.0"

def test_parse_json_log():
    json_content = '[{"timestamp": "2026-06-05T22:30:00Z", "source_ip": "192.0.2.100", "username": "admin", "event_type": "SSH_LOGIN", "status_code": 0, "message": "Failed SSH login"}]'
    result = parse_json_log(json_content)
    assert len(result) == 1
    assert result[0]["event_type"] == "SSH_LOGIN"
    assert result[0]["source_ip"] == "192.0.2.100"
    assert result[0]["status_code"] == 0
