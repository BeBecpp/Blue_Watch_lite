# BlueWatch Lite

BlueWatch Lite is a local-only defensive cybersecurity training project. It ingests fictional sample logs, parses security events, runs safe rule-based detections, and shows alerts in a React dashboard.

## Safety Scope

This project is intentionally defensive and educational.

- It does not scan networks.
- It does not exploit systems.
- It does not collect credentials.
- It uses only local sample logs and documentation-reserved IP ranges.

## Features

- FastAPI backend with SQLite storage
- React + Vite + TypeScript frontend
- Tailwind CSS UI
- Demo log loader
- Linux SSH auth.log parser
- Nginx access log parser
- Generic JSON security event parser
- Rule-based detections:
  - SSH brute force
  - Successful login after failures
  - HTTP 401/403/404 burst
  - Sensitive path probing
  - Unusual or scanner-like User Agent
  - Impossible travel simulation using local mock IP-to-country mapping
- Dashboard summary cards
- Alert detail view with matched evidence
- Rule enable/disable and threshold editing
- Event search
- Markdown incident report generation and download

## Project Structure

```text
BlueWatch_Lite/
  backend/
    app/
      crud.py
      database.py
      detector.py
      main.py
      models.py
      parser.py
      schemas.py
    tests/
      test_detector.py
      test_parser.py
    requirements.txt
    run.py
  frontend/
    src/
      App.tsx
      main.tsx
      styles.css
    package.json
    vite.config.ts
    tailwind.config.js
  sample_logs/
    auth_ssh.log
    generic_security.json
    nginx_access.log
  docs/
    MANUAL_QA.md
    WALKTHROUGH.md
```

## Backend Setup

From the project root:

```bash
cd backend
python -m venv .venv
```

Activate the environment.

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run tests:

```bash
cd ..
PYTHONPATH=backend pytest -q backend/tests
```

On Windows PowerShell:

```powershell
$env:PYTHONPATH="backend"
pytest -q backend/tests
```

Start the API:

```bash
cd backend
python run.py
```

API base URL:

```text
http://127.0.0.1:8000/api
```

Interactive API docs:

```text
http://127.0.0.1:8000/docs
```

## Frontend Setup

Open a second terminal from the project root:

```bash
cd frontend
npm install
npm run dev
```

Frontend URL:

```text
http://127.0.0.1:5173
```

Build check:

```bash
npm run build
```

## Recommended Demo Flow

1. Start backend with `python backend/run.py`.
2. Start frontend with `npm run dev` inside `frontend`.
3. Open `http://127.0.0.1:5173`.
4. Click **Load Demo Logs**.
5. Review dashboard cards and severity breakdown.
6. Open the **Alerts** page.
7. Open alert details and inspect matched events.
8. Open **Rules**, disable a rule, then enable it again.
9. Open **Events** and search by source IP or message text.
10. Open **Report**, generate a Markdown report, then download it.

## Notes

- The SQLite database file `bluewatch.db` is created at runtime.
- Demo loading clears previous events and alerts to avoid duplicates.
- Rule settings are stored locally in SQLite.
- All sample IPs are from RFC 5737 documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
