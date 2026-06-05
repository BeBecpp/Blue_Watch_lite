# BlueWatch Lite

```txt
  /./.// /./.// /./.// /./.// /././/

   ____  _            __        __    _       _
  | __ )| |_   _  ___ \ \      / /_ _| |_ ___| |__
  |  _ \| | | | |/ _ \ \ \ /\ / / _` | __/ __| '_ \
  | |_) | | |_| |  __/  \ V  V / (_| | || (__| | | |
  |____/|_|\__,_|\___|   \_/\_/ \__,_|\__\___|_| |_|

  [//] BLUEWATCH LITE
  [//] LOCAL SIEM DASHBOARD
  [//] DEFENSIVE SECURITY PROJECT
```

BlueWatch Lite is a small local SIEM-style dashboard made for defensive cybersecurity practice.

It loads sample security logs, parses them, runs detection rules, and displays suspicious activity as alerts. The main goal of this project is to understand how basic blue-team tools work behind the scenes.

This project is fully local. It does not scan, attack, exploit, or connect to real targets.

---

## What this project does

BlueWatch Lite follows a simple security monitoring flow:

```txt
security logs -> parser -> database -> detection rules -> alerts -> dashboard
```

It helps practice:

* reading security logs
* parsing SSH and web events
* writing simple detection rules
* reviewing alerts
* filtering events
* generating a basic incident report

---

## Project Scheme

```txt
                ┌────────────────────┐
                │    Sample Logs      │
                │ SSH / Web / JSON    │
                └──────────┬─────────┘
                           │
                           ▼
                ┌────────────────────┐
                │     Log Parser      │
                │ normalizes events   │
                └──────────┬─────────┘
                           │
                           ▼
                ┌────────────────────┐
                │    SQLite DB        │
                │ stores events/rules │
                └──────────┬─────────┘
                           │
                           ▼
                ┌────────────────────┐
                │ Detection Engine    │
                │ rule-based alerts   │
                └──────────┬─────────┘
                           │
           ┌───────────────┼────────────────┐
           ▼               ▼                ▼
     ┌───────────┐   ┌───────────┐   ┌───────────┐
     │ Dashboard │   │  Alerts   │   │  Report   │
     └───────────┘   └───────────┘   └───────────┘
```

---

## Features

* Load demo security logs
* Parse SSH auth logs, web access logs, and JSON events
* Detect suspicious activity with built-in rules
* View alert details
* Search and filter events
* Enable or disable detection rules
* Generate a Markdown incident report
* Run everything locally

---

## Detection Rules

BlueWatch Lite includes simple defensive detection rules:

* SSH brute force attempts
* Successful login after multiple failed attempts
* HTTP 401 / 403 / 404 bursts from one IP
* Path probing like `/admin`, `/.env`, `/wp-login.php`
* Empty or scanner-like user agents
* Mock impossible travel detection

---

## Tech Stack

Backend:

* Python
* FastAPI
* SQLite
* Pytest

Frontend:

* React
* TypeScript
* Vite
* Tailwind CSS

---

## How to Run

Clone the repository:

```bash
git clone https://github.com/BeBecpp/Blue_Watch_lite.git
cd Blue_Watch_lite
```

---

### 1. Run the Backend

Open a terminal and run:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Backend runs on:

```txt
http://127.0.0.1:8000
```

API documentation:

```txt
http://127.0.0.1:8000/docs
```

Note: opening `http://127.0.0.1:8000/` may show `404 Not Found`. That is normal. Use `/docs` for the API page.

---

### 2. Run the Frontend

Open another terminal and run:

```powershell
cd frontend
npm install
npm run dev
```

Frontend runs on:

```txt
http://127.0.0.1:5173
```

Open that URL in your browser.

---

## How to Use

After opening the frontend:

1. Click **Load Demo Logs**
2. Open the **Dashboard**
3. Check alert counts and event statistics
4. Go to **Alerts**
5. Open an alert and review the details
6. Go to **Rules**
7. Try disabling and enabling a rule
8. Go to **Events**
9. Search logs by IP, username, or message
10. Go to **Report**
11. Generate a Markdown incident report

---

## Run Tests

From the project root:

```powershell
$env:PYTHONPATH="backend"
pytest -q backend/tests
```

Expected result:

```txt
10 passed
```

---

## Troubleshooting

### `vite is not recognized`

Frontend dependencies were not installed correctly.

Run:

```powershell
cd frontend
Remove-Item -Recurse -Force node_modules -ErrorAction SilentlyContinue
Remove-Item -Force package-lock.json -ErrorAction SilentlyContinue
npm config set registry https://registry.npmjs.org/
npm install
npm run dev
```

### Frontend shows zero alerts

Click:

```txt
Load Demo Logs
```

The demo data must be loaded first.

### Backend shows `404 Not Found`

This is normal if you open:

```txt
http://127.0.0.1:8000/
```

Use:

```txt
http://127.0.0.1:8000/docs
```

---

## Safety

BlueWatch Lite is a defensive learning project.

It does not:

* scan public IP addresses
* exploit systems
* steal credentials
* run malware
* attack real networks

All demo activity is based on local sample logs.

---

## GitHub Topics

Recommended repository topics:

```txt
cybersecurity
blue-team
siem
defensive-security
log-analysis
incident-response
security-dashboard
fastapi
react
typescript
sqlite
python
```

---

## Notes

This project is not meant to be a production SIEM. It is a small learning project for understanding the basic flow of security monitoring tools.
