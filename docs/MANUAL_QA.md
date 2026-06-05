# Manual QA Checklist

Use this checklist after installing backend and frontend dependencies.

## Backend

- [ ] `PYTHONPATH=backend pytest -q backend/tests` passes.
- [ ] `python backend/run.py` starts FastAPI on `127.0.0.1:8000`.
- [ ] `GET /api/health` returns status `ok`.
- [ ] `POST /api/logs/demo` returns success.
- [ ] `GET /api/dashboard/stats` returns non-zero event count after demo logs load.
- [ ] `GET /api/alerts` returns alerts for all built-in rule categories.
- [ ] `GET /api/report/generate` returns Markdown text.

## Frontend

- [ ] `npm run build` passes in `frontend/`.
- [ ] `npm run dev` starts Vite on `127.0.0.1:5173`.
- [ ] Dashboard opens without console errors.
- [ ] **Load Demo Logs** updates event and alert counts.
- [ ] Dashboard shows severity counts, top source IPs, top usernames, and recent alerts.
- [ ] Alerts page can filter by severity.
- [ ] Alerts page can filter by source IP.
- [ ] Alert detail panel shows matched raw events.
- [ ] Rules page can disable and re-enable a rule.
- [ ] Rules page can edit threshold count and window seconds.
- [ ] Events page can search raw messages.
- [ ] Ingest page can paste a small sample log and analyze it.
- [ ] Report page generates and downloads a `.md` file.

## Expected Demo Detection Coverage

After clicking **Load Demo Logs**, the demo data should trigger these rule IDs:

- `ssh_brute_force`
- `ssh_login_after_fail`
- `http_status_burst`
- `path_probing`
- `unusual_user_agent`
- `impossible_travel`
