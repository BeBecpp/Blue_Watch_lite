from datetime import datetime
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session

from . import crud, models, schemas
from .database import engine, get_db

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="BlueWatch Lite API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

with Session(engine) as session:
    crud.detector.init_rules(session)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "BlueWatch Lite"}


@app.post("/api/logs/ingest")
def ingest_logs(payload: schemas.RawLogCreate, db: Session = Depends(get_db)):
    try:
        raw_log = crud.ingest_raw_log(db, payload.content, payload.format_type)
        return {
            "status": "success",
            "message": "Logs parsed and analyzed.",
            "raw_log_id": raw_log.id,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to ingest logs: {exc}") from exc


@app.post("/api/logs/demo")
def load_demo(db: Session = Depends(get_db)):
    try:
        crud.load_demo_logs(db)
        return {"status": "success", "message": "Demo logs loaded successfully."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load demo logs: {exc}") from exc


@app.delete("/api/logs/clear")
def clear_logs(db: Session = Depends(get_db)):
    crud.clear_security_data(db)
    return {"status": "success", "message": "Events and alerts cleared."}


@app.get("/api/dashboard/stats", response_model=schemas.DashboardStats)
def get_stats(db: Session = Depends(get_db)):
    return crud.get_dashboard_stats(db)


@app.get("/api/events", response_model=List[schemas.ParsedEventResponse])
def get_events(
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    return crud.get_parsed_events(
        db,
        source_ip=source_ip,
        username=username,
        start_time=start_time,
        end_time=end_time,
        search=search,
    )


@app.get("/api/alerts", response_model=List[schemas.AlertResponse])
def get_alerts(
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Session = Depends(get_db),
):
    return crud.get_alerts(
        db,
        severity=severity,
        source_ip=source_ip,
        username=username,
        start_time=start_time,
        end_time=end_time,
    )


@app.get("/api/alerts/{alert_id}", response_model=schemas.AlertDetailResponse)
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)):
    alert = crud.get_alert_detail(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert


@app.get("/api/rules", response_model=List[schemas.RuleResponse])
def get_rules(db: Session = Depends(get_db)):
    return crud.get_rules(db)


@app.put("/api/rules/{rule_id}", response_model=schemas.RuleResponse)
def update_rule_settings(rule_id: str, rule_update: schemas.RuleUpdate, db: Session = Depends(get_db)):
    rule = crud.update_rule(db, rule_id, rule_update)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found.")
    return rule


@app.post("/api/rules/reset", response_model=List[schemas.RuleResponse])
def reset_rules_settings(db: Session = Depends(get_db)):
    return crud.reset_rules(db)


@app.get("/api/report/generate")
def get_report(db: Session = Depends(get_db)):
    try:
        return Response(content=crud.generate_report_markdown(db), media_type="text/markdown")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {exc}") from exc
