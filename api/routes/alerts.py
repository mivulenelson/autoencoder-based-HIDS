import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, ConfigDict

from api.dependencies import get_db
from src.database import crud

logger = logging.getLogger("HIDS_Alerts")

router = APIRouter(prefix="/alerts", tags=["Threat Intel"])

# Severity tiers — matches CheckConstraint in models.py and crud.py
SEVERITY_VALUES = ["Low", "Medium", "High", "Critical"]
_SEVERITY_PATTERN = f"^({'|'.join(SEVERITY_VALUES)})$"


# ── Request / response schemas ────────────────────────────────────────────────
class FeedbackPayload(BaseModel):
    """Analyst feedback on a specific alert."""
    is_false_positive: bool
    comment: str = Field(
        default="",
        max_length=512,   # Bug fix: original had no max_length — unbounded DB write
        description="Optional analyst note (max 512 characters).",
    )


class AlertSummary(BaseModel):
    """
    Lightweight alert representation for list responses.
    """
    id:                   int
    timestamp:            Optional[datetime]
    source_ip:            Optional[str]
    dest_ip:              Optional[str]
    source_port:          Optional[int]
    dest_port:            Optional[int]
    protocol:             Optional[str]
    is_encrypted:         bool
    reconstruction_error: float
    threshold_at_time:    float
    severity:             str
    is_false_positive:    bool

    model_config = ConfigDict(from_attributes=True)


# ── GET /alerts/ — paginated list ────────────────────────────────────────────
@router.get("/", summary="Retrieve paginated security alerts")
async def get_alerts(
    skip:     int = Query(0,   ge=0,  description="Pagination offset"),
    limit:    int = Query(100, ge=1, le=500, description="Max records to return"),
    severity: Optional[str] = Query(
        None,
        pattern=_SEVERITY_PATTERN,
        description="Filter by severity tier: Low | Medium | High | Critical",
    ),
    is_encrypted: Optional[bool] = Query(
        None,
        description=(
            "Filter by TLS/HTTPS-class port heuristic: true = encrypted-only, "
            "false = plaintext-only, omit = no filter. Mirrors the same "
            "distinction eda_encrypted_subset.ipynb isolates offline."
        ),
    ),
    from_ts: Optional[datetime] = Query(
        None,
        description="Return alerts on or after this UTC timestamp (ISO-8601)",
        examples="2026-04-01T00:00:00Z",
    ),
    to_ts: Optional[datetime] = Query(
        None,
        description="Return alerts on or before this UTC timestamp (ISO-8601)",
        examples="2026-04-02T23:59:59Z",
    ),
    db: Session = Depends(get_db),
):
    """
    Returns a paginated list of security alerts, ordered most-recent first.

    **Filters**
    - `severity` — one of Low, Medium, High, Critical
    - `is_encrypted` — true/false to isolate TLS/HTTPS-class vs plaintext alerts
    - `from_ts` / `to_ts` — ISO-8601 UTC timestamps for a date range window
    """
    from src.database.models import NetworkAlert

    query = db.query(NetworkAlert)

    if severity:
        query = query.filter(NetworkAlert.severity == severity)
    if is_encrypted is not None:
        query = query.filter(NetworkAlert.is_encrypted == is_encrypted)
    if from_ts:
        query = query.filter(NetworkAlert.timestamp >= from_ts)
    if to_ts:
        query = query.filter(NetworkAlert.timestamp <= to_ts)

    total = query.count()
    rows  = (
        query
        .order_by(NetworkAlert.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    logger.debug(f"GET /alerts/ → {len(rows)}/{total} rows")

    return {
        "total":   total,
        "count":   len(rows),
        "skip":    skip,
        "limit":   limit,
        "results": rows,
    }


# ── GET /alerts/stats — aggregate counts ─────────────────────────────────────
@router.get("/stats", summary="Severity + encryption breakdown for the dashboard metrics panel")
async def get_alert_stats(db: Session = Depends(get_db)):
    """
    Returns the total alert count, a breakdown by severity tier, AND a
    breakdown by encryption status. Used by the PySide6 dashboard metrics
    panel — avoids fetching full alert objects just to display summary
    numbers.

    Response example:
    ```json
    {
      "total": 1423,
      "by_severity": {
        "Low": 980, "Medium": 312, "High": 98, "Critical": 33
      },
      "by_encryption": {
        "encrypted": 210, "plaintext": 1213
      },
      "false_positive_count": 45
    }
    ```
    """
    from src.database.models import NetworkAlert
    from sqlalchemy import func as sqlfunc

    rows = (
        db.query(NetworkAlert.severity, sqlfunc.count(NetworkAlert.id))
        .group_by(NetworkAlert.severity)
        .all()
    )
    by_severity = {sev: count for sev, count in rows}
    total       = sum(by_severity.values())

    # NEW: reuses crud.count_alerts_by_encryption() directly — that helper
    # already existed and was fully functional, just never called from here.
    encryption_counts = crud.count_alerts_by_encryption(db)
    by_encryption = {
        "encrypted": encryption_counts.get(True, 0),
        "plaintext": encryption_counts.get(False, 0),
    }

    fp_count = (
        db.query(sqlfunc.count(NetworkAlert.id))
        .filter(NetworkAlert.is_false_positive == True)   # noqa: E712
        .scalar()
    )

    return {
        "total":                total,
        "by_severity":          {k: by_severity.get(k, 0) for k in SEVERITY_VALUES},
        "by_encryption":        by_encryption,
        "false_positive_count": fp_count,
    }


# ── GET /alerts/{id} — single record ─────────────────────────────────────────
@router.get("/{alert_id}", summary="Retrieve a single alert by ID")
async def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    """
    Returns the full alert record including the 22-feature vector stored
    in `flow_features`, so analysts can inspect exactly what the model saw.

    No response_model is applied here, so the raw ORM object — including
    is_encrypted/source_port/dest_port — is already serialized automatically
    without needing any change when new columns are added to models.py.
    """
    alert = crud.get_alert_by_id(db, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert id={alert_id} not found.",
        )
    return alert


# ── PATCH /alerts/{id}/feedback — analyst classification ─────────────────────
@router.patch("/{alert_id}/feedback", summary="Submit analyst TP/FP feedback")
async def submit_feedback(
    alert_id: int,
    payload:  FeedbackPayload,
    db:       Session = Depends(get_db),
):
    """
    Records analyst classification of an alert as True Positive or False Positive.

    False Positives are collected by `FeedbackLoopService` and used to
    fine-tune the Autoencoder via `POST /system/retrain`, reducing future
    false alarms on similar benign traffic patterns.

    Returns the **full updated alert object** so the UI can update its
    local state without a follow-up GET request.
    """
    updated = crud.update_feedback(
        db,
        alert_id=alert_id,
        is_fp=payload.is_false_positive,
        comment=payload.comment,
    )

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert id={alert_id} not found.",
        )

    logger.info(
        f"Feedback recorded — alert_id={alert_id} "
        f"is_fp={payload.is_false_positive}"
    )

    # Bug fix: this claimed to return "the full updated alert object" but
    # was silently missing is_encrypted/source_port/dest_port — added here.
    return {
        "status":               "updated",
        "alert_id":             alert_id,
        "is_false_positive":    updated.is_false_positive,
        "analyst_comment":      updated.analyst_comment,
        "severity":             updated.severity,
        "reconstruction_error": updated.reconstruction_error,
        "threshold_at_time":    updated.threshold_at_time,
        "source_ip":            updated.source_ip,
        "dest_ip":              updated.dest_ip,
        "source_port":          updated.source_port,
        "dest_port":            updated.dest_port,
        "is_encrypted":         updated.is_encrypted,
        "timestamp":            updated.timestamp,
    }