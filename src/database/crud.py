import logging
from typing import Optional

from sqlalchemy.orm import Session

from src.database import models

logger = logging.getLogger("HIDS_CRUD")


# ── Feature dimension constant ────────────────────────────────────────────────
# Mirrors parser.py FEATURE_NAMES length — used to validate stored vectors
EXPECTED_INPUT_DIM = 22


# ── Severity classification ───────────────────────────────────────────────────
def _compute_severity(score: float, threshold: float) -> str:
    """
    Maps a MAE reconstruction error to a 4-tier severity label.

    Tier boundaries are relative to the detection threshold so they
    scale automatically when the threshold is recalibrated.

    Severity  | Condition
    --------- | -----------------------------------------
    Critical  | score > threshold + 3× threshold  (score > 4× threshold)
    High      | score > threshold + 1.5× threshold (score > 2.5× threshold)
    Medium    | score > threshold + 0.5× threshold (score > 1.5× threshold)
    Low       | score > threshold (just above — anomaly but weak signal)

    Returns "Low" for scores at or below threshold so the function is
    safe to call unconditionally from create_alert().
    """
    if score <= threshold:
        return "Low"
    diff = score - threshold
    if diff > threshold * 3.0:
        return "Critical"
    elif diff > threshold * 1.5:
        return "High"
    elif diff > threshold * 0.5:
        return "Medium"
    return "Low"


# ── Alert CRUD ────────────────────────────────────────────────────────────────
def create_alert(db: Session, alert_data: dict) -> models.NetworkAlert:
    """
    Persists a new AI-detected anomaly alert to the database.

    Accepts both the FastAPI response structure and the internal sniffer
    naming conventions so MonitorService can call this directly.
    """
    # ── Score ─────────────────────────────────────────────────────────────────
    score = float(
        alert_data.get("reconstruction_error")
        or alert_data.get("score", 0.0)
    )

    # ── Threshold ─────────────────────────────────────────────────────────────
    threshold = float(
        alert_data.get("threshold_at_time")
        or alert_data.get("threshold", 0.5)
    )

    # ── 4-tier severity ───────────────────────────────────────────────────────
    severity = _compute_severity(score, threshold)

    # ── Feature vector — normalise to {"vector": [...], "dim": N} ─────────────
    raw_features = (
        alert_data.get("flow_features")
        or alert_data.get("features", [])
    )
    if isinstance(raw_features, list):
        features_payload = {
            "vector": raw_features,
            "dim": len(raw_features),
        }
    elif isinstance(raw_features, dict) and "vector" in raw_features:
        features_payload = raw_features
    else:
        features_payload = {"vector": [], "dim": 0}

    # Warn if dimension is wrong
    stored_dim = features_payload.get("dim", 0)
    if stored_dim not in (0, EXPECTED_INPUT_DIM):
        logger.warning(
            f"create_alert: feature vector has {stored_dim} dims, "
            f"expected {EXPECTED_INPUT_DIM}. Check parser.py."
        )

    src_port = alert_data.get("src_port")
    dst_port = alert_data.get("dst_port")
    is_encrypted = bool(alert_data.get("is_encrypted", False))

    # ── FIX: Allow passes of is_false_positive directly on creation ─────────
    # If a test/market packet is flagged directly as a false positive, preserve it!
    is_fp_initial = bool(
        alert_data.get("is_false_positive", False)
        or alert_data.get("is_fp", False)
    )

    db_alert = models.NetworkAlert(
        source_ip            = alert_data.get("src_ip") or alert_data.get("source_ip", "unknown"),
        dest_ip              = alert_data.get("dst_ip") or alert_data.get("dest_ip",   "unknown"),
        source_port           = src_port,
        dest_port             = dst_port,
        protocol             = alert_data.get("proto")  or alert_data.get("protocol",  "unknown"),
        is_encrypted          = is_encrypted,
        reconstruction_error = score,
        threshold_at_time    = threshold,
        severity             = severity,
        flow_features        = features_payload,
        is_false_positive    = is_fp_initial,
        analyst_comment      = alert_data.get("analyst_comment"),
    )

    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)

    logger.info(
        f"Alert created — id={db_alert.id} severity={severity} "
        f"score={score:.6f} threshold={threshold:.6f} "
        f"encrypted={is_encrypted} is_fp={is_fp_initial}"
    )
    return db_alert


def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    is_encrypted: Optional[bool] = None,
) -> list:
    """Retrieves paginated alerts ordered by most recent first."""
    query = db.query(models.NetworkAlert)

    if severity:
        query = query.filter(models.NetworkAlert.severity == severity)

    if is_encrypted is not None:
        query = query.filter(models.NetworkAlert.is_encrypted == is_encrypted)

    return (
        query
        .order_by(models.NetworkAlert.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_alert_by_id(db: Session, alert_id: int) -> Optional[models.NetworkAlert]:
    """Returns a single alert by primary key, or None if not found."""
    return (
        db.query(models.NetworkAlert)
        .filter(models.NetworkAlert.id == alert_id)
        .first()
    )


def update_feedback(
    db: Session,
    alert_id: int,
    is_fp: bool,
    comment: str = "",
) -> Optional[models.NetworkAlert]:
    """
    Records analyst feedback on an alert (True Positive / False Positive).
    """
    alert = (
        db.query(models.NetworkAlert)
        .filter(models.NetworkAlert.id == alert_id)
        .first()
    )

    if alert is None:
        logger.warning(f"update_feedback: alert id={alert_id} not found.")
        return None

    alert.is_false_positive = is_fp
    alert.analyst_comment   = comment
    db.commit()
    db.refresh(alert)

    logger.info(
        f"Feedback recorded — alert id={alert_id} "
        f"is_fp={is_fp} comment='{comment[:50]}'"
    )
    return alert


def get_false_positives(db: Session, include_retrained: bool = False) -> list:
    """Returns analyst-confirmed False Positive alerts pending retraining."""
    query = (
        db.query(models.NetworkAlert)
        .filter(models.NetworkAlert.is_false_positive == True)   # noqa: E712
        .order_by(models.NetworkAlert.timestamp.asc())
    )
    if not include_retrained:
        query = query.filter(
            (models.NetworkAlert.analyst_comment == None) |           # noqa: E711
            (~models.NetworkAlert.analyst_comment.like("[RETRAINED]%"))
        )
    return query.all()


def count_pending_retraining(db: Session) -> int:
    """Returns the count of FP alerts not yet used in retraining."""
    return (
        db.query(models.NetworkAlert)
        .filter(models.NetworkAlert.is_false_positive == True)        # noqa: E712
        .filter(
            (models.NetworkAlert.analyst_comment == None) |           # noqa: E711
            (~models.NetworkAlert.analyst_comment.like("[RETRAINED]%"))
        )
        .count()
    )


def count_alerts_by_severity(db: Session) -> dict:
    """Returns a summary dict of alert counts grouped by severity tier."""
    from sqlalchemy import func as sqlfunc
    rows = (
        db.query(models.NetworkAlert.severity, sqlfunc.count(models.NetworkAlert.id))
        .group_by(models.NetworkAlert.severity)
        .all()
    )
    return {severity: count for severity, count in rows}


def count_alerts_by_encryption(db: Session) -> dict:
    """Returns a summary dict of alert counts grouped by is_encrypted."""
    from sqlalchemy import func as sqlfunc
    rows = (
        db.query(models.NetworkAlert.is_encrypted, sqlfunc.count(models.NetworkAlert.id))
        .group_by(models.NetworkAlert.is_encrypted)
        .all()
    )
    counts = {True: 0, False: 0}
    counts.update({bool(is_enc): count for is_enc, count in rows})
    return counts