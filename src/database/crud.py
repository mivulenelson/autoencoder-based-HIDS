"""
crud.py — HIDS Sentinel v2.0 database operations
Place at: src/database/crud.py

SOC ANALYST MAP (22 features):
  * create_alert()                  -> normalises ANY payload shape into 22 stored features
  * get_alert_features_by_id(db,id) -> {name: value} for one packet (all 22 keys)
  * get_alert_features(alert)       -> same, from an already-loaded alert
  * Schema definition               -> src/database/feature_schema.py
"""
import logging
from typing import Optional

from sqlalchemy.orm import Session

from src.database import models
from src.database.feature_schema import (
    FEATURE_COUNT, build_feature_payload, compute_severity,
    count_present, extract_features, features_to_dict,
)

logger = logging.getLogger("HIDS_CRUD")

EXPECTED_INPUT_DIM = FEATURE_COUNT

# Kept for backward compatibility — one shared rule in feature_schema.py
_compute_severity = compute_severity


def _first_present(d: dict, *keys):
    for k in keys:
        v = d.get(k)
        if v is not None:
            return v
    return None


# ── Alert CRUD ────────────────────────────────────────────────────────────────
def create_alert(db: Session, alert_data: dict, commit: bool = True) -> models.NetworkAlert:
    """
    Persists a new AI-detected anomaly alert.

    commit=False lets a caller save many alerts in ONE transaction (see dashboard's
    AlertPersistWorker); the caller must then commit.

    Accepts both the FastAPI response structure and the internal sniffer
    naming conventions. The 22 features are accepted as:
      - "flow_features" / "features"  (list, dict, or {"vector": [...]})
      - flat top-level keys (flow_duration, fwd_iat_mean, ...)
    and are always stored in the same normalised shape.
    """
    score = float(alert_data.get("reconstruction_error") or alert_data.get("score", 0.0))
    threshold = float(alert_data.get("threshold_at_time") or alert_data.get("threshold", 0.5))
    severity = compute_severity(score, threshold)

    # ── 22-feature vector ─────────────────────────────────────────────────────
    raw_features = _first_present(alert_data, "flow_features", "features")
    if isinstance(raw_features, (list, tuple)) and len(raw_features) not in (0, FEATURE_COUNT):
        logger.warning(
            f"create_alert: feature vector has {len(raw_features)} dims, "
            f"expected {FEATURE_COUNT}. Check parser.py."
        )

    values = extract_features(raw_features)
    if count_present(values) == 0:
        values = extract_features(alert_data)          # flat-key payloads
    captured = count_present(values)
    if 0 < captured < FEATURE_COUNT:
        logger.warning(
            f"create_alert: only {captured}/{FEATURE_COUNT} features captured. "
            f"Missing ones are stored as null."
        )
    features_payload = build_feature_payload(values)

    src_port = alert_data.get("src_port")
    dst_port = alert_data.get("dst_port")
    is_encrypted = bool(alert_data.get("is_encrypted", False))
    is_fp_initial = bool(alert_data.get("is_false_positive", False) or alert_data.get("is_fp", False))

    db_alert = models.NetworkAlert(
        source_ip            = alert_data.get("src_ip") or alert_data.get("source_ip", "unknown"),
        dest_ip              = alert_data.get("dst_ip") or alert_data.get("dest_ip", "unknown"),
        source_port          = src_port,
        dest_port            = dst_port,
        protocol             = alert_data.get("proto") or alert_data.get("protocol", "unknown"),
        is_encrypted         = is_encrypted,
        reconstruction_error = score,
        threshold_at_time    = threshold,
        severity             = severity,
        flow_features        = features_payload,
        is_false_positive    = is_fp_initial,
        analyst_comment      = alert_data.get("analyst_comment"),
    )

    db.add(db_alert)
    if commit:
        db.commit()
        db.refresh(db_alert)
    else:
        db.flush()          # assigns db_alert.id; caller commits once for the whole batch

    logger.info(
        f"Alert created — id={db_alert.id} severity={severity} "
        f"score={score:.6f} threshold={threshold:.6f} "
        f"features={captured}/{FEATURE_COUNT} encrypted={is_encrypted} is_fp={is_fp_initial}"
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
    return query.order_by(models.NetworkAlert.timestamp.desc()).offset(skip).limit(limit).all()


def get_alert_by_id(db: Session, alert_id: int) -> Optional[models.NetworkAlert]:
    """Returns a single alert by primary key, or None if not found."""
    return db.query(models.NetworkAlert).filter(models.NetworkAlert.id == alert_id).first()


def get_alert_features(alert: models.NetworkAlert) -> dict:
    """All 22 features of an alert as an ordered {name: value|None} dict."""
    return features_to_dict(extract_features(alert.flow_features))


def get_alert_features_by_id(db: Session, alert_id: int) -> Optional[dict]:
    """All 22 features of one packet by alert ID, or None if the alert is unknown."""
    alert = get_alert_by_id(db, alert_id)
    return None if alert is None else get_alert_features(alert)


def update_feedback(db: Session, alert_id: int, is_fp: bool, comment: str = "") -> Optional[models.NetworkAlert]:
    """Records analyst feedback on an alert (True Positive / False Positive)."""
    alert = get_alert_by_id(db, alert_id)
    if alert is None:
        logger.warning(f"update_feedback: alert id={alert_id} not found.")
        return None

    alert.is_false_positive = is_fp
    alert.analyst_comment   = comment
    db.commit()
    db.refresh(alert)

    logger.info(f"Feedback recorded — alert id={alert_id} is_fp={is_fp} comment='{comment[:50]}'")
    return alert


def _pending_filter(query):
    return query.filter(
        (models.NetworkAlert.analyst_comment == None) |           # noqa: E711
        (~models.NetworkAlert.analyst_comment.like("[RETRAINED]%"))
    )


def get_false_positives(db: Session, include_retrained: bool = False) -> list:
    """Returns analyst-confirmed False Positive alerts pending retraining."""
    query = (
        db.query(models.NetworkAlert)
        .filter(models.NetworkAlert.is_false_positive == True)   # noqa: E712
        .order_by(models.NetworkAlert.timestamp.asc())
    )
    if not include_retrained:
        query = _pending_filter(query)
    return query.all()


def count_pending_retraining(db: Session) -> int:
    """Returns the count of FP alerts not yet used in retraining."""
    query = db.query(models.NetworkAlert).filter(models.NetworkAlert.is_false_positive == True)  # noqa: E712
    return _pending_filter(query).count()


def count_alerts_by_severity(db: Session) -> dict:
    """Alert counts grouped by severity tier."""
    from sqlalchemy import func as sqlfunc
    rows = (
        db.query(models.NetworkAlert.severity, sqlfunc.count(models.NetworkAlert.id))
        .group_by(models.NetworkAlert.severity).all()
    )
    return {severity: count for severity, count in rows}


def count_alerts_by_encryption(db: Session) -> dict:
    """Alert counts grouped by is_encrypted."""
    from sqlalchemy import func as sqlfunc
    rows = (
        db.query(models.NetworkAlert.is_encrypted, sqlfunc.count(models.NetworkAlert.id))
        .group_by(models.NetworkAlert.is_encrypted).all()
    )
    counts = {True: 0, False: 0}
    counts.update({bool(is_enc): count for is_enc, count in rows})
    return counts


# ── One-off cleanup for rows saved before the severity fix ────────────────────
def count_sub_threshold_alerts(db: Session) -> int:
    """Alerts whose MAE never exceeded their own threshold (benign flows logged as alerts)."""
    return (
        db.query(models.NetworkAlert)
        .filter(models.NetworkAlert.reconstruction_error <= models.NetworkAlert.threshold_at_time)
        .filter(models.NetworkAlert.analyst_comment == None)      # noqa: E711  (never reviewed)
        .count()
    )


def purge_sub_threshold_alerts(db: Session, dry_run: bool = True) -> int:
    """
    Deletes never-reviewed alerts with MAE <= threshold (they were benign flows
    wrongly saved as incidents). dry_run=True only counts. Reviewed alerts are kept.

        from src.database.connection import SessionLocal
        from src.database.crud import purge_sub_threshold_alerts
        db = SessionLocal(); print(purge_sub_threshold_alerts(db))                  # preview
        print(purge_sub_threshold_alerts(db, dry_run=False)); db.close()            # delete
    """
    q = (
        db.query(models.NetworkAlert)
        .filter(models.NetworkAlert.reconstruction_error <= models.NetworkAlert.threshold_at_time)
        .filter(models.NetworkAlert.analyst_comment == None)      # noqa: E711
    )
    n = q.count()
    if not dry_run and n:
        q.delete(synchronize_session=False)
        db.commit()
        logger.info(f"Purged {n} sub-threshold alerts.")
    return n