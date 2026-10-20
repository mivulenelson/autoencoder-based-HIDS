"""
models.py — HIDS Sentinel v2.0 database models
Place at: src/database/models.py

SOC ANALYST MAP (22 features):
  * Stored in  alerts.flow_features  as {"vector": [22], "names": [22], "dim": 22, "captured": n}
  * Read them in Python with  alert.feature_map  (name -> value, always 22 keys)
  * Names / order / grouping live in src/database/feature_schema.py
"""
from sqlalchemy import (
    Column, Integer, String, Float,
    DateTime, JSON, Boolean, CheckConstraint, Index
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

from src.database.feature_schema import (
    FEATURE_COUNT, extract_features, features_to_dict, count_present,
)

Base = declarative_base()

# Valid severity tiers — enforced at DB level AND matched in crud.py / alerts route
SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")


class NetworkAlert(Base):
    """
    Forensic table for AI-detected anomalies.

    Every row is one network flow that exceeded the Autoencoder
    reconstruction-error threshold. The full 22-feature vector is stored in
    `flow_features` so analysts can reconstruct exactly what the model saw.

    Feedback columns (is_false_positive / analyst_comment) feed the adaptive
    retraining loop (§3.2.2, §3.3.2).
    """

    __tablename__ = "alerts"

    # ── Primary key & timestamp ───────────────────────────────────────────────
    id        = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(),
                       nullable=False, index=True)

    # ── 5-tuple connection identifiers ────────────────────────────────────────
    source_ip   = Column(String(45), nullable=True, index=True)
    dest_ip     = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    dest_port   = Column(Integer, nullable=True)
    protocol    = Column(String(10), nullable=True)

    # TLS/HTTPS-class port heuristic (see parser.py). Heuristic, not a guarantee.
    is_encrypted = Column(Boolean, nullable=False, default=False, index=True)

    # ── AI detection metadata ─────────────────────────────────────────────────
    reconstruction_error = Column(Float, nullable=False)   # MAE from Autoencoder
    threshold_at_time    = Column(Float, nullable=False)   # threshold used at detection

    severity = Column(
        String(20),
        CheckConstraint(f"severity IN {SEVERITY_LEVELS}", name="chk_severity_valid"),
        nullable=False,
    )

    # ── 22-feature audit vector ───────────────────────────────────────────────
    # {"vector": [f0..f21], "names": [...22], "dim": 22, "captured": n}
    # Missing values are null (not 0). Order (matches parser.py):
    #    0  flow_duration          8  fwd_pkt_len_min      16 pkt_count
    #    1  fwd_iat_mean           9  fwd_pkt_len_max      17 unique_ttl_count
    #    2  fwd_iat_std           10  total_fwd_bytes      18 ttl_mean
    #    3  fwd_iat_min           11  flow_pkts_per_sec    19 tcp_flag_ratio
    #    4  fwd_iat_max           12  flow_bytes_per_sec   20 has_udp
    #    5  fwd_iat_total         13  pkt_len_variance     21 has_tcp
    #    6  fwd_pkt_len_mean      14  burst_ratio
    #    7  fwd_pkt_len_std       15  active_time_ratio
    flow_features = Column(JSON, nullable=True)

    # ── Analyst feedback loop ─────────────────────────────────────────────────
    is_false_positive = Column(Boolean, nullable=False, default=False)
    analyst_comment   = Column(String(512), nullable=True)   # None = never reviewed

    __table_args__ = (
        Index("ix_alerts_severity_timestamp", "severity", "timestamp"),
    )

    # ── Convenience accessors for analysts / reports ──────────────────────────
    @property
    def feature_values(self) -> list:
        """Ordered list of 22 values (None where not captured)."""
        return extract_features(self.flow_features)

    @property
    def feature_map(self) -> dict:
        """OrderedDict name -> value; always contains all 22 names."""
        return features_to_dict(self.feature_values)

    @property
    def features_captured(self) -> int:
        return count_present(self.feature_values)

    @property
    def is_reviewed(self) -> bool:
        """True once an analyst has submitted feedback (comment is not None)."""
        return self.analyst_comment is not None or bool(self.is_false_positive)

    def __repr__(self) -> str:
        return (
            f"<NetworkAlert id={self.id} severity={self.severity} "
            f"score={self.reconstruction_error:.6f} "
            f"features={self.features_captured}/{FEATURE_COUNT} "
            f"encrypted={self.is_encrypted} fp={self.is_false_positive} ts={self.timestamp}>"
        )


class FlowLog(Base):
    """
    High-volume telemetry table for ALL captured flows (benign + anomalous).
    Optional — disable in production if storage is constrained.
    """

    __tablename__ = "flow_logs"

    id        = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    data      = Column(JSON, nullable=True)   # raw 22-feature vector + sniffer metadata

    def __repr__(self) -> str:
        return f"<FlowLog id={self.id} ts={self.timestamp}>"