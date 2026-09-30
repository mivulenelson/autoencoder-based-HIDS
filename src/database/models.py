from sqlalchemy import (
    Column, Integer, String, Float,
    DateTime, JSON, Boolean, CheckConstraint, Index
)
from sqlalchemy.orm import declarative_base   # Fixed: declarative_base moved in SQLAlchemy 2.x
from sqlalchemy.sql import func

Base = declarative_base()

# Valid severity tiers — enforced at DB level AND matched in crud.py / alerts route
SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")


class NetworkAlert(Base):
    """
    Forensic table for AI-detected anomalies.

    Every row represents one network flow that exceeded the Autoencoder
    reconstruction error threshold.  The full 22-feature vector is stored
    as JSONB so analysts can reconstruct exactly what the model saw.

    Feedback columns (is_false_positive / analyst_comment) feed the
    adaptive retraining loop described in the proposal (§3.2.2, §3.3.2).
    """

    __tablename__ = "alerts"

    # ── Primary key & timestamp ───────────────────────────────────────────────
    id        = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # ── 5-tuple connection identifiers ────────────────────────────────────────
    source_ip = Column(String(45), nullable=True,  index=True)   # IPv4 (see parser.py IPv6 limitation note)
    dest_ip   = Column(String(45), nullable=True,  index=True)
    source_port = Column(Integer, nullable=True)   # NEW — from parser.py flow_meta["src_port"]
    dest_port   = Column(Integer, nullable=True)   # NEW — from parser.py flow_meta["dst_port"]
    protocol  = Column(String(10), nullable=True)

    # NEW: TLS/HTTPS-class port heuristic — mirrors ENCRYPTED_PORTS in
    # eda_encrypted_subset.ipynb and parser.py's is_encrypted flow_meta flag.
    # A heuristic proxy, not a cryptographic guarantee — see parser.py's
    # docstring for the full caveat. indexed for fast "encrypted-only
    # alerts" filtering, matching the pattern already used for severity.
    is_encrypted = Column(Boolean, nullable=False, default=False, index=True)

    # ── AI detection metadata ─────────────────────────────────────────────────
    reconstruction_error = Column(Float, nullable=False)   # MAE from Autoencoder
    threshold_at_time    = Column(Float, nullable=False)   # threshold used at detection time

    # 4-tier severity — validated at DB level so no invalid values can be stored
    severity = Column(
        String(20),
        CheckConstraint(
            f"severity IN {SEVERITY_LEVELS}",
            name="chk_severity_valid"
        ),
        nullable=False,
    )

    # ── 22-feature audit vector ───────────────────────────────────────────────
    # Stored as {"vector": [f0, f1, ..., f21], "dim": 22} for JSONB audit trail.
    # Feature order matches PacketParser._compute_features() / FEATURE_NAMES
    # in parser.py exactly (corrected — the previous version of this comment
    # documented an unrelated, stale feature schema):
    #
    #    0  flow_duration          8  fwd_pkt_len_min      16 pkt_count
    #    1  fwd_iat_mean           9  fwd_pkt_len_max      17 unique_ttl_count
    #    2  fwd_iat_std           10  total_fwd_bytes      18 ttl_mean
    #    3  fwd_iat_min           11  flow_pkts_per_sec    19 tcp_flag_ratio
    #    4  fwd_iat_max           12  flow_bytes_per_sec   20 has_udp
    #    5  fwd_iat_total         13  pkt_len_variance     21 has_tcp
    #    6  fwd_pkt_len_mean      14  burst_ratio
    #    7  fwd_pkt_len_std       15  active_time_ratio
    #
    # NOTE: unique_ttl_count / ttl_mean have no exact CICFlowMeter equivalent
    # (see training_validated.ipynb's Feature Schema Compatibility Note) —
    # that limitation applies only to CIC-IDS2017 cross-dataset validation,
    # NOT to values stored here, which come directly from parser.py against
    # real live packets.
    flow_features = Column(JSON, nullable=True)

    # ── Analyst feedback loop ─────────────────────────────────────────────────
    # When is_false_positive=True, FeedbackLoopService extracts the flow_features
    # vector and uses it to fine-tune the Autoencoder weights (proposal §3.2.2).
    is_false_positive = Column(Boolean, nullable=False, default=False)
    analyst_comment   = Column(String(512), nullable=True)

    # ── Composite index for fast dashboard queries ────────────────────────────
    __table_args__ = (
        Index("ix_alerts_severity_timestamp", "severity", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<NetworkAlert id={self.id} severity={self.severity} "
            f"score={self.reconstruction_error:.6f} "
            f"encrypted={self.is_encrypted} "
            f"fp={self.is_false_positive} ts={self.timestamp}>"
        )


class FlowLog(Base):
    """
    High-volume telemetry table for ALL captured flows (benign + anomalous).

    Optional — disable in production if storage is constrained.
    Useful for retrospective analysis and training data collection.
    """

    __tablename__ = "flow_logs"

    id        = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Stores the raw 22-feature vector and any metadata from the sniffer
    data = Column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<FlowLog id={self.id} ts={self.timestamp}>"