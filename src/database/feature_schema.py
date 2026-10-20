"""
feature_schema.py — SINGLE SOURCE OF TRUTH for the 22-feature vector
=====================================================================
HIDS Sentinel v2.0

Every file that stores, shows or exports the 22 behavioural features imports
from here, so names, order, grouping and formatting are identical everywhere.

Place this file at:  src/database/feature_schema.py

╔══════════════════════════════════════════════════════════════════════════╗
║  SOC ANALYST MAP — WHERE TO FIND ALL 22 FEATURES OF A PACKET             ║
╠══════════════════════════════════════════════════════════════════════════╣
║  1. Console Grid  (left)  Live Flow Feature Vector strip                 ║
║       - latest alert, or the row you click (click = pin that packet)     ║
║       - double-click a row = open it in the Forensic Inspector           ║
║  2. Console Grid  (right) Alert History -> select a row                  ║
║       - "22-Feature Forensic Inspector": all 22, grouped, n/a if missing ║
║  3. Forensic Reports -> Generate                                         ║
║       - Section 3 = incident table, Section 4 = 22 features per alert    ║
║       - IDs match the ID column in Alert History                         ║
║  4. Database: table `alerts`, column `flow_features` (JSON)              ║
║       - {"vector": [22 values], "names": [22 names], "dim": 22}          ║
║       - Python: NetworkAlert.feature_map  /  crud.get_alert_features()   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import json
import math
from collections import OrderedDict
from typing import Any, Dict, List, Mapping, Optional, Tuple

# ── Canonical schema (order MUST match parser.py FEATURE_NAMES) ──────────────
FEATURE_COUNT: int = 22

FEATURE_NAMES: Tuple[str, ...] = (
    "flow_duration", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max",
    "fwd_iat_total", "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min",
    "fwd_pkt_len_max", "total_fwd_bytes", "flow_pkts_per_sec", "flow_bytes_per_sec",
    "pkt_len_variance", "burst_ratio", "active_time_ratio", "pkt_count",
    "unique_ttl_count", "ttl_mean", "tcp_flag_ratio", "has_udp", "has_tcp",
)

FEATURE_INDEX: Dict[str, int] = {n: i for i, n in enumerate(FEATURE_NAMES)}

# Short labels used by the compact badge strip in the Real-Time Monitor
FEATURE_SHORT_NAMES: Dict[str, str] = {
    "flow_duration": "flow_dur",   "fwd_iat_mean": "iat_mean",
    "fwd_iat_std": "iat_std",      "fwd_iat_min": "iat_min",
    "fwd_iat_max": "iat_max",      "fwd_iat_total": "iat_total",
    "fwd_pkt_len_mean": "pkt_len_u", "fwd_pkt_len_std": "pkt_len_s",
    "fwd_pkt_len_min": "pkt_len_min", "fwd_pkt_len_max": "pkt_len_max",
    "total_fwd_bytes": "fwd_bytes", "flow_pkts_per_sec": "pkts/s",
    "flow_bytes_per_sec": "bytes/s", "pkt_len_variance": "pkt_var",
    "burst_ratio": "burst_ratio",  "active_time_ratio": "active_t",
    "pkt_count": "pkt_count",      "unique_ttl_count": "uniq_ttl",
    "ttl_mean": "ttl_u",           "tcp_flag_ratio": "tcp_flags",
    "has_udp": "has_udp",          "has_tcp": "has_tcp",
}

FEATURE_GROUPS: "OrderedDict[str, Tuple[str, ...]]" = OrderedDict([
    ("timing",     ("flow_duration", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min",
                    "fwd_iat_max", "fwd_iat_total")),
    ("volume",     ("fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min",
                    "fwd_pkt_len_max", "total_fwd_bytes")),
    ("rate",       ("flow_pkts_per_sec", "flow_bytes_per_sec")),
    ("burstiness", ("pkt_len_variance", "burst_ratio", "active_time_ratio")),
    ("session",    ("pkt_count", "unique_ttl_count", "ttl_mean")),
    ("protocol",   ("tcp_flag_ratio", "has_udp", "has_tcp")),
])

INTEGER_FEATURES = frozenset({"pkt_count", "unique_ttl_count", "has_udp", "has_tcp"})

# Accept both canonical and short names as dictionary keys
_ALIAS_TO_INDEX: Dict[str, int] = dict(FEATURE_INDEX)
_ALIAS_TO_INDEX.update({short: FEATURE_INDEX[full] for full, short in FEATURE_SHORT_NAMES.items()})

# Keys under which a payload may nest its feature data
_NESTED_KEYS = ("flow_features", "features", "feature_vector", "vector", "feature_map")

DEFAULT_THRESHOLD: float = 0.4313


# ── Extraction ────────────────────────────────────────────────────────────────
def _to_float(value: Any) -> Optional[float]:
    if value is None or (isinstance(value, (str, bytes)) and not str(value).strip()):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def extract_features(source: Any, _depth: int = 0) -> List[Optional[float]]:
    """
    Returns an ORDERED list of exactly 22 values (None = not captured), no
    matter which shape the source uses:

      * flat dict with names      {"flow_duration": 1.2, "fwd_iat_mean": ...}
      * flat dict with short names {"flow_dur": 1.2, ...}
      * nested dict               {"features": {...}} / {"flow_features": {...}}
      * DB payload                {"vector": [22 values], "dim": 22}
      * list / tuple / ndarray    [v0 ... v21]   (or [[v0 ... v21]])
      * JSON string of any above
    """
    values: List[Optional[float]] = [None] * FEATURE_COUNT
    if source is None or _depth > 3:
        return values

    if isinstance(source, (str, bytes, bytearray)):
        try:
            source = json.loads(source)
        except (ValueError, TypeError):
            return values

    if hasattr(source, "tolist") and not isinstance(source, Mapping):
        source = source.tolist()

    if isinstance(source, (list, tuple)):
        if source and isinstance(source[0], (list, tuple)):
            source = source[0]
        for i, v in enumerate(list(source)[:FEATURE_COUNT]):
            values[i] = _to_float(v)
        return values

    if isinstance(source, Mapping):
        for key in _NESTED_KEYS:
            nested = source.get(key)
            if nested is None:
                continue
            nv = extract_features(nested, _depth + 1)
            if any(v is not None for v in nv):
                return nv
        for k, v in source.items():
            idx = _ALIAS_TO_INDEX.get(k) if isinstance(k, str) else None
            if idx is not None:
                values[idx] = _to_float(v)
    return values


def count_present(values: List[Optional[float]]) -> int:
    return sum(1 for v in values if v is not None)


def merge_features(primary: List[Optional[float]],
                   fallback: List[Optional[float]]) -> List[Optional[float]]:
    """Fills gaps in `primary` with values from `fallback`."""
    return [p if p is not None else f for p, f in zip(primary, fallback)]


def features_to_dict(values: List[Optional[float]]) -> "OrderedDict[str, Optional[float]]":
    return OrderedDict((n, values[i]) for i, n in enumerate(FEATURE_NAMES))


def build_feature_payload(values: List[Optional[float]]) -> dict:
    """
    JSON stored in alerts.flow_features. Missing values are stored as null
    (never as 0, so an analyst can tell 'not captured' from 'zero').
    Keeps the legacy {"vector", "dim"} keys; adds "names" and "captured".
    """
    n = count_present(values)
    if n == 0:
        return {"vector": [], "dim": 0, "names": list(FEATURE_NAMES), "captured": 0}
    return {"vector": list(values), "dim": FEATURE_COUNT,
            "names": list(FEATURE_NAMES), "captured": n}


# ── Formatting (identical in Inspector, Reports, console) ─────────────────────
def format_feature_value(name: str, value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    if name in INTEGER_FEATURES:
        return f"{int(round(value))}"
    if value == 0:
        return "0.00000"
    if abs(value) >= 1e6 or abs(value) < 1e-4:
        return f"{value:.4e}"
    return f"{value:.5f}"


def completeness_text(values: List[Optional[float]]) -> str:
    return f"{count_present(values)}/{FEATURE_COUNT}"


def render_feature_lines(values: List[Optional[float]], indent: str = "  ") -> List[str]:
    """All 22 features, grouped, numbered 00-21. Missing ones show 'n/a'."""
    lines: List[str] = []
    for group, names in FEATURE_GROUPS.items():
        lines.append(f"{indent}[ {group.upper()} ]")
        for name in names:
            i = FEATURE_INDEX[name]
            lines.append(f"{indent}    {i:02d}  {name:<20}  =  {format_feature_value(name, values[i])}")
    return lines


# ── Shared helpers ────────────────────────────────────────────────────────────
def compute_severity(score: float, threshold: float) -> str:
    """4-tier severity relative to the threshold (same rule everywhere)."""
    if score <= threshold:
        return "Low"
    diff = score - threshold
    if diff > threshold * 3.0:
        return "Critical"
    if diff > threshold * 1.5:
        return "High"
    if diff > threshold * 0.5:
        return "Medium"
    return "Low"


def flow_fingerprint(payload: Mapping) -> str:
    """Stable key used to jump from a Console row to its Alert History row."""
    src = payload.get("src_ip") or payload.get("source_ip") or "unknown"
    dst = payload.get("dst_ip") or payload.get("dest_ip") or "unknown"
    try:
        score = float(payload.get("reconstruction_error") or payload.get("score")
                      or payload.get("mse_score") or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    return f"{src}|{dst}|{score:.8f}"


SOC_NAVIGATION_GUIDE: Tuple[Tuple[str, str], ...] = (
    ("Console Grid > Live Flow Feature Vector",
     "22 badges for the latest alert. Click a row to pin that packet; double-click to open it in the Inspector."),
    ("Console Grid > Alert History > Forensic Inspector",
     "Select any row: all 22 features, grouped and numbered, plus connection, MAE, tau, impact."),
    ("Forensic Reports > Generate Forensic Report",
     "Section 3 lists incidents; Section 4 repeats all 22 features per alert. Alert IDs match Alert History."),
    ("Database: alerts.flow_features",
     "JSON {vector, names, dim, captured}. Python: NetworkAlert.feature_map or crud.get_alert_features_by_id()."),
    ("Code: src/database/feature_schema.py",
     "Feature names, order, grouping and formatting are defined here only."),
)