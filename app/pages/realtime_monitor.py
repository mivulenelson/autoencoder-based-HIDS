# app/pages/realtime_monitor.py[cite: 4]
import os
import threading
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from dotenv import load_dotenv
from PySide6.QtCore import QThread, Qt, QTimer, Slot, QMetaObject, Q_ARG
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QHeaderView, QLabel, QScrollArea, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.components.charts import LiveSignalChart
from app.components.metrics import FeatureBadge, HIDStatusCard, MetricCard
from src.services.monitor_service import MonitorService
from theme import (
    C_ACCENT, C_ACCENT_DIM, C_AMBER, C_AMBER_DIM,
    C_BG_APP, C_BG_PANEL, C_GREEN, C_GREEN_DIM,
    C_RED, C_TEXT_DIM, C_TEXT_PRI,
    C_TEXT_SEC, FONT_MONO, FONT_SIZE_XS, QSS_BASE, QSS_TABLE,
)

load_dotenv()

_FALLBACK_THRESHOLD: float = 0.4313

FEATURE_NAMES: List[str] = [
    "flow_dur",    "iat_mean",   "iat_std",
    "iat_min",     "iat_max",    "iat_total",
    "pkt_len_u",   "pkt_len_s",  "pkt_len_min",
    "pkt_len_max", "fwd_bytes",  "pkts/s",
    "bytes/s",     "pkt_var",    "burst_ratio",
    "active_t",    "pkt_count",  "uniq_ttl",
    "ttl_u",       "tcp_flags",  "has_udp",
    "has_tcp",
]


def _create_section_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setStyleSheet(
        f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_XS}; "
        f"font-weight: 700; letter-spacing: 1.2px; "
        f"background: transparent; margin-top: 4px;"
    )
    return lbl


def _build_glow_separator() -> QFrame:
    sep = QFrame()
    sep.setFixedHeight(1)
    sep.setStyleSheet(
        f"background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
        f"stop:0 {C_BG_APP}, stop:0.35 {C_ACCENT_DIM}, "
        f"stop:0.65 {C_ACCENT_DIM}, stop:1 {C_BG_APP}); border: none;"
    )
    return sep


class RealTimeMonitor(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setStyleSheet(QSS_BASE + QSS_TABLE)
        self.setObjectName("RealTimeMonitor")

        self.service = MonitorService()
        self.MAX_ROWS = 100
        self.alert_timestamps: List[datetime] = []
        self.live_threshold: float = _FALLBACK_THRESHOLD
        self.api_url = os.getenv("HIDS_API_URL", "http://127.0.0.1:9000")

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        hdr = QHBoxLayout()
        hdr.setSpacing(12)

        icon_lbl = QLabel("⬡")
        icon_lbl.setStyleSheet(f"color: {C_ACCENT}; font-size: 22px; background: transparent;")

        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title = QLabel("REAL-TIME INTRUSION DETECTION CONSOLE")
        title.setStyleSheet(
            f"color: {C_TEXT_PRI}; font-size: 16px; font-weight: 700; "
            f"font-family: {FONT_MONO}; letter-spacing: 0.8px; background: transparent;"
        )
        subtitle = QLabel("HIDS SENTINEL V2.0  /  BEHAVIORAL NETWORK TELEMETRY")
        subtitle.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; font-weight: 600; "
            f"letter-spacing: 0.8px; background: transparent;"
        )
        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        hdr.addWidget(icon_lbl)
        hdr.addLayout(title_box)
        hdr.addStretch()

        self.live_pill = QLabel("● LIVE")
        self._update_live_indicator(True)
        hdr.addWidget(self.live_pill)
        root.addLayout(hdr)

        root.addWidget(_build_glow_separator())

        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)

        self.mse_card = MetricCard("Avg Recon MAE", "0.00000", C_ACCENT,
                                  f"tau = {self.live_threshold:.4f}", "MAE")
        self.rate_card = MetricCard("Alert Rate", "0", C_GREEN, "per minute", "/min")
        self.status_card = HIDStatusCard()

        kpi_row.addWidget(self.mse_card, stretch=1)
        kpi_row.addWidget(self.rate_card, stretch=1)
        kpi_row.addWidget(self.status_card, stretch=1)
        root.addLayout(kpi_row)

        self.chart = LiveSignalChart()
        root.addWidget(self.chart, stretch=3)

        root.addWidget(_create_section_label("Live Flow Feature Vector — 22 Behavioral Metrics"))

        feat_scroll = QScrollArea()
        feat_scroll.setWidgetResizable(True)
        feat_scroll.setFixedHeight(78)
        feat_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        feat_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        feat_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        feat_inner = QWidget()
        feat_inner.setStyleSheet("background: transparent;")
        feat_row = QHBoxLayout(feat_inner)
        feat_row.setContentsMargins(0, 2, 0, 2)
        feat_row.setSpacing(6)

        self.feat_badges: Dict[str, FeatureBadge] = {}
        for name in FEATURE_NAMES:
            badge = FeatureBadge(name, "-")
            self.feat_badges[name] = badge
            feat_row.addWidget(badge)
        feat_row.addStretch()

        feat_scroll.setWidget(feat_inner)
        root.addWidget(feat_scroll)

        root.addWidget(_create_section_label("Active Flow Log & Anomaly Console"))

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "TIME", "SOURCE IP", "DEST IP", "PROTO",
            "ENC", "MAE SCORE", "VERDICT", "SEVERITY"
        ])
        self._configure_table_formatting(self.table)
        root.addWidget(self.table, stretch=2)

        self.service.new_metrics.connect(self.chart.update_signal)
        self.service.new_metrics.connect(self._on_new_mse)
        self.service.new_alert.connect(self._on_alert)
        self.status_card.status_changed.connect(self._toggle_engine)

        if self.status_card.switch.isChecked():
            self.service.start_engine()

        self._rate_timer = QTimer(self)
        self._rate_timer.timeout.connect(self._refresh_rate)
        self._rate_timer.start(1000)

        # Synchronize threshold with backend on startup[cite: 1, 4]
        self._fetch_backend_threshold()

    def _fetch_backend_threshold(self):
        def _fetch():
            try:
                res = requests.get(f"{self.api_url}/ready", timeout=2)
                if res.status_code == 200:
                    data = res.json()
                    tau = float(data.get("threshold", _FALLBACK_THRESHOLD))
                    QMetaObject.invokeMethod(
                        self, "set_live_threshold",
                        Qt.QueuedConnection, Q_ARG(float, tau)
                    )
            except Exception as exc:
                pass
        threading.Thread(target=_fetch, daemon=True).start()

    def _configure_table_formatting(self, table: QTableWidget) -> None:
        hh = table.horizontalHeader()
        hh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        hh.setSectionResizeMode(0, QHeaderView.Interactive)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.Interactive)
        hh.setSectionResizeMode(4, QHeaderView.Interactive)
        hh.setSectionResizeMode(5, QHeaderView.Interactive)
        hh.setSectionResizeMode(6, QHeaderView.Interactive)
        hh.setSectionResizeMode(7, QHeaderView.Interactive)

        table.setColumnWidth(0, 80)
        table.setColumnWidth(3, 70)
        table.setColumnWidth(4, 55)
        table.setColumnWidth(5, 95)
        table.setColumnWidth(6, 95)
        table.setColumnWidth(7, 85)

        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setFocusPolicy(Qt.NoFocus)
        table.verticalHeader().setDefaultSectionSize(32)
        table.setAlternatingRowColors(True)

    @Slot(float)
    def set_live_threshold(self, value: float) -> None:
        if value is None or value <= 0:
            return
        self.live_threshold = float(value)
        self.chart.set_threshold(self.live_threshold)
        self.mse_card.set_subtitle(f"tau = {self.live_threshold:.4f}", C_TEXT_DIM)

    def _update_live_indicator(self, live: bool) -> None:
        if live:
            self.live_pill.setText("● LIVE")
            self.live_pill.setStyleSheet(
                f"color: {C_GREEN}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
                f"font-family: {FONT_MONO}; background: {C_GREEN_DIM}; padding: 4px 12px; "
                f"border-radius: 10px; border: 1px solid {C_GREEN};"
            )
        else:
            self.live_pill.setText("◼ PAUSED")
            self.live_pill.setStyleSheet(
                f"color: {C_AMBER}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
                f"font-family: {FONT_MONO}; background: {C_AMBER_DIM}; padding: 4px 12px; "
                f"border-radius: 10px; border: 1px solid {C_AMBER};"
            )

    @Slot(float)
    def _on_new_mse(self, mse: float) -> None:
        above = mse >= self.live_threshold
        color = C_RED if above else C_ACCENT
        self.mse_card.set_value(f"{mse:.5f}", color)
        self.mse_card.set_subtitle(
            f"tau = {self.live_threshold:.4f}  {'⚠ ANOMALY' if above else '✓ Normal'}",
            C_RED if above else C_TEXT_DIM,
        )

    @Slot(bool)
    def _toggle_engine(self, on: bool) -> None:
        if on:
            self.service.start_engine()
        else:
            self.service.stop_engine()
        self._update_live_indicator(on)

    @Slot()
    def _refresh_rate(self) -> None:
        cutoff = datetime.now() - timedelta(minutes=1)
        self.alert_timestamps = [t for t in self.alert_timestamps if t > cutoff]
        rate = len(self.alert_timestamps)
        color = C_RED if rate > 10 else C_AMBER if rate > 0 else C_GREEN
        self.rate_card.set_value(str(rate), color)

    @Slot(dict)
    def _on_alert(self, data: dict) -> None:
        self._update_feature_strip(data)
        self.table.insertRow(0)

        try:
            raw_ts = float(data.get("timestamp", 0))
            if raw_ts > 1e11:
                raw_ts /= 1000.0
            ts_str = datetime.fromtimestamp(raw_ts).strftime("%H:%M:%S")
        except Exception:
            ts_str = datetime.now().strftime("%H:%M:%S")

        src = str(data.get("src_ip") or data.get("source_ip") or "unknown")
        dst = str(data.get("dst_ip") or data.get("dest_ip") or "unknown")
        proto = str(data.get("protocol", "IP"))
        is_encrypted = bool(data.get("is_encrypted", False))
        mse = float(data.get("reconstruction_error") or data.get("score", 0))

        if mse >= self.live_threshold:
            diff = mse - self.live_threshold
            sev_str = "Critical" if diff > self.live_threshold * 2.0 else "High"
            verdict = "MALICIOUS"
            self.alert_timestamps.append(datetime.now())
        elif mse >= self.live_threshold * 0.75:
            sev_str = "Low"
            verdict = "LOW"
        else:
            sev_str = "Normal"
            verdict = "NORMAL"

        if sev_str == "Critical":
            sev_fg = QColor(C_RED)
        elif sev_str == "High":
            sev_fg = QColor(C_AMBER)
        elif sev_str == "Low":
            sev_fg = QColor(C_TEXT_SEC)
        else:
            sev_fg = QColor(C_GREEN)

        mono_font = QFont("JetBrains Mono", 9)
        if not mono_font.exactMatch():
            mono_font = QFont("Consolas", 9)
        bold_font = QFont(mono_font)
        bold_font.setBold(True)

        enc_text = "⬤ YES" if is_encrypted else "○ no"
        enc_color = QColor(C_ACCENT) if is_encrypted else QColor(C_TEXT_DIM)

        cells = [ts_str, src, dst, proto, enc_text, f"{mse:.5f}", verdict, sev_str]
        fonts = [mono_font, mono_font, mono_font, mono_font, bold_font, mono_font, bold_font, bold_font]

        for col, (text, font) in enumerate(zip(cells, fonts)):
            item = QTableWidgetItem(text)
            item.setFont(font)
            item.setBackground(QColor(C_BG_PANEL))

            if col == 4:
                item.setForeground(enc_color)
                item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            elif col == 6:
                if verdict == "MALICIOUS":
                    item.setForeground(QColor(C_RED))
                elif verdict == "LOW":
                    item.setForeground(QColor(C_AMBER))
                else:
                    item.setForeground(QColor(C_GREEN))
                item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            elif col == 7:
                item.setForeground(sev_fg)
                item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            else:
                item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)

            self.table.setItem(0, col, item)

        if self.table.rowCount() > self.MAX_ROWS:
            self.table.removeRow(self.table.rowCount() - 1)

    def _update_feature_strip(self, data: dict) -> None:
        mapping = {
            "flow_dur":    data.get("flow_duration", 0),
            "iat_mean":    data.get("fwd_iat_mean", 0),
            "iat_std":     data.get("fwd_iat_std", 0),
            "iat_min":     data.get("fwd_iat_min", 0),
            "iat_max":     data.get("fwd_iat_max", 0),
            "iat_total":   data.get("fwd_iat_total", 0),
            "pkt_len_u":   data.get("fwd_pkt_len_mean", 0),
            "pkt_len_s":   data.get("fwd_pkt_len_std", 0),
            "pkt_len_min": data.get("fwd_pkt_len_min", 0),
            "pkt_len_max": data.get("fwd_pkt_len_max", 0),
            "fwd_bytes":   data.get("total_fwd_bytes", 0),
            "pkts/s":      data.get("flow_pkts_per_sec", 0),
            "bytes/s":     data.get("flow_bytes_per_sec", 0),
            "pkt_var":     data.get("pkt_len_variance", 0),
            "burst_ratio": data.get("burst_ratio", 0),
            "active_t":    data.get("active_time_ratio", 0),
            "pkt_count":   data.get("pkt_count", 0),
            "uniq_ttl":    data.get("unique_ttl_count", 0),
            "ttl_u":       data.get("ttl_mean", 0),
            "tcp_flags":   data.get("tcp_flag_ratio", 0),
            "has_udp":     data.get("has_udp", 0),
            "has_tcp":     data.get("has_tcp", 0),
        }
        mse = float(data.get("reconstruction_error") or data.get("score", 0))
        for name, val in mapping.items():
            badge = self.feat_badges.get(name)
            if badge:
                badge.update_value(f"{float(val):.3f}", alert=(mse >= self.live_threshold))