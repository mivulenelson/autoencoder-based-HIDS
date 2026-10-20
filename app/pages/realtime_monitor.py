# app/pages/realtime_monitor.py
"""
Real-Time Monitor — HIDS Sentinel v2.0

SOC ANALYST MAP (22 features):
  * "Live Flow Feature Vector" strip = all 22 badges for the newest alert.
  * CLICK a row in the Active Flow Log  -> strip PINS to that packet
    (live updates pause; press RESUME LIVE to go back).
  * DOUBLE-CLICK a row                  -> opens it in Alert History >
    22-Feature Forensic Inspector (wired in dashboard.py).
  * Strip header shows "n/22 captured"; missing values display "n/a".
  * Feature names/order: src/database/feature_schema.py
"""
import os
import threading
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from dotenv import load_dotenv
from PySide6.QtCore import Qt, QTimer, Slot, Signal, QMetaObject, Q_ARG
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QHeaderView, QLabel, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from app.components.charts import LiveSignalChart
from app.components.metrics import FeatureBadge, HIDStatusCard, MetricCard
from src.services.monitor_service import MonitorService
from src.database.feature_schema import (
    FEATURE_COUNT, FEATURE_NAMES, FEATURE_SHORT_NAMES,
    compute_severity, count_present, extract_features, format_feature_value,
)
from theme import (
    C_ACCENT, C_ACCENT_DIM, C_AMBER, C_AMBER_DIM,
    C_BG_APP, C_BG_PANEL, C_GREEN, C_GREEN_DIM,
    C_RED, C_TEXT_DIM, C_TEXT_PRI,
    C_TEXT_SEC, FONT_MONO, FONT_SIZE_XS, QSS_BASE, QSS_TABLE,
)

load_dotenv()

_FALLBACK_THRESHOLD: float = 0.4313


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
    # Emitted on double-click of a flow row; dashboard routes it to the Inspector
    packet_selected = Signal(dict)
    # Emitted whenever the live threshold really changes (Settings, retraining, backend)
    threshold_changed = Signal(float)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setStyleSheet(QSS_BASE + QSS_TABLE)
        self.setObjectName("RealTimeMonitor")

        self.service = MonitorService()
        self.MAX_ROWS = 100
        self.alert_timestamps: List[datetime] = []
        self.live_threshold: float = _FALLBACK_THRESHOLD
        self.api_url = os.getenv("HIDS_API_URL", "http://127.0.0.1:9000")

        self._pinned: bool = False
        self._last_live_payload: Optional[dict] = None

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

        # ── 22-feature strip header: title + completeness + pin controls ──────
        feat_hdr = QHBoxLayout()
        feat_hdr.setSpacing(10)
        feat_hdr.addWidget(_create_section_label(
            f"Live Flow Feature Vector — {FEATURE_COUNT} Behavioral Metrics"))
        feat_hdr.addStretch()

        self.feat_status = QLabel(f"0/{FEATURE_COUNT} captured  ·  awaiting first flow")
        self.feat_status.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; font-family: {FONT_MONO}; "
            f"background: transparent;"
        )
        feat_hdr.addWidget(self.feat_status)

        self.resume_btn = QPushButton("RESUME LIVE")
        self.resume_btn.setCursor(Qt.PointingHandCursor)
        self.resume_btn.setVisible(False)
        self.resume_btn.setStyleSheet(
            f"QPushButton {{ color: {C_AMBER}; background: {C_AMBER_DIM}; "
            f"border: 1px solid {C_AMBER}; border-radius: 4px; padding: 1px 10px; "
            f"font-size: {FONT_SIZE_XS}; font-weight: 700; font-family: {FONT_MONO}; }}"
        )
        self.resume_btn.clicked.connect(self._resume_live)
        feat_hdr.addWidget(self.resume_btn)
        root.addLayout(feat_hdr)

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

        # Keyed by CANONICAL name; label shown is the short name
        self.feat_badges: Dict[str, FeatureBadge] = {}
        for name in FEATURE_NAMES:
            badge = FeatureBadge(FEATURE_SHORT_NAMES[name], "-")
            self.feat_badges[name] = badge
            feat_row.addWidget(badge)
        feat_row.addStretch()

        feat_scroll.setWidget(feat_inner)
        root.addWidget(feat_scroll)

        root.addWidget(_create_section_label(
            "Active Flow Log & Anomaly Console  —  click = pin 22 features  ·  double-click = open in Forensic Inspector"))

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
        self.table.itemSelectionChanged.connect(self._on_row_selection_changed)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)

        if self.status_card.switch.isChecked():
            self.service.start_engine()

        self._rate_timer = QTimer(self)
        self._rate_timer.timeout.connect(self._refresh_rate)
        self._rate_timer.start(1000)

        # Synchronize threshold with backend on startup
        self._fetch_backend_threshold()

    # ── Backend threshold ─────────────────────────────────────────────────────
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
            except Exception:
                pass
        threading.Thread(target=_fetch, daemon=True).start()

    def _configure_table_formatting(self, table: QTableWidget) -> None:
        hh = table.horizontalHeader()
        hh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        hh.setSectionResizeMode(0, QHeaderView.Interactive)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        for c in range(3, 8):
            hh.setSectionResizeMode(c, QHeaderView.Interactive)

        table.setColumnWidth(0, 92)
        table.setColumnWidth(3, 70)
        table.setColumnWidth(4, 62)
        table.setColumnWidth(5, 95)
        table.setColumnWidth(6, 95)
        table.setColumnWidth(7, 85)

        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setFocusPolicy(Qt.NoFocus)
        table.verticalHeader().setDefaultSectionSize(32)
        table.setAlternatingRowColors(True)

    @Slot(float)
    def set_live_threshold(self, value: float) -> None:
        if value is None or value <= 0:
            return
        changed = abs(float(value) - self.live_threshold) > 1e-9
        self.live_threshold = float(value)
        self.chart.set_threshold(self.live_threshold)
        self.mse_card.set_subtitle(f"tau = {self.live_threshold:.4f}", C_TEXT_DIM)
        if changed:
            self.threshold_changed.emit(self.live_threshold)

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

    # ── New alert -> table row (+ strip if not pinned) ────────────────────────
    @Slot(dict)
    def _on_alert(self, data: dict) -> None:
        payload = dict(data)
        self._last_live_payload = payload
        if not self._pinned:
            self._update_feature_strip(payload, live=True)

        self.table.insertRow(0)

        try:
            raw_ts = float(payload.get("timestamp", 0))
            if raw_ts > 1e11:
                raw_ts /= 1000.0
            ts_str = datetime.fromtimestamp(raw_ts).strftime("%H:%M:%S")
        except Exception:
            ts_str = datetime.now().strftime("%H:%M:%S")

        src = str(payload.get("src_ip") or payload.get("source_ip") or "unknown")
        dst = str(payload.get("dst_ip") or payload.get("dest_ip") or "unknown")
        proto = str(payload.get("protocol", "IP"))
        is_encrypted = bool(payload.get("is_encrypted", False))
        mse = float(payload.get("reconstruction_error") or payload.get("score", 0))

        # Severity uses the SAME 4-tier rule as the database and Alert History
        if mse >= self.live_threshold:
            sev_str = compute_severity(mse, self.live_threshold)
            verdict = "MALICIOUS"
            self.alert_timestamps.append(datetime.now())
        elif mse >= self.live_threshold * 0.75:
            sev_str = "Low"
            verdict = "LOW"
        else:
            sev_str = "Normal"
            verdict = "NORMAL"

        sev_fg = {
            "Critical": QColor(C_RED),
            "High":     QColor(C_AMBER),
            "Medium":   QColor(C_ACCENT),
            "Low":      QColor(C_TEXT_SEC),
        }.get(sev_str, QColor(C_GREEN))

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

            if col == 0:
                # The full packet payload travels with its row (survives row shifts)
                item.setData(Qt.UserRole, payload)

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

    # ── Pin / resume / open-in-inspector ──────────────────────────────────────
    def _payload_for_row(self, row: int) -> Optional[dict]:
        item = self.table.item(row, 0)
        data = item.data(Qt.UserRole) if item else None
        return data if isinstance(data, dict) else None

    @Slot()
    def _on_row_selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            payload = self._payload_for_row(rows[0].row())
            if payload:
                self._pinned = True
                self.resume_btn.setVisible(True)
                self._update_feature_strip(payload, live=False)
                return
        self._pinned = False
        self.resume_btn.setVisible(False)
        if self._last_live_payload:
            self._update_feature_strip(self._last_live_payload, live=True)

    @Slot()
    def _resume_live(self) -> None:
        self.table.clearSelection()     # triggers _on_row_selection_changed

    @Slot(int, int)
    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        payload = self._payload_for_row(row)
        if payload:
            self.packet_selected.emit(payload)

    # ── 22-feature strip ──────────────────────────────────────────────────────
    def _update_feature_strip(self, data: dict, live: bool = True) -> None:
        values = extract_features(data)
        captured = count_present(values)
        mse = float(data.get("reconstruction_error") or data.get("score", 0) or 0)
        above = mse >= self.live_threshold

        for i, name in enumerate(FEATURE_NAMES):
            badge = self.feat_badges.get(name)
            if badge:
                badge.update_value(format_feature_value(name, values[i]),
                                   alert=(above and values[i] is not None))

        src = data.get("src_ip") or data.get("source_ip") or "unknown"
        dst = data.get("dst_ip") or data.get("dest_ip") or "unknown"
        mode = "LIVE" if live else "📌 PINNED"
        colour = C_GREEN if captured == FEATURE_COUNT else (C_AMBER if captured else C_RED)
        self.feat_status.setText(f"{captured}/{FEATURE_COUNT} captured  ·  {mode}  ·  {src} → {dst}")
        self.feat_status.setStyleSheet(
            f"color: {colour}; font-size: {FONT_SIZE_XS}; font-family: {FONT_MONO}; "
            f"background: transparent;"
        )