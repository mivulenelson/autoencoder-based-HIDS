# app/pages/ingestion.py
"""
Network Ingestion Engine — HIDS Sentinel v2.0
Modernized, high-performance packet ingestion visualizer and telemetry monitor
with non-blocking interface hot-swapping.
"""

import math
import random
import time
import threading
import logging
import os
from typing import Dict, List, Optional

import psutil
import requests
from PySide6.QtCore import QPointF, QRectF, Signal, Slot, Qt, QTimer
from PySide6.QtGui import (
    QBrush, QColor, QFont, QFontMetrics, QLinearGradient, QPainter,
    QPainterPath, QPen,
)
from PySide6.QtWidgets import (
    QComboBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
    QPushButton, QScrollArea, QSizePolicy, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from theme import (
    C_ACCENT, C_ACCENT_DIM, C_ACCENT_LT, C_AMBER, C_AMBER_DIM,
    C_BG_APP, C_BG_PANEL, C_BG_SURFACE, C_BORDER, C_BORDER_LT,
    C_GREEN, C_GREEN_DIM, C_RED, C_RED_DIM, C_TEXT_DIM, C_TEXT_PRI,
    C_TEXT_SEC, C_VIOLET, C_VIOLET_DIM, FONT_MONO, FONT_SIZE_LG,
    FONT_SIZE_MD, FONT_SIZE_SM, FONT_SIZE_XS, FONT_UI, QSS_BASE,
    QSS_BTN_PRIMARY, QSS_INPUT, QSS_TABLE,
)

logger = logging.getLogger("HIDS_Ingestion")

FEATURE_GROUPS: Dict[str, List[str]] = {
    "TIMING":     ["flow_duration", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max", "fwd_iat_total"],
    "VOLUME":     ["fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min", "fwd_pkt_len_max", "total_fwd_bytes"],
    "RATE":       ["flow_pkts_per_sec", "flow_bytes_per_sec"],
    "BURSTINESS": ["pkt_len_variance", "burst_ratio", "active_time_ratio"],
    "SESSION":    ["pkt_count", "unique_ttl_count", "ttl_mean"],
    "PROTOCOL":   ["tcp_flag_ratio", "has_udp", "has_tcp"],
}

_GROUP_COLOR_MAP: Dict[str, str] = {
    "TIMING":     C_ACCENT,
    "VOLUME":     C_VIOLET,
    "RATE":       C_GREEN,
    "BURSTINESS": C_AMBER,
    "SESSION":    C_ACCENT_LT,
    "PROTOCOL":   C_VIOLET,
}

FEATURE_ORDER = [f for feats in FEATURE_GROUPS.values() for f in feats]


def _get_group_color(group_name: str) -> str:
    return _GROUP_COLOR_MAP.get(group_name, C_ACCENT)


class FeatureSignalBar(QWidget):
    BAR_W = 28
    MAX_BAR_H = 200
    LABEL_H = 44
    WIDGET_W = 50

    def __init__(self, name: str, color_hex: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.name = name
        self._color = QColor(color_hex)
        self._short = name.replace("fwd_", "").replace("flow_", "").replace("_", "\n")

        self._display = 0.05
        self._target = 0.05
        self._raw_value = 0.0
        self._rolling_max = 1e-6
        self._last_update = 0.0
        self._idle_phase = random.uniform(0.0, 2.0 * math.pi)

        self.setFixedWidth(self.WIDGET_W)
        self.setMinimumHeight(self.MAX_BAR_H + self.LABEL_H + 12)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

    def push_value(self, raw: float) -> None:
        self._raw_value = raw
        self._last_update = time.monotonic()
        self._rolling_max = max(self._rolling_max * 0.992, abs(raw), 1e-6)
        self._target = max(0.05, min(1.0, abs(raw) / self._rolling_max))

    def tick(self, idle_phase_offset: float = 0.0) -> None:
        now = time.monotonic()
        is_idle = (now - self._last_update) > 3.0

        if is_idle:
            phase = self._idle_phase + idle_phase_offset
            self._target = 0.18 + 0.10 * math.sin(phase)
            self._idle_phase += 0.02

        delta = self._target - self._display
        if abs(delta) > 0.001:
            self._display += delta * 0.15
        else:
            self._display = self._target

        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        width = self.width()
        height = self.height()
        bar_area_h = height - self.LABEL_H
        bar_h = max(8, int(self._display * bar_area_h))

        center_x = width // 2
        bar_x = center_x - (self.BAR_W // 2)
        bar_y = bar_area_h - bar_h

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(C_BG_SURFACE))
        painter.drawRoundedRect(bar_x, 0, self.BAR_W, bar_area_h, 6, 6)

        if bar_h > 0:
            grad = QLinearGradient(0, bar_y, 0, bar_area_h)
            top_c = QColor(self._color)
            top_c.setAlpha(240)
            bot_c = QColor(self._color)
            bot_c.setAlpha(140)

            grad.setColorAt(0.0, top_c)
            grad.setColorAt(1.0, bot_c)
            painter.setBrush(QBrush(grad))
            painter.drawRoundedRect(bar_x, bar_y, self.BAR_W, bar_h, 6, 6)

            cap_col = QColor(self._color).lighter(150)
            painter.setPen(QPen(cap_col, 2.5))
            painter.drawLine(bar_x + 3, bar_y + 1, bar_x + self.BAR_W - 3, bar_y + 1)

        lbl_rect = QRectF(2, bar_area_h + 6, width - 4, self.LABEL_H)
        label_col = QColor(C_TEXT_DIM) if (time.monotonic() - self._last_update > 3.0) else QColor(C_TEXT_PRI)
        
        painter.setPen(label_col)
        font = QFont("JetBrains Mono", 9)
        if not font.exactMatch():
            font = QFont("Consolas", 9)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(lbl_rect, Qt.AlignHCenter | Qt.AlignTop | Qt.TextWordWrap, self._short)
        painter.end()


class FeatureSignalStrip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")
        self._bars: Dict[str, FeatureSignalBar] = {}
        self._global_phase = 0.0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(10)

        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)

        for group_name, feats in FEATURE_GROUPS.items():
            g_color = _get_group_color(group_name)
            width = len(feats) * FeatureSignalBar.WIDGET_W + (len(feats) - 1) * 8

            grp_frame = QFrame()
            grp_frame.setFixedWidth(width)
            grp_frame.setStyleSheet(f"border: none; border-bottom: 2px solid {g_color}; background: transparent;")
            grp_inner = QHBoxLayout(grp_frame)
            grp_inner.setContentsMargins(4, 0, 0, 3)

            grp_lbl = QLabel(group_name)
            grp_lbl.setStyleSheet(f"color: {g_color}; font-size: {FONT_SIZE_SM}; font-weight: 700; font-family: {FONT_MONO}; letter-spacing: 0.9px; background: transparent;")
            grp_inner.addWidget(grp_lbl)
            grp_inner.addStretch()
            header_layout.addWidget(grp_frame)

            if group_name != list(FEATURE_GROUPS.keys())[-1]:
                spacer = QWidget()
                spacer.setFixedWidth(16)
                header_layout.addWidget(spacer)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        bar_layout = QHBoxLayout()
        bar_layout.setContentsMargins(0, 0, 0, 0)
        bar_layout.setSpacing(0)

        for group_name, feats in FEATURE_GROUPS.items():
            g_color = _get_group_color(group_name)
            for feat in feats:
                bar = FeatureSignalBar(feat, g_color)
                self._bars[feat] = bar
                bar_layout.addWidget(bar)
                bar_layout.addSpacing(8)

            if group_name != list(FEATURE_GROUPS.keys())[-1]:
                rule = QFrame()
                rule.setFixedWidth(1)
                rule.setStyleSheet(f"background: {C_BORDER_LT}; border: none;")
                bar_layout.addSpacing(8)
                bar_layout.addWidget(rule)
                bar_layout.addSpacing(8)

        bar_layout.addStretch()
        layout.addLayout(bar_layout)

        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._tick_all)
        self._anim_timer.start(33)

    def push_values(self, data: dict) -> None:
        for name, bar in self._bars.items():
            if name in data:
                try:
                    bar.push_value(float(data[name]))
                except (TypeError, ValueError):
                    pass

    def _tick_all(self) -> None:
        self._global_phase += 0.02
        for bar in self._bars.values():
            bar.tick(self._global_phase)


class IngestionPage(QWidget):
    interface_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(QSS_BASE + QSS_TABLE + QSS_INPUT)
        self._flow_count = 0
        self.api_url = os.getenv("HIDS_API_URL", "http://127.0.0.1:9000")

        # Main Layout for the IngestionPage widget
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Create outer scroll area to make the entire page scrollable
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        root = QVBoxLayout(container)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        hdr = QHBoxLayout()
        icon = QLabel("⬡")
        icon.setStyleSheet(f"color: {C_VIOLET}; font-size: 22px; background: transparent;")
        
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        
        title = QLabel("NETWORK INGESTION ENGINE")
        title.setStyleSheet(f"color: {C_TEXT_PRI}; font-size: 16px; font-weight: 700; font-family: {FONT_MONO}; letter-spacing: 0.8px; background: transparent;")
        subtitle = QLabel("REAL-TIME PACKET CAPTURE  →  FEATURE EXTRACTION PIPELINE  →  INFERENCE FEED")
        subtitle.setStyleSheet(f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; font-weight: 600; letter-spacing: 0.5px; background: transparent;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        hdr.addWidget(icon)
        hdr.addLayout(title_box)
        hdr.addStretch()
        root.addLayout(hdr)

        root.addWidget(self._build_divider())

        kpi_grid = QGridLayout()
        kpi_grid.setSpacing(12)
        
        self.lbl_bandwidth = self._create_metric_card(kpi_grid, 0, 0, "THROUGHPUT", "0.0 Mb/s", C_ACCENT_LT)
        self.lbl_drops = self._create_metric_card(kpi_grid, 0, 1, "PACKET DROPS", "0 d/s", C_TEXT_PRI)
        self.lbl_buffer = self._create_metric_card(kpi_grid, 0, 2, "BUFFER OCCUPANCY", "0.0 %", C_ACCENT_LT)
        self.lbl_extracted = self._create_metric_card(kpi_grid, 0, 3, "FLOWS PROCESSED", "0", C_GREEN, subtitle="22 / 22 Features Active")
        root.addLayout(kpi_grid)

        cfg_card = QFrame()
        cfg_card.setStyleSheet(f"QFrame {{ background-color: {C_BG_PANEL}; border: 1px solid {C_BORDER}; border-radius: 8px; }}")
        cfg = QHBoxLayout(cfg_card)
        cfg.setContentsMargins(16, 12, 16, 12)
        cfg.setSpacing(12)

        cfg.addWidget(self._create_field_label("Interface:"))
        self.iface_box = QComboBox()
        try:
            self._detected_ifaces = list(psutil.net_if_addrs().keys()) or ["eth0", "lo"]
        except Exception:
            self._detected_ifaces = ["eth0", "lo"]
        
        self.iface_box.addItems(self._detected_ifaces)
        cfg.addWidget(self.iface_box)

        vsep = QFrame()
        vsep.setFrameShape(QFrame.VLine)
        vsep.setFixedHeight(18)
        vsep.setStyleSheet(f"background: {C_BORDER}; border: none;")
        cfg.addWidget(vsep)

        cfg.addWidget(self._create_field_label("Filter Preset:"))
        self.filter_box = QComboBox()
        self.filter_box.addItems([
            "Promiscuous (All IP Traffic)",
            "TCP Flows Only",
            "UDP Streams Only",
            "HTTPS / TLS (Port 443)",
        ])
        self.filter_box.setEnabled(False)
        cfg.addWidget(self.filter_box)

        cfg.addStretch()

        self.btn_swif = QPushButton("HOT-SWAP INTERFACE")
        self.btn_swif.setStyleSheet(QSS_BTN_PRIMARY)
        self.btn_swif.setCursor(Qt.PointingHandCursor)
        self.btn_swif.clicked.connect(self._on_interface_swapped)
        cfg.addWidget(self.btn_swif)

        root.addWidget(cfg_card)

        root.addWidget(self._create_section_header("Flow Feature Extraction Pipeline (L3/L4 Realtime)"))

        strip_card = QFrame()
        strip_card.setStyleSheet(f"QFrame {{ background-color: {C_BG_PANEL}; border: 1px solid {C_BORDER}; border-radius: 8px; }}")
        strip_outer = QVBoxLayout(strip_card)
        strip_outer.setContentsMargins(16, 14, 16, 12)
        strip_outer.setSpacing(10)

        self.signal_strip = FeatureSignalStrip()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedHeight(290)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        scroll.setWidget(self.signal_strip)
        strip_outer.addWidget(scroll)

        legend_row = QHBoxLayout()
        for g_name, g_color in _GROUP_COLOR_MAP.items():
            lbl = QLabel(f"■ {g_name}")
            lbl.setStyleSheet(f"color: {g_color}; font-size: {FONT_SIZE_XS}; background: transparent;")
            legend_row.addWidget(lbl)
            legend_row.addSpacing(8)

        self._lbl_status_idle = QLabel("● IDLE — Waiting for frame capture...")
        self._lbl_status_idle.setStyleSheet(f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; font-family: {FONT_MONO}; background: transparent;")
        legend_row.addStretch()
        legend_row.addWidget(self._lbl_status_idle)
        strip_outer.addLayout(legend_row)

        root.addWidget(strip_card)

        root.addWidget(self._create_section_header("Monitored Network Adapters"))

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["INTERFACE", "PACKET RATE", "ERRORS", "STATUS"])
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 130)

        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.verticalHeader().setDefaultSectionSize(32)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(160) # Ensure table is fully viewable when scrolled

        self._populate_interface_table()
        root.addWidget(self.table)

        scroll_area.setWidget(container)
        main_layout.addWidget(scroll_area)

        try:
            self._prev_total = psutil.net_io_counters(pernic=False)
            self._prev_counters = psutil.net_io_counters(pernic=True)
        except Exception:
            self._prev_total = None
            self._prev_counters = {}

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_telemetry)
        self._poll_timer.start(1000)

    @Slot(dict)
    def update_feature_strip(self, data: dict) -> None:
        self._flow_count += 1
        self.lbl_extracted.setText(f"{self._flow_count:,}")

        self._lbl_status_idle.setText(f"● INGESTING — Flow #{self._flow_count}")
        self._lbl_status_idle.setStyleSheet(f"color: {C_GREEN}; font-size: {FONT_SIZE_XS}; font-family: {FONT_MONO}; background: transparent;")

        self.signal_strip.push_values(data)

        if not hasattr(self, "_reset_timer"):
            self._reset_timer = QTimer(self)
            self._reset_timer.setSingleShot(True)
            self._reset_timer.timeout.connect(self._revert_idle_label)
        self._reset_timer.start(3500)

    @Slot()
    def _revert_idle_label(self) -> None:
        self._lbl_status_idle.setText("● IDLE — Waiting for frame capture...")
        self._lbl_status_idle.setStyleSheet(f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; font-family: {FONT_MONO}; background: transparent;")

    def _create_metric_card(self, grid: QGridLayout, row: int, col: int, title: str, value: str, accent_color: str, subtitle: str = "") -> QLabel:
        card = QFrame()
        card.setStyleSheet(f"QFrame {{ background-color: {C_BG_PANEL}; border: 1px solid {C_BORDER}; border-top: 2px solid {accent_color}; border-radius: 6px; }}")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(f"color: {C_TEXT_DIM}; font-size: 9px; font-weight: 700; letter-spacing: 0.8px; background: transparent;")

        lbl_val = QLabel(value)
        lbl_val.setStyleSheet(f"color: {accent_color}; font-size: {FONT_SIZE_LG}; font-weight: 700; font-family: {FONT_MONO}; background: transparent;")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)

        if subtitle:
            lbl_sub = QLabel(subtitle)
            lbl_sub.setStyleSheet(f"color: {C_TEXT_DIM}; font-size: 9px; background: transparent;")
            layout.addWidget(lbl_sub)

        grid.addWidget(card, row, col)
        return lbl_val

    def _create_section_header(self, text: str) -> QLabel:
        lbl = QLabel(text.upper())
        lbl.setStyleSheet(f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_XS}; font-weight: 700; letter-spacing: 1px; background: transparent; margin-top: 4px;")
        return lbl

    def _create_field_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_SM}; font-weight: 600; background: transparent;")
        return lbl

    def _build_divider(self) -> QFrame:
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {C_BG_APP}, stop:0.5 {C_VIOLET_DIM}, stop:1 {C_BG_APP}); border: none;")
        return sep

    def _populate_interface_table(self) -> None:
        font_mono = QFont("JetBrains Mono", 9)
        if not font_mono.exactMatch():
            font_mono = QFont("Consolas", 9)

        font_bold = QFont(font_mono)
        font_bold.setBold(True)

        for row, name in enumerate(self._detected_ifaces):
            self.table.insertRow(row)
            active = (row == 0)

            item_iface = QTableWidgetItem(f"  {name}")
            item_rate = QTableWidgetItem("0 p/s")
            item_err = QTableWidgetItem("0")
            item_status = QTableWidgetItem("● MONITORING" if active else "○ STANDBY")

            for item in (item_iface, item_rate, item_err):
                item.setFont(font_mono)

            item_status.setFont(font_bold)
            item_status.setForeground(QColor(C_GREEN if active else C_TEXT_DIM))

            self.table.setItem(row, 0, item_iface)
            self.table.setItem(row, 1, item_rate)
            self.table.setItem(row, 2, item_err)
            self.table.setItem(row, 3, item_status)

    @Slot()
    def _on_interface_swapped(self) -> None:
        selected = self.iface_box.currentText().strip()
        self.interface_changed.emit(selected)

        for r in range(self.table.rowCount()):
            iface_item = self.table.item(r, 0)
            status_item = self.table.item(r, 3)
            if iface_item and status_item:
                is_selected = (iface_item.text().strip() == selected)
                status_item.setText("● MONITORING" if is_selected else "○ STANDBY")
                status_item.setForeground(QColor(C_GREEN if is_selected else C_TEXT_DIM))

        def notify_backend_interface():
            try:
                requests.post(f"{self.api_url}/api/interface", json={"interface": selected}, timeout=3)
            except Exception as exc:
                logger.warning(f"Failed to instruct backend to switch interface: {exc}")

        threading.Thread(target=notify_backend_interface, daemon=True).start()

    @Slot()
    def _poll_telemetry(self) -> None:
        if not self._prev_total:
            return

        try:
            curr_total = psutil.net_io_counters(pernic=False)
            curr_pernic = psutil.net_io_counters(pernic=True)
        except Exception:
            return

        bytes_delta = (curr_total.bytes_sent - self._prev_total.bytes_sent) + (
            curr_total.bytes_recv - self._prev_total.bytes_recv
        )
        mbps = (bytes_delta * 8) / 1_000_000.0
        self.lbl_bandwidth.setText(f"{mbps:.2f} Mb/s")

        drops_delta = (curr_total.dropin - self._prev_total.dropin) + (
            curr_total.dropout - self._prev_total.dropout
        )
        self.lbl_drops.setText(f"{drops_delta} d/s")
        self.lbl_drops.setStyleSheet(
            f"color: {C_RED if drops_delta > 0 else C_TEXT_PRI}; "
            f"font-size: {FONT_SIZE_LG}; font-weight: 700; font-family: {FONT_MONO}; background: transparent;"
        )

        for r in range(self.table.rowCount()):
            iface_item = self.table.item(r, 0)
            rate_item = self.table.item(r, 1)
            err_item = self.table.item(r, 2)

            if iface_item and rate_item:
                iface_name = iface_item.text().strip()
                prev_p = self._prev_counters.get(iface_name)
                curr_p = curr_pernic.get(iface_name)

                if prev_p and curr_p:
                    pkt_delta = (curr_p.packets_sent - prev_p.packets_sent) + (
                        curr_p.packets_recv - prev_p.packets_recv
                    )
                    rate_item.setText(f"{max(0, pkt_delta)} p/s")

                    err_delta = (curr_p.errin - prev_p.errin) + (curr_p.errout - prev_p.errout)
                    if err_delta > 0 and err_item:
                        curr_errs = int(err_item.text().strip() or "0")
                        err_item.setText(str(curr_errs + err_delta))
                else:
                    rate_item.setText("0 p/s")

        self._prev_total = curr_total
        self._prev_counters = curr_pernic