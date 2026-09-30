# app/pages/alert_history.py
"""
Alert History & Forensic Inspector — HIDS Sentinel v2.0
Enterprise forensic incident inspector, 22-feature vector visualizer, and analyst feedback module.
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from PySide6.QtCore import QRegularExpression, Qt, Signal, Slot
from PySide6.QtGui import (
    QColor, QFont, QFontMetrics, QSyntaxHighlighter,
    QTextCharFormat,
)

from PySide6.QtGui import (
    QColor, QFont, QFontMetrics, QSyntaxHighlighter,
    QTextCharFormat,
)

from PySide6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QPushButton, QRadioButton, QSplitter, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from src.database.connection import SessionLocal
from src.database.crud import update_feedback
from theme import (
    C_ACCENT, C_ACCENT_DIM, C_ACCENT_LT, C_AMBER, C_AMBER_DIM,
    C_BG_APP, C_BG_PANEL, C_BG_SURFACE, C_BORDER, C_BORDER_LT,
    C_GREEN, C_GREEN_DIM, C_RED, C_RED_DIM, C_TEXT_DIM, C_TEXT_PRI,
    C_TEXT_SEC, C_VIOLET, C_VIOLET_DIM, FONT_MONO, FONT_SIZE_LG,
    FONT_SIZE_MD, FONT_SIZE_SM, FONT_SIZE_XS, FONT_UI, QSS_BASE,
    QSS_BTN_SUCCESS, QSS_INPUT, QSS_TABLE,
)

MAX_COMMENT_LENGTH = 512

FEATURE_GROUPS: Dict[str, list] = {
    "timing":     ["flow_duration", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max", "fwd_iat_total"],
    "volume":     ["fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min", "fwd_pkt_len_max", "total_fwd_bytes"],
    "rate":       ["flow_pkts_per_sec", "flow_bytes_per_sec"],
    "burstiness": ["pkt_len_variance", "burst_ratio", "active_time_ratio"],
    "session":    ["pkt_count", "unique_ttl_count", "ttl_mean"],
    "protocol":   ["tcp_flag_ratio", "has_udp", "has_tcp"],
}


# ── Forensic Terminal Highlighter ─────────────────────────────────────────────

class ForensicSyntaxHighlighter(QSyntaxHighlighter):
    """Applies terminal syntax styling to forensic inspection logs."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rules = []

        # Header rule
        header_fmt = QTextCharFormat()
        header_fmt.setForeground(QColor(C_ACCENT_LT))
        header_fmt.setFontWeight(QFont.Bold)
        self._rules.append((QRegularExpression(r"^═+.*$"), header_fmt))
        self._rules.append((QRegularExpression(r"^\s*\[\s*[A-Z]+\s*\]"), header_fmt))

        # Threat Assessment rule
        crit_fmt = QTextCharFormat()
        crit_fmt.setForeground(QColor(C_RED))
        crit_fmt.setFontWeight(QFont.Bold)
        self._rules.append((QRegularExpression(r"Critical\s*—.*"), crit_fmt))

        high_fmt = QTextCharFormat()
        high_fmt.setForeground(QColor(C_AMBER))
        high_fmt.setFontWeight(QFont.Bold)
        self._rules.append((QRegularExpression(r"High\s*—.*"), high_fmt))

        # Key-Value Pair rule
        key_fmt = QTextCharFormat()
        key_fmt.setForeground(QColor(C_TEXT_SEC))
        self._rules.append((QRegularExpression(r"^\s*[a-zA-Z0-9_]+\s*="), key_fmt))

        # Numeric values rule
        val_fmt = QTextCharFormat()
        val_fmt.setForeground(QColor(C_GREEN))
        val_fmt.setFontWeight(QFont.Bold)
        self._rules.append((QRegularExpression(r"=\s*[0-9\.\-]+"), val_fmt))

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt in self._rules:
            match_iter = pattern.globalMatch(text)
            while match_iter.hasNext():
                m = match_iter.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)


# ── Main Alert History Component ──────────────────────────────────────────────

class AlertHistory(QWidget):
    feedback_submitted = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setStyleSheet(QSS_BASE + QSS_TABLE + QSS_INPUT)

        self.current_selected_id: Optional[str] = None
        self.row_payload_cache: Dict[str, dict] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Header Section ──
        hdr = QHBoxLayout()
        icon = QLabel("⬡")
        icon.setStyleSheet(f"color: {C_RED}; font-size: 22px; background: transparent;")

        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title = QLabel("ALERT HISTORY & FORENSIC INSPECTOR")
        title.setStyleSheet(
            f"color: {C_TEXT_PRI}; font-size: 16px; font-weight: 700; "
            f"font-family: {FONT_MONO}; letter-spacing: 0.8px; background: transparent;"
        )
        subtitle = QLabel("HISTORICAL INCIDENT LOG  /  22-FEATURE VECTOR ANALYSIS  /  REMEDIATION")
        subtitle.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; font-weight: 600; "
            f"letter-spacing: 0.5px; background: transparent;"
        )
        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        hdr.addWidget(icon)
        hdr.addLayout(title_box)
        hdr.addStretch()
        root.addLayout(hdr)

        root.addWidget(self._build_divider())

        # ── Main Splitter View ──
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setHandleWidth(2)
        self.splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {C_BORDER}; }}")

        # LEFT PANEL: Alert History Table
        left_panel = QFrame()
        left_panel.setStyleSheet("background: transparent; border: none;")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        left_layout.setSpacing(10)

        left_layout.addWidget(self._create_section_label("Historical Incident Log"))

        self.alert_table = QTableWidget(0, 8)
        self.alert_table.setHorizontalHeaderLabels([
            "TIME", "ID", "SOURCE IP", "DEST IP", "PROTO", "ENC", "SEVERITY", "STATUS"
        ])
        
        hh = self.alert_table.horizontalHeader()
        hh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        hh.setSectionResizeMode(0, QHeaderView.Interactive)
        hh.setSectionResizeMode(1, QHeaderView.Interactive)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.Interactive)
        hh.setSectionResizeMode(5, QHeaderView.Interactive)
        hh.setSectionResizeMode(6, QHeaderView.Interactive)
        hh.setSectionResizeMode(7, QHeaderView.Interactive)

        self.alert_table.setColumnWidth(0, 80)
        self.alert_table.setColumnWidth(1, 55)
        self.alert_table.setColumnWidth(4, 65)
        self.alert_table.setColumnWidth(5, 45)
        self.alert_table.setColumnWidth(6, 85)
        self.alert_table.setColumnWidth(7, 95)

        self.alert_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.alert_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alert_table.setFocusPolicy(Qt.NoFocus)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.verticalHeader().setDefaultSectionSize(32)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.selectionModel().selectionChanged.connect(self.load_alert_details)

        left_layout.addWidget(self.alert_table)
        self.splitter.addWidget(left_panel)

        # RIGHT PANEL: Forensic Terminal & Remediation Form
        right_panel = QFrame()
        right_panel.setStyleSheet("background: transparent; border: none;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 0, 0, 0)
        right_layout.setSpacing(12)

        right_layout.addWidget(self._create_section_label("22-Feature Forensic Inspector"))

        self.json_view = QTextEdit()
        self.json_view.setReadOnly(True)
        self.json_view.setStyleSheet(f"""
            QTextEdit {{
                background-color: {C_BG_APP};
                border: 1px solid {C_BORDER};
                border-left: 3px solid {C_ACCENT};
                border-radius: 6px;
                padding: 12px 14px;
                font-family: {FONT_MONO};
                font-size: {FONT_SIZE_SM};
                color: {C_TEXT_PRI};
                line-height: 1.5;
            }}
            QTextEdit:focus {{
                border-left: 3px solid {C_ACCENT_LT};
            }}
        """)
        self.highlighter = ForensicSyntaxHighlighter(self.json_view.document())
        self.json_view.setPlainText(
            "// ─────────────────────────────────────────────────────\n"
            "// Select an alert row from the log to inspect its full\n"
            "// 22-feature behavioral vector, connection details,\n"
            "// and threat intelligence assessment.\n"
            "// ─────────────────────────────────────────────────────"
        )
        right_layout.addWidget(self.json_view, stretch=3)

        right_layout.addWidget(self._create_section_label("Analyst Remediation Feedback"))

        # Remediation Form
        form_card = QFrame()
        form_card.setStyleSheet(
            f"QFrame {{ background-color: {C_BG_PANEL}; border: 1px solid {C_BORDER}; "
            f"border-top: 2px solid {C_VIOLET}; border-radius: 8px; }}"
        )
        form_box = QVBoxLayout(form_card)
        form_box.setContentsMargins(16, 14, 16, 14)
        form_box.setSpacing(10)

        lbl_verdict = QLabel("ANALYST VERDICT")
        lbl_verdict.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: 9px; font-weight: 700; "
            f"letter-spacing: 0.8px; background: transparent;"
        )
        form_box.addWidget(lbl_verdict)

        radio_row = QHBoxLayout()
        radio_row.setSpacing(20)
        self.radio_group = QButtonGroup(self)

        self.fp_btn = QRadioButton("False Positive (Mute)")
        self.fp_btn.setStyleSheet(
            f"QRadioButton {{ color: {C_AMBER}; font-size: {FONT_SIZE_MD}; font-weight: 600; "
            f"spacing: 6px; background: transparent; }}"
            f"QRadioButton::indicator {{ width: 14px; height: 14px; border-radius: 7px; "
            f"border: 2px solid {C_AMBER}; background: {C_BG_SURFACE}; }}"
            f"QRadioButton::indicator:checked {{ background: {C_AMBER}; }}"
        )
        self.tp_btn = QRadioButton("True Positive (Escalate)")
        self.tp_btn.setStyleSheet(
            f"QRadioButton {{ color: {C_RED}; font-size: {FONT_SIZE_MD}; font-weight: 600; "
            f"spacing: 6px; background: transparent; }}"
            f"QRadioButton::indicator {{ width: 14px; height: 14px; border-radius: 7px; "
            f"border: 2px solid {C_RED}; background: {C_BG_SURFACE}; }}"
            f"QRadioButton::indicator:checked {{ background: {C_RED}; }}"
        )

        self.radio_group.addButton(self.fp_btn, 0)
        self.radio_group.addButton(self.tp_btn, 1)
        self.fp_btn.clicked.connect(self._on_verdict_selected)
        self.tp_btn.clicked.connect(self._on_verdict_selected)

        radio_row.addWidget(self.fp_btn)
        radio_row.addWidget(self.tp_btn)
        radio_row.addStretch()
        form_box.addLayout(radio_row)

        notes_header = QHBoxLayout()
        lbl_notes = QLabel("REMEDIATION NOTES")
        lbl_notes.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: 9px; font-weight: 700; "
            f"letter-spacing: 0.8px; background: transparent;"
        )
        self.lbl_char_count = QLabel(f"0 / {MAX_COMMENT_LENGTH}")
        self.lbl_char_count.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: 9px; font-family: {FONT_MONO}; background: transparent;"
        )
        notes_header.addWidget(lbl_notes)
        notes_header.addStretch()
        notes_header.addWidget(self.lbl_char_count)
        form_box.addLayout(notes_header)

        self.comment_box = QTextEdit()
        self.comment_box.setPlaceholderText("Provide classification rationale or mitigation notes...")
        self.comment_box.setMaximumHeight(65)
        self.comment_box.setStyleSheet(
            f"QTextEdit {{ background: {C_BG_SURFACE}; border: 1px solid {C_BORDER}; "
            f"border-radius: 6px; padding: 6px 8px; color: {C_TEXT_PRI}; "
            f"font-size: {FONT_SIZE_SM}; font-family: {FONT_UI}; }}"
            f"QTextEdit:focus {{ border: 1px solid {C_VIOLET}; }}"
        )
        self.comment_box.textChanged.connect(self._update_char_count)
        form_box.addWidget(self.comment_box)

        self.submit_btn = QPushButton("COMMIT TO RETRAINING PIPELINE")
        self.submit_btn.setEnabled(False)
        self.submit_btn.setStyleSheet(QSS_BTN_SUCCESS)
        self.submit_btn.setCursor(Qt.PointingHandCursor)
        self.submit_btn.clicked.connect(self.submit_analyst_feedback)
        form_box.addWidget(self.submit_btn)

        right_layout.addWidget(form_card)
        self.splitter.addWidget(right_panel)
        self.splitter.setSizes([580, 420])

        root.addWidget(self.splitter, stretch=1)

    # ── Public Methods ──

    def add_alert(
        self,
        alert_id: Any,
        timestamp: Any,
        source_ip: str,
        severity: str,
        full_data: dict,
        dest_ip: str = "unknown",
        protocol: str = "IP",
        is_encrypted: bool = False,
    ) -> None:
        row = self.alert_table.rowCount()
        self.alert_table.insertRow(row)

        ts_item = QTableWidgetItem(str(timestamp))
        id_item = QTableWidgetItem(str(alert_id))
        src_item = QTableWidgetItem(str(source_ip))
        dst_item = QTableWidgetItem(str(dest_ip))
        proto_item = QTableWidgetItem(str(protocol))
        enc_item = QTableWidgetItem("⬤ Y" if is_encrypted else "○ n")
        
        sev_str = str(severity).upper().strip()
        sev_item = QTableWidgetItem(sev_str)
        stat_item = QTableWidgetItem("UNRESOLVED")

        ts_item.setData(Qt.ItemDataRole.UserRole, alert_id)
        self.row_payload_cache[str(alert_id)] = full_data

        mono_font = QFont("JetBrains Mono", 9)
        if not mono_font.exactMatch():
            mono_font = QFont("Consolas", 9)

        bold_font = QFont(mono_font)
        bold_font.setBold(True)

        for item in (ts_item, id_item, src_item, dst_item, proto_item):
            item.setFont(mono_font)
        for item in (enc_item, sev_item, stat_item):
            item.setFont(bold_font)

        # Severity level formatting
        if "CRITICAL" in sev_str:
            sev_color = QColor(C_RED)
        elif "HIGH" in sev_str:
            sev_color = QColor(C_AMBER)
        elif "MEDIUM" in sev_str:
            sev_color = QColor(C_ACCENT)
        else:
            sev_color = QColor(C_TEXT_SEC)

        sev_item.setForeground(sev_color)
        stat_item.setForeground(QColor(C_RED) if "CRITICAL" in sev_str else QColor(C_AMBER))
        enc_item.setForeground(QColor(C_ACCENT) if is_encrypted else QColor(C_TEXT_DIM))
        enc_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)

        for col, item in enumerate(
            [ts_item, id_item, src_item, dst_item, proto_item, enc_item, sev_item, stat_item]
        ):
            self.alert_table.setItem(row, col, item)

    # ── Slots & Event Handlers ──

    @Slot()
    def load_alert_details(self) -> None:
        selected = self.alert_table.selectionModel().selectedRows()
        if not selected:
            self.current_selected_id = None
            self.submit_btn.setEnabled(False)
            return

        row = selected[0].row()
        alert_id = str(self.alert_table.item(row, 0).data(Qt.ItemDataRole.UserRole))
        self.current_selected_id = alert_id
        payload = self.row_payload_cache.get(alert_id, {})
        self.json_view.setPlainText(self._render_forensic_block(alert_id, payload))
        
        self.submit_btn.setEnabled(self.fp_btn.isChecked() or self.tp_btn.isChecked())

    @Slot()
    def submit_analyst_feedback(self) -> None:
        if not self.current_selected_id:
            return

        is_false_positive: Optional[bool] = None
        if self.fp_btn.isChecked():
            is_false_positive = True
        elif self.tp_btn.isChecked():
            is_false_positive = False

        if is_false_positive is None:
            self.json_view.append("\n\n// ⚠  Select a verdict (False Positive / True Positive) before committing.")
            return

        notes = self.comment_box.toPlainText().strip()[:MAX_COMMENT_LENGTH]

        if self.current_selected_id == "0":
            self.json_view.append(
                "\n\n// ⚠ Alert was not persisted to DB. Decision applied locally."
            )
            self._mark_row_resolved(self.current_selected_id)
            self.feedback_submitted.emit()
            self._reset_form()
            return

        try:
            alert_int_id = int(self.current_selected_id)
        except ValueError:
            self.json_view.append(f"\n\n// ✖ Invalid Alert ID format: '{self.current_selected_id}'.")
            return

        db = SessionLocal()
        try:
            updated = update_feedback(db, alert_int_id, is_false_positive, notes)
            if updated is None:
                self.json_view.append(
                    f"\n\n// ⚠ Alert #{alert_int_id} missing from database. Updating interface state locally."
                )

            self._mark_row_resolved(self.current_selected_id)
            self.feedback_submitted.emit()
            self._reset_form()

        except Exception as err:
            db.rollback()
            self.json_view.append(f"\n\n// ✖ Database update failed:\n// {err}")
        finally:
            db.close()

    @Slot()
    def _on_verdict_selected(self) -> None:
        if self.current_selected_id is not None:
            self.submit_btn.setEnabled(True)

    @Slot()
    def _update_char_count(self) -> None:
        length = len(self.comment_box.toPlainText())
        self.lbl_char_count.setText(f"{length} / {MAX_COMMENT_LENGTH}")
        if length > MAX_COMMENT_LENGTH:
            self.lbl_char_count.setStyleSheet(f"color: {C_RED}; font-size: 9px; font-family: {FONT_MONO};")
        else:
            self.lbl_char_count.setStyleSheet(f"color: {C_TEXT_DIM}; font-size: 9px; font-family: {FONT_MONO};")

    # ── Internal Helpers ──

    def _render_forensic_block(self, alert_id: str, payload: dict) -> str:
        if not payload:
            return json.dumps({"error": "Telemetry payload unavailable"}, indent=2)

        mse = float(payload.get("reconstruction_error") or payload.get("score", 0.0))
        src = payload.get("src_ip") or payload.get("source_ip") or "unknown"
        dst = payload.get("dst_ip") or payload.get("dest_ip") or "unknown"
        proto = payload.get("protocol", "IP")
        is_enc = bool(payload.get("is_encrypted", False))
        tau = float(payload.get("threshold_at_time") or payload.get("threshold", 0.4313))
        impact, mitigation = self._calculate_cyber_impact(mse, tau)

        width = 58
        lines = []
        lines.append("═" * width)
        lines.append(f"  ALERT #{alert_id:<8}  FORENSIC VECTOR INSPECTION")
        lines.append("═" * width)
        lines.append(f"  Connection  :  {src}  →  {dst}  ({proto})")
        lines.append(f"  Encryption  :  {'ENCRYPTED (TLS/HTTPS)' if is_enc else 'Plaintext'}")
        lines.append(f"  Recon. MAE  :  {mse:.6f}")
        lines.append(f"  Evaluated   :  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
        lines.append("")
        lines.append("  THREAT INTELLIGENCE ASSESSMENT")
        lines.append("  " + "─" * (width - 2))
        lines.append(f"  Impact      :  {impact}")
        lines.append(f"  Mitigation  :  {mitigation}")
        lines.append("")
        lines.append("  22-FEATURE VECTOR (Grouped)")
        lines.append("  " + "─" * (width - 2))

        features = payload.get("features", payload)
        any_found = False

        for group, names in FEATURE_GROUPS.items():
            group_lines = []
            for name in names:
                if name in features:
                    any_found = True
                    val = features[name]
                    try:
                        val_str = f"{float(val):.5f}"
                    except (TypeError, ValueError):
                        val_str = str(val)
                    group_lines.append(f"      {name:<22}  =  {val_str}")
            if group_lines:
                lines.append(f"  [ {group.upper()} ]")
                lines.extend(group_lines)

        if not any_found:
            lines.append("      (No feature telemetry stored for this alert)")

        lines.append("")
        lines.append("═" * width)
        return "\n".join(lines)

    def _calculate_cyber_impact(self, mse: float, tau: float = 0.4313) -> Tuple[str, str]:
        diff = mse - tau
        if mse <= tau:
            return (
                "Low — Marginal deviation within expected parameters.",
                "No immediate action required.",
            )
        elif diff > tau * 3.0:
            return (
                "Critical — Extreme reconstruction error. Potential payload injection.",
                "Isolate source endpoint immediately and alert incident response.",
            )
        elif diff > tau * 1.5:
            return (
                "High — Out-of-bounds behavioral anomaly detected.",
                "Inspect protocol signatures. Apply traffic filtering if verified.",
            )
        elif diff > tau * 0.5:
            return (
                "Medium — Moderate threshold deviation.",
                "Correlate with additional network flows from host.",
            )
        return (
            "Low — Slight anomaly signature.",
            "Flag for model baseline calibration.",
        )

    def _mark_row_resolved(self, alert_id_str: str) -> None:
        for r in range(self.alert_table.rowCount()):
            cell = self.alert_table.item(r, 0)
            if cell and str(cell.data(Qt.ItemDataRole.UserRole)) == alert_id_str:
                status_item = self.alert_table.item(r, 7)
                if status_item:
                    status_item.setText("✓ RESOLVED")
                    status_item.setForeground(QColor(C_GREEN))
                break

    def _reset_form(self) -> None:
        self.comment_box.clear()
        self.radio_group.setExclusive(False)
        self.fp_btn.setChecked(False)
        self.tp_btn.setChecked(False)
        self.radio_group.setExclusive(True)
        self.submit_btn.setEnabled(False)
        self.alert_table.clearSelection()
        self.current_selected_id = None

    def _create_section_label(self, text: str) -> QLabel:
        lbl = QLabel(text.upper())
        lbl.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
            f"letter-spacing: 1px; background: transparent; margin-top: 2px;"
        )
        return lbl

    def _build_divider(self) -> QFrame:
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(
            f"background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            f"stop:0 {C_BG_APP}, stop:0.5 {C_RED_DIM}, stop:1 {C_BG_APP}); border: none;"
        )
        return sep