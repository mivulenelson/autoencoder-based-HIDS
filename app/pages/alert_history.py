# app/pages/alert_history.py
"""
Alert History & Forensic Inspector — HIDS Sentinel v2.0

SOC ANALYST MAP (22 features):
  * Select ANY row in the Historical Incident Log -> the right-hand
    "22-Feature Forensic Inspector" shows ALL 22 features, grouped and
    numbered 00-21 (missing values show "n/a", never a fake 0).
  * FEAT column = how many of the 22 were captured (22/22 green, else amber).
  * If the live payload is incomplete, the Inspector fills the gaps from the
    database row (alerts.flow_features) and says where each value came from.
  * The inspector footer lists where else to find the same packet.
  * Feature names/order: src/database/feature_schema.py
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from PySide6.QtCore import QRegularExpression, Qt, Signal, Slot
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QPushButton, QRadioButton, QSplitter, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from src.database.connection import SessionLocal
from src.database.crud import get_alert_by_id, update_feedback
from src.database.feature_schema import (
    DEFAULT_THRESHOLD, FEATURE_COUNT, completeness_text, count_present,
    extract_features, flow_fingerprint, merge_features, render_feature_lines,
)
from theme import (
    C_ACCENT, C_ACCENT_LT, C_AMBER, C_BG_APP, C_BG_PANEL, C_BG_SURFACE,
    C_BORDER, C_GREEN, C_RED, C_RED_DIM, C_TEXT_DIM, C_TEXT_PRI,
    C_TEXT_SEC, C_VIOLET, FONT_MONO, FONT_SIZE_MD, FONT_SIZE_SM,
    FONT_SIZE_XS, FONT_UI, QSS_BASE, QSS_BTN_SUCCESS, QSS_INPUT, QSS_TABLE,
)

MAX_COMMENT_LENGTH = 512
MAX_ROWS = 500          # oldest rows are dropped from the VIEW (the database keeps everything)

# Table columns
COL_TIME, COL_ID, COL_SRC, COL_DST, COL_PROTO, COL_ENC, COL_FEAT, COL_SEV, COL_STATUS = range(9)


# ── Forensic Terminal Highlighter ─────────────────────────────────────────────
class ForensicSyntaxHighlighter(QSyntaxHighlighter):
    """Applies terminal syntax styling to forensic inspection logs."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rules = []

        def fmt(color, bold=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Bold)
            return f

        self._rules.append((QRegularExpression(r"^═+.*$"), fmt(C_ACCENT_LT, True)))
        self._rules.append((QRegularExpression(r"^\s*\[\s*[A-Z]+\s*\]"), fmt(C_ACCENT_LT, True)))
        self._rules.append((QRegularExpression(r"Critical\s*—.*"), fmt(C_RED, True)))
        self._rules.append((QRegularExpression(r"High\s*—.*"), fmt(C_AMBER, True)))
        self._rules.append((QRegularExpression(r"^\s*⚠.*$"), fmt(C_AMBER, True)))
        self._rules.append((QRegularExpression(r"^\s*(\d+\s+)?[a-zA-Z0-9_]+\s*="), fmt(C_TEXT_SEC)))
        self._rules.append((QRegularExpression(r"=\s*[0-9\.\-+eE]+"), fmt(C_GREEN, True)))
        self._rules.append((QRegularExpression(r"=\s*n/a"), fmt(C_AMBER, True)))

    def highlightBlock(self, text: str) -> None:
        for pattern, f in self._rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), f)


# ── Main Alert History Component ──────────────────────────────────────────────
class AlertHistory(QWidget):
    feedback_submitted = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setStyleSheet(QSS_BASE + QSS_TABLE + QSS_INPUT)

        self.current_selected_id: Optional[str] = None      # row key
        self.row_payload_cache: Dict[str, dict] = {}
        self.row_ts_cache: Dict[str, str] = {}
        self._flow_key_to_row_key: Dict[str, str] = {}
        self._unsaved_counter = 0
        self._pending_counter = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Header ──
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

        self.tau_lbl = QLabel("LIVE τ = —")
        self.tau_lbl.setToolTip("Each row keeps the threshold it was detected with. "
                                "Changing τ affects NEW alerts only.")
        self.tau_lbl.setStyleSheet(
            f"color: {C_ACCENT_LT}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
            f"font-family: {FONT_MONO}; background: transparent;"
        )
        hdr.addWidget(self.tau_lbl)
        root.addLayout(hdr)
        root.addWidget(self._build_divider())

        # ── Splitter ──
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setHandleWidth(2)
        self.splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {C_BORDER}; }}")

        # LEFT: table
        left_panel = QFrame()
        left_panel.setStyleSheet("background: transparent; border: none;")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)
        left_layout.setSpacing(10)
        left_layout.addWidget(self._create_section_label("Historical Incident Log  —  select a row to inspect all 22 features"))

        self.alert_table = QTableWidget(0, 9)
        self.alert_table.setHorizontalHeaderLabels([
            "TIME", "ID", "SOURCE IP", "DEST IP", "PROTO", "ENC", "FEAT", "SEVERITY", "STATUS"
        ])
        hh = self.alert_table.horizontalHeader()
        hh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        for c in range(9):
            hh.setSectionResizeMode(c, QHeaderView.Interactive)
        hh.setSectionResizeMode(COL_SRC, QHeaderView.Stretch)
        hh.setSectionResizeMode(COL_DST, QHeaderView.Stretch)

        for col, w in ((COL_TIME, 92), (COL_ID, 55), (COL_PROTO, 65), (COL_ENC, 62),
                       (COL_FEAT, 62), (COL_SEV, 92), (COL_STATUS, 118)):
            self.alert_table.setColumnWidth(col, w)

        self.alert_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.alert_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alert_table.setFocusPolicy(Qt.NoFocus)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.verticalHeader().setDefaultSectionSize(32)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.selectionModel().selectionChanged.connect(
            lambda *_: self.load_alert_details()
        )

        left_layout.addWidget(self.alert_table)

        self.empty_lbl = QLabel()
        self.empty_lbl.setAlignment(Qt.AlignCenter)
        self.empty_lbl.setWordWrap(True)
        self.empty_lbl.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_SM}; font-family: {FONT_MONO}; "
            f"background: transparent; padding: 24px;"
        )
        left_layout.addWidget(self.empty_lbl, stretch=1)
        self._live_tau: Optional[float] = None
        self._refresh_empty_state()

        self.splitter.addWidget(left_panel)

        # RIGHT: inspector + form
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
            }}
            QTextEdit:focus {{ border-left: 3px solid {C_ACCENT_LT}; }}
        """)
        self.highlighter = ForensicSyntaxHighlighter(self.json_view.document())
        self.json_view.setPlainText(
            "Select an alert row from the log to inspect its full\n"
            "22-feature behavioral vector, connection details,\n"
            "and threat intelligence assessment.\n\n"
            "Tip: in the Console Grid, double-click a flow row to jump here.\n"
        )
        right_layout.addWidget(self.json_view, stretch=3)

        right_layout.addWidget(self._create_section_label("Analyst Remediation Feedback"))

        form_card = QFrame()
        form_card.setObjectName("FormCard")
        form_card.setStyleSheet(
            f"QFrame#FormCard {{ background-color: {C_BG_PANEL}; border: 1px solid {C_BORDER}; "
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

        def radio_css(color):
            return (
                f"QRadioButton {{ color: {color}; font-size: {FONT_SIZE_MD}; font-weight: 600; "
                f"spacing: 6px; background: transparent; }}"
                f"QRadioButton::indicator {{ width: 14px; height: 14px; border-radius: 7px; "
                f"border: 2px solid {color}; background: {C_BG_SURFACE}; }}"
                f"QRadioButton::indicator:checked {{ background: {color}; }}"
            )

        self.fp_btn = QRadioButton("False Positive (Mute)")
        self.fp_btn.setStyleSheet(radio_css(C_AMBER))
        self.tp_btn = QRadioButton("True Positive (Escalate)")
        self.tp_btn.setStyleSheet(radio_css(C_RED))

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

    # ── Public API ────────────────────────────────────────────────────────────
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
        resolved: bool = False,
    ) -> str:
        """
        Adds an alert row (newest on TOP) and returns its row key.
          alert_id = real DB id  -> key "<id>"
          alert_id = None        -> key "pending-N": saved in the background, the
                                    dashboard later calls assign_db_id()
          alert_id = 0 / ""      -> key "unsaved-N": could not be persisted
        """
        persisted = alert_id not in (None, 0, "0", "")
        if persisted:
            row_key = str(alert_id)
            dup = self._find_row(row_key)
            if dup >= 0:
                self._remove_row(dup)
        elif alert_id is None:
            self._pending_counter += 1
            row_key = f"pending-{self._pending_counter}"
        else:
            self._unsaved_counter += 1
            row_key = f"unsaved-{self._unsaved_counter}"

        row = 0
        self.alert_table.insertRow(row)

        captured = count_present(extract_features(full_data))

        ts_item = QTableWidgetItem(str(timestamp))
        id_item = QTableWidgetItem(str(alert_id) if persisted else ("…" if alert_id is None else "—"))
        src_item = QTableWidgetItem(str(source_ip))
        dst_item = QTableWidgetItem(str(dest_ip))
        proto_item = QTableWidgetItem(str(protocol))
        enc_item = QTableWidgetItem("⬤ Y" if is_encrypted else "○ n")
        feat_item = QTableWidgetItem(f"{captured}/{FEATURE_COUNT}")
        sev_str = str(severity).upper().strip()
        sev_item = QTableWidgetItem(sev_str)
        stat_item = QTableWidgetItem("✓ RESOLVED" if resolved else "UNRESOLVED")

        ts_item.setData(Qt.ItemDataRole.UserRole, row_key)
        self.row_payload_cache[row_key] = full_data
        self.row_ts_cache[row_key] = str(timestamp)
        self._flow_key_to_row_key[flow_fingerprint(full_data)] = row_key

        mono_font = QFont("JetBrains Mono", 9)
        if not mono_font.exactMatch():
            mono_font = QFont("Consolas", 9)
        bold_font = QFont(mono_font)
        bold_font.setBold(True)

        for item in (ts_item, id_item, src_item, dst_item, proto_item):
            item.setFont(mono_font)
        for item in (enc_item, feat_item, sev_item, stat_item):
            item.setFont(bold_font)

        if "CRITICAL" in sev_str:
            sev_color = QColor(C_RED)
        elif "HIGH" in sev_str:
            sev_color = QColor(C_AMBER)
        elif "MEDIUM" in sev_str:
            sev_color = QColor(C_ACCENT)
        else:
            sev_color = QColor(C_TEXT_SEC)

        sev_item.setForeground(sev_color)
        stat_item.setForeground(QColor(C_GREEN) if resolved
                                else QColor(C_RED) if "CRITICAL" in sev_str else QColor(C_AMBER))
        enc_item.setForeground(QColor(C_ACCENT) if is_encrypted else QColor(C_TEXT_DIM))
        enc_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        feat_item.setForeground(QColor(C_GREEN) if captured == FEATURE_COUNT else QColor(C_AMBER))
        feat_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)

        items = [ts_item, id_item, src_item, dst_item, proto_item, enc_item, feat_item, sev_item, stat_item]
        for col, item in enumerate(items):
            self.alert_table.setItem(row, col, item)

        while self.alert_table.rowCount() > MAX_ROWS:
            self._remove_row(self.alert_table.rowCount() - 1)
        self._refresh_empty_state()
        return row_key

    def _refresh_empty_state(self) -> None:
        empty = self.alert_table.rowCount() == 0
        self.alert_table.setVisible(not empty)
        self.empty_lbl.setVisible(empty)
        if empty:
            tau = f"τ = {self._live_tau:.4f}" if self._live_tau else "the threshold τ"
            self.empty_lbl.setText(
                f"No anomalies above {tau} yet.\n\n"
                "Flows below the threshold are NORMAL and stay in the Console Grid log.\n"
                "Incidents appear here the moment a flow's MAE exceeds τ, and earlier\n"
                "incidents from the database are loaded when the app starts."
            )

    def load_recent_from_db(self, limit: int = 200) -> int:
        """
        Fills the log with the newest real incidents already stored in the database
        (MAE above the threshold they were detected with), so history survives a restart.
        """
        from src.database.models import NetworkAlert
        db = SessionLocal()
        try:
            rows = (
                db.query(NetworkAlert)
                .filter(NetworkAlert.reconstruction_error > NetworkAlert.threshold_at_time)
                .order_by(NetworkAlert.id.desc())
                .limit(limit)
                .all()
            )
            rows.reverse()                       # oldest first -> newest ends on top
            added = 0
            for al in rows:
                if self._find_row(str(al.id)) >= 0:
                    continue
                ts = al.timestamp
                if ts is not None:
                    if ts.tzinfo is None:        # SQLite stores UTC without tz info
                        ts = ts.replace(tzinfo=timezone.utc)
                    ts = ts.astimezone()
                    today = ts.date() == datetime.now().astimezone().date()
                    ts_text = ts.strftime("%H:%M:%S" if today else "%m-%d %H:%M")
                else:
                    ts_text = "n/a"
                payload = {
                    "id": al.id,
                    "src_ip": al.source_ip, "dst_ip": al.dest_ip,
                    "src_port": al.source_port, "dst_port": al.dest_port,
                    "protocol": al.protocol, "is_encrypted": al.is_encrypted,
                    "reconstruction_error": al.reconstruction_error,
                    "threshold_at_time": al.threshold_at_time,
                    "flow_features": al.flow_features,
                }
                self.add_alert(
                    al.id, ts_text, al.source_ip or "unknown", al.severity, payload,
                    dest_ip=al.dest_ip or "unknown", protocol=al.protocol or "IP",
                    is_encrypted=bool(al.is_encrypted), resolved=al.is_reviewed,
                )
                added += 1
            return added
        except Exception:
            return 0
        finally:
            db.close()

    # ── Row bookkeeping ───────────────────────────────────────────────────────
    def _find_row(self, row_key: str) -> int:
        for r in range(self.alert_table.rowCount()):
            cell = self.alert_table.item(r, COL_TIME)
            if cell and str(cell.data(Qt.ItemDataRole.UserRole)) == row_key:
                return r
        return -1

    def _remove_row(self, row: int) -> None:
        cell = self.alert_table.item(row, COL_TIME)
        key = str(cell.data(Qt.ItemDataRole.UserRole)) if cell else None
        self.alert_table.removeRow(row)
        if key is not None:
            self.row_payload_cache.pop(key, None)
            self.row_ts_cache.pop(key, None)
            self._flow_key_to_row_key = {
                fk: rk for fk, rk in self._flow_key_to_row_key.items() if rk != key
            }
            if self.current_selected_id == key:
                self.current_selected_id = None
                self.submit_btn.setEnabled(False)
        self._refresh_empty_state()

    def assign_db_id(self, row_key: str, db_id: Optional[int]) -> None:
        """Called when the background saver finishes: swaps the provisional key for the real DB id."""
        row = self._find_row(row_key)
        if row < 0:
            return                                  # row already scrolled out of the view
        if db_id:
            new_key = str(db_id)
            other = self._find_row(new_key)
            if other >= 0 and other != row:         # same alert already listed -> keep one
                self._remove_row(other)
                row = self._find_row(row_key)
                if row < 0:
                    return
        else:
            self._unsaved_counter += 1
            new_key = f"unsaved-{self._unsaved_counter}"

        self.alert_table.item(row, COL_TIME).setData(Qt.ItemDataRole.UserRole, new_key)
        id_cell = self.alert_table.item(row, COL_ID)
        if id_cell:
            id_cell.setText(str(db_id) if db_id else "—")

        if row_key in self.row_payload_cache:
            self.row_payload_cache[new_key] = self.row_payload_cache.pop(row_key)
        if row_key in self.row_ts_cache:
            self.row_ts_cache[new_key] = self.row_ts_cache.pop(row_key)
        for fk, rk in list(self._flow_key_to_row_key.items()):
            if rk == row_key:
                self._flow_key_to_row_key[fk] = new_key
        if self.current_selected_id == row_key:
            self.current_selected_id = new_key

    @Slot(float)
    def set_live_threshold(self, tau: float) -> None:
        self.tau_lbl.setText(f"LIVE τ = {tau:.4f}")
        self._live_tau = tau
        self._refresh_empty_state()

    # Narrow window (Console + History side by side): stack table over inspector
    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        want = Qt.Vertical if self.width() < 1000 else Qt.Horizontal
        if self.splitter.orientation() != want:
            self.splitter.setOrientation(want)
            self.splitter.setSizes([320, 480] if want == Qt.Vertical else [580, 420])

    def select_by_payload(self, payload: dict) -> bool:
        """Selects (and scrolls to) the history row for a packet picked in the Console."""
        row_key = self._flow_key_to_row_key.get(flow_fingerprint(payload))
        if row_key is None:
            return False
        for r in range(self.alert_table.rowCount()):
            cell = self.alert_table.item(r, COL_TIME)
            if cell and str(cell.data(Qt.ItemDataRole.UserRole)) == row_key:
                self.alert_table.selectRow(r)
                self.alert_table.scrollToItem(cell)
                return True
        return False

    # ── Slots ─────────────────────────────────────────────────────────────────
    def load_alert_details(self) -> None:
        selected = self.alert_table.selectionModel().selectedRows()
        if not selected:
            self.current_selected_id = None
            self.submit_btn.setEnabled(False)
            return

        row = selected[0].row()
        row_key = str(self.alert_table.item(row, COL_TIME).data(Qt.ItemDataRole.UserRole))
        self.current_selected_id = row_key
        payload = self.row_payload_cache.get(row_key, {})

        # 1) values from the live payload, 2) fill gaps from the DB row
        values = extract_features(payload)
        sources = "live payload"
        snap = self._load_db_snapshot(row_key)
        if snap is not None and count_present(values) < FEATURE_COUNT:
            db_values = extract_features(snap.get("flow_features"))
            merged = merge_features(values, db_values)
            if count_present(merged) > count_present(values):
                sources = "database" if count_present(values) == 0 else "live payload + database"
                values = merged
        elif snap is not None:
            sources = "live payload (database row also present)"

        feat_cell = self.alert_table.item(row, COL_FEAT)
        if feat_cell is not None:
            n = count_present(values)
            feat_cell.setText(f"{n}/{FEATURE_COUNT}")
            feat_cell.setForeground(QColor(C_GREEN) if n == FEATURE_COUNT else QColor(C_AMBER))

        self.json_view.setPlainText(
            self._render_forensic_block(row_key, payload, values, snap, sources)
        )
        self.json_view.verticalScrollBar().setValue(0)
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

        if self.current_selected_id.startswith("pending-"):
            self.json_view.append("\n\n// ⏳ This alert is still being saved to the database. Try again in a moment.")
            return

        if self.current_selected_id.startswith("unsaved-"):
            self.json_view.append("\n\n// ⚠ Alert was not persisted to DB. Decision applied locally.")
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
        color = C_RED if length > MAX_COMMENT_LENGTH else C_TEXT_DIM
        self.lbl_char_count.setStyleSheet(
            f"color: {color}; font-size: 9px; font-family: {FONT_MONO}; background: transparent;"
        )

    # ── Internals ─────────────────────────────────────────────────────────────
    def _load_db_snapshot(self, row_key: str) -> Optional[dict]:
        """Reads the persisted alert (if any) for this row; never raises."""
        try:
            alert_id = int(row_key)
        except ValueError:
            return None
        if alert_id <= 0:
            return None
        db = SessionLocal()
        try:
            a = get_alert_by_id(db, alert_id)
            if a is None:
                return None
            return {
                "flow_features": a.flow_features,
                "source_port": a.source_port,
                "dest_port": a.dest_port,
                "threshold": a.threshold_at_time,
                "severity": a.severity,
                "is_false_positive": a.is_false_positive,
                "analyst_comment": a.analyst_comment,
            }
        except Exception:
            return None
        finally:
            db.close()

    def _render_forensic_block(self, row_key: str, payload: dict, values: list,
                               snap: Optional[dict], sources: str) -> str:
        if not payload and snap is None:
            return json.dumps({"error": "Telemetry payload unavailable"}, indent=2)

        snap = snap or {}
        mse = float(payload.get("reconstruction_error") or payload.get("score") or 0.0)
        src = payload.get("src_ip") or payload.get("source_ip") or "unknown"
        dst = payload.get("dst_ip") or payload.get("dest_ip") or "unknown"
        proto = payload.get("protocol", "IP")
        is_enc = bool(payload.get("is_encrypted", False))
        tau = float(payload.get("threshold_at_time") or payload.get("threshold")
                    or snap.get("threshold") or DEFAULT_THRESHOLD)
        sp = payload.get("src_port") or snap.get("source_port")
        dp = payload.get("dst_port") or snap.get("dest_port")
        src_s = f"{src}:{sp}" if sp else str(src)
        dst_s = f"{dst}:{dp}" if dp else str(dst)
        impact, mitigation = self._calculate_cyber_impact(mse, tau)
        persisted = not row_key.startswith(("unsaved-", "pending-"))
        captured = count_present(values)

        width = 58
        L = []
        L.append("═" * width)
        L.append(f"  ALERT #{row_key if persisted else 'UNSAVED':<8}  FORENSIC VECTOR INSPECTION")
        L.append("═" * width)
        L.append(f"  Connection  :  {src_s}  →  {dst_s}  ({proto})")
        L.append(f"  Encryption  :  {'ENCRYPTED (TLS/HTTPS)' if is_enc else 'Plaintext'}")
        L.append(f"  Recon. MAE  :  {mse:.6f}   (tau = {tau:.6f})")
        L.append(f"  Detected    :  {self.row_ts_cache.get(row_key, 'n/a')}")
        if snap:
            L.append(f"  DB severity :  {snap.get('severity')}")
            if snap.get("analyst_comment") is not None or snap.get("is_false_positive"):
                verdict = "False Positive" if snap.get("is_false_positive") else "True Positive"
                L.append(f"  Prior review:  {verdict}  — {snap.get('analyst_comment') or 'no notes'}")
        L.append("")
        L.append("  THREAT INTELLIGENCE ASSESSMENT")
        L.append("  " + "─" * (width - 2))
        L.append(f"  Impact      :  {impact}")
        L.append(f"  Mitigation  :  {mitigation}")
        L.append("")
        L.append(f"  22-FEATURE VECTOR  —  {completeness_text(values)} captured")
        L.append(f"  Source      :  {sources}")
        L.append("  " + "─" * (width - 2))
        L.extend(render_feature_lines(values, indent="  "))
        if captured < FEATURE_COUNT:
            L.append("")
            L.append(f"  ⚠ {FEATURE_COUNT - captured} feature(s) not captured (n/a). "
                     f"Check parser.py / MonitorService payload.")
        L.append("")
        L.append("  WHERE ELSE TO FIND THIS PACKET")
        L.append("  " + "─" * (width - 2))
        L.append("  Console Grid   : click / double-click the flow row (22 badges)")
        L.append(f"  Report         : Forensic Reports > Section 4 (Alert ID {row_key if persisted else 'n/a - unsaved'})")
        L.append("  Database       : alerts.flow_features  (NetworkAlert.feature_map)")
        L.append("")
        L.append("═" * width)
        return "\n".join(L)

    def _calculate_cyber_impact(self, mse: float, tau: float = DEFAULT_THRESHOLD) -> Tuple[str, str]:
        diff = mse - tau
        if mse <= tau:
            return ("Low — Marginal deviation within expected parameters.", "No immediate action required.")
        elif diff > tau * 3.0:
            return ("Critical — Extreme reconstruction error. Potential payload injection.",
                    "Isolate source endpoint immediately and alert incident response.")
        elif diff > tau * 1.5:
            return ("High — Out-of-bounds behavioral anomaly detected.",
                    "Inspect protocol signatures. Apply traffic filtering if verified.")
        elif diff > tau * 0.5:
            return ("Medium — Moderate threshold deviation.",
                    "Correlate with additional network flows from host.")
        return ("Low — Slight anomaly signature.", "Flag for model baseline calibration.")

    def _mark_row_resolved(self, row_key: str) -> None:
        for r in range(self.alert_table.rowCount()):
            cell = self.alert_table.item(r, COL_TIME)
            if cell and str(cell.data(Qt.ItemDataRole.UserRole)) == row_key:
                status_item = self.alert_table.item(r, COL_STATUS)
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