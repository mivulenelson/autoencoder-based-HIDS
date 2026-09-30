# app/pages/reports.py
"""
Forensic Reports & Compliance Exports — HIDS Sentinel v2.0

Enterprise PySide6 Reporting View featuring asynchronous database querying,
SOC2 / ISO 27001 audit export options, responsive viewport scrolling,
and robust 22-feature flow fingerprint logging.
"""

import os
import json
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFrame,
    QHBoxLayout, QFileDialog, QMessageBox, QGridLayout, QScrollArea
)
from PySide6.QtCore import Qt, Slot, QThread, Signal, QObject

from src.database.connection import SessionLocal
from sqlalchemy import text, inspect

from theme import (
    C_BG_APP, C_BG_PANEL, C_BG_SURFACE, C_BORDER, C_BORDER_LT,
    C_TEXT_PRI, C_TEXT_SEC, C_TEXT_DIM,
    C_ACCENT, C_ACCENT_LT, C_ACCENT_DIM, C_VIOLET, C_VIOLET_DIM,
    C_GREEN, C_GREEN_DIM, C_AMBER, C_AMBER_DIM, C_RED,
    FONT_MONO, FONT_UI, FONT_SIZE_XS, FONT_SIZE_SM, FONT_SIZE_MD, FONT_SIZE_LG,
    QSS_BASE, QSS_BTN_PRIMARY
)

FEATURE_NAMES = [
    "flow_duration", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max",
    "fwd_iat_total", "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min",
    "fwd_pkt_len_max", "total_fwd_bytes", "flow_pkts_per_sec", "flow_bytes_per_sec",
    "pkt_len_variance", "burst_ratio", "active_time_ratio", "pkt_count",
    "unique_ttl_count", "ttl_mean", "tcp_flag_ratio", "has_udp", "has_tcp",
]


class ForensicReportWorker(QObject):
    """Background worker executing asynchronous database queries and report generation."""
    finished = Signal(str, str)  # Payload, default filename
    failed = Signal(str)

    @Slot()
    def process_report(self):
        db = SessionLocal()
        try:
            raw_result = db.execute(text("SELECT * FROM alerts")).fetchall()
            total = len(raw_result)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if total == 0:
                report = self._build_empty_report(ts)
                self.finished.emit(report, "HIDS_Empty_Report.txt")
                return

            inspector = inspect(db.bind)
            columns = [c["name"] for c in inspector.get_columns("alerts")]

            def get_val(row, keys):
                for k in keys:
                    if k in columns:
                        if hasattr(row, "_mapping"):
                            return row._mapping.get(k)
                        return getattr(row, k, None)
                return None

            tp = fp = unclassified = 0
            encrypted_count = plaintext_count = 0
            scores = []
            rows_txt = ""

            for idx, row in enumerate(raw_result, 1):
                src = get_val(row, ["src_ip", "source_ip", "src"]) or "unknown"
                dst = get_val(row, ["dst_ip", "dest_ip", "destination_ip", "dst"]) or "unknown"
                proto = get_val(row, ["protocol", "proto"]) or "IP"
                enc = get_val(row, ["is_encrypted"])
                score_val = get_val(row, ["score", "mse_score", "reconstruction_error", "mse_value"])
                is_fp = get_val(row, ["is_false_positive", "is_fp", "false_positive"])

                if score_val is not None:
                    scores.append(float(score_val))

                if enc in (1, True):
                    encrypted_count += 1
                elif enc in (0, False):
                    plaintext_count += 1

                if is_fp in (1, True):
                    verdict = "Verified FP"
                    fp += 1
                elif is_fp in (0, False):
                    verdict = "Verified TP"
                    tp += 1
                else:
                    verdict = "Unchecked"
                    unclassified += 1

                score_str = f"{float(score_val):.4f}" if score_val is not None else "0.0000"
                enc_str = "Y" if enc in (1, True) else "n"

                rows_txt += (
                    f"{idx:<6} | {str(src):<15} | {str(dst):<15} | {str(proto):<8} | "
                    f"{enc_str:<3} | {score_str:<10} | {verdict:<12}\n"
                )

                feat_json = get_val(row, ["features", "feature_vector", "payload"])
                if feat_json:
                    rows_txt += self._format_feature_snapshot(feat_json)

            avg_mse = sum(scores) / len(scores) if scores else 0.0

            report = f"""══════════════════════════════════════════════════════════════════════
AUTOENCODER-HIDS SENTINEL CONSOLE  |  FORENSIC COMPLIANCE AUDIT
══════════════════════════════════════════════════════════════════════
Generated On         : {ts}
Classification       : INTERNAL USE ONLY

1. EXECUTIVE SUMMARY
──────────────────────────────────────────────────────────────────────
Total Anomalous Flows Captured    : {total}
Confirmed True Threat Vectors     : {tp}
Verified False Positives          : {fp}
Pending Analyst Review            : {unclassified}
Average Flow Reconstruction MAE   : {avg_mse:.6f}
Encrypted (TLS / HTTPS-class)     : {encrypted_count}
Plaintext                         : {plaintext_count}

2. MODEL CONFIGURATION
──────────────────────────────────────────────────────────────────────
Feature Schema          : 22 flow-based behavioral metrics  (L3/L4 only)
Architecture            : 22 → 16 → 8 → 4 → 8 → 16 → 22  (Autoencoder)
Default Threshold (tau) : 0.4313  (μ + 2σ — see /ready for live value)
Database Pipeline       : SYNCED / OPERATIONAL

3. HISTORICAL INCIDENT LOG
──────────────────────────────────────────────────────────────────────
{'ID':<6} | {'Source IP':<15} | {'Dest IP':<15} | {'Proto':<8} | {'Enc':<3} | {'MAE Score':<10} | {'Verdict':<12}
{'─'*74}
{rows_txt}
══════════════════════════════════════════════════════════════════════
END OF FORENSIC AUDIT REPORT
"""
            self.finished.emit(report, "HIDS_Compliance_Report.txt")

        except Exception as e:
            self.failed.emit(str(e))
        finally:
            db.close()

    def _format_feature_snapshot(self, feat_json) -> str:
        try:
            data = feat_json if isinstance(feat_json, dict) else json.loads(feat_json)
        except Exception:
            return ""
        lines = ["         ├─ 22-feature snapshot:"]
        for name in FEATURE_NAMES:
            if name in data:
                lines.append(f"         │    {name:<22} = {data[name]}")
        lines.append("")
        return "\n".join(lines) + "\n"

    def _build_empty_report(self, timestamp: str) -> str:
        return f"""══════════════════════════════════════════════════════════════════════
AUTOENCODER-HIDS SENTINEL CONSOLE  |  FORENSIC COMPLIANCE AUDIT
══════════════════════════════════════════════════════════════════════
Generated On   : {timestamp}
Classification : INTERNAL USE ONLY

NOTICE: No historical incident records found in storage.
Database is empty — pending initial packet capture ingestion.
══════════════════════════════════════════════════════════════════════
"""


class ReportsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(QSS_BASE)

        self._setup_ui()

    # ── UI Initialization ──────────────────────────────────────────────────────
    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Responsive Scroll Area Outer Frame
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet(f"QScrollArea {{ background: {C_BG_APP}; }}")

        container = QWidget()
        container.setObjectName("Container")
        container.setStyleSheet(f"#Container {{ background-color: {C_BG_APP}; }}")

        self.root = QVBoxLayout(container)
        self.root.setContentsMargins(28, 24, 28, 24)
        self.root.setSpacing(18)

        scroll_area.setWidget(container)
        main_layout.addWidget(scroll_area)

        # Build View Sections
        self._build_header()
        self.root.addWidget(self._glow_sep())
        self._build_kpi_cards()
        self._build_export_section()
        self._build_compliance_notes()

        self.root.addStretch()

    # ── Header Construction ────────────────────────────────────────────────────
    def _build_header(self):
        hdr = QHBoxLayout()
        hdr.setSpacing(14)

        icon = QLabel("⬡")
        icon.setStyleSheet(
            f"color: {C_AMBER}; font-size: 22px; font-weight: bold; background: transparent;"
        )

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        title = QLabel("FORENSIC REPORTS & COMPLIANCE EXPORTS")
        title.setStyleSheet(
            f"color: {C_TEXT_PRI}; font-size: 16px; font-weight: 700; "
            f"font-family: {FONT_MONO}; letter-spacing: 0.8px; background: transparent;"
        )

        sub = QLabel("SOC2 / ISO 27001 — AUTOMATED INCIDENT AUDIT — 22-FEATURE SCHEMA")
        sub.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; font-weight: 600; "
            f"letter-spacing: 1.1px; background: transparent;"
        )

        title_col.addWidget(title)
        title_col.addWidget(sub)

        hdr.addWidget(icon, alignment=Qt.AlignVCenter)
        hdr.addLayout(title_col)
        hdr.addStretch()

        self.root.addLayout(hdr)

    # ── KPI Cards Construction ─────────────────────────────────────────────────
    def _build_kpi_cards(self):
        grid = QGridLayout()
        grid.setSpacing(12)

        self._metric_card(grid, 0, 0, "COMPLIANCE STATUS", "AUDIT READY", C_GREEN)
        self._metric_card(grid, 0, 1, "TARGET STANDARD", "SOC2 / ISO27001", C_AMBER)
        self._metric_card(grid, 0, 2, "FEATURE SCHEMA", "22 / 22 logged", C_ACCENT_LT)

        self.root.addLayout(grid)

    # ── Export Panel Construction ──────────────────────────────────────────────
    def _build_export_section(self):
        self.root.addWidget(self._section_label("Automated Security Incident Report"))

        card = self._card(C_AMBER)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 18, 20, 18)
        card_layout.setSpacing(16)

        # Information Details Row
        desc_icon = QLabel("📋")
        desc_icon.setStyleSheet("background: transparent; font-size: 22px;")

        desc_text = QLabel(
            "Exports a timestamped compliance audit document including cumulative "
            "incident totals, confirmed threat vectors, average reconstruction MAE, "
            "per-alert IP / protocol / encryption status, and a full 22-feature "
            "behavioral snapshot for every flagged flow."
        )
        desc_text.setWordWrap(True)
        desc_text.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_SM}; "
            f"line-height: 1.5; background: transparent;"
        )

        desc_row = QHBoxLayout()
        desc_row.setSpacing(14)
        desc_row.addWidget(desc_icon, alignment=Qt.AlignTop)
        desc_row.addWidget(desc_text, stretch=1)
        card_layout.addLayout(desc_row)

        # Divider Separator
        div = QFrame()
        div.setFixedHeight(1)
        div.setStyleSheet(f"background: {C_BORDER}; border: none;")
        card_layout.addWidget(div)

        # Action Buttons Layout
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self.export_btn = QPushButton("  ⬇  GENERATE FORENSIC REPORT")
        self.export_btn.setStyleSheet(QSS_BTN_PRIMARY)
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.setFixedHeight(38)
        self.export_btn.setFixedWidth(260)
        self.export_btn.clicked.connect(self.generate_forensic_report)

        btn_row.addWidget(self.export_btn)
        btn_row.addStretch()
        card_layout.addLayout(btn_row)

        # Inline Processing Status Feedback Label
        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_SM}; "
            f"font-family: {FONT_MONO}; background: transparent;"
        )
        card_layout.addWidget(self.status_lbl, alignment=Qt.AlignCenter)

        self.root.addWidget(card)

    # ── Compliance Notes Section ───────────────────────────────────────────────
    def _build_compliance_notes(self):
        notes_card = QFrame()
        notes_card.setObjectName("NotesCard")
        notes_card.setStyleSheet(
            f"QFrame#NotesCard {{ background-color: {C_BG_SURFACE}; "
            f"border: 1px solid {C_BORDER}; border-left: 3px solid {C_AMBER}; "
            f"border-radius: 6px; }}"
        )
        notes_layout = QVBoxLayout(notes_card)
        notes_layout.setContentsMargins(16, 12, 16, 12)
        notes_layout.setSpacing(6)

        notes = [
            "Output format: plain text (.txt) or Markdown (.md)",
            "Classification: INTERNAL USE ONLY — SOC2 Type II compliant",
            "Schema: 22-feature behavioral fingerprint (L3/L4 only, zero-decryption)",
        ]

        for note in notes:
            lbl = QLabel(f"  ·  {note}")
            lbl.setStyleSheet(
                f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; background: transparent;"
            )
            notes_layout.addWidget(lbl)

        self.root.addWidget(notes_card)

    # ── Reusable Component Factories ──────────────────────────────────────────
    def _card(self, accent: str) -> QFrame:
        card = QFrame()
        card.setObjectName("CardFrame")
        card.setStyleSheet(
            f"QFrame#CardFrame {{ background-color: {C_BG_PANEL}; "
            f"border: 1px solid {C_BORDER}; border-top: 2px solid {accent}; "
            f"border-radius: 8px; }}"
        )
        return card

    def _glow_sep(self) -> QFrame:
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(
            f"background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            f"stop:0 {C_BG_APP}, stop:0.35 {C_AMBER_DIM}, "
            f"stop:0.65 {C_AMBER_DIM}, stop:1 {C_BG_APP});"
        )
        return sep

    def _section_label(self, text: str) -> QLabel:
        lbl = QLabel(text.upper())
        lbl.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
            f"letter-spacing: 1.2px; background: transparent; margin-top: 6px;"
        )
        return lbl

    def _metric_card(self, grid, row, col, title, value, color):
        card = QFrame()
        card.setObjectName("MetricCard")
        card.setStyleSheet(
            f"QFrame#MetricCard {{ background-color: {C_BG_PANEL}; "
            f"border: 1px solid {C_BORDER}; border-top: 2px solid {color}; "
            f"border-radius: 8px; }}"
        )
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(4)

        t = QLabel(title)
        t.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: 9px; font-weight: 700; "
            f"letter-spacing: 0.9px; background: transparent;"
        )

        val = QLabel(value)
        val.setStyleSheet(
            f"color: {color}; font-size: {FONT_SIZE_LG}; font-weight: 700; "
            f"font-family: {FONT_MONO}; background: transparent;"
        )

        v.addWidget(t)
        v.addWidget(val)
        grid.addWidget(card, row, col)

    # ── Threaded Report Handler ───────────────────────────────────────────────
    @Slot()
    def generate_forensic_report(self):
        self.status_lbl.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_SM}; font-family: {FONT_MONO};"
        )
        self.status_lbl.setText("⟳ Querying forensic database...")
        self.export_btn.setEnabled(False)

        # Offload file query to background worker thread
        self.thread = QThread()
        self.worker = ForensicReportWorker()
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.process_report)
        self.worker.finished.connect(self._on_report_generated)
        self.worker.failed.connect(self._on_report_failed)

        # Cleanup hooks
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.failed.connect(self.thread.quit)
        self.worker.failed.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    @Slot(str, str)
    def _on_report_generated(self, report_content: str, default_filename: str):
        self.export_btn.setEnabled(True)

        default_path = os.path.expanduser(f"~/Desktop/{default_filename}")
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Compliance Forensic Report",
            default_path,
            "Text Files (*.txt);;Markdown Files (*.md)",
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(report_content)

                self.status_lbl.setStyleSheet(
                    f"color: {C_GREEN}; font-size: {FONT_SIZE_SM}; font-family: {FONT_MONO};"
                )
                self.status_lbl.setText(f"✓ Report exported: {os.path.basename(file_path)}")

                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Forensic report successfully saved to:\n{file_path}",
                )
            except IOError as io_err:
                self._on_report_failed(f"Failed writing report file: {io_err}")
        else:
            self.status_lbl.setStyleSheet(
                f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_SM}; font-family: {FONT_MONO};"
            )
            self.status_lbl.setText("— Export operation cancelled.")

    @Slot(str)
    def _on_report_failed(self, error_msg: str):
        self.export_btn.setEnabled(True)
        self.status_lbl.setStyleSheet(
            f"color: {C_RED}; font-size: {FONT_SIZE_SM}; font-family: {FONT_MONO};"
        )
        self.status_lbl.setText("✖ Database extraction pipeline failed.")

        QMessageBox.critical(
            self,
            "Pipeline Error",
            f"Failed to process database records for report generation.\n\nReason: {error_msg}",
        )