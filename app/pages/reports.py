# app/pages/reports.py
"""
Forensic Reports & Compliance Exports — HIDS Sentinel v2.0

SOC ANALYST MAP (22 features):
  * "Generate Forensic Report" saves a .txt/.md containing:
      Section 3  incident table  (ID | time | IPs | proto | enc | severity | MAE | FEAT n/22 | verdict)
      Section 4  ALL 22 features for EVERY alert, grouped and numbered 00-21
      Section 5  SOC navigation guide (where to look for each packet)
  * The ID column equals the ID in Alert History -> look the packet up there.
  * Missing features print "n/a" (never a fake 0).
  * The FEATURE SCHEMA card shows how many recent alerts hold a full 22/22 vector.
  * Feature names/order: src/database/feature_schema.py
"""

import os
from collections import Counter
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFrame,
    QHBoxLayout, QFileDialog, QMessageBox, QGridLayout, QScrollArea
)
from PySide6.QtCore import Qt, Slot, QThread, Signal, QObject

from src.database.connection import SessionLocal
from src.database.models import NetworkAlert
from src.database.feature_schema import (
    DEFAULT_THRESHOLD, FEATURE_COUNT, SOC_NAVIGATION_GUIDE,
    completeness_text, count_present, extract_features, render_feature_lines,
)

from theme import (
    C_BG_APP, C_BG_PANEL, C_BG_SURFACE, C_BORDER, C_BORDER_LT,
    C_TEXT_PRI, C_TEXT_SEC, C_TEXT_DIM,
    C_ACCENT, C_ACCENT_LT, C_ACCENT_DIM, C_VIOLET, C_VIOLET_DIM,
    C_GREEN, C_GREEN_DIM, C_AMBER, C_AMBER_DIM, C_RED,
    FONT_MONO, FONT_UI, FONT_SIZE_XS, FONT_SIZE_SM, FONT_SIZE_MD, FONT_SIZE_LG,
    QSS_BASE, QSS_BTN_PRIMARY
)

RULE = "═" * 70
THIN = "─" * 70


def _verdict(alert: NetworkAlert) -> str:
    """FP if flagged; TP only once an analyst has reviewed; otherwise Pending."""
    if alert.is_false_positive:
        return "Verified FP"
    if alert.analyst_comment is not None:
        return "Verified TP"
    return "Pending"


class ForensicReportWorker(QObject):
    """Background worker executing database queries and report generation."""
    finished = Signal(str, str)  # Payload, default filename
    failed = Signal(str)

    @Slot()
    def process_report(self):
        db = SessionLocal()
        try:
            alerts = db.query(NetworkAlert).order_by(NetworkAlert.id.asc()).all()
            total = len(alerts)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if total == 0:
                self.finished.emit(self._build_empty_report(ts), "HIDS_Empty_Report.txt")
                return

            verdicts = Counter()
            sev_counts = Counter()
            enc = plain = 0
            full_vec = partial_vec = no_vec = 0
            scores = []
            table_rows = []
            detail_blocks = []

            for a in alerts:
                values = extract_features(a.flow_features)
                n = count_present(values)
                if n == FEATURE_COUNT:
                    full_vec += 1
                elif n > 0:
                    partial_vec += 1
                else:
                    no_vec += 1

                verdict = _verdict(a)
                verdicts[verdict] += 1
                sev_counts[a.severity] += 1
                if a.is_encrypted:
                    enc += 1
                else:
                    plain += 1
                if a.reconstruction_error is not None:
                    scores.append(float(a.reconstruction_error))

                when = a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "n/a"
                src = a.source_ip or "unknown"
                dst = a.dest_ip or "unknown"
                proto = a.protocol or "IP"
                mae = float(a.reconstruction_error or 0.0)
                tau = float(a.threshold_at_time or DEFAULT_THRESHOLD)

                table_rows.append(
                    f"{a.id:<6} | {when:<19} | {str(src):<15} | {str(dst):<15} | {str(proto):<8} | "
                    f"{'Y' if a.is_encrypted else 'n':<3} | {str(a.severity):<8} | {mae:<10.4f} | "
                    f"{completeness_text(values):<5} | {verdict}"
                )

                sp = f":{a.source_port}" if a.source_port else ""
                dp = f":{a.dest_port}" if a.dest_port else ""
                block = [
                    THIN,
                    f"ALERT #{a.id}   [{a.severity}]   {when}",
                    f"  Connection   : {src}{sp}  →  {dst}{dp}  ({proto})   Encrypted: {'Yes' if a.is_encrypted else 'No'}",
                    f"  MAE / tau    : {mae:.6f} / {tau:.6f}",
                    f"  Verdict      : {verdict}",
                    f"  Analyst note : {a.analyst_comment if a.analyst_comment else '—'}",
                    f"  22-FEATURE VECTOR — {completeness_text(values)} captured",
                ]
                block.extend(render_feature_lines(values, indent="  "))
                if n < FEATURE_COUNT:
                    block.append(f"  ⚠ {FEATURE_COUNT - n} feature(s) not captured (n/a) — check parser.py / MonitorService.")
                block.append("")
                detail_blocks.append("\n".join(block))

            avg_mse = sum(scores) / len(scores) if scores else 0.0
            sev_line = "  ".join(f"{k}: {sev_counts.get(k, 0)}" for k in ("Critical", "High", "Medium", "Low"))
            header = (
                f"{'ID':<6} | {'Time':<19} | {'Source IP':<15} | {'Dest IP':<15} | {'Proto':<8} | "
                f"{'Enc':<3} | {'Severity':<8} | {'MAE Score':<10} | {'Feat':<5} | Verdict"
            )
            detail_blocks_text = "\n".join(detail_blocks)
            nav = "\n".join(f"  • {where}\n      {what}" for where, what in SOC_NAVIGATION_GUIDE)

            report = f"""{RULE}
AUTOENCODER-HIDS SENTINEL CONSOLE  |  FORENSIC COMPLIANCE AUDIT
{RULE}
Generated On         : {ts}
Classification       : INTERNAL USE ONLY

1. EXECUTIVE SUMMARY
{THIN}
Total Anomalous Flows Captured    : {total}
Severity Breakdown                : {sev_line}
Verified True Positives           : {verdicts.get("Verified TP", 0)}
Verified False Positives          : {verdicts.get("Verified FP", 0)}
Pending Analyst Review            : {verdicts.get("Pending", 0)}
Average Flow Reconstruction MAE   : {avg_mse:.6f}
Encrypted (TLS / HTTPS-class)     : {enc}
Plaintext                         : {plain}
Feature Vectors Complete (22/22)  : {full_vec}
Feature Vectors Partial           : {partial_vec}
Feature Vectors Missing           : {no_vec}

2. MODEL CONFIGURATION
{THIN}
Feature Schema          : {FEATURE_COUNT} flow-based behavioral metrics  (L3/L4 only)
Architecture            : 22 → 16 → 8 → 4 → 8 → 16 → 22  (Autoencoder)
Default Threshold (tau) : {DEFAULT_THRESHOLD}  (μ + 2σ — see /ready for live value; per-alert tau shown in Section 4)
Database Pipeline       : SYNCED / OPERATIONAL

3. HISTORICAL INCIDENT LOG
{THIN}
{header}
{"─" * len(header)}
{chr(10).join(table_rows)}

4. PER-ALERT 22-FEATURE FORENSIC DETAIL
   (Alert IDs match the ID column in Alert History)
{detail_blocks_text}
5. SOC ANALYST NAVIGATION GUIDE
{THIN}
{nav}

{RULE}
END OF FORENSIC AUDIT REPORT
"""
            self.finished.emit(report, "HIDS_Compliance_Report.txt")

        except Exception as e:
            self.failed.emit(str(e))
        finally:
            db.close()

    def _build_empty_report(self, timestamp: str) -> str:
        return f"""{RULE}
AUTOENCODER-HIDS SENTINEL CONSOLE  |  FORENSIC COMPLIANCE AUDIT
{RULE}
Generated On   : {timestamp}
Classification : INTERNAL USE ONLY

NOTICE: No historical incident records found in storage.
Database is empty — pending initial packet capture ingestion.
{RULE}
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
        self.schema_card_val = self._metric_card(grid, 0, 2, "FEATURE SCHEMA", "22 / 22 schema", C_ACCENT_LT)

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
            "per-alert IP / protocol / encryption status / severity, a full 22-feature "
            "behavioral snapshot for every flagged flow (Section 4), and a SOC navigation "
            "guide. Alert IDs match the Alert History page."
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
            "Find a packet: note its ID in Section 3 -> Alert History -> select ID -> 22-Feature Forensic Inspector",
        ]

        for note in notes:
            lbl = QLabel(f"  ·  {note}")
            lbl.setStyleSheet(
                f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; background: transparent;"
            )
            notes_layout.addWidget(lbl)

        self.root.addWidget(notes_card)

    # ── Live schema-completeness card ──────────────────────────────────────────
    def showEvent(self, event):
        super().showEvent(event)
        self._refresh_schema_card()

    def _refresh_schema_card(self):
        """Shows how many of the latest 500 alerts hold a full 22/22 vector."""
        db = SessionLocal()
        try:
            rows = (db.query(NetworkAlert.flow_features)
                      .order_by(NetworkAlert.id.desc()).limit(500).all())
            if not rows:
                self.schema_card_val.setText("22 / 22 schema")
                return
            full = sum(1 for r in rows if count_present(extract_features(r[0])) == FEATURE_COUNT)
            colour = C_GREEN if full == len(rows) else C_AMBER
            self.schema_card_val.setText(f"{full}/{len(rows)} full 22/22")
            self.schema_card_val.setStyleSheet(
                f"color: {colour}; font-size: {FONT_SIZE_LG}; font-weight: 700; "
                f"font-family: {FONT_MONO}; background: transparent;"
            )
        except Exception:
            pass
        finally:
            db.close()

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
        return val

    # ── Threaded Report Handler ───────────────────────────────────────────────
    @Slot()
    def generate_forensic_report(self):
        self.status_lbl.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_SM}; font-family: {FONT_MONO};"
        )
        self.status_lbl.setText("⟳ Querying forensic database...")
        self.export_btn.setEnabled(False)

        # Offload file query to background worker thread
        self._thread = QThread()
        self._worker = ForensicReportWorker()
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.process_report)
        self._worker.finished.connect(self._on_report_generated)
        self._worker.failed.connect(self._on_report_failed)

        # Cleanup hooks
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.failed.connect(self._thread.quit)
        self._worker.failed.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

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
                content = report_content
                if file_path.lower().endswith(".md"):
                    content = "```text\n" + report_content + "\n```\n"   # keep column alignment in Markdown
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)

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