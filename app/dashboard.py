# dashboard.py
"""
Sentinel Dashboard — HIDS Sentinel v2.0 (main window)

SOC ANALYST MAP (22 features) — how a packet's 22 features are reachable:
  * Console Grid (left)   : feature strip; click a flow row = pin, double-click = jump to Inspector
  * Console Grid (right)  : Alert History -> 22-Feature Forensic Inspector (FEAT column = n/22)
  * Forensic Reports      : Section 4 lists all 22 features for every alert
  * Status bar "VECTORS"  : live count of features captured for the LAST flow (was a hard-coded 22/22)
  * Triage Queue button   : jumps to Alert History and selects the newest row
  * Feature schema        : src/database/feature_schema.py
"""
import logging
import os
import queue
import sys
from datetime import datetime, timezone

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QToolBar, QSplitter,
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QSizePolicy, QPushButton,
    QFrame
)
from PySide6.QtGui import QAction, QActionGroup, QColor
from PySide6.QtCore import Qt, Slot, QTimer, QSize, QCoreApplication, QThread, Signal
from dotenv import load_dotenv
from PySide6.QtGui import QPalette

from pages.realtime_monitor import RealTimeMonitor
from pages.alert_history    import AlertHistory
from pages.settings         import Settings
from pages.ingestion        import IngestionPage
from pages.analysis         import AnalysisPage
from pages.reports          import ReportsPage
from pages.docs             import DocsPage

from src.database.connection import SessionLocal, create_tables
from src.database.crud       import create_alert
from src.database.feature_schema import (
    FEATURE_COUNT as SCHEMA_FEATURE_COUNT,
    compute_severity, count_present, extract_features,
)

from theme import (
    C_BG_APP, C_BG_PANEL, C_BG_SURFACE, C_BORDER, C_BORDER_LT,
    C_TEXT_PRI, C_TEXT_SEC, C_TEXT_DIM,
    C_ACCENT, C_ACCENT_LT, C_ACCENT_DIM, C_VIOLET,
    C_GREEN, C_GREEN_DIM, C_AMBER, C_RED,
    FONT_MONO, FONT_SIZE_XS,
    QSS_BASE,
)

load_dotenv()
THEME_PREFERENCE = os.getenv("GUI_THEME", "dark").lower()

MODEL_ARCH    = "22 → 16 → 8 → 4 → 8 → 16 → 22"
MODEL_NAME    = "baseline_ae.keras  v1.0.4"
FEATURE_COUNT = SCHEMA_FEATURE_COUNT

IDX_CONSOLE   = 0
IDX_INGESTION = 1
IDX_ANALYSIS  = 2
IDX_SETTINGS  = 3
IDX_REPORTS   = 4
IDX_DOCS      = 5

OPS_SPLIT_RATIO = (0.55, 0.45)

NAV_NODES = [
    ("Console Grid",     IDX_CONSOLE,   "⬡", C_ACCENT),
    ("Packet Ingestion", IDX_INGESTION, "⬡", C_VIOLET),
    ("Model Analysis",   IDX_ANALYSIS,  "⬡", C_VIOLET),
    ("Forensic Reports", IDX_REPORTS,   "⬡", C_AMBER),
    ("Settings",         IDX_SETTINGS,  "⬡", C_ACCENT_LT),
    ("Docs",             IDX_DOCS,      "⬡", C_ACCENT_LT),
]


logger = logging.getLogger("HIDS_Dashboard")


class AlertPersistWorker(QThread):
    """
    Saves alerts to the database OFF the UI thread, in batches.

    The UI used to run a full-table lookup plus a commit() for every alert on the
    GUI thread; a burst of alerts (e.g. after lowering the threshold) froze the
    window. Now the row appears instantly and its DB id arrives a moment later.
    """
    persisted = Signal(str, int)          # row_key, db_id (0 = could not save)

    BATCH = 200

    def __init__(self, parent=None):
        super().__init__(parent)
        self._q: "queue.Queue" = queue.Queue()      # unbounded: alerts are never dropped

    def submit(self, row_key: str, payload: dict) -> None:
        self._q.put((row_key, dict(payload)))

    def stop(self) -> None:
        self._q.put(None)
        self.wait(5000)

    def run(self) -> None:
        stop = False
        while not stop:
            item = self._q.get()
            if item is None:
                break
            batch = [item]
            while len(batch) < self.BATCH:
                try:
                    nxt = self._q.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:
                    stop = True
                    break
                batch.append(nxt)
            self._save_batch(batch)

    def _save_batch(self, batch) -> None:
        db = SessionLocal()
        try:
            try:                                     # fast path: ONE commit for the batch
                ids = [self._save(db, p, commit=False) for _, p in batch]
                db.commit()
                for (key, _), db_id in zip(batch, ids):
                    self.persisted.emit(key, db_id)
                return
            except Exception as exc:
                db.rollback()
                logger.warning(f"Batch save failed ({exc}); retrying one by one.")

            for key, payload in batch:               # slow path isolates a bad record
                try:
                    db_id = self._save(db, payload, commit=True)
                except Exception as exc:
                    db.rollback()
                    logger.warning(f"Alert persist failed: {exc}")
                    db_id = 0
                self.persisted.emit(key, db_id)
        finally:
            db.close()

    @staticmethod
    def _save(db, payload: dict, commit: bool = True) -> int:
        existing = payload.get("id") or payload.get("alert_id")
        if existing:
            return int(existing)

        # Did the monitor service already store this flow? Check only the newest rows
        # (primary-key order, cheap) instead of scanning the whole table by float value.
        from src.database.models import NetworkAlert
        from sqlalchemy import desc
        score = float(payload.get("reconstruction_error") or payload.get("score") or 0.0)
        src = payload.get("src_ip") or payload.get("source_ip") or "unknown"
        dst = payload.get("dst_ip") or payload.get("dest_ip") or "unknown"
        for row in db.query(NetworkAlert).order_by(desc(NetworkAlert.id)).limit(100):
            if (abs(float(row.reconstruction_error) - score) < 1e-9
                    and row.source_ip == src and row.dest_ip == dst):
                return int(row.id)
        return int(create_alert(db, payload, commit=commit).id)


class SOCHeaderMetric(QFrame):
    def __init__(self, label: str, value: str, val_color: str = C_ACCENT_LT, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            f"QFrame {{ background: {C_BG_SURFACE}; border: 1px solid {C_BORDER}; border-radius: 4px; padding: 2px 8px; }}"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(6)

        lbl = QLabel(label.upper())
        lbl.setStyleSheet(f"color: {C_TEXT_DIM}; font-size: 9px; font-weight: 700; font-family: {FONT_MONO};")
        
        self.val_lbl = QLabel(value)
        self.val_lbl.setStyleSheet(f"color: {val_color}; font-size: 11px; font-weight: 700; font-family: {FONT_MONO};")

        layout.addWidget(lbl)
        layout.addWidget(self.val_lbl)

    def set_value(self, text: str, color: str = None):
        self.val_lbl.setText(text)
        if color:
            self.val_lbl.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: 700; font-family: {FONT_MONO};")


class SentinelDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(
            "AUTOENCODER-HIDS  ·  Sentinel Command Console  ·  SOC Behavioral Intrusion Ops"
        )
        self.resize(1720, 980)
        self.setMinimumSize(1280, 720)
        self.setStyleSheet(QSS_BASE)

        try:
            # create_tables() = create_all() + lightweight migrations, so older
            # databases get source_port / dest_port / is_encrypted automatically.
            create_tables()
            print("SOC Engine: database schema verified / migrated.")
        except Exception as e:
            print(f"Database Connection Failure: {e}")

        self.monitor_page   = RealTimeMonitor()
        self.alerts_page    = AlertHistory()
        self.ingestion_page = IngestionPage()
        self.analysis_page  = AnalysisPage()
        self.reports_page   = ReportsPage()
        self.docs_page      = DocsPage()
        self.settings_page  = Settings(
            theme_callback=self.apply_theme,
            monitor_ref=self.monitor_page,
        )

        self.operations_split_widget = QWidget()
        self.operations_split_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        split_layout = QHBoxLayout(self.operations_split_widget)
        split_layout.setContentsMargins(0, 0, 0, 0)
        split_layout.setSpacing(0)

        self.ops_splitter = QSplitter(Qt.Horizontal)
        self.ops_splitter.setHandleWidth(4)
        self.ops_splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {C_BG_PANEL};
                border-left: 1px solid {C_BORDER};
                border-right: 1px solid {C_BORDER};
            }}
            QSplitter::handle:hover {{
                background-color: {C_ACCENT};
            }}
        """)
        self.ops_splitter.addWidget(self.monitor_page)
        self.ops_splitter.addWidget(self.alerts_page)
        self.ops_splitter.setStretchFactor(0, 55)
        self.ops_splitter.setStretchFactor(1, 45)
        split_layout.addWidget(self.ops_splitter)

        self.main_stack = QStackedWidget()
        self.main_stack.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.main_stack.addWidget(self.operations_split_widget)
        self.main_stack.addWidget(self.ingestion_page)
        self.main_stack.addWidget(self.analysis_page)
        self.main_stack.addWidget(self.settings_page)
        self.main_stack.addWidget(self.reports_page)
        self.main_stack.addWidget(self.docs_page)

        central = QWidget()
        cl = QVBoxLayout(central)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(self.main_stack, stretch=1)
        cl.addWidget(self._build_status_strip())
        self.setCentralWidget(central)

        self._persist_worker = AlertPersistWorker(self)
        self._persist_worker.persisted.connect(self._on_alert_persisted)
        self._persist_worker.start()

        # Load the newest stored incidents once the window is up (history survives restarts)
        QTimer.singleShot(0, self.alerts_page.load_recent_from_db)

        self.monitor_page.service.new_alert.connect(self._route_alert_to_history)
        self.monitor_page.service.new_alert.connect(self._update_soc_header_counters)
        # Double-click a flow row in the Console -> open it in the Forensic Inspector
        self.monitor_page.packet_selected.connect(self._open_in_inspector)
        # One threshold, everywhere: console -> status bar + Alert History label;
        # retraining recalibration -> console.
        self.monitor_page.threshold_changed.connect(self._on_threshold_changed)
        self.analysis_page.threshold_updated.connect(self.monitor_page.set_live_threshold)

        if hasattr(self.ingestion_page, "update_feature_strip"):
            self.monitor_page.service.new_alert.connect(
                self.ingestion_page.update_feature_strip
            )

        if hasattr(self.settings_page, "interface_changed"):
            self.settings_page.interface_changed.connect(
                self._handle_interface_changed
            )
        self.ingestion_page.interface_changed.connect(
            self._handle_interface_changed
        )
        self.alerts_page.feedback_submitted.connect(
            self.analysis_page.increment_pending_counter
        )

        self._total_incidents_count = 0
        self._build_nav()
        self._apply_soc_theme(THEME_PREFERENCE)

        QTimer.singleShot(0, self._enforce_split_ratio)

    @Slot(str)
    def _handle_interface_changed(self, interface_name: str = None):
        try:
            if hasattr(self.monitor_page, "restart_interface"):
                if interface_name:
                    self.monitor_page.restart_interface(interface_name)
                else:
                    self.monitor_page.restart_interface()
            elif hasattr(self.monitor_page, "_restart_interface"):
                self.monitor_page._restart_interface()
        except Exception as e:
            print(f"Interface restart error: {e}")

    def _build_nav(self):
        self.nav_toolbar = QToolBar("SOC Command Bar")
        self.nav_toolbar.setObjectName("SOCNavToolbar")
        self.nav_toolbar.setMovable(False)
        self.nav_toolbar.setAllowedAreas(Qt.TopToolBarArea)
        self.nav_toolbar.setIconSize(QSize(0, 0))
        
        self.nav_toolbar.setAutoFillBackground(True)
        pal = self.nav_toolbar.palette()
        pal.setColor(QPalette.Window, QColor(C_BG_PANEL))
        self.nav_toolbar.setPalette(pal)
        
        self.addToolBar(self.nav_toolbar)

        brand_wrap = QWidget()
        brand_wrap.setStyleSheet("background: transparent;")
        bw_lay = QHBoxLayout(brand_wrap)
        bw_lay.setContentsMargins(8, 2, 16, 2)
        bw_lay.setSpacing(10)

        brand_icon = QLabel("⬢")
        brand_icon.setStyleSheet(f"color: {C_ACCENT}; font-size: 18px; background: transparent;")
        
        brand_text = QLabel("HIDS SENTINEL")
        brand_text.setStyleSheet(
            f"color: {C_TEXT_PRI}; font-size: 14px; font-weight: 900; "
            f"font-family: {FONT_MONO}; letter-spacing: 1.5px; background: transparent;"
        )
        brand_sub = QLabel("SOC BEHAVIORAL MONITOR")
        brand_sub.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: 9px; font-weight: 700; "
            f"font-family: {FONT_MONO}; letter-spacing: 0.8px; background: transparent;"
        )
        bw_col = QVBoxLayout()
        bw_col.setSpacing(0)
        bw_col.setContentsMargins(0, 0, 0, 0)
        bw_col.addWidget(brand_text)
        bw_col.addWidget(brand_sub)
        
        bw_lay.addWidget(brand_icon)
        bw_lay.addLayout(bw_col)
        self.nav_toolbar.addWidget(brand_wrap)

        div1 = QFrame()
        div1.setFrameShape(QFrame.VLine)
        div1.setFixedWidth(1)
        div1.setFixedHeight(28)
        div1.setStyleSheet(f"background: {C_BORDER}; border: none;")
        self.nav_toolbar.addWidget(div1)

        self.nav_group = QActionGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_actions: dict = {}

        for label, idx, _icon, _color in NAV_NODES:
            action = QAction(label, self)
            action.setCheckable(True)
            if idx == IDX_CONSOLE:
                action.setChecked(True)
            action.triggered.connect(lambda checked=False, i=idx: self._go_to_page(i))
            self.nav_group.addAction(action)
            self.nav_toolbar.addAction(action)
            self.nav_actions[idx] = action

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        spacer.setStyleSheet("background: transparent;")
        self.nav_toolbar.addWidget(spacer)

        self.header_metrics_wrap = QWidget()
        self.header_metrics_wrap.setStyleSheet("background: transparent;")
        hm_lay = QHBoxLayout(self.header_metrics_wrap)
        hm_lay.setContentsMargins(0, 0, 8, 0)
        hm_lay.setSpacing(6)

        self.m_threat_level = SOCHeaderMetric("DEFCON", "LEVEL 4 / NORMAL", C_GREEN)
        self.m_active_iface = SOCHeaderMetric("IFACE", "eth0 (PROMISC)", C_TEXT_PRI)
        self.m_alerts_count = SOCHeaderMetric("ALERTS", "0 DETECTED", C_TEXT_SEC)

        hm_lay.addWidget(self.m_threat_level)
        hm_lay.addWidget(self.m_active_iface)
        hm_lay.addWidget(self.m_alerts_count)

        self.nav_toolbar.addWidget(self.header_metrics_wrap)

        self.engine_dot = QLabel("● ENGINE ACTIVE")
        self.engine_dot.setStyleSheet(
            f"color: {C_GREEN}; font-size: {FONT_SIZE_XS}; font-weight: 800; "
            f"font-family: {FONT_MONO}; background: {C_GREEN_DIM}; "
            f"border: 1px solid {C_GREEN}; border-radius: 4px; "
            f"padding: 4px 10px; margin-right: 8px;"
        )
        self.nav_toolbar.addWidget(self.engine_dot)

    def _go_to_page(self, index: int, focus_alerts: bool = False) -> None:
        self.main_stack.setCurrentIndex(index)
        action = self.nav_actions.get(index)
        if action is not None:
            action.setChecked(True)
        if focus_alerts and hasattr(self, "alerts_page"):
            self.alerts_page.alert_table.setFocus()
            if self.alerts_page.alert_table.rowCount() > 0:
                self.alerts_page.alert_table.selectRow(0)

    def _score_and_tau(self, data: dict):
        """MAE score of a flow and the LIVE threshold the console is using."""
        try:
            mse = float(data.get("reconstruction_error") or data.get("score")
                        or data.get("mse_score") or 0.0)
        except (TypeError, ValueError):
            mse = 0.0
        tau = float(getattr(getattr(self, "monitor_page", None), "live_threshold", 0.4313))
        return mse, tau

    @Slot(dict)
    def _update_soc_header_counters(self, alert_data: dict):
        # Live feature completeness of the last flow (replaces hard-coded 22/22)
        captured = count_present(extract_features(alert_data))
        self.chip_vectors_val.setText(f"{captured}/{FEATURE_COUNT} FEATURES (last flow)")
        self.chip_vectors_val.setStyleSheet(
            f"color: {C_GREEN if captured == FEATURE_COUNT else C_AMBER}; font-size: {FONT_SIZE_XS}; "
            f"font-weight: 700; font-family: {FONT_MONO}; background: transparent;"
        )

        # Only flows ABOVE the threshold are incidents. The severity label the
        # monitor service attaches to every flow is ignored; score vs tau decides.
        mse, tau = self._score_and_tau(alert_data)
        if mse < tau:
            return
        self._total_incidents_count += 1
        sev = compute_severity(mse, tau)

        if sev in ("High", "Critical"):
            self.m_threat_level.set_value("DEFCON 2 / ELEVATED", C_RED)
            self.m_alerts_count.set_value(f"{self._total_incidents_count} HIGH THREATS", C_RED)
        else:
            self.m_alerts_count.set_value(f"{self._total_incidents_count} DETECTED", C_AMBER)

    def _build_status_strip(self) -> QWidget:
        strip = QWidget()
        strip.setFixedHeight(34)
        strip.setStyleSheet(
            f"background-color: {C_BG_PANEL}; border-top: 1px solid {C_BORDER};"
        )
        row = QHBoxLayout(strip)
        row.setContentsMargins(12, 0, 12, 0)
        row.setSpacing(14)

        def chip(label: str, value: str, colour: str = C_TEXT_PRI) -> QWidget:
            w = QWidget()
            w.setStyleSheet("background: transparent;")
            lay = QHBoxLayout(w)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(5)
            l_lbl = QLabel(label)
            l_lbl.setStyleSheet(
                f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; "
                f"font-weight: 700; background: transparent; letter-spacing: 0.5px;"
            )
            v_lbl = QLabel(value)
            v_lbl.setStyleSheet(
                f"color: {colour}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
                f"font-family: {FONT_MONO}; background: transparent;"
            )
            lay.addWidget(l_lbl)
            lay.addWidget(v_lbl)
            return w, v_lbl

        w, _ = chip("MODEL:", MODEL_NAME, C_ACCENT_LT);  row.addWidget(w)
        w, _ = chip("ARCH:", MODEL_ARCH, C_TEXT_SEC);    row.addWidget(w)
        w, self.chip_vectors_val = chip("VECTORS:", f"schema {FEATURE_COUNT} FEATURES · awaiting flow", C_TEXT_SEC)
        row.addWidget(w)
        w, self.chip_tau_val = chip(
            "THRESHOLD τ:", f"{getattr(self.monitor_page, 'live_threshold', 0.4313):.4f}", C_ACCENT_LT)
        row.addWidget(w)

        vsep = QFrame()
        vsep.setFrameShape(QFrame.VLine)
        vsep.setFixedHeight(16)
        vsep.setStyleSheet(f"background: {C_BORDER}; border: none;")
        row.addWidget(vsep)
        row.addStretch()

        ghost_ss = f"""
            QPushButton {{
                color: {C_TEXT_SEC};
                background: {C_BG_SURFACE};
                border: 1px solid {C_BORDER};
                border-radius: 4px;
                padding: 2px 10px;
                font-size: {FONT_SIZE_XS};
                font-weight: 700;
                letter-spacing: 0.4px;
                font-family: {FONT_MONO};
                min-height: 20px;
            }}
            QPushButton:hover {{
                color: {C_ACCENT_LT};
                border-color: {C_ACCENT};
                background: {C_ACCENT_DIM};
            }}
        """

        self.btn_view_alerts = QPushButton("Triage Queue")
        self.btn_view_alerts.setCursor(Qt.PointingHandCursor)
        self.btn_view_alerts.setStyleSheet(ghost_ss)
        self.btn_view_alerts.clicked.connect(
            lambda: self._go_to_page(IDX_CONSOLE, focus_alerts=True)
        )
        row.addWidget(self.btn_view_alerts)

        self.btn_open_analysis = QPushButton("Deep Analysis")
        self.btn_open_analysis.setCursor(Qt.PointingHandCursor)
        self.btn_open_analysis.setStyleSheet(ghost_ss)
        self.btn_open_analysis.clicked.connect(
            lambda: self._go_to_page(IDX_ANALYSIS)
        )
        row.addWidget(self.btn_open_analysis)

        self.status_clock = QLabel()
        self.status_clock.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_XS}; "
            f"font-family: {FONT_MONO}; font-weight: 700; background: transparent; padding-left: 6px;"
        )
        row.addWidget(self.status_clock)

        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._update_clock_display)
        self._clock_timer.start(1000)
        self._update_clock_display()

        return strip

    def _update_clock_display(self):
        now_local = datetime.now().strftime("%H:%M:%S")
        now_utc = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.status_clock.setText(f"LOCAL: {now_local}  |  UTC: {now_utc} Z")
        # keep the τ chip in sync with the backend threshold fetched by the monitor
        if hasattr(self, "chip_tau_val"):
            self.chip_tau_val.setText(f"{getattr(self.monitor_page, 'live_threshold', 0.4313):.4f}")

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._enforce_split_ratio()

    def _enforce_split_ratio(self) -> None:
        if not hasattr(self, "ops_splitter"):
            return
        total = self.ops_splitter.width()
        if total <= 0:
            return
        left  = int(total * OPS_SPLIT_RATIO[0])
        right = total - left
        self.ops_splitter.setSizes([left, right])

    def _apply_soc_theme(self, theme_name: str):
        try:
            if theme_name.lower() in ("dark", "system"):
                panel_bg = C_BG_PANEL
                base = QSS_BASE + f"""
                    QMainWindow {{ background-color: {C_BG_APP}; }}
                    QToolBar#SOCNavToolbar {{
                        background-color: {C_BG_PANEL};
                        border-bottom: 2px solid {C_BORDER};
                        padding: 4px 12px;
                        spacing: 6px;
                    }}
                """
                nav_btn_ss = f"""
                    QToolButton {{
                        color: {C_TEXT_SEC};
                        font-size: 11px;
                        font-weight: 700;
                        font-family: {FONT_MONO};
                        letter-spacing: 0.6px;
                        padding: 5px 14px;
                        border-radius: 4px;
                        border: 1px solid transparent;
                        background: transparent;
                    }}
                    QToolButton:hover {{
                        color: {C_ACCENT_LT};
                        background: {C_BG_SURFACE};
                        border-color: {C_BORDER_LT};
                    }}
                    QToolButton:checked {{
                        color: {C_ACCENT_LT};
                        background: {C_ACCENT_DIM};
                        border: 1px solid {C_ACCENT};
                    }}
                """
            else:
                panel_bg = "#ffffff"
                base = """
                    QWidget { background-color: #f0f2f6; color: #111827; }
                    QMainWindow { background-color: #f0f2f6; }
                    QToolBar#SOCNavToolbar { background-color: #ffffff; border-bottom: 1px solid #d1d5db; padding: 4px 14px; }
                """
                nav_btn_ss = """
                    QToolButton { color: #374151; font-size: 11px; font-weight: 700; padding: 5px 12px; border-radius: 4px; }
                    QToolButton:checked { background: #eff6ff; border: 1px solid #3b82f6; color: #2563eb; }
                """

            self.setStyleSheet(base)
            if hasattr(self, "nav_toolbar"):
                self.nav_toolbar.setStyleSheet(nav_btn_ss)
                pal = self.nav_toolbar.palette()
                pal.setColor(QPalette.Window, QColor(panel_bg))
                self.nav_toolbar.setPalette(pal)
        except Exception as e:
            print(f"Theme Engine Warning: {e}")

    @Slot(dict)
    def _route_alert_to_history(self, data: dict):
        try:
            mse, tau = self._score_and_tau(data)

            # Benign flows (MAE below tau) stay in the console's flow log only.
            if mse < tau:
                return

            payload = dict(data)
            # Severity is derived ONLY from score vs threshold (never from the monitor
            # service's label), and the threshold used is stamped on the alert so the
            # row stays correct even after the analyst changes tau later.
            severity = compute_severity(mse, tau)
            payload["severity"] = severity
            payload["threshold"] = tau
            payload["threshold_at_time"] = tau

            timestamp    = datetime.now().strftime("%H:%M:%S")
            src_ip       = payload.get("src_ip") or payload.get("source_ip") or "unknown"
            dst_ip       = payload.get("dst_ip") or payload.get("dest_ip") or "unknown"
            protocol     = payload.get("protocol", "IP")
            is_encrypted = bool(payload.get("is_encrypted", False))
            alert_id     = payload.get("id") or payload.get("alert_id")

            # Row appears immediately; the database id arrives asynchronously.
            row_key = self.alerts_page.add_alert(
                alert_id, timestamp, src_ip, severity, payload,
                dest_ip=dst_ip, protocol=protocol, is_encrypted=is_encrypted,
            )
            if not alert_id:
                self._persist_worker.submit(row_key, payload)
        except Exception as err:
            print(f"Alert routing error: {err}")

    @Slot(str, int)
    def _on_alert_persisted(self, row_key: str, db_id: int) -> None:
        self.alerts_page.assign_db_id(row_key, db_id or None)

    @Slot(float)
    def _on_threshold_changed(self, tau: float) -> None:
        self.chip_tau_val.setText(f"{tau:.4f}")
        self.alerts_page.set_live_threshold(tau)

    def closeEvent(self, event) -> None:
        try:
            self._persist_worker.stop()
        finally:
            super().closeEvent(event)

    @Slot(dict)
    def _open_in_inspector(self, data: dict) -> None:
        """Console double-click -> show Alert History with this packet's 22 features."""
        self._go_to_page(IDX_CONSOLE)
        if not self.alerts_page.select_by_payload(data):
            print("[INFO] Packet not yet in Alert History; it appears once routed/persisted.")

    @Slot(str)
    def apply_theme(self, theme_name: str):
        normalized = theme_name.lower()
        self._apply_soc_theme(normalized)
        if hasattr(self, "settings_page") and self.settings_page:
            self.settings_page.update_theme(normalized)


if __name__ == "__main__":
    if not QCoreApplication.testAttribute(Qt.AA_ShareOpenGLContexts):
        QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts, True)
    
    sys.argv.append("--no-sandbox")
    sys.argv.append("--disable-dev-shm-usage")
    sys.argv.append("--disable-gpu")
    sys.argv.append("--disable-software-rasterizer")

    app = QApplication(sys.argv)
    app.setApplicationName("HIDS Sentinel Command Center")
    app.setApplicationDisplayName("HIDS Sentinel Console")
    window = SentinelDashboard()
    window.show()
    sys.exit(app.exec())