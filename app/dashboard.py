# dashboard.py[cite: 2]
import os
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
from PySide6.QtCore import Qt, Slot, QTimer, QSize, QCoreApplication
from dotenv import load_dotenv
from PySide6.QtGui import QPalette

from pages.realtime_monitor import RealTimeMonitor
from pages.alert_history    import AlertHistory
from pages.settings         import Settings
from pages.ingestion        import IngestionPage
from pages.analysis         import AnalysisPage
from pages.reports          import ReportsPage
from pages.docs             import DocsPage

from src.database.connection import engine, SessionLocal
from src.database.models     import Base
from src.database.crud       import create_alert

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
FEATURE_COUNT = 22

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
            Base.metadata.create_all(bind=engine)
            print("SQLite Core: SOC Engine Schema synced successfully.")
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

        self.monitor_page.service.new_alert.connect(self._route_alert_to_history)
        self.monitor_page.service.new_alert.connect(self._update_soc_header_counters)

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

    @Slot(dict)
    def _update_soc_header_counters(self, alert_data: dict):
        self._total_incidents_count += 1
        sev = alert_data.get("severity", "Low")
        
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
            return w

        row.addWidget(chip("MODEL:", MODEL_NAME, C_ACCENT_LT))
        row.addWidget(chip("ARCH:", MODEL_ARCH, C_TEXT_SEC))
        row.addWidget(chip("VECTORS:", f"{FEATURE_COUNT}/{FEATURE_COUNT} FEATURES", C_GREEN))
        row.addWidget(chip("THRESHOLD τ:", f"{getattr(self.monitor_page, 'live_threshold', 0.4313):.4f}", C_ACCENT_LT))

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
            timestamp    = datetime.now().strftime("%H:%M:%S")
            src_ip       = data.get("src_ip")   or data.get("source_ip") or "unknown"
            dst_ip       = data.get("dst_ip")   or data.get("dest_ip")   or "unknown"
            protocol     = data.get("protocol", "IP")
            is_encrypted = bool(data.get("is_encrypted", False))

            mse = float(
                data.get("reconstruction_error")
                or data.get("score")
                or data.get("mse_score")
                or 0.0
            )
            tau = getattr(
                getattr(self, "monitor_page", None),
                "live_threshold",
                0.4313,
            )
            raw_sev = data.get("severity")
            if raw_sev and str(raw_sev).strip() in ("Low", "Medium", "High", "Critical"):
                severity = str(raw_sev).strip()
            else:
                diff = mse - tau
                if mse <= tau:
                    severity = "Low"
                elif diff > tau * 3.0:
                    severity = "Critical"
                elif diff > tau * 1.5:
                    severity = "High"
                elif diff > tau * 0.5:
                    severity = "Medium"
                else:
                    severity = "Low"

            alert_id = data.get("id") or data.get("alert_id")
            if not alert_id:
                db = SessionLocal()
                try:
                    from src.database.models import NetworkAlert
                    from sqlalchemy import desc
                    score = float(data.get("reconstruction_error") or data.get("score") or 0.0)
                    row = (db.query(NetworkAlert)
                             .filter(NetworkAlert.reconstruction_error == score)
                             .order_by(desc(NetworkAlert.id))
                             .first())
                    if row:
                        alert_id = row.id
                        data["id"] = alert_id
                    else:
                        data_for_db = dict(data)
                        data_for_db.setdefault("threshold_at_time", tau)
                        data_for_db.setdefault("threshold", tau)
                        db_alert = create_alert(db, data_for_db)
                        alert_id = db_alert.id
                except Exception as db_err:
                    db.rollback()
                    print(f"[WARNING] SOC Alert Lookup: {db_err}")
                    alert_id = None
                finally:
                    db.close()

            if hasattr(self, "alerts_page") and alert_id is not None:
                self.alerts_page.add_alert(
                    alert_id, timestamp, src_ip, severity, data,
                    dest_ip=dst_ip,
                    protocol=protocol,
                    is_encrypted=is_encrypted,
                )
            elif hasattr(self, "alerts_page"):
                data["_unpersisted"] = True
                self.alerts_page.add_alert(
                    0, timestamp, src_ip, severity, data,
                    dest_ip=dst_ip,
                    protocol=protocol,
                    is_encrypted=is_encrypted,
                )
        except Exception as err:
            print(f"Alert routing error: {err}")

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