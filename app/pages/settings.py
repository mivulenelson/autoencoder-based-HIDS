# app/pages/settings.py[cite: 3]
import os
import threading
import logging
import requests
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QComboBox, QSlider, QLabel,
    QFrame, QHBoxLayout, QPushButton, QScrollArea, QDoubleSpinBox
)
from PySide6.QtCore import Qt, Signal, Slot

from theme import (
    C_BG_APP, C_BG_PANEL, C_BG_SURFACE, C_BORDER, C_BORDER_LT,
    C_TEXT_PRI, C_TEXT_SEC, C_TEXT_DIM,
    C_ACCENT, C_ACCENT_LT, C_ACCENT_DIM, C_VIOLET,
    C_GREEN,
    FONT_MONO, FONT_SIZE_XS, FONT_SIZE_SM, FONT_SIZE_MD,
    QSS_BASE, QSS_BTN_SUCCESS
)

logger = logging.getLogger("HIDS_Settings")

_QSS_COMBO = lambda accent: f"""
    QComboBox {{
        background-color: {C_BG_SURFACE};
        color: {C_TEXT_PRI};
        font-family: {FONT_MONO};
        font-size: {FONT_SIZE_SM};
        border: 1px solid {C_BORDER_LT};
        border-radius: 5px;
        padding: 6px 10px;
        min-height: 28px;
    }}
    QComboBox:hover {{ border-color: {accent}; }}
    QComboBox:focus {{ border-color: {accent}; border-width: 1px; }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 28px;
        border-left: 1px solid {C_BORDER};
        border-top-right-radius: 5px;
        border-bottom-right-radius: 5px;
        background: {C_BG_PANEL};
    }}
    QComboBox::down-arrow {{
        width: 10px; height: 10px; image: none;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 5px solid {C_ACCENT_LT};
    }}
    QComboBox QAbstractItemView {{
        background-color: {C_BG_PANEL}; color: {C_TEXT_PRI};
        font-family: {FONT_MONO}; font-size: {FONT_SIZE_SM};
        border: 1px solid {C_BORDER_LT}; border-radius: 4px;
        selection-background-color: {C_ACCENT_DIM};
        selection-color: {C_ACCENT_LT}; outline: 0px; padding: 4px;
    }}
    QComboBox QAbstractItemView::item {{ min-height: 26px; padding: 4px 8px; border-radius: 3px; }}
    QComboBox QAbstractItemView::item:hover {{ background-color: {C_ACCENT_DIM}; color: {C_ACCENT_LT}; }}
"""

_QSS_SPINBOX = f"""
    QDoubleSpinBox {{
        background-color: {C_BG_SURFACE};
        color: {C_ACCENT_LT};
        font-family: {FONT_MONO};
        font-weight: 700;
        font-size: {FONT_SIZE_SM};
        border: 1px solid {C_BORDER_LT};
        border-radius: 5px;
        padding: 5px 8px;
        min-height: 28px;
    }}
    QDoubleSpinBox:focus {{ border-color: {C_ACCENT}; }}
    QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{ width: 0px; height: 0px; }}
"""

_QSS_SLIDER = f"""
    QSlider::groove:horizontal {{
        border: 1px solid {C_BORDER_LT}; height: 6px; background: {C_BG_SURFACE}; border-radius: 3px;
    }}
    QSlider::sub-page:horizontal {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {C_VIOLET}, stop:1 {C_ACCENT});
        border-radius: 3px;
    }}
    QSlider::add-page:horizontal {{ background: {C_BG_SURFACE}; border-radius: 3px; }}
    QSlider::handle:horizontal {{
        background: {C_ACCENT_LT}; border: 2px solid {C_BG_APP}; width: 16px; height: 16px; margin: -5px 0; border-radius: 8px;
    }}
    QSlider::handle:horizontal:hover {{ background: {C_ACCENT}; border-color: {C_BG_PANEL}; }}
"""


class Settings(QWidget):
    settings_saved = Signal(dict)

    def __init__(self, theme_callback, monitor_ref, parent=None):
        super().__init__(parent)
        self.main_monitor_page = monitor_ref
        self.theme_callback    = theme_callback
        self.current_theme     = os.getenv("GUI_THEME", "dark").lower()
        self.api_url           = os.getenv("HIDS_API_URL", "http://127.0.0.1:9000")

        self._setup_ui()
        self._connect_signals()
        self._fetch_backend_threshold()

    def _fetch_backend_threshold(self):
        """Fetch active threshold from backend /ready endpoint on startup[cite: 1, 3]."""
        def _fetch():
            try:
                res = requests.get(f"{self.api_url}/ready", timeout=2)
                if res.status_code == 200:
                    data = res.json()
                    tau = float(data.get("threshold", 0.43))
                    # Update UI in main thread if needed or via signals
                    from PySide6.QtCore import QMetaObject, Q_ARG
                    QMetaObject.invokeMethod(
                        self.thresh_spinbox, "setValue",
                        Qt.QueuedConnection, Q_ARG(float, tau)
                    )
            except Exception as exc:
                logger.debug(f"Could not fetch initial threshold from backend: {exc}")

        threading.Thread(target=_fetch, daemon=True).start()

    def _setup_ui(self):
        self.setStyleSheet(QSS_BASE)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet(f"""
            QScrollArea {{ background: {C_BG_APP}; border: none; }}
            QScrollBar:vertical {{ background: {C_BG_SURFACE}; width: 5px; border-radius: 2px; }}
            QScrollBar::handle:vertical {{ background: {C_BORDER_LT}; border-radius: 2px; min-height: 20px; }}
            QScrollBar::handle:vertical:hover {{ background: {C_ACCENT}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        """)

        container = QWidget()
        container.setObjectName("SettingsContainer")
        container.setStyleSheet(f"#SettingsContainer {{ background-color: {C_BG_APP}; }}")

        self.root = QVBoxLayout(container)
        self.root.setContentsMargins(32, 28, 32, 32)
        self.root.setSpacing(20)

        scroll_area.setWidget(container)
        main_layout.addWidget(scroll_area)

        self._build_header()
        self.root.addWidget(self._glow_sep(C_ACCENT_DIM))
        self._build_interface_section()
        self._build_detection_section()
        self._build_system_info_section()
        self._build_footer_actions()
        self.root.addStretch()

    def _build_header(self):
        hdr = QHBoxLayout()
        hdr.setSpacing(14)

        icon = QLabel("⬡")
        icon.setStyleSheet(
            f"color: {C_ACCENT_LT}; font-size: 24px; font-weight: bold; background: transparent;"
        )

        title_col = QVBoxLayout()
        title_col.setSpacing(3)

        title = QLabel("SYSTEM CONFIGURATION")
        title.setStyleSheet(
            f"color: {C_TEXT_PRI}; font-size: 17px; font-weight: 700; "
            f"font-family: {FONT_MONO}; letter-spacing: 0.8px; background: transparent;"
        )

        sub = QLabel("INTERFACE ENVIRONMENT  /  DETECTION POLICY")
        sub.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; font-weight: 600; "
            f"letter-spacing: 1.2px; background: transparent;"
        )

        title_col.addWidget(title)
        title_col.addWidget(sub)

        hdr.addWidget(icon, alignment=Qt.AlignVCenter)
        hdr.addLayout(title_col)
        hdr.addStretch()

        self.root.addLayout(hdr)

    def _build_interface_section(self):
        self.root.addWidget(self._section_label("Interface Environment"))
        card, card_layout = self._card(C_ACCENT_LT)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(16)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        self.theme_sel = QComboBox()
        self.theme_sel.addItems(["Dark", "Light", "System"])
        self.theme_sel.setStyleSheet(_QSS_COMBO(C_ACCENT_LT))
        idx = self.theme_sel.findText(self.current_theme.capitalize())
        if idx >= 0:
            self.theme_sel.setCurrentIndex(idx)

        self.refresh_rate = QComboBox()
        self.refresh_rate.addItems(["500 ms", "1000 ms", "2000 ms", "5000 ms"])
        self.refresh_rate.setCurrentIndex(1)
        self.refresh_rate.setStyleSheet(_QSS_COMBO(C_ACCENT_LT))

        form.addRow(self._form_label("Global GUI Theme"), self.theme_sel)
        form.addRow(self._form_label("Dashboard Refresh Rate"), self.refresh_rate)

        card_layout.addLayout(form)
        self.root.addWidget(card)

    def _build_detection_section(self):
        self.root.addWidget(
            self._section_label("Detection Policy — Autoencoder Inference Engine")
        )
        card, card_layout = self._card(C_VIOLET)

        thresh_form = QFormLayout()
        thresh_form.setSpacing(16)
        thresh_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        thresh_form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        slider_row = QHBoxLayout()
        slider_row.setSpacing(12)

        self.thresh_slider = QSlider(Qt.Horizontal)
        self.thresh_slider.setRange(10, 200)
        self.thresh_slider.setValue(43)
        self.thresh_slider.setCursor(Qt.PointingHandCursor)
        self.thresh_slider.setStyleSheet(_QSS_SLIDER)

        self.thresh_spinbox = QDoubleSpinBox()
        self.thresh_spinbox.setRange(0.10, 2.00)
        self.thresh_spinbox.setSingleStep(0.01)
        self.thresh_spinbox.setValue(0.43)
        self.thresh_spinbox.setDecimals(2)
        self.thresh_spinbox.setPrefix("τ = ")
        self.thresh_spinbox.setFixedWidth(108)
        self.thresh_spinbox.setStyleSheet(_QSS_SPINBOX)

        slider_row.addWidget(self.thresh_slider, stretch=1)
        slider_row.addWidget(self.thresh_spinbox)

        thresh_form.addRow(
            self._form_label("Anomaly Threshold (μ + k·σ)"), slider_row
        )

        hint = QLabel(
            "Flows with reconstruction MAE above this value are flagged as ANOMALY. "
            "Lower values increase sensitivity; raise to reduce false positives."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; "
            f"font-family: {FONT_MONO}; background: transparent; "
            f"padding-left: 4px; margin-top: -6px;"
        )
        thresh_form.addRow(QLabel(""), hint)

        model_frame = QFrame()
        model_frame.setStyleSheet(
            f"background: {C_BG_SURFACE}; border: 1px solid {C_BORDER}; "
            f"border-radius: 5px;"
        )
        mfl = QHBoxLayout(model_frame)
        mfl.setContentsMargins(12, 8, 12, 8)
        mfl.setSpacing(16)

        for label, value, color in [
            ("MODEL",     "baseline_ae.keras",              C_ACCENT_LT),
            ("VERSION",   "v1.0.4",                         C_GREEN),
            ("ARCH",      "22→16→8→4→8→16→22",              C_VIOLET),
            ("VECTORS",   "22 features",                    C_TEXT_SEC),
        ]:
            col = QVBoxLayout()
            col.setSpacing(2)
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"color: {C_TEXT_DIM}; font-family: {FONT_MONO}; "
                f"font-size: 8px; letter-spacing: 1px; background: transparent; border: none;"
            )
            val = QLabel(value)
            val.setStyleSheet(
                f"color: {color}; font-family: {FONT_MONO}; font-size: {FONT_SIZE_XS}; "
                f"font-weight: 700; background: transparent; border: none;"
            )
            col.addWidget(lbl)
            col.addWidget(val)
            mfl.addLayout(col)
            if label != "VECTORS":
                div = QFrame()
                div.setFrameShape(QFrame.VLine)
                div.setStyleSheet(f"background: {C_BORDER}; border: none; max-width: 1px;")
                mfl.addWidget(div)

        mfl.addStretch()
        thresh_form.addRow(self._form_label("Active Model Pipeline"), model_frame)

        card_layout.addLayout(thresh_form)
        self.root.addWidget(card)

    def _build_system_info_section(self):
        self.root.addWidget(self._section_label("Runtime Environment"))
        card, card_layout = self._card(C_TEXT_DIM)

        grid = QHBoxLayout()
        grid.setSpacing(0)

        entries = [
            ("API ENDPOINT",   os.getenv("HIDS_API_URL",           "http://127.0.0.1:9000")),
            ("MODEL PATH",     os.getenv("HIDS_MODEL_PATH",         "/app/models/baseline_ae.keras")),
            ("DATABASE",       os.getenv("DATABASE_URL",            "sqlite////app/db/hids_forensics.db")),
            ("THRESHOLD CFG",  os.getenv("HIDS_THRESHOLD_CONFIG",   "/app/configs/threshold.yaml")),
        ]

        for i, (key, val) in enumerate(entries):
            col = QVBoxLayout()
            col.setSpacing(4)
            col.setContentsMargins(0, 0, 0, 0)

            k = QLabel(key)
            k.setStyleSheet(
                f"color: {C_TEXT_DIM}; font-family: {FONT_MONO}; font-size: 8px; "
                f"letter-spacing: 1.2px; font-weight: 700; background: transparent;"
            )
            v = QLabel(val)
            v.setWordWrap(True)
            v.setStyleSheet(
                f"color: {C_TEXT_SEC}; font-family: {FONT_MONO}; font-size: {FONT_SIZE_XS}; "
                f"background: transparent;"
            )
            col.addWidget(k)
            col.addWidget(v)
            grid.addLayout(col, 1)

            if i < len(entries) - 1:
                div = QFrame()
                div.setFrameShape(QFrame.VLine)
                div.setFixedWidth(1)
                div.setStyleSheet(f"background: {C_BORDER}; border: none; margin: 0 16px;")
                grid.addWidget(div)

        card_layout.addLayout(grid)
        self.root.addWidget(card)

    def _build_footer_actions(self):
        self.root.addWidget(self._glow_sep(C_ACCENT_DIM))

        footer = QHBoxLayout()
        footer.setContentsMargins(0, 8, 0, 0)
        footer.setSpacing(16)

        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(
            f"color: {C_GREEN}; font-family: {FONT_MONO}; font-size: {FONT_SIZE_SM}; "
            f"font-weight: 600; background: transparent;"
        )

        self.save_btn = QPushButton("SAVE CONFIGURATION")
        self.save_btn.setStyleSheet(QSS_BTN_SUCCESS)
        self.save_btn.setCursor(Qt.PointingHandCursor)
        self.save_btn.setFixedHeight(36)
        self.save_btn.setFixedWidth(220)

        footer.addWidget(self.status_lbl)
        footer.addStretch()
        footer.addWidget(self.save_btn)
        self.root.addLayout(footer)

    def _card(self, accent: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("SettingsCard")
        card.setStyleSheet(
            f"QFrame#SettingsCard {{"
            f"  background-color: {C_BG_PANEL};"
            f"  border: 1px solid {C_BORDER};"
            f"  border-top: 2px solid {accent};"
            f"  border-radius: 8px;"
            f"}}"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)
        return card, layout

    def _glow_sep(self, color: str) -> QFrame:
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(
            f"background: qlineargradient("
            f"x1:0, y1:0, x2:1, y2:0, "
            f"stop:0 {C_BG_APP}, stop:0.3 {color}, stop:0.7 {color}, stop:1 {C_BG_APP}"
            f");"
        )
        return sep

    def _section_label(self, text: str) -> QLabel:
        lbl = QLabel(text.upper())
        lbl.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
            f"letter-spacing: 1.4px; background: transparent; margin-top: 4px;"
        )
        return lbl

    def _form_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color: {C_TEXT_PRI}; font-size: {FONT_SIZE_MD}; "
            f"font-weight: 500; background: transparent;"
        )
        lbl.setMinimumWidth(200)
        return lbl

    def _connect_signals(self):
        self.theme_sel.currentTextChanged.connect(self._on_theme_changed)
        self.thresh_slider.valueChanged.connect(self._sync_slider_to_spinbox)
        self.thresh_spinbox.valueChanged.connect(self._sync_spinbox_to_slider)
        self.save_btn.clicked.connect(self.on_save_clicked)

    @Slot(str)
    def _on_theme_changed(self, theme_name: str):
        self.current_theme = theme_name.lower()
        if callable(self.theme_callback):
            self.theme_callback(theme_name)

    @Slot(int)
    def _sync_slider_to_spinbox(self, val: int):
        self.thresh_spinbox.blockSignals(True)
        self.thresh_spinbox.setValue(val / 100.0)
        self.thresh_spinbox.blockSignals(False)

    @Slot(float)
    def _sync_spinbox_to_slider(self, val: float):
        self.thresh_slider.blockSignals(True)
        self.thresh_slider.setValue(int(val * 100))
        self.thresh_slider.blockSignals(False)

    @Slot()
    def on_save_clicked(self):
        theme   = self.theme_sel.currentText()
        tau     = self.thresh_spinbox.value()
        refresh = self.refresh_rate.currentText()

        payload = {"theme": theme, "threshold": tau, "refresh_rate": refresh}
        self.settings_saved.emit(payload)

        # Instantly update the active RealTimeMonitor reference in memory[cite: 3]
        if self.main_monitor_page and hasattr(self.main_monitor_page, "set_live_threshold"):
            self.main_monitor_page.set_live_threshold(tau)

        def _notify():
            try:
                requests.post(f"{self.api_url}/api/config", json=payload, timeout=3)
            except Exception as exc:
                logger.warning(f"Backend config sync failed: {exc}")

        threading.Thread(target=_notify, daemon=True).start()
        self.status_lbl.setText("✓  Configuration successfully committed.")

    @Slot(str)
    def update_theme(self, theme_name: str):
        self.current_theme = theme_name.lower()
        idx = self.theme_sel.findText(self.current_theme.capitalize())
        if idx >= 0:
            self.theme_sel.blockSignals(True)
            self.theme_sel.setCurrentIndex(idx)
            self.theme_sel.blockSignals(False)