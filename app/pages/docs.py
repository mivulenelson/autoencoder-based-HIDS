"""
Documentation Page: AUTOENCODER-HIDS Sentinel Console  v2.0

Renders the project documentation natively using pure PySide6 UI widgets,
featuring a side-by-side sidebar navigation layout with precise vertical
scroll positioning.

No QtWebEngine. No external browser. No fallback needed.
Works identically in Docker, locally, and on headless servers.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QGridLayout, QPushButton,
)
from PySide6.QtCore import Qt, QTimer

from theme import (
    C_BG_APP, C_BG_PANEL, C_BG_SURFACE,
    C_BORDER, C_BORDER_LT,
    C_TEXT_PRI, C_TEXT_SEC, C_TEXT_DIM,
    C_ACCENT, C_ACCENT_LT, C_ACCENT_DIM,
    C_VIOLET, C_GREEN, C_AMBER, C_RED,
    FONT_MONO, FONT_UI,
    QSS_BASE,
)


class DocsPage(QWidget):
    """
    Renders full project documentation natively inside the app.

    Scroll fix: every section builder writes into a dedicated container
    QWidget added to self._lay as a real child.  _scroll_to_section maps
    that container's top-left corner into the scroll-area coordinate space,
    giving exact y-positions regardless of content height.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(QSS_BASE)

        self._active_key: str | None = None
        # key -> (container_widget, sidebar_button | None)
        self._section_widgets: dict[str, tuple[QWidget, QPushButton | None]] = {}
        self._pending_sidebar_btns: dict[str, QPushButton] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top bar ──────────────────────────────────────────────────────────
        topbar = QFrame()
        topbar.setFixedHeight(56)
        topbar.setStyleSheet(
            f"background: {C_BG_PANEL}; border-bottom: 1px solid {C_ACCENT_DIM};"
        )
        topbar_lay = QHBoxLayout(topbar)
        topbar_lay.setContentsMargins(28, 0, 28, 0)
        topbar_lay.setSpacing(16)

        brand = QLabel("⬡  AUTOENCODER-HIDS  ·  SENTINEL CONSOLE")
        brand.setStyleSheet(
            f"color: {C_ACCENT}; font-family: {FONT_MONO}; font-size: 15px; "
            f"font-weight: 700; letter-spacing: 0.5px;"
        )
        topbar_lay.addWidget(brand)

        ver = QLabel("v2.0")
        ver.setStyleSheet(
            f"color: {C_ACCENT}; font-family: {FONT_MONO}; font-size: 13px; "
            f"font-weight: 600; background: {C_ACCENT_DIM}; border: 1px solid {C_ACCENT}; "
            f"border-radius: 4px; padding: 2px 7px;"
        )
        topbar_lay.addWidget(ver)
        topbar_lay.addStretch()

        self._top_btns: dict[str, QPushButton] = {}
        top_links_layout = QHBoxLayout()
        top_links_layout.setSpacing(6)
        for text, key in [
            ("Overview",     "overview"),
            ("Architecture", "architecture"),
            ("Pages",        "pages"),
            ("Docker",       "docker"),
            ("Tests",        "tests"),
            ("Quickstart",   "quickstart"),
        ]:
            btn = QPushButton(text)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(self._top_btn_qss(False))
            btn.clicked.connect(lambda checked=False, k=key: self._scroll_to_section(k))
            self._top_btns[key] = btn
            top_links_layout.addWidget(btn)

        topbar_lay.addLayout(top_links_layout)
        root.addWidget(topbar)

        # ── Body ─────────────────────────────────────────────────────────────
        body_widget = QWidget()
        body_widget.setStyleSheet(f"background: {C_BG_APP};")
        body_lay = QHBoxLayout(body_widget)
        body_lay.setContentsMargins(0, 0, 0, 0)
        body_lay.setSpacing(0)

        # ── Sidebar ──────────────────────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet(
            f"background: {C_BG_PANEL}; border-right: 1px solid {C_BORDER};"
        )
        sidebar_scroll = QScrollArea(sidebar)
        sidebar_scroll.setWidgetResizable(True)
        sidebar_scroll.setStyleSheet("background: transparent; border: none;")
        sidebar_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        sidebar_content = QWidget()
        sidebar_content.setStyleSheet("background: transparent;")
        self._sidebar_lay = QVBoxLayout(sidebar_content)
        self._sidebar_lay.setContentsMargins(0, 24, 0, 24)
        self._sidebar_lay.setSpacing(18)

        self._add_sidebar_group("Getting Started", [
            ("Overview",      "overview"),
            ("Quickstart",    "quickstart"),
            ("Prerequisites", "prerequisites"),
        ])
        self._add_sidebar_group("System Design", [
            ("Architecture",      "architecture"),
            ("Autoencoder Model", "model"),
            ("Data Pipeline",     "pipeline"),
        ])
        self._add_sidebar_group("Dashboard", [
            ("Pages",         "pages"),
            ("Design System", "theme"),
        ])
        self._add_sidebar_group("Deployment", [
            ("Docker Setup",     "docker"),
            ("Volumes",          "volumes"),
            ("Environment",      "env"),
            ("Compose Profiles", "profiles"),
        ])
        self._add_sidebar_group("Validation", [
            ("Component Tests",  "tests"),
        ])
        self._add_sidebar_group("Reference", [
            ("Feature Vector", "features"),
            ("API Endpoints",  "api"),
        ])

        self._sidebar_lay.addStretch()
        sidebar_scroll.setWidget(sidebar_content)

        sidebar_lay = QVBoxLayout(sidebar)
        sidebar_lay.setContentsMargins(0, 0, 0, 0)
        sidebar_lay.addWidget(sidebar_scroll)
        body_lay.addWidget(sidebar)

        # ── Main scroll area ─────────────────────────────────────────────────
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet(f"""
            QScrollArea {{ background: {C_BG_APP}; border: none; }}
            QScrollBar:vertical {{
                background: {C_BG_SURFACE}; width: 6px; border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: {C_BORDER_LT}; border-radius: 3px; min-height: 24px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {C_ACCENT}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        """)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self._content = QWidget()
        self._content.setStyleSheet(f"background: {C_BG_APP};")
        self._lay = QVBoxLayout(self._content)
        self._lay.setContentsMargins(56, 48, 56, 72)
        self._lay.setSpacing(0)

        # ── Build sections ───────────────────────────────────────────────────
        self._build_hero()

        for key, builder in [
            ("overview",     self._build_section_01_overview),
            ("architecture", self._build_section_02_architecture),
            ("model",        self._build_section_model),
            ("pipeline",     self._build_section_pipeline),
            ("pages",        self._build_section_03_pages),
            ("theme",        self._build_section_theme),
            ("docker",       self._build_section_04_docker),
            ("volumes",      self._build_section_volumes),
            ("env",          self._build_section_env),
            ("profiles",     self._build_section_profiles),
            ("tests",        self._build_section_tests),
            ("quickstart",   self._build_section_05_quickstart),
            ("prerequisites",self._build_section_prerequisites),
            ("features",     self._build_section_06_features),
            ("api",          self._build_section_api),
        ]:
            self._begin_section(key)
            builder()
            self._end_section()

        self._lay.addStretch()
        self.scroll.setWidget(self._content)
        body_lay.addWidget(self.scroll)
        root.addWidget(body_widget)

        # Wire sidebar button refs now that all sections exist
        self._patch_sidebar_refs()

    # ════════════════════════════════════════════════════════════════════════
    # Section ownership — the core fix
    # ════════════════════════════════════════════════════════════════════════

    def _begin_section(self, key: str):
        """Create a container QWidget and redirect self._lay into it."""
        container = QWidget()
        container.setStyleSheet("background: transparent;")
        container.setObjectName(f"sec_{key}")
        container_lay = QVBoxLayout(container)
        container_lay.setContentsMargins(0, 0, 0, 0)
        container_lay.setSpacing(0)
        self._outer_lay = self._lay
        self._lay.addWidget(container)
        self._lay = container_lay
        self._pending_key = key
        self._pending_container = container

    def _end_section(self):
        """Restore outer layout and register the completed container."""
        self._section_widgets[self._pending_key] = (self._pending_container, None)
        self._lay = self._outer_lay

    def _scroll_to_section(self, key: str):
        """Scroll so the section container's top aligns with the viewport top."""
        if key not in self._section_widgets:
            return
        container, _ = self._section_widgets[key]
        def _do_scroll():
            pos = container.mapTo(self._content, container.rect().topLeft())
            self.scroll.verticalScrollBar().setValue(pos.y())
        QTimer.singleShot(0, _do_scroll)
        self._set_active(key)

    # ════════════════════════════════════════════════════════════════════════
    # Active-state highlighting
    # ════════════════════════════════════════════════════════════════════════

    def _set_active(self, key: str):
        for k, (_, btn) in self._section_widgets.items():
            if btn:
                btn.setStyleSheet(self._sidebar_btn_qss(False))
        for k, btn in self._top_btns.items():
            btn.setStyleSheet(self._top_btn_qss(False))
        _, sidebar_btn = self._section_widgets.get(key, (None, None))
        if sidebar_btn:
            sidebar_btn.setStyleSheet(self._sidebar_btn_qss(True))
        if key in self._top_btns:
            self._top_btns[key].setStyleSheet(self._top_btn_qss(True))
        self._active_key = key

    def _patch_sidebar_refs(self):
        """Attach the sidebar QPushButton references collected during build."""
        for key, btn in self._pending_sidebar_btns.items():
            if key in self._section_widgets:
                container, _ = self._section_widgets[key]
                self._section_widgets[key] = (container, btn)

    # ════════════════════════════════════════════════════════════════════════
    # Nav style helpers
    # ════════════════════════════════════════════════════════════════════════

    def _top_btn_qss(self, active: bool) -> str:
        if active:
            return (
                f"color: {C_ACCENT}; background: {C_ACCENT_DIM}; "
                f"border: 1px solid {C_ACCENT}; border-radius: 14px; "
                f"padding: 5px 14px; font-family: {FONT_UI}; font-size: 14px; font-weight: 600;"
            )
        return (
            f"color: {C_TEXT_SEC}; background: transparent; "
            f"border: 1px solid transparent; border-radius: 14px; "
            f"padding: 5px 14px; font-family: {FONT_UI}; font-size: 14px;"
        )

    def _sidebar_btn_qss(self, active: bool) -> str:
        if active:
            return (
                f"QPushButton {{"
                f"  color: {C_ACCENT}; background: {C_ACCENT_DIM}; border: none; "
                f"  border-left: 3px solid {C_ACCENT}; text-align: left; "
                f"  padding: 8px 20px; font-family: {FONT_UI}; font-size: 14px; font-weight: 600;"
                f"}}"
            )
        return (
            f"QPushButton {{"
            f"  color: {C_TEXT_SEC}; background: transparent; border: none; "
            f"  border-left: 3px solid transparent; text-align: left; "
            f"  padding: 8px 20px; font-family: {FONT_UI}; font-size: 14px;"
            f"}}"
            f"QPushButton:hover {{"
            f"  color: {C_ACCENT}; background: {C_ACCENT_DIM}; "
            f"  border-left: 3px solid {C_ACCENT};"
            f"}}"
        )

    def _add_sidebar_group(self, title: str, links: list):
        group = QWidget()
        group.setStyleSheet("background: transparent;")
        gl = QVBoxLayout(group)
        gl.setContentsMargins(0, 0, 0, 0)
        gl.setSpacing(3)

        lbl = QLabel(title.upper())
        lbl.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-family: {FONT_MONO}; font-size: 11px; "
            f"font-weight: 700; letter-spacing: 1.4px; padding: 0 20px 6px;"
        )
        gl.addWidget(lbl)

        for text, key in links:
            btn = QPushButton(text)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(self._sidebar_btn_qss(False))
            btn.clicked.connect(lambda checked=False, k=key: self._scroll_to_section(k))
            gl.addWidget(btn)
            self._pending_sidebar_btns[key] = btn

        self._sidebar_lay.addWidget(group)

    # ════════════════════════════════════════════════════════════════════════
    # Content helpers (with increased font sizes for enhanced readability)
    # ════════════════════════════════════════════════════════════════════════

    def _div(self, spacing_before: int = 36):
        self._lay.addSpacing(spacing_before)
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFixedHeight(1)
        line.setStyleSheet(f"background: {C_BORDER}; border: none;")
        self._lay.addWidget(line)

    def _eyebrow(self, text: str):
        self._lay.addSpacing(16)
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color: {C_ACCENT}; font-family: {FONT_MONO}; font-size: 12px; "
            f"font-weight: 700; letter-spacing: 1.6px;"
        )
        self._lay.addWidget(lbl)
        self._lay.addSpacing(6)

    def _h2(self, text: str):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color: {C_TEXT_PRI}; font-family: {FONT_UI}; font-size: 24px; "
            f"font-weight: 700; border-bottom: 1px solid {C_BORDER}; padding-bottom: 12px;"
        )
        self._lay.addWidget(lbl)
        self._lay.addSpacing(16)

    def _h3(self, text: str, color: str = None):
        color = color or C_ACCENT_LT
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color: {color}; font-family: {FONT_UI}; font-size: 17px; "
            f"font-weight: 700; margin-top: 20px;"
        )
        self._lay.addWidget(lbl)
        self._lay.addSpacing(8)

    def _para(self, text: str):
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.RichText)
        lbl.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-family: {FONT_UI}; "
            f"font-size: 15px; line-height: 1.8; margin-bottom: 10px;"
        )
        self._lay.addWidget(lbl)

    def _code(self, text: str):
        frame = QFrame()
        frame.setStyleSheet(
            f"background: {C_BG_SURFACE}; border: 1px solid {C_BORDER_LT}; border-radius: 8px;"
        )
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(20, 16, 20, 16)
        lbl = QLabel(text)
        lbl.setWordWrap(False)
        lbl.setTextFormat(Qt.PlainText)
        lbl.setStyleSheet(
            f"color: {C_ACCENT_LT}; font-family: {FONT_MONO}; "
            f"font-size: 13px; background: transparent; line-height: 1.7;"
        )
        fl.addWidget(lbl)
        self._lay.addWidget(frame)
        self._lay.addSpacing(14)

    def _card_grid(self, cards: list, cols: int = 2):
        gw = QWidget()
        gw.setStyleSheet("background: transparent;")
        grid = QGridLayout(gw)
        grid.setSpacing(16)
        grid.setContentsMargins(0, 0, 0, 0)
        for i, (title, color, body) in enumerate(cards):
            card = QFrame()
            card.setStyleSheet(
                f"background: {C_BG_PANEL}; border: 1px solid {C_BORDER}; border-radius: 10px;"
            )
            cl = QVBoxLayout(card)
            cl.setContentsMargins(22, 20, 22, 20)
            cl.setSpacing(10)
            t = QLabel(f"⬡  {title}")
            t.setStyleSheet(
                f"color: {color}; font-family: {FONT_UI}; font-size: 15px; "
                f"font-weight: 700; background: transparent; border: none;"
            )
            cl.addWidget(t)
            b = QLabel(body)
            b.setWordWrap(True)
            b.setStyleSheet(
                f"color: {C_TEXT_SEC}; font-family: {FONT_UI}; font-size: 14px; "
                f"line-height: 1.7; background: transparent; border: none;"
            )
            cl.addWidget(b)
            grid.addWidget(card, i // cols, i % cols)
        self._lay.addWidget(gw)
        self._lay.addSpacing(16)

    def _table(self, headers: list, rows: list):
        t = QFrame()
        t.setStyleSheet(
            f"background: {C_BG_PANEL}; border: 1px solid {C_BORDER}; border-radius: 8px;"
        )
        tl = QVBoxLayout(t)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.setSpacing(0)
        hrow = QFrame()
        hrow.setStyleSheet(
            f"background: {C_BG_SURFACE}; border-bottom: 1px solid {C_ACCENT_DIM};"
        )
        hrl = QHBoxLayout(hrow)
        hrl.setContentsMargins(18, 12, 18, 12)
        hrl.setSpacing(0)
        for i, h in enumerate(headers):
            hl = QLabel(h.upper())
            hl.setStyleSheet(
                f"color: {C_TEXT_SEC}; font-family: {FONT_MONO}; font-size: 12px; "
                f"font-weight: 700; letter-spacing: 1.1px; background: transparent; border: none;"
            )
            hrl.addWidget(hl, 1 if i > 0 else 0)
            if i == 0:
                hl.setFixedWidth(200)
        tl.addWidget(hrow)
        for ri, row in enumerate(rows):
            rframe = QFrame()
            rframe.setStyleSheet(
                f"background: {C_BG_PANEL if ri % 2 == 0 else C_BG_SURFACE}; border: none;"
            )
            rl = QHBoxLayout(rframe)
            rl.setContentsMargins(18, 12, 18, 12)
            rl.setSpacing(0)
            for ci, cell in enumerate(row):
                cl = QLabel(str(cell))
                cl.setWordWrap(True)
                if ci == 0:
                    cl.setStyleSheet(
                        f"color: {C_ACCENT_LT}; font-family: {FONT_MONO}; font-size: 13px; "
                        f"background: transparent; border: none;"
                    )
                    cl.setFixedWidth(200)
                    rl.addWidget(cl)
                else:
                    cl.setStyleSheet(
                        f"color: {C_TEXT_SEC}; font-family: {FONT_UI}; font-size: 14px; "
                        f"background: transparent; border: none;"
                    )
                    rl.addWidget(cl, 1)
            tl.addWidget(rframe)
        self._lay.addWidget(t)
        self._lay.addSpacing(16)

    def _step_list(self, steps: list):
        for i, step in enumerate(steps):
            title, body = step[0], step[1]
            code = step[2] if len(step) > 2 else None
            row = QFrame()
            row.setStyleSheet("background: transparent; border: none;")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            rl.setSpacing(16)
            rl.setAlignment(Qt.AlignTop)
            num = QLabel(str(i + 1))
            num.setFixedSize(28, 28)
            num.setAlignment(Qt.AlignCenter)
            num.setStyleSheet(
                f"color: {C_ACCENT}; background: {C_ACCENT_DIM}; "
                f"border: 1px solid {C_ACCENT}; border-radius: 14px; "
                f"font-family: {FONT_MONO}; font-size: 13px; font-weight: 700;"
            )
            rl.addWidget(num, 0, Qt.AlignTop)
            inner = QWidget()
            inner.setStyleSheet("background: transparent;")
            il = QVBoxLayout(inner)
            il.setContentsMargins(0, 0, 0, 0)
            il.setSpacing(6)
            tl = QLabel(title)
            tl.setStyleSheet(
                f"color: {C_TEXT_PRI}; font-family: {FONT_UI}; font-size: 15px; font-weight: 700;"
            )
            il.addWidget(tl)
            bl = QLabel(body)
            bl.setWordWrap(True)
            bl.setStyleSheet(
                f"color: {C_TEXT_SEC}; font-family: {FONT_UI}; font-size: 14px; line-height: 1.7;"
            )
            il.addWidget(bl)
            if code:
                cf = QFrame()
                cf.setStyleSheet(
                    f"background: {C_BG_SURFACE}; border: 1px solid {C_BORDER_LT}; border-radius: 6px;"
                )
                cfl = QVBoxLayout(cf)
                cfl.setContentsMargins(16, 12, 16, 12)
                cl = QLabel(code)
                cl.setStyleSheet(
                    f"color: {C_ACCENT_LT}; font-family: {FONT_MONO}; "
                    f"font-size: 13px; background: transparent; border: none;"
                )
                cfl.addWidget(cl)
                il.addWidget(cf)
            rl.addWidget(inner, 1)
            self._lay.addWidget(row)
            self._lay.addSpacing(16)

    def _callout(self, icon: str, text: str, color: str):
        frame = QFrame()
        frame.setStyleSheet(
            f"background: {C_BG_PANEL}; border-left: 3px solid {color}; border-radius: 6px;"
        )
        fl = QHBoxLayout(frame)
        fl.setContentsMargins(18, 14, 18, 14)
        fl.setSpacing(14)
        ic = QLabel(icon)
        ic.setStyleSheet(
            f"color: {color}; font-size: 15px; background: transparent; border: none;"
        )
        ic.setFixedWidth(22)
        fl.addWidget(ic, 0, Qt.AlignTop)
        tx = QLabel(text)
        tx.setWordWrap(True)
        tx.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-family: {FONT_UI}; font-size: 14px; "
            f"line-height: 1.7; background: transparent; border: none;"
        )
        fl.addWidget(tx, 1)
        self._lay.addWidget(frame)
        self._lay.addSpacing(14)

    # ════════════════════════════════════════════════════════════════════════
    # Section builders
    # ════════════════════════════════════════════════════════════════════════

    def _build_hero(self):
        hero = QFrame()
        hero.setStyleSheet(
            f"background: {C_BG_PANEL}; border: 1px solid {C_BORDER_LT}; border-radius: 12px;"
        )
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(40, 34, 40, 34)
        hl.setSpacing(14)
        eye = QLabel("Nelson & Jonathan  ·  UTAMU Final Year Project  ·  2026")
        eye.setStyleSheet(
            f"color: {C_ACCENT}; font-family: {FONT_MONO}; font-size: 12px; "
            f"font-weight: 700; letter-spacing: 1.6px; background: transparent; border: none;"
        )
        hl.addWidget(eye)
        title = QLabel("Autoencoder-HIDS  Sentinel Console")
        title.setStyleSheet(
            f"color: {C_TEXT_PRI}; font-family: {FONT_UI}; font-size: 28px; "
            f"font-weight: 800; background: transparent; border: none;"
        )
        hl.addWidget(title)
        desc = QLabel(
            "A host-based network intrusion detection system powered by a symmetric autoencoder. "
            "Captures live packets, extracts 22 behavioral flow features, reconstructs them through "
            "a trained neural network, and flags anomalies when reconstruction error exceeds a "
            "calibrated threshold — all surfaced in a real-time PySide6 dashboard."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(
            f"color: {C_TEXT_SEC}; font-family: {FONT_UI}; font-size: 15px; "
            f"line-height: 1.8; background: transparent; border: none;"
        )
        hl.addWidget(desc)
        chips_frame = QFrame()
        chips_frame.setStyleSheet("background: transparent; border: none;")
        cfl = QHBoxLayout(chips_frame)
        cfl.setContentsMargins(0, 6, 0, 0)
        cfl.setSpacing(10)
        for label, fg, bg in [
            ("Python 3.12",      C_ACCENT,  C_ACCENT_DIM),
            ("PySide6 · Qt6",    C_VIOLET,  "#1E1A3D"),
            ("FastAPI · SQLite", C_ACCENT,  C_ACCENT_DIM),
            ("Keras · TF",       C_GREEN,   "#00331A"),
            ("Docker Compose",   C_AMBER,   "#332200"),
            ("Scapy · psutil",   C_VIOLET,  "#1E1A3D"),
        ]:
            c = QLabel(label)
            c.setStyleSheet(
                f"color: {fg}; background: {bg}; border: 1px solid {fg}; "
                f"border-radius: 12px; padding: 5px 14px; "
                f"font-family: {FONT_MONO}; font-size: 12px; font-weight: 600;"
            )
            cfl.addWidget(c)
        cfl.addStretch()
        hl.addWidget(chips_frame)
        self._lay.addWidget(hero)
        self._lay.addSpacing(36)

    def _build_section_01_overview(self):
        self._eyebrow("01 — OVERVIEW")
        self._h2("What it does")
        self._para(
            "The HIDS Sentinel Console monitors network traffic on a chosen interface, extracts "
            "per-flow behavioral statistics, and runs them through a trained autoencoder to detect "
            "patterns that deviate from a learned baseline of normal activity[cite: 7]. High reconstruction "
            "error signals a potential intrusion."
        )
        self._para(
            "The system is split into two Docker containers: a **FastAPI backend** that handles "
            "live capture, model inference, and database persistence, and a **PySide6 dashboard** "
            "that renders alerts, charts, and forensic detail in real time over a shared SQLite volume[cite: 7]."
        )
        self._card_grid([
            ("Real-Time Detection", C_ACCENT,
             "Live packet capture via Scapy. Flow features extracted per connection. "
             "Autoencoder inference on every captured flow with sub-second latency."),
            ("Forensic Inspection", C_VIOLET,
             "Every alert persists to SQLite with full 22-feature breakdown, destination IP, "
             "protocol, encryption status, and analyst feedback fields."),
            ("Feedback Retraining", C_GREEN,
             "Analysts mark false positives directly in the dashboard. Accumulated flags "
             "feed a retraining pipeline that recalibrates the threshold automatically."),
            ("Compliance Reports", C_AMBER,
             "One-click generation of structured forensic reports covering threat summary, "
             "per-incident breakdown, and top anomalous flows — exportable as plain text."),
        ])
        self._lay.addSpacing(28)

    def _build_section_02_architecture(self):
        self._div()
        self._eyebrow("02 — SYSTEM DESIGN")
        self._h2("Architecture & Directory Structure")
        self._para(
            "A clean, modular two-container architecture sharing data over Docker named volumes. "
            "The backend runs with `NET_RAW` and `NET_ADMIN` capabilities for "
            "raw socket capture, while the dashboard mounts the host X11 socket for GUI rendering[cite: 7]. "
            "Below is the project's source code layout:"
        )
        self._code(
         "autoencoder-hids/\n"
            "├── .github/workflows/          # CI/CD pipelines[cite: 8]\n"
            "│   ├── ci.yml                  # Build and test workflow[cite: 8]\n"
            "│   └── lint.yml                # Code formatting and linting check[cite: 8]\n"
            "├── api/                        # FastAPI Backend & REST Endpoints[cite: 8]\n"
            "│   ├── routes/                 # Endpoint routers[cite: 8]\n"
            "│   │   ├── alerts.py           # Anomaly alert query endpoints[cite: 8]\n"
            "│   │   └── detection.py        # Live detection stream endpoints[cite: 8]\n"
            "│   ├── dependencies.py         # Shared FastAPI route dependencies[cite: 8]\n"
            "│   └── main.py                 # FastAPI application entrypoint & server setup[cite: 8]\n"
            "├── configs/                    # Application configuration files[cite: 9]\n"
            "│   └── threshold.yaml          # Anomaly threshold definitions[cite: 9]\n"
            "├── data/                       # Dataset samples and temporary features[cite: 9]\n"
            "│   ├── processed_test_data.csv # Preprocessed test data for validation[cite: 9]\n"
            "│   └── temp_benign_features.csv# Temporary benign feature logs[cite: 9]\n"
            "├── docker/                     # Deployment configuration[cite: 10]\n"
            "│   ├── docker-compose.yml      # Multi-container orchestration & volumes[cite: 10]\n"
            "│   ├── Dockerfile.backend      # Python 3.12 image for FastAPI backend[cite: 10]\n"
            "│   └── Dockerfile.dashboard    # PySide6 GUI container image configuration[cite: 10]\n"
            "├── docs/                       # Project documentation[cite: 10]\n"
            "│   └── hids_docs.html          # Compiled system documentation HTML[cite: 10]\n"
            "├── experiments/                # Research notebooks, datasets, and figures[cite: 11]\n"
            "│   ├── datasets/               # Training datasets (CIC-IDS2017, VPN, nonVPN)[cite: 11]\n"
            "│   ├── figures/                # EDA and model training visualization figures[cite: 11]\n"
            "│   ├── notebooks/              # Jupyter notebooks for model prototyping[cite: 11]\n"
            "│   └── threshold_tuning.py     # Script for tuning detection thresholds[cite: 11]\n"
            "├── logs/                       # Application execution and API logs[cite: 11, 12]\n"
            "│   └── hids_api.log            # Backend service log output[cite: 12]\n"
            "├── models/                     # Trained weights & preprocessing artifacts[cite: 12]\n"
            "│   ├── baseline_ae.keras       # Trained Keras autoencoder weights (v1.0.4)[cite: 12]\n"
            "│   └── scaler.pkl              # Fitted StandardScaler for feature normalization[cite: 12]\n"
            "├── presentation_slides/        # Project slide deck materials[cite: 12]\n"
            "├── src/                        # Main source code (Backend logic & PySide6 UI)[cite: 12, 13, 14]\n"
            "│   ├── database/               # SQLite database session & CRUD operations[cite: 12]\n"
            "│   │   ├── connection.py       # SQLAlchemy database engine connection[cite: 12]\n"
            "│   │   ├── crud.py             # Database helper queries for alerts[cite: 12]\n"
            "│   │   └── models.py           # SQLAlchemy ORM table definitions[cite: 12]\n"
            "│   ├── detection/              # Autoencoder neural net & inference engine[cite: 12, 13]\n"
            "│   │   ├── layers/             # Custom neural network layers[cite: 12]\n"
            "│   │   │   └── dense_block.py  # Custom dense block architecture[cite: 12]\n"
            "│   │   ├── evaluator.py        # Reconstruction error calculator[cite: 13]\n"
            "│   │   └── model.py            # Keras autoencoder network architecture[cite: 13]\n"
            "│   ├── ingestion/              # Scapy packet capture & feature parsing[cite: 13]\n"
            "│   │   ├── parser.py           # Packet parser and feature extractor[cite: 13]\n"
            "│   │   └── sniffer.py          # Raw socket network packet capture loop[cite: 13]\n"
            "│   ├── pages/                  # PySide6 dashboard views & UI pages[cite: 9]\n"
            "│   │   ├── alert_history.py    # Historical alert viewer view[cite: 9]\n"
            "│   │   ├── analysis.py         # Traffic analysis charts and deep-dive view[cite: 9]\n"
            "│   │   ├── docs.py             # In-app documentation viewer[cite: 9]\n"
            "│   │   ├── ingestion.py        # Live feature ingestion and stream view[cite: 9]\n"
            "│   │   ├── realtime_monitor.py # Real-time system monitoring view[cite: 9]\n"
            "│   │   ├── reports.py          # Forensic reporting view[cite: 9]\n"
            "│   │   └── settings.py         # Configuration settings page[cite: 9]\n"
            "│   ├── services/               # Background integration services[cite: 14]\n"
            "│   │   ├── feedback_loop.py    # Model feedback and retraining loop service[cite: 14]\n"
            "│   │   └── monitor_service.py  # System health and background monitoring service[cite: 14]\n"
            "│   ├── dashboard.py            # Main PySide6 application window container[cite: 9]\n"
            "│   └── theme.py                # Design system tokens & global QSS stylesheet[cite: 9]\n"
            "├── tests/                      # Component and integration test suites[cite: 14]\n"
            "│   ├── test_api.py             # Validates FastAPI endpoints & SQLite persistence[cite: 14]\n"
            "│   ├── test_hids.py            # Core system integration test suite[cite: 14]\n"
            "│   ├── test_hids_ui.py         # Validates PySide6 UI component rendering[cite: 14]\n"
            "│   ├── test_master_hids.py     # Master end-to-end HIDS test suite[cite: 14]\n"
            "│   └── test_master_hids_2.py   # Extended master system test suite[cite: 14]\n"
            "├── .gitignore                  # Git exclusion rules[cite: 11]\n"
            "├── evaluate_model.py           # Model performance evaluation script[cite: 14]\n"
            "├── README.md                   # Project description and setup instructions[cite: 14]\n"
            "└── requirements.txt            # Python dependencies specification[cite: 14]"
        )
        self._lay.addSpacing(20)

    def _build_section_model(self):
        self._h3("Autoencoder Model")
        self._para(
            "A symmetric feed-forward autoencoder trained on benign traffic. Anomalies produce "
            "higher mean-squared reconstruction error (MSE). The detection threshold τ is derived "
            "from the training MSE distribution[cite: 7]."
        )
        self._code(
            "Architecture:  22 → 16 → 8 → 4 → 8 → 16 → 22\n\n"
            "Input  (22)  →  Dense(16, relu)  →  Dense(8, relu)  →  Dense(4, relu)\n"
            "                                                              ↓  bottleneck\n"
            "Output (22)  ←  Dense(16, relu)  ←  Dense(8, relu)  ←  Dense(4, relu)\n\n"
            "Threshold τ :  MSE_baseline + k·σ   (stored in configs/threshold.yaml)\n"
            "Scaler      :  StandardScaler        (stored in models/scaler.pkl)\n"
            "Weights     :  models/baseline_ae.keras  v1.0.4"
        )
        self._lay.addSpacing(20)

    def _build_section_pipeline(self):
        self._h3("Data Pipeline")
        self._step_list([
            ("Packet Capture",
             "Scapy sniffs raw packets on the selected network interface with NET_RAW. "
             "Flows are grouped by 5-tuple: src_ip, dst_ip, src_port, dst_port, protocol."),
            ("Feature Extraction",
             "22 behavioral statistics are computed per flow — inter-arrival timing, "
             "packet length distribution, byte rates, burstiness, TTL diversity, and protocol flags."),
            ("Normalisation",
             "Features are scaled using the saved scaler.pkl (fitted on training data) "
             "before inference to match the training distribution."),
            ("Autoencoder Inference",
             "The 22-dimensional vector passes through encoder → bottleneck → decoder. "
             "MSE between input and reconstruction is the anomaly score."),
            ("Alert Routing",
             "If MSE > τ, a new alert is written to SQLite and emitted as a Qt signal. "
             "The Sentinel Console updates in real time — no polling needed."),
        ])
        self._lay.addSpacing(28)

    def _build_section_03_pages(self):
        self._div()
        self._eyebrow("03 — DASHBOARD")
        self._h2("Application pages")
        self._para(
            "The dashboard is a QMainWindow with a QStackedWidget and a persistent navigation bar[cite: 7]. "
            "Six pages are available; the Console Grid is the default view on startup."
        )
        self._card_grid([
            ("Console Grid  [IDX 0]", C_ACCENT,
             "Split-panel: real-time alert feed (55%) and alert history (45%). "
             "Live signal chart plots reconstruction error over time."),
            ("Packet Ingestion  [IDX 1]", C_VIOLET,
             "Network interface selector, live system telemetry (CPU, memory, byte rates), "
             "and a 22-bar animated feature strip — colour-coded by feature group."),
            ("Model Analysis  [IDX 2]", C_VIOLET,
             "KPI cards: accuracy, false-positive count, threshold value. Per-feature "
             "reconstruction error chart. Retraining pipeline via POST /system/retrain."),
            ("Alert History  [IDX 3]", C_ACCENT,
             "Filterable alert table with verdict badges. Click any row to expand full "
             "forensic panel: 22-feature breakdown, reconstruction score, analyst feedback form."),
            ("Forensic Reports  [IDX 4]", C_AMBER,
             "Generates structured plain-text compliance report with per-incident breakdown, "
             "TP/FP ratios, and top-10 anomalous flows. Exportable via QFileDialog."),
            ("Settings  [IDX 5]", C_ACCENT_LT,
             "Theme selector, interface dropdown, detection threshold slider with live readout, "
             "runtime environment info panel."),
        ])
        self._lay.addSpacing(20)

    def _build_section_theme(self):
        self._h3("Design System — theme.py tokens")
        self._table(
            ["Token", "Value", "Role"],
            [
                ["C_BG_APP",     "#0A0E1A",           "Deepest background — window root"],
                ["C_BG_PANEL",   "#0F1526",           "Card and panel surfaces"],
                ["C_BG_SURFACE", "#161D30",           "Inner surfaces, chip backgrounds"],
                ["C_ACCENT",     "#00D4FF",           "Primary electric cyan — nav, borders, links"],
                ["C_VIOLET",     "#7B61FF",           "Secondary accent — analysis / ingestion pages"],
                ["C_GREEN",      "#00FF88",           "Success / NORMAL verdict indicators"],
                ["C_AMBER",      "#FFB020",           "Warning / reports page accent"],
                ["C_RED",        "#FF3366",           "Threat / ANOMALY verdict indicators"],
                ["FONT_MONO",    "JetBrains Mono",    "All data, metrics, feature values"],
                ["FONT_UI",      "Inter / system-ui", "Labels, descriptions, prose"],
            ]
        )
        self._lay.addSpacing(28)

    def _build_section_04_docker(self):
        self._div()
        self._eyebrow("04 — DEPLOYMENT")
        self._h2("Docker setup")
        self._para(
            "The project ships two Dockerfiles and a Compose file, both built from python:3.12-slim[cite: 7]. "
            "Runtime Python dependencies are loaded from the host virtualenv via a bind-mount "
            "(HOST_SITE_PACKAGES) rather than being re-installed in the image."
        )
        self._callout("⚠", (
            "Root required. Both containers run as root for Scapy raw socket access. "
            "The cap_add: [NET_RAW, NET_ADMIN] entries are mandatory[cite: 7]."
        ), C_AMBER)
        self._lay.addSpacing(20)

    def _build_section_volumes(self):
        self._h3("Named volumes")
        self._table(
            ["Volume", "Mount path", "Purpose"],
            [
                ["hids_models",  "/app/models/",  "Keras weights, scaler pickle, optional threshold.yaml"],
                ["hids_db",      "/app/db/",       "SQLite database (hids_forensics.db) — shared read-write"],
                ["hids_configs", "/app/configs/",  "threshold.yaml with calibrated τ value"],
                ["hids_logs",    "/app/logs/",     "Backend service logs (backend container only)"],
            ]
        )
        self._lay.addSpacing(20)

    def _build_section_env(self):
        self._h3("Environment variables")
        self._table(
            ["Variable", "Default / Notes"],
            [
                ["DATABASE_URL",          "sqlite:////app/db/hids_forensics.db"],
                ["HIDS_MODEL_PATH",       "/app/models/baseline_ae.keras"],
                ["HIDS_SCALER_PATH",      "/app/models/scaler.pkl"],
                ["HIDS_THRESHOLD_CONFIG", "/app/configs/threshold.yaml"],
                ["API_PORT",              "9000"],
                ["LOG_LEVEL",             "INFO  (DEBUG in dev profile)"],
                ["HOST_SITE_PACKAGES",    "Required — set in docker/.env"],
            ]
        )
        self._lay.addSpacing(20)

    def _build_section_profiles(self):
        self._h3("Compose profiles")
        self._table(
            ["Profile", "Services started", "Use when"],
            [
                ["gui",     "backend + dashboard",         "Normal operation on a workstation with a display"],
                ["backend", "backend only",                "Headless / API-only deployment"],
                ["dev",     "backend_dev + dashboard_dev", "Local dev — live source mounts, faster healthcheck"],
            ]
        )
        self._callout("ℹ", (
            "X11 forwarding: the dashboard container requires DISPLAY set to a reachable X server "
            "and /tmp/.X11-unix mounted. run.sh calls xhost +local:docker automatically[cite: 7]. "
            "On headless servers use:  Xvfb :99 &  export DISPLAY=:99"
        ), C_ACCENT)
        self._lay.addSpacing(28)

    def _build_section_tests(self):
        self._div()
        self._eyebrow("TESTING & VALIDATION")
        self._h2("Component-Specific Test Suites")
        self._para(
            "To maintain modularity and target specific pipeline layers independently, the system "
            "uses isolated test files for each component rather than a single monolithic runner."
        )
        self._table(
            ["Test Module / File", "Target Component", "Execution Command"],
            [
                ["tests/test_features.py", "22-Dimensional Feature Extraction", "PYTHONPATH=.:app:src pytest tests/test_features.py -v"],
                ["tests/test_model.py", "Autoencoder Inference & Thresholding", "PYTHONPATH=.:app:src pytest tests/test_model.py -v"],
                ["tests/test_api.py", "FastAPI Endpoints & SQLite CRUD", "PYTHONPATH=.:app:src pytest tests/test_api.py -v"],
                ["tests/test_dashboard.py", "PySide6 UI Widgets & Poller Thread", "PYTHONPATH=.:app:src pytest tests/test_dashboard.py -v"],
            ]
        )
        self._callout("✓", (
            "Container testing: To run specific tests inside the Docker development container, "
            "execute: docker compose --profile dev exec backend_dev pytest tests/test_model.py -v"
        ), C_GREEN)
        self._lay.addSpacing(28)

    def _build_section_05_quickstart(self):
        self._div()
        self._eyebrow("05 — QUICKSTART")
        self._h2("Getting started")
        self._step_list([
            ("Create and activate the virtualenv", "",
             "python3.12 -m venv env\nsource env/bin/activate\npip install -r requirements.txt"),
            ("Set HOST_SITE_PACKAGES in docker/.env",
             "Find your venv site-packages path and paste it into docker/.env.",
             "python3 -c \"import site; print(site.getsitepackages()[0])\"\n"
             "# then in docker/.env:\nHOST_SITE_PACKAGES=/path/to/env/lib/python3.12/site-packages"),
            ("Place trained model files",
             "Both files must exist before run.sh can generate threshold.yaml.",
             "models/\n├── baseline_ae.keras\n└── scaler.pkl"),
            ("Launch with run.sh",
             "The script activates venv, generates threshold.yaml, loads model files into "
             "Docker volumes, runs xhost +local:docker, and starts the gui profile.",
             "chmod +x docker/run.sh\n./docker/run.sh"),
            ("Backend only (headless)", "",
             "cd docker && docker compose --env-file .env --profile backend up --build"),
            ("Development mode",
             "Both containers mount the project root at /app — edits to src/ or app/ are live.",
             "cd docker && docker compose --env-file .env --profile dev up --build"),
        ])
        self._callout("✓", (
            "Healthcheck: the dashboard container will not start until the backend responds 200 "
            "on GET /ready. On first run this can take up to 30 s while the model loads."
        ), C_GREEN)
        self._lay.addSpacing(20)

    def _build_section_prerequisites(self):
        self._h3("Prerequisites")
        self._table(
            ["Requirement", "Detail"],
            [
                ["OS",          "Linux (Ubuntu 22.04+) with X11 display for the dashboard"],
                ["Docker",      "20.10+ with Compose v2 plugin  (docker compose, not docker-compose)"],
                ["Python",      "3.12 — for venv and generate_threshold.py"],
                ["Model files", "models/baseline_ae.keras and models/scaler.pkl must exist before first launch"],
            ]
        )
        self._lay.addSpacing(28)

    def _build_section_06_features(self):
        self._div()
        self._eyebrow("06 — REFERENCE")
        self._h2("Feature vector — 22 dimensions")
        self._para(
            "Features are extracted per TCP/UDP flow and grouped into six semantic categories. "
            "The same 22-element order is used throughout: model input/output, the forensic inspector, "
            "the feature strip, and the per-feature error chart[cite: 7]."
        )
        self._table(
            ["#  Feature", "Group", "Description"],
            [
                ["0   flow_duration",     "Timing",     "Total duration of the flow in seconds"],
                ["1   fwd_iat_mean",      "Timing",     "Mean inter-arrival time of forward packets"],
                ["2   fwd_iat_std",       "Timing",     "Standard deviation of inter-arrival times"],
                ["3   fwd_iat_min",       "Timing",     "Minimum inter-arrival time"],
                ["4   fwd_iat_max",       "Timing",     "Maximum inter-arrival time"],
                ["5   fwd_iat_total",     "Timing",     "Sum of all inter-arrival times"],
                ["6   fwd_pkt_len_mean",  "Volume",     "Mean forward packet length in bytes"],
                ["7   fwd_pkt_len_std",   "Volume",     "Std deviation of forward packet lengths"],
                ["8   fwd_pkt_len_min",   "Volume",     "Minimum packet length in the flow"],
                ["9   fwd_pkt_len_max",   "Volume",     "Maximum packet length in the flow"],
                ["10  total_fwd_bytes",   "Volume",     "Total bytes transferred in forward direction"],
                ["11  flow_pkts_per_sec", "Rate",       "Packets per second over flow duration"],
                ["12  flow_bytes_per_sec","Rate",       "Bytes per second over flow duration"],
                ["13  pkt_len_variance",  "Burstiness", "Variance in packet lengths"],
                ["14  burst_ratio",       "Burstiness", "Proportion of time the flow was in burst mode"],
                ["15  active_time_ratio", "Burstiness", "Fraction of flow duration with active traffic"],
                ["16  pkt_count",         "Session",    "Total packet count for the flow"],
                ["17  unique_ttl_count",  "Session",    "Number of distinct TTL values observed"],
                ["18  ttl_mean",          "Session",    "Mean TTL across all packets in the flow"],
                ["19  tcp_flag_ratio",    "Protocol",   "Ratio of control flag packets (SYN/FIN/RST)"],
                ["20  has_udp",           "Protocol",   "Binary — 1 if flow contains UDP packets"],
                ["21  has_tcp",           "Protocol",   "Binary — 1 if flow contains TCP packets"],
            ]
        )
        self._lay.addSpacing(20)

    def _build_section_api(self):
        self._h3("API endpoints  (backend port 9000)")
        self._table(
            ["Method  Path", "Description"],
            [
                ["GET     /ready",           "Health probe — 200 when model loaded and DB accessible"],
                ["POST    /capture/start",    "Begin packet capture on selected interface"],
                ["POST    /capture/stop",     "Stop capture and flush current flow buffer"],
                ["GET     /alerts",           "Paginated list of stored alerts from the database"],
                ["POST    /system/retrain",   "Trigger retraining on analyst-flagged false positives"],
                ["GET     /system/threshold", "Return current detection threshold τ"],
            ]
        )
        self._lay.addSpacing(28)