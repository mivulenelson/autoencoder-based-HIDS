# theme.py  --  HIDS Sentinel Console  |  Visual Identity v2.0
"""
Design system for the Autoencoder-HIDS Sentinel Console.

Palette: Deep navy base (#0A0E1A), electric cyan primary accent (#00D4FF),
         electric violet secondary (#7B61FF), threat red (#FF3366),
         success green (#00FF88), amber warning (#FFB020).

Typography: JetBrains Mono / cross-platform monospace for all data/code;
            System sans-serif for clean UI prose.
"""

# ── Base Surfaces ─────────────────────────────────────────────────────────────
C_BG_APP       = "#0A0E1A"   # Deepest background canvas
C_BG_PANEL     = "#0F1526"   # Primary card / panel surface
C_BG_SURFACE   = "#161D30"   # Inner surface / input / chip background
C_BG_HOVER     = "#1C2540"   # Active hover state / highlighted row

# ── Borders & Dividers ────────────────────────────────────────────────────────
C_BORDER       = "#1E2D4A"   # Standard structural border
C_BORDER_LT    = "#263552"   # Lighter subtle divider

# ── Text Palette ──────────────────────────────────────────────────────────────
C_TEXT_PRI     = "#E8EAF0"   # Primary body text
C_TEXT_SEC     = "#8B9CC8"   # Secondary / label text
C_TEXT_DIM     = "#4A5578"   # Dimmed labels / placeholders / disables

# ── Accent — Electric Cyan ────────────────────────────────────────────────────
C_ACCENT       = "#00D4FF"   # Primary cyan accent
C_ACCENT_LT    = "#66E8FF"   # Lighter cyan for values & highlight text
C_ACCENT_DIM   = "#003D4D"   # Low-contrast cyan tint for panel highlights

# ── Accent — Electric Violet ──────────────────────────────────────────────────
C_VIOLET       = "#7B61FF"   # Secondary visual highlight
C_VIOLET_DIM   = "#1E1A3D"   # Low-contrast violet background tint

# ── Semantic Alerts & Status ──────────────────────────────────────────────────
C_GREEN        = "#00FF88"   # Operational / Healthy
C_GREEN_DIM    = "#00331A"
C_AMBER        = "#FFB020"   # Warning / Threshold Warning
C_AMBER_DIM    = "#332200"
C_RED          = "#FF3366"   # Anomaly / Threat Alert
C_RED_DIM      = "#200010"

# ── Typography Stacks ─────────────────────────────────────────────────────────
FONT_MONO = "'JetBrains Mono', 'Fira Code', 'Hack', 'Cascadia Code', 'Consolas', monospace"
FONT_UI   = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"

# ── Standard Font Scale ───────────────────────────────────────────────────────
FONT_SIZE_XS   = "10px"
FONT_SIZE_SM   = "11px"
FONT_SIZE_MD   = "13px"
FONT_SIZE_LG   = "15px"
FONT_SIZE_XL   = "18px"
FONT_SIZE_2X   = "24px"

# ── Global Application QSS ────────────────────────────────────────────────────
QSS_BASE = f"""
    QWidget {{
        background-color: {C_BG_APP};
        color: {C_TEXT_PRI};
        font-family: {FONT_UI};
    }}
    QToolBar {{
        background-color: {C_BG_PANEL};
        border-bottom: 2px solid {C_BORDER};
        padding: 4px 12px;
        spacing: 6px;
    }}
    QToolBar QWidget {{
        background-color: transparent;
    }}
    QScrollBar:vertical {{
        background: {C_BG_SURFACE};
        width: 6px;
        border-radius: 3px;
        border: none;
        margin: 0px;
    }}
    QScrollBar::handle:vertical {{
        background: {C_BORDER_LT};
        border-radius: 3px;
        min-height: 20px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {C_ACCENT};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
        background: none;
    }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: none;
    }}
    QScrollBar:horizontal {{
        background: {C_BG_SURFACE};
        height: 6px;
        border-radius: 3px;
        border: none;
        margin: 0px;
    }}
    QScrollBar::handle:horizontal {{
        background: {C_BORDER_LT};
        border-radius: 3px;
        min-width: 20px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {C_ACCENT};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0px;
        background: none;
    }}
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
        background: none;
    }}
    QToolTip {{
        background-color: {C_BG_SURFACE};
        color: {C_TEXT_PRI};
        border: 1px solid {C_ACCENT};
        border-radius: 4px;
        padding: 5px 9px;
        font-size: {FONT_SIZE_XS};
        font-family: {FONT_MONO};
    }}
"""

# ── Table & Data Grid Styling ────────────────────────────────────────────────
QSS_TABLE = f"""
    QTableWidget, QTableView {{
        background-color: {C_BG_PANEL};
        alternate-background-color: {C_BG_SURFACE};
        gridline-color: {C_BORDER};
        border: 1px solid {C_BORDER};
        border-radius: 8px;
        selection-background-color: {C_ACCENT_DIM};
        selection-color: {C_ACCENT_LT};
        outline: none;
    }}
    QHeaderView::section {{
        background-color: {C_BG_SURFACE};
        color: {C_TEXT_SEC};
        font-size: 9px;
        font-weight: 700;
        letter-spacing: 1.0px;
        padding: 6px 10px;
        border: none;
        border-bottom: 1px solid {C_ACCENT_DIM};
        border-right: 1px solid {C_BORDER};
        text-transform: uppercase;
    }}
    QTableWidget::item, QTableView::item {{
        padding: 4px 8px;
        border-bottom: 1px solid {C_BORDER};
    }}
    QTableWidget::item:selected, QTableView::item:selected {{
        background-color: {C_ACCENT_DIM};
        color: {C_ACCENT_LT};
    }}
    QTableCornerButton::section {{
        background-color: {C_BG_SURFACE};
        border: none;
        border-bottom: 1px solid {C_ACCENT_DIM};
        border-right: 1px solid {C_BORDER};
    }}
"""

# ── Form Inputs, Controls & Code Editors ──────────────────────────────────────
QSS_INPUT = f"""
    QComboBox {{
        background-color: {C_BG_SURFACE};
        border: 1px solid {C_BORDER};
        border-radius: 6px;
        padding: 5px 10px;
        color: {C_TEXT_PRI};
        font-size: {FONT_SIZE_MD};
        min-height: 28px;
    }}
    QComboBox:hover {{
        border: 1px solid {C_ACCENT};
    }}
    QComboBox:focus {{
        border: 1px solid {C_ACCENT};
        outline: none;
    }}
    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}
    QComboBox::down-arrow {{
        image: none;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 5px solid {C_TEXT_SEC};
        margin-right: 8px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {C_BG_SURFACE};
        border: 1px solid {C_ACCENT};
        border-radius: 4px;
        selection-background-color: {C_ACCENT_DIM};
        selection-color: {C_ACCENT_LT};
        color: {C_TEXT_PRI};
        outline: none;
        padding: 4px;
    }}
    QLineEdit, QTextEdit, QPlainTextEdit {{
        background-color: {C_BG_SURFACE};
        border: 1px solid {C_BORDER};
        border-radius: 6px;
        padding: 8px;
        color: {C_TEXT_PRI};
        font-size: {FONT_SIZE_MD};
        selection-background-color: {C_ACCENT_DIM};
        selection-color: {C_ACCENT_LT};
    }}
    QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover {{
        border: 1px solid {C_BORDER_LT};
    }}
    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border: 1px solid {C_ACCENT};
        outline: none;
    }}
    QRadioButton {{
        color: {C_TEXT_PRI};
        font-size: {FONT_SIZE_MD};
        font-weight: 500;
        spacing: 8px;
        background: transparent;
    }}
    QRadioButton::indicator {{
        width: 14px;
        height: 14px;
        border-radius: 8px;
        border: 1px solid {C_BORDER_LT};
        background: {C_BG_SURFACE};
    }}
    QRadioButton::indicator:hover {{
        border: 1px solid {C_ACCENT};
    }}
    QRadioButton::indicator:checked {{
        border: 2px solid {C_ACCENT};
        background: {C_ACCENT};
    }}
"""

# ── Action Buttons ────────────────────────────────────────────────────────────
QSS_BTN_PRIMARY = f"""
    QPushButton {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {C_ACCENT}, stop:1 {C_VIOLET});
        color: #000000;
        border: none;
        border-radius: 6px;
        padding: 8px 20px;
        font-size: {FONT_SIZE_SM};
        font-weight: 700;
        letter-spacing: 0.8px;
        min-height: 32px;
    }}
    QPushButton:hover {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {C_ACCENT_LT}, stop:1 #9580FF);
    }}
    QPushButton:pressed {{
        background: {C_ACCENT_DIM};
        color: {C_ACCENT};
    }}
    QPushButton:disabled {{
        background: {C_BG_SURFACE};
        color: {C_TEXT_DIM};
        border: 1px solid {C_BORDER};
    }}
"""

QSS_BTN_SUCCESS = f"""
    QPushButton {{
        background: transparent;
        color: {C_GREEN};
        border: 1px solid {C_GREEN};
        border-radius: 6px;
        padding: 8px 20px;
        font-size: {FONT_SIZE_SM};
        font-weight: 700;
        letter-spacing: 0.8px;
        min-height: 32px;
    }}
    QPushButton:hover {{
        background: {C_GREEN_DIM};
        border: 1px solid {C_GREEN};
        color: {C_GREEN};
    }}
    QPushButton:pressed {{
        background: {C_GREEN_DIM};
        color: #FFFFFF;
    }}
    QPushButton:disabled {{
        background: transparent;
        color: {C_TEXT_DIM};
        border: 1px solid {C_BORDER};
    }}
"""

QSS_BTN_GHOST = f"""
    QPushButton {{
        background: transparent;
        color: {C_TEXT_SEC};
        border: 1px solid {C_BORDER};
        border-radius: 6px;
        padding: 6px 14px;
        font-size: {FONT_SIZE_SM};
        font-weight: 600;
        letter-spacing: 0.5px;
        min-height: 28px;
    }}
    QPushButton:hover {{
        color: {C_ACCENT};
        border: 1px solid {C_ACCENT};
        background: {C_BG_SURFACE};
    }}
    QPushButton:pressed {{
        background: {C_ACCENT_DIM};
        color: {C_ACCENT_LT};
    }}
    QPushButton:disabled {{
        color: {C_TEXT_DIM};
        border: 1px solid {C_BORDER};
    }}
"""