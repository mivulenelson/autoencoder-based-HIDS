# app/components/metrics.py
"""
SOC Metric Card Components — HIDS Sentinel v2.0
Enterprise network metrics, custom toggle controls, feature vector badges,
and model validation visualization cards.
"""

from typing import Optional

from PySide6.QtCore import Qt, Signal, Property, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QCheckBox, QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget
)

from theme import (
    C_ACCENT, C_ACCENT_DIM, C_ACCENT_LT, C_AMBER, C_AMBER_DIM,
    C_BG_APP, C_BG_PANEL, C_BG_SURFACE, C_BORDER, C_BORDER_LT,
    C_GREEN, C_GREEN_DIM, C_RED, C_RED_DIM, C_TEXT_DIM, C_TEXT_PRI,
    C_TEXT_SEC, C_VIOLET, C_VIOLET_DIM, FONT_MONO, FONT_SIZE_2X,
    FONT_SIZE_LG, FONT_SIZE_MD, FONT_SIZE_SM, FONT_SIZE_XL, FONT_SIZE_XS,
    FONT_UI,
)


class MetricCard(QFrame):
    """
    High-density KPI metric card featuring top-accent color coding,
    eyebrow titles, distinct unit chips, and primary value readouts.
    """

    def __init__(
        self,
        title: str,
        value: str = "—",
        color: str = C_ACCENT,
        subtitle: str = "",
        unit: str = "",
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self._accent_color = color
        self.setMinimumWidth(160)
        self._apply_style(color)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(4)

        # ── Header Row ──
        hdr = QHBoxLayout()
        hdr.setContentsMargins(0, 0, 0, 0)
        hdr.setSpacing(6)

        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; "
            f"font-weight: 700; letter-spacing: 1.0px; background: transparent;"
        )
        hdr.addWidget(self.title_label)
        hdr.addStretch()

        if unit:
            self.unit_label = QLabel(unit)
            self.unit_label.setStyleSheet(
                f"color: {color}; font-size: {FONT_SIZE_XS}; "
                f"font-family: {FONT_MONO}; font-weight: 700; "
                f"background: {C_BG_SURFACE}; "
                f"border: 1px solid {C_BORDER}; border-radius: 4px; "
                f"padding: 1px 6px;"
            )
            hdr.addWidget(self.unit_label)
        root.addLayout(hdr)

        # ── Value Display ──
        self.value_label = QLabel(str(value))
        self.value_label.setStyleSheet(
            f"color: {color}; font-size: {FONT_SIZE_2X}; font-weight: 700; "
            f"font-family: {FONT_MONO}; background: transparent;"
        )
        root.addWidget(self.value_label)

        # ── Subtitle Line ──
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: {FONT_SIZE_XS}; background: transparent;"
        )
        root.addWidget(self.subtitle_label)

    def _apply_style(self, color: str) -> None:
        self._accent_color = color
        self.setStyleSheet(
            f"QFrame#MetricCard {{"
            f"    background-color: {C_BG_PANEL};"
            f"    border: 1px solid {C_BORDER};"
            f"    border-top: 2px solid {color};"
            f"    border-radius: 8px;"
            f"}}"
        )

    def set_value(self, val: str, color: Optional[str] = None) -> None:
        self.value_label.setText(val)
        target_color = color or self._accent_color
        self.value_label.setStyleSheet(
            f"color: {target_color}; font-size: {FONT_SIZE_2X}; font-weight: 700; "
            f"font-family: {FONT_MONO}; background: transparent;"
        )
        if color:
            self._apply_style(color)

    def set_subtitle(self, text: str, color: str = C_TEXT_DIM) -> None:
        self.subtitle_label.setText(text)
        self.subtitle_label.setStyleSheet(
            f"color: {color}; font-size: {FONT_SIZE_XS}; background: transparent;"
        )


class HIDStatusCard(MetricCard):
    """
    Engine control KPI card featuring live status indicators and
    a custom capture toggle switch.
    """
    status_changed = Signal(bool)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(
            title="HIDS Engine",
            value="ACTIVE",
            color=C_GREEN,
            subtitle="Detection active",
            parent=parent,
        )

        self.switch = QCheckBox("● CAPTURE ACTIVE")
        self.switch.setChecked(True)
        self.switch.setCursor(Qt.PointingHandCursor)
        self._update_switch_style(True)
        self.switch.stateChanged.connect(self._on_toggle)

        # Inject toggle switch beneath subtitle
        self.layout().addWidget(self.switch)

    def _update_switch_style(self, active: bool) -> None:
        color = C_GREEN if active else C_AMBER
        label = "● CAPTURE ACTIVE" if active else "◼ CAPTURE PAUSED"
        self.switch.setText(label)
        self.switch.setStyleSheet(
            f"QCheckBox {{"
            f"    color: {color}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
            f"    font-family: {FONT_MONO}; spacing: 8px; background: transparent; "
            f"    letter-spacing: 0.6px; margin-top: 4px;"
            f"}}"
            f"QCheckBox::indicator {{"
            f"    width: 14px; height: 14px; border: 1px solid {color}; "
            f"    border-radius: 3px; background: {C_BG_SURFACE};"
            f"}}"
            f"QCheckBox::indicator:checked {{"
            f"    background: {color}; border-color: {color};"
            f"}}"
        )

    def _on_toggle(self, state: int) -> None:
        active = (state == Qt.CheckState.Checked.value or state == 2)
        color = C_GREEN if active else C_AMBER
        
        self.set_value("ACTIVE" if active else "PAUSED", color)
        self.set_subtitle(
            "Detection active" if active else "Engine paused",
            color,
        )
        self._update_switch_style(active)
        self.status_changed.emit(active)


class FeatureBadge(QFrame):
    """
    Compact behavioral feature badge used in live telemetry strips.
    Shifts top-border and text accents to threat red during high reconstruction errors.
    """

    def __init__(self, feature_name: str, value: str = "0.000", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("FeatureBadge")
        self._is_alert = False

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 6, 8, 6)
        lay.setSpacing(2)

        self.name_lbl = QLabel(feature_name.lower())
        self.name_lbl.setStyleSheet(
            f"color: {C_TEXT_DIM}; font-size: 8px; font-weight: 700; "
            f"letter-spacing: 0.5px; background: transparent;"
        )
        lay.addWidget(self.name_lbl)

        self.val_lbl = QLabel(value)
        self.val_lbl.setStyleSheet(
            f"color: {C_ACCENT}; font-size: {FONT_SIZE_SM}; "
            f"font-family: {FONT_MONO}; font-weight: 700; background: transparent;"
        )
        lay.addWidget(self.val_lbl)

        self._apply_style(False)

    def _apply_style(self, alert: bool) -> None:
        border_top = C_RED if alert else C_ACCENT_DIM
        self.setStyleSheet(
            f"QFrame#FeatureBadge {{"
            f"    background-color: {C_BG_SURFACE};"
            f"    border: 1px solid {C_BORDER};"
            f"    border-top: 2px solid {border_top};"
            f"    border-radius: 5px;"
            f"}}"
        )

    def update_value(self, val: str, alert: bool = False) -> None:
        self.val_lbl.setText(val)
        if alert != self._is_alert:
            self._is_alert = alert
            self._apply_style(alert)

        color = C_RED if alert else C_ACCENT
        self.val_lbl.setStyleSheet(
            f"color: {color}; font-size: {FONT_SIZE_SM}; "
            f"font-family: {FONT_MONO}; font-weight: 700; background: transparent;"
        )


class EncryptionBadge(QFrame):
    """
    Pill badge rendering connection encryption status (e.g. TLS/HTTPS heuristic).
    """

    def __init__(self, is_encrypted: bool = False, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("EncryptionBadge")

        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 4, 10, 4)
        lay.setSpacing(6)

        self.icon_lbl = QLabel()
        self.text_lbl = QLabel()

        lay.addWidget(self.icon_lbl)
        lay.addWidget(self.text_lbl)

        self.set_encrypted(is_encrypted)

    def set_encrypted(self, is_encrypted: bool) -> None:
        if is_encrypted:
            icon, text, color, bg_dim, border = (
                "🔒", "ENCRYPTED", C_ACCENT, C_ACCENT_DIM, C_ACCENT
            )
        else:
            icon, text, color, bg_dim, border = (
                "○", "PLAINTEXT", C_TEXT_DIM, C_BG_SURFACE, C_BORDER
            )

        self.setStyleSheet(
            f"QFrame#EncryptionBadge {{"
            f"    background-color: {bg_dim};"
            f"    border: 1px solid {border};"
            f"    border-radius: 10px;"
            f"}}"
        )

        self.icon_lbl.setText(icon)
        self.icon_lbl.setStyleSheet(
            f"font-size: {FONT_SIZE_XS}; background: transparent;"
        )

        self.text_lbl.setText(text)
        self.text_lbl.setStyleSheet(
            f"color: {color}; font-size: {FONT_SIZE_XS}; font-weight: 700; "
            f"font-family: {FONT_MONO}; letter-spacing: 0.6px; background: transparent;"
        )


def make_validation_card(
    split_data: Optional[dict],
    metric_key: str,
    title: str,
    unit: str = "",
) -> MetricCard:
    """
    Factory function generating a formatted MetricCard from validation JSON splits.
    Handles uncalibrated states and missing metric boundaries gracefully.
    """
    if split_data is None or metric_key not in split_data:
        return MetricCard(
            title=title,
            value="—",
            color=C_AMBER,
            subtitle="Not yet validated — run training_validated.ipynb §9",
            unit=unit,
        )

    value = split_data[metric_key]
    try:
        value_f = float(value)
    except (TypeError, ValueError):
        return MetricCard(
            title=title,
            value="ERR",
            color=C_RED,
            subtitle="Malformed value in validation metrics payload",
            unit=unit,
        )

    # Color threshold assignment based on standard evaluation scores
    if value_f >= 0.90:
        color = C_GREEN
    elif value_f >= 0.75:
        color = C_ACCENT
    elif value_f >= 0.50:
        color = C_AMBER
    else:
        color = C_RED

    samples = split_data.get("n_samples")
    subtitle = f"n = {samples:,}" if isinstance(samples, int) else ""

    return MetricCard(
        title=title,
        value=f"{value_f:.3f}",
        color=color,
        subtitle=subtitle,
        unit=unit,
    )