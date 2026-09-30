# app/components/charts.py
"""
LiveSignalChart & MiniBarChart  —  HIDS Sentinel v2.0

Visual redesign: deeper navy canvas, multi-layer glow on the signal
line (outer soft halo + inner core), violet/cyan gradient fill under
the waveform, sharper threshold danger-zone, and a polished pulsing
live-node indicator.

All bugs from the prior pass are carried forward (already fixed):
  - _clamp() guards self._pulse to [0.0, 1.0] (no negative setAlpha).
  - _alpha_color() uses QColor.setAlpha() to avoid AARRGGBB vs RRGGBBAA.
  - set_threshold() for live tau propagation post-retrain.
  - MiniBarChart with animated easing and gradient fill bars.
"""

from typing import Dict, Optional

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Slot
from PySide6.QtGui import (
    QBrush, QColor, QFont, QFontMetrics, QLinearGradient, QPainter,
    QPainterPath, QPen, QRadialGradient,
)
from PySide6.QtWidgets import QSizePolicy, QWidget

from theme import (
    C_ACCENT, C_ACCENT_DIM, C_ACCENT_LT, C_AMBER, C_BG_APP,
    C_BG_PANEL, C_BG_SURFACE, C_BORDER, C_GREEN, C_RED,
    C_TEXT_DIM, C_TEXT_PRI, C_TEXT_SEC, C_VIOLET,
)

_FALLBACK_THRESHOLD = 0.4313


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _alpha_color(hex_color: str, alpha: int) -> QColor:
    """Builds a QColor with given 0-255 alpha via setAlpha().
    Avoids the AARRGGBB vs RRGGBBAA hex string ordering trap."""
    c = QColor(hex_color)
    c.setAlpha(int(_clamp(alpha, 0, 255)))
    return c


class LiveSignalChart(QWidget):
    """
    Scrolling waveform — Autoencoder MAE reconstruction error over time.

    Visual upgrades v2.0:
      • Deep navy panel background matching C_BG_PANEL exactly.
      • Three-layer signal: wide soft halo (outer glow) + medium violet
        glow + sharp cyan/red core line — a "laser" appearance.
      • Waveform fill: violet → cyan gradient (fades out at the bottom).
      • Threshold danger zone: deeper red tint, sharper dashed rule.
      • Live node: radial glow burst on the last datapoint.
      • Grid lines tinted very slightly cyan for depth.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumHeight(200)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.max_points = 60
        self.data_points = [0.02] * self.max_points
        self.threshold = _FALLBACK_THRESHOLD

        self._pulse = 0.0
        self._pulse_dir = 1

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)   # ~30 fps

    def set_threshold(self, value: float) -> None:
        """Propagate a newly-calibrated threshold from /ready or /retrain."""
        if value is None or value <= 0:
            return
        self.threshold = float(value)
        self.update()

    # ── Animation tick ────────────────────────────────────────────────────────
    def _tick(self) -> None:
        self._pulse += 0.06 * self._pulse_dir
        self._pulse = _clamp(self._pulse, 0.0, 1.0)
        if self._pulse >= 1.0:
            self._pulse_dir = -1
        elif self._pulse <= 0.0:
            self._pulse_dir = 1
        self.update()

    @Slot(float)
    def update_signal(self, value: float) -> None:
        self.data_points.append(float(value))
        if len(self.data_points) > self.max_points:
            self.data_points.pop(0)

    # ── Paint ─────────────────────────────────────────────────────────────────
    def paintEvent(self, _event) -> None:
        painter = QPainter()
        try:
            painter.begin(self)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setRenderHint(QPainter.TextAntialiasing)
            self._draw(painter)
        finally:
            if painter.isActive():
                painter.end()

    def _draw(self, p: QPainter) -> None:
        W, H = self.width(), self.height()
        PAD_L, PAD_R, PAD_T, PAD_B = 54, 14, 16, 28
        plot_w = W - PAD_L - PAD_R
        plot_h = H - PAD_T - PAD_B

        # ── Canvas ───────────────────────────────────────────────────────────
        p.fillRect(self.rect(), QColor(C_BG_APP))

        # Panel with subtle border
        panel_rect = QRectF(0.5, 0.5, W - 1, H - 1)
        p.setPen(QPen(QColor(C_BORDER), 1))
        p.setBrush(QColor(C_BG_PANEL))
        p.drawRoundedRect(panel_rect, 8, 8)

        # ── Scale ────────────────────────────────────────────────────────────
        data_max = max(max(self.data_points), self.threshold * 1.3)
        y_max = data_max * 1.15

        def to_y(val: float) -> float:
            norm = _clamp(val / y_max, 0.0, 1.0)
            return PAD_T + plot_h * (1.0 - norm)

        def to_x(idx: int) -> float:
            if len(self.data_points) < 2:
                return float(PAD_L)
            return PAD_L + (idx / (self.max_points - 1)) * plot_w

        # ── Grid ─────────────────────────────────────────────────────────────
        tick_font = QFont("JetBrains Mono", 7)
        if not tick_font.exactMatch():
            tick_font = QFont("Consolas", 7)
        p.setFont(tick_font)
        fm = QFontMetrics(tick_font)

        n_ticks = 5
        for i in range(n_ticks + 1):
            frac = i / n_ticks
            val = frac * y_max
            cy = PAD_T + plot_h * (1.0 - frac)

            # Grid line — very slightly tinted cyan
            grid_col = _alpha_color(C_ACCENT, 18)
            p.setPen(QPen(grid_col, 1, Qt.PenStyle.DotLine))
            p.drawLine(PAD_L, int(cy), W - PAD_R, int(cy))

            # Y-axis label
            lbl = f"{val:.3f}"
            tw = fm.horizontalAdvance(lbl)
            p.setPen(QColor(C_TEXT_DIM))
            p.drawText(int(PAD_L - tw - 6), int(cy + fm.ascent() / 2), lbl)

        # ── Threshold danger zone ─────────────────────────────────────────────
        thresh_y = to_y(self.threshold)

        danger_grad = QLinearGradient(0, PAD_T, 0, thresh_y)
        danger_grad.setColorAt(0.0, _alpha_color(C_RED, 55))
        danger_grad.setColorAt(1.0, _alpha_color(C_RED, 0))
        p.setBrush(QBrush(danger_grad))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRect(QRectF(PAD_L, PAD_T, plot_w, thresh_y - PAD_T))

        # Threshold dashed rule
        thresh_pen = QPen(QColor(C_RED), 1.4, Qt.PenStyle.DashLine)
        thresh_pen.setDashPattern([6, 4])
        p.setPen(thresh_pen)
        p.drawLine(PAD_L, int(thresh_y), W - PAD_R, int(thresh_y))

        # Threshold label
        lbl_font = QFont("JetBrains Mono", 7, QFont.Weight.Bold)
        if not lbl_font.exactMatch():
            lbl_font = QFont("Consolas", 7, QFont.Weight.Bold)
        p.setFont(lbl_font)
        p.setPen(QColor(C_RED))
        p.drawText(
            int(PAD_L + 6),
            int(thresh_y - 5),
            f"τ THRESHOLD  {self.threshold:.4f}",
        )

        if len(self.data_points) < 2:
            return

        pts = [
            QPointF(to_x(i), to_y(v))
            for i, v in enumerate(self.data_points)
        ]

        # ── Waveform fill — violet→cyan gradient ──────────────────────────────
        fill_path = QPainterPath()
        fill_path.moveTo(pts[0].x(), PAD_T + plot_h)
        for pt in pts:
            fill_path.lineTo(pt)
        fill_path.lineTo(pts[-1].x(), PAD_T + plot_h)
        fill_path.closeSubpath()

        fill_grad = QLinearGradient(0, PAD_T, 0, PAD_T + plot_h)
        fill_grad.setColorAt(0.0, _alpha_color(C_ACCENT, 70))
        fill_grad.setColorAt(0.4, _alpha_color(C_VIOLET, 30))
        fill_grad.setColorAt(1.0, _alpha_color(C_ACCENT, 0))
        p.setBrush(QBrush(fill_grad))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawPath(fill_path)

        # ── Cubic-smooth signal path ──────────────────────────────────────────
        sig_path = QPainterPath()
        sig_path.moveTo(pts[0])
        for i in range(1, len(pts)):
            cx = (pts[i - 1].x() + pts[i].x()) / 2
            sig_path.cubicTo(
                cx, pts[i - 1].y(),
                cx, pts[i].y(),
                pts[i].x(), pts[i].y(),
            )

        last_val = self.data_points[-1]
        above_thr = last_val >= self.threshold
        line_color = C_RED if above_thr else C_ACCENT_LT
        core_color = C_RED if above_thr else C_ACCENT

        # Layer 1: wide soft outer halo
        halo_pen = QPen(
            _alpha_color(core_color, 28),
            11,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
            Qt.PenJoinStyle.RoundJoin,
        )
        p.setPen(halo_pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(sig_path)

        # Layer 2: medium violet glow
        mid_pen = QPen(
            _alpha_color(C_VIOLET if not above_thr else C_RED, 70),
            5,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
            Qt.PenJoinStyle.RoundJoin,
        )
        p.setPen(mid_pen)
        p.drawPath(sig_path)

        # Layer 3: sharp core line
        core_pen = QPen(
            QColor(line_color),
            1.8,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
            Qt.PenJoinStyle.RoundJoin,
        )
        p.setPen(core_pen)
        p.drawPath(sig_path)

        # ── Live node with radial glow burst ─────────────────────────────────
        lx, ly = pts[-1].x(), pts[-1].y()
        node_base = QColor(C_RED if above_thr else C_GREEN)

        # Radial glow
        pulse_r = 8 + self._pulse * 9
        glow = QRadialGradient(QPointF(lx, ly), pulse_r)
        glow_alpha = int(_clamp(160 * (1.0 - self._pulse), 0, 255))
        glow.setColorAt(
            0.0, _alpha_color(C_RED if above_thr else C_GREEN, glow_alpha)
        )
        glow.setColorAt(
            1.0, _alpha_color(C_RED if above_thr else C_GREEN, 0)
        )
        p.setBrush(QBrush(glow))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(lx, ly), pulse_r, pulse_r)

        # Solid centre dot
        p.setBrush(QBrush(node_base))
        p.setPen(QPen(QColor(C_BG_APP), 1.5))
        p.drawEllipse(QPointF(lx, ly), 5, 5)

        # Value label next to node
        val_font = QFont("JetBrains Mono", 8, QFont.Weight.Bold)
        if not val_font.exactMatch():
            val_font = QFont("Consolas", 8, QFont.Weight.Bold)
        p.setFont(val_font)
        p.setPen(QColor(line_color))
        p.drawText(int(lx) + 12, int(ly) + 4, f"{last_val:.5f}")

        # ── Time-axis annotations ─────────────────────────────────────────────
        axis_font = QFont("JetBrains Mono", 7)
        if not axis_font.exactMatch():
            axis_font = QFont("Consolas", 7)
        p.setFont(axis_font)
        p.setPen(QColor(C_TEXT_DIM))
        p.drawText(PAD_L + 2, H - 6, "← older")
        right_lbl = "now →"
        fw = QFontMetrics(axis_font).horizontalAdvance(right_lbl)
        p.drawText(W - PAD_R - fw, H - 6, right_lbl)


class MiniBarChart(QWidget):
    """
    Compact horizontal bar chart for by_severity / by_encryption
    breakdowns (the {label: count} dicts from /alerts/stats).

    Visual upgrades v2.0:
      • Navy background panel.
      • Per-bar gradient: lighter at left, full colour at right.
      • Track background uses C_BG_SURFACE instead of bare C_BORDER.
      • Count labels rendered in the bar's own accent colour.
      • Smooth easing animation unchanged.
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumHeight(140)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        self._labels: list = []
        self._target_values: Dict[str, float] = {}
        self._display_values: Dict[str, float] = {}
        self._colors: Dict[str, str] = {}

        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._animate_step)
        self._anim_timer.start(16)

    def set_data(
        self,
        data: Dict[str, int],
        colors: Optional[Dict[str, str]] = None,
    ) -> None:
        self._labels = list(data.keys())
        self._target_values = {k: float(v) for k, v in data.items()}
        self._colors = colors or {}
        for label in self._labels:
            self._display_values.setdefault(label, 0.0)

    def _animate_step(self) -> None:
        changed = False
        for label in self._labels:
            target = self._target_values.get(label, 0.0)
            current = self._display_values.get(label, 0.0)
            if abs(target - current) > 0.05:
                self._display_values[label] = current + (target - current) * 0.18
                changed = True
            else:
                self._display_values[label] = target
        if changed:
            self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter()
        try:
            painter.begin(self)
            painter.setRenderHint(QPainter.Antialiasing)
            self._draw(painter)
        finally:
            if painter.isActive():
                painter.end()

    def _draw(self, p: QPainter) -> None:
        W, H = self.width(), self.height()

        # Navy background
        p.fillRect(self.rect(), QColor(C_BG_PANEL))

        if not self._labels:
            p.setPen(QColor(C_TEXT_DIM))
            empty_font = QFont("JetBrains Mono", 8)
            if not empty_font.exactMatch():
                empty_font = QFont("Consolas", 8)
            p.setFont(empty_font)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data")
            return

        display = {k: self._display_values.get(k, 0.0) for k in self._labels}
        max_val = max(max(display.values(), default=0.0), 1.0)

        n_bars = len(self._labels)
        pad_left = 90
        pad_right = 50
        pad_v = 10
        gap = (H - 2 * pad_v) / n_bars
        bar_h = gap * 0.58

        label_font = QFont("JetBrains Mono", 8, QFont.Weight.Bold)
        count_font = QFont("JetBrains Mono", 9, QFont.Weight.Bold)
        for f in (label_font, count_font):
            if not f.exactMatch():
                f.setFamily("Consolas")

        for i, label in enumerate(self._labels):
            value = display[label]
            colour = QColor(self._colors.get(label, C_ACCENT))

            y_center = pad_v + gap * i + gap / 2
            bar_y = y_center - bar_h / 2
            max_bar_w = W - pad_left - pad_right
            bar_w = max(0.0, (value / max_val) * max_bar_w)

            # Track (unfilled)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C_BG_SURFACE))
            p.drawRoundedRect(
                pad_left, int(bar_y), int(max_bar_w), int(bar_h), 4, 4
            )

            # Filled bar — left-to-right gradient
            if bar_w > 0:
                grad = QLinearGradient(pad_left, 0, pad_left + bar_w, 0)
                fill_lt = colour.lighter(130)
                fill_lt.setAlpha(200)
                grad.setColorAt(0.0, fill_lt)
                grad.setColorAt(1.0, colour)
                p.setBrush(QBrush(grad))
                p.drawRoundedRect(
                    pad_left, int(bar_y), int(bar_w), int(bar_h), 4, 4
                )

            # Label (left of bar)
            p.setPen(QColor(C_TEXT_SEC))
            p.setFont(label_font)
            p.drawText(
                6,
                int(y_center) - 10,
                pad_left - 12,
                20,
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                label.upper(),
            )

            # Count (right of bar, in bar's own colour)
            p.setPen(colour)
            p.setFont(count_font)
            p.drawText(
                int(pad_left + bar_w) + 8,
                int(y_center) - 10,
                pad_right,
                20,
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                str(int(round(value))),
            )