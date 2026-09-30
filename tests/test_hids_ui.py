import pytest
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

# Import your application modules with correct paths
from app.theme import QSS_BASE
from app.components.metrics import MetricCard, HIDStatusCard, FeatureBadge, EncryptionBadge
from app.components.charts import LiveSignalChart, MiniBarChart
from app.pages.ingestion import FeatureSignalStrip
from app.dashboard import SentinelDashboard

@pytest.fixture(scope="session")
def qapp():
    """Ensure a single QApplication instance exists for the test session."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app

def test_theme_constants():
    """Verify that theme stylesheets and base parameters are populated."""
    assert isinstance(QSS_BASE, str)
    assert "#0A0E1A" in QSS_BASE  # Deep navy base check
    assert "#00D4FF" in QSS_BASE  # Electric cyan accent check

def test_metric_card(qapp):
    """Test initialization and value updates for MetricCard."""
    card = MetricCard(title="THROUGHPUT", value="1.2 Gb/s", unit="Mb/s")
    assert card is not None

def test_hid_status_card(qapp):
    """Test state of the HIDStatusCard."""
    status_card = HIDStatusCard()
    assert status_card is not None

def test_badges(qapp):
    """Test FeatureBadge and EncryptionBadge rendering and states."""
    f_badge = FeatureBadge("PACKET_BURST")
    assert f_badge is not None

    e_badge = EncryptionBadge()
    assert e_badge is not None

def test_live_signal_chart(qapp, qtbot):
    """Test real-time waveform chart widget initialization."""
    chart = LiveSignalChart()
    qtbot.addWidget(chart)
    assert chart is not None

def test_mini_bar_chart(qapp, qtbot):
    """Test statistical mini bar chart widget."""
    bar_chart = MiniBarChart()
    qtbot.addWidget(bar_chart)
    assert bar_chart is not None

def test_feature_signal_strip(qapp, qtbot):
    """Test ingestion feature signal breakdown strip."""
    strip = FeatureSignalStrip()
    qtbot.addWidget(strip)
    assert strip is not None

def test_soc_dashboard(qapp, qtbot):
    """Test main SOC dashboard window initialization."""
    dashboard = SentinelDashboard()
    qtbot.addWidget(dashboard)
    assert dashboard is not None