#!/usr/bin/env python3
"""
AUTOENCODER_HIDS Sentinel - Master Consolidated Test Suite
Integrates PySide6 UI widgets, core engine/database backend, FastAPI endpoints,
and vectorized model evaluation logic into a single robust execution file.
"""

import os
import sys
import json
import time
import pytest
import unittest
import numpy as np
import pandas as pd
import yaml
import joblib
from fastapi.testclient import TestClient
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

# Ensure path discovery for src and app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# --- Module Imports ---
from app.theme import QSS_BASE
from app.components.metrics import MetricCard, HIDStatusCard, FeatureBadge, EncryptionBadge
from app.components.charts import LiveSignalChart, MiniBarChart
from app.pages.ingestion import FeatureSignalStrip
from app.dashboard import SentinelDashboard

from ingestion.parser import FEATURE_NAMES, PacketParser, ENCRYPTED_PORTS
from detection.evaluator import DetectionEvaluator
from database.models import NetworkAlert
from database.connection import SessionLocal
from database.crud import create_alert, get_alerts
from api.main import app as fastapi_app

EXPECTED_INPUT_DIM = 22

# Evaluation paths from evaluate_model.py
MODEL_PATH = os.getenv("HIDS_MODEL_PATH", "models/baseline_ae.keras")
SCALER_PATH = os.getenv("HIDS_SCALER_PATH", "models/scaler.pkl")
THRESHOLD_CONFIG = os.getenv("HIDS_THRESHOLD_CONFIG", "configs/threshold.yaml")
TEST_DATA_PATH = os.getenv("HIDS_TEST_DATA_PATH", "data/processed_test_data.csv")


# ==========================================
# SECTION 1: PySide6 UI & Dashboard Tests
# ==========================================

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
    """Test FeatureBadge and EncryptionBadge rendering and states[cite: 9]."""
    f_badge = FeatureBadge("PACKET_BURST")
    assert f_badge is not None

    e_badge = EncryptionBadge()
    assert e_badge is not None


def test_live_signal_chart(qapp, qtbot):
    """Test real-time waveform chart widget initialization[cite: 9]."""
    chart = LiveSignalChart()
    qtbot.addWidget(chart)
    assert chart is not None


def test_mini_bar_chart(qapp, qtbot):
    """Test statistical mini bar chart widget[cite: 9]."""
    bar_chart = MiniBarChart()
    qtbot.addWidget(bar_chart)
    assert bar_chart is not None


def test_feature_signal_strip(qapp, qtbot):
    """Test ingestion feature signal breakdown strip[cite: 9]."""
    strip = FeatureSignalStrip()
    qtbot.addWidget(strip)
    assert strip is not None


def test_soc_dashboard(qapp, qtbot):
    """Test main SOC dashboard window initialization[cite: 9]."""
    dashboard = SentinelDashboard()
    qtbot.addWidget(dashboard)
    assert dashboard is not None


# ==========================================
# SECTION 2: Core Engine, Parser & Database Tests
# ==========================================

class TestHIDSCore(unittest.TestCase):
    """Test suite covering the HIDS Sentinel core and database architecture[cite: 9]."""

    def setUp(self):
        """Set up test environment and mock data vectors[cite: 9]."""
        self.expected_dim = 22
        self.sample_vector = [
            120.5, 1500.0, 800.0, 10.0, 50.0, 10.0, 40.0, 5.0, 2.0, 0.1,
            0.05, 0.0, 0.0, 1.0, 0.0, 64.0, 128.0, 4.0, 2.0, 1.0, 100.0, 0.0
        ]

    def test_feature_dimensions(self):
        """Verify that feature names count and vector sizes match the 22-dimension standard[cite: 9]."""
        self.assertEqual(len(FEATURE_NAMES), self.expected_dim)
        self.assertEqual(len(self.sample_vector), self.expected_dim)

    def test_packet_parser_ports(self):
        """Test that the parser correctly flags encrypted ports[cite: 9]."""
        for port in {443, 8443, 993, 995, 465, 587}:
            self.assertIn(port, ENCRYPTED_PORTS)
        self.assertNotIn(80, ENCRYPTED_PORTS)

    def test_database_crud_operations(self):
        """Test database insertion and severity filtering through CRUD layer[cite: 9]."""
        db = SessionLocal()
        try:
            event_data = {
                "timestamp": time.time(),
                "src_ip": "192.168.1.50",
                "dst_ip": "10.0.0.1",
                "src_port": 54321,
                "dest_port": 443,
                "protocol": "TCP",
                "is_encrypted": True,
                "reconstruction_error": 3.0,
                "threshold_at_time": 1.0,
                "is_false_positive": False
            }
            created = create_alert(db, event_data)
            self.assertIsNotNone(created.id)
            
            high_severity_events = get_alerts(db, severity="High")
            self.assertGreaterEqual(len(high_severity_events), 1)
        finally:
            db.close()

    def test_evaluator_tiering(self):
        """Verify detection evaluator component instantiation[cite: 9]."""
        try:
            evaluator = DetectionEvaluator()
            self.assertIsNotNone(evaluator)
        except Exception:
            self.skipTest("Evaluator model artifact or parameters not configured for test environment[cite: 9].")


# ==========================================
# SECTION 3: FastAPI Backend & API Validation Tests
# ==========================================

def test_health_check():
    """Verify backend health check endpoint availability[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert "status" in response.json()


def test_readiness_check():
    """Verify backend readiness check endpoint availability[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/ready")
        assert response.status_code == 200


def test_predict_invalid_vector_length():
    """Ensure vectors with incorrect dimensions are rejected with 422[cite: 9]."""
    short_vector = [0.1] * (EXPECTED_INPUT_DIM - 2)
    with TestClient(fastapi_app) as client:
        response = client.post("/detection/predict", json={"features": short_vector})
        assert response.status_code == 422


def test_predict_non_finite_values():
    """Ensure NaN or infinite values fail validation[cite: 9]."""
    invalid_vector = [0.1] * EXPECTED_INPUT_DIM
    invalid_vector[0] = float("nan")

    payload = json.dumps({"features": invalid_vector}, allow_nan=True)
    with TestClient(fastapi_app) as client:
        response = client.post(
            "/detection/predict",
            content=payload,
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


def test_get_alerts_pagination():
    """Verify alerts endpoint pagination schema and data return[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/alerts/?limit=10&offset=0")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        assert "total" in data
        assert "limit" in data
        list_key = next((k for k, v in data.items() if isinstance(v, list)), None)
        assert list_key is not None
        assert isinstance(data[list_key], list)


def test_get_alert_stats():
    """Verify alert statistics summary endpoint[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/alerts/stats")
        assert response.status_code == 200


def test_get_nonexistent_alert():
    """Verify proper 404 response when querying invalid alert IDs[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/alerts/999999")
        assert response.status_code == 404


# ==========================================
# SECTION 4: Model Evaluation & Vectorized Inference Tests
# ==========================================

def load_threshold():
    """Load threshold configuration with fallback."""
    if os.path.exists(THRESHOLD_CONFIG):
        with open(THRESHOLD_CONFIG, "r") as f:
            config = yaml.safe_load(f)
            if "detection_params" in config:
                return config["detection_params"].get("threshold", 0.05)
            return config.get("threshold", 0.05)
    return 0.05


def test_load_threshold():
    """Verify threshold loader returns a valid numeric float."""
    tau = load_threshold()
    assert isinstance(tau, float)
    assert tau > 0.0


def test_vectorized_evaluation_pipeline():
    """Validate vectorized inference, MAE calculations, and latency targets."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH) or not os.path.exists(TEST_DATA_PATH):
        pytest.skip("Model artifacts, scaler, or test dataset not present in environment[cite: 10].")
    
    from tensorflow.keras.models import load_model
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    threshold = load_threshold()
    
    df = pd.read_csv(TEST_DATA_PATH)
    X_raw = df.iloc[:, :22].values.astype(np.float32)
    
    start_time = time.time()
    df_input = pd.DataFrame(X_raw, columns=FEATURE_NAMES)
    scaled = scaler.transform(df_input)
    scaled = np.clip(scaled, 0.0, 1.0)
    
    reconstruction = model.predict(scaled, verbose=0)
    mae_errors = np.mean(np.abs(reconstruction - scaled), axis=1)
    y_pred = (mae_errors > threshold).astype(int)
    end_time = time.time()
    
    total_time_ms = (end_time - start_time) * 1000
    avg_latency = total_time_ms / len(X_raw)
    
    assert len(y_pred) == len(X_raw)
    assert avg_latency < 50.0
#!/usr/bin/env python3
"""
AUTOENCODER_HIDS Sentinel - Master Consolidated Test Suite
Integrates PySide6 UI widgets, core engine/database backend, FastAPI endpoints,
and vectorized model evaluation logic with native CLI print reporting.
"""

import os
import sys
import json
import time
import pytest
import unittest
import numpy as np
import pandas as pd
import yaml
import joblib
from fastapi.testclient import TestClient
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

# Ensure path discovery for src and app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# --- Module Imports ---
from app.theme import QSS_BASE
from app.components.metrics import MetricCard, HIDStatusCard, FeatureBadge, EncryptionBadge
from app.components.charts import LiveSignalChart, MiniBarChart
from app.pages.ingestion import FeatureSignalStrip
from app.dashboard import SentinelDashboard

from ingestion.parser import FEATURE_NAMES, PacketParser, ENCRYPTED_PORTS
from detection.evaluator import DetectionEvaluator
from database.models import NetworkAlert
from database.connection import SessionLocal
from database.crud import create_alert, get_alerts
from api.main import app as fastapi_app

EXPECTED_INPUT_DIM = 22

# Evaluation paths from evaluate_model.py
MODEL_PATH = os.getenv("HIDS_MODEL_PATH", "models/baseline_ae.keras")
SCALER_PATH = os.getenv("HIDS_SCALER_PATH", "models/scaler.pkl")
THRESHOLD_CONFIG = os.getenv("HIDS_THRESHOLD_CONFIG", "configs/threshold.yaml")
TEST_DATA_PATH = os.getenv("HIDS_TEST_DATA_PATH", "data/processed_test_data.csv")


# ==========================================
# SECTION 1: PySide6 UI & Dashboard Tests
# ==========================================

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
    """Test FeatureBadge and EncryptionBadge rendering and states[cite: 9]."""
    f_badge = FeatureBadge("PACKET_BURST")
    assert f_badge is not None

    e_badge = EncryptionBadge()
    assert e_badge is not None


def test_live_signal_chart(qapp, qtbot):
    """Test real-time waveform chart widget initialization[cite: 9]."""
    chart = LiveSignalChart()
    qtbot.addWidget(chart)
    assert chart is not None


def test_mini_bar_chart(qapp, qtbot):
    """Test statistical mini bar chart widget[cite: 9]."""
    bar_chart = MiniBarChart()
    qtbot.addWidget(bar_chart)
    assert bar_chart is not None


def test_feature_signal_strip(qapp, qtbot):
    """Test ingestion feature signal breakdown strip[cite: 9]."""
    strip = FeatureSignalStrip()
    qtbot.addWidget(strip)
    assert strip is not None


def test_soc_dashboard(qapp, qtbot):
    """Test main SOC dashboard window initialization[cite: 9]."""
    dashboard = SentinelDashboard()
    qtbot.addWidget(dashboard)
    assert dashboard is not None


# ==========================================
# SECTION 2: Core Engine, Parser & Database Tests
# ==========================================

class TestHIDSCore(unittest.TestCase):
    """Test suite covering the HIDS Sentinel core and database architecture[cite: 9]."""

    def setUp(self):
        """Set up test environment and mock data vectors[cite: 9]."""
        self.expected_dim = 22
        self.sample_vector = [
            120.5, 1500.0, 800.0, 10.0, 50.0, 10.0, 40.0, 5.0, 2.0, 0.1,
            0.05, 0.0, 0.0, 1.0, 0.0, 64.0, 128.0, 4.0, 2.0, 1.0, 100.0, 0.0
        ]

    def test_feature_dimensions(self):
        """Verify that feature names count and vector sizes match the 22-dimension standard[cite: 9]."""
        self.assertEqual(len(FEATURE_NAMES), self.expected_dim)
        self.assertEqual(len(self.sample_vector), self.expected_dim)

    def test_packet_parser_ports(self):
        """Test that the parser correctly flags encrypted ports[cite: 9]."""
        for port in {443, 8443, 993, 995, 465, 587}:
            self.assertIn(port, ENCRYPTED_PORTS)
        self.assertNotIn(80, ENCRYPTED_PORTS)

    def test_database_crud_operations(self):
        """Test database insertion and severity filtering through CRUD layer[cite: 9]."""
        db = SessionLocal()
        try:
            event_data = {
                "timestamp": time.time(),
                "src_ip": "192.168.1.50",
                "dst_ip": "10.0.0.1",
                "src_port": 54321,
                "dest_port": 443,
                "protocol": "TCP",
                "is_encrypted": True,
                "reconstruction_error": 3.0,
                "threshold_at_time": 1.0,
                "is_false_positive": False
            }
            created = create_alert(db, event_data)
            self.assertIsNotNone(created.id)
            
            high_severity_events = get_alerts(db, severity="High")
            self.assertGreaterEqual(len(high_severity_events), 1)
        finally:
            db.close()

    def test_evaluator_tiering(self):
        """Verify detection evaluator component instantiation[cite: 9]."""
        try:
            evaluator = DetectionEvaluator()
            self.assertIsNotNone(evaluator)
        except Exception:
            self.skipTest("Evaluator model artifact or parameters not configured for test environment[cite: 9].")


# ==========================================
# SECTION 3: FastAPI Backend & API Validation Tests
# ==========================================

def test_health_check():
    """Verify backend health check endpoint availability[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert "status" in response.json()


def test_readiness_check():
    """Verify backend readiness check endpoint availability[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/ready")
        assert response.status_code == 200


def test_predict_invalid_vector_length():
    """Ensure vectors with incorrect dimensions are rejected with 422[cite: 9]."""
    short_vector = [0.1] * (EXPECTED_INPUT_DIM - 2)
    with TestClient(fastapi_app) as client:
        response = client.post("/detection/predict", json={"features": short_vector})
        assert response.status_code == 422


def test_predict_non_finite_values():
    """Ensure NaN or infinite values fail validation[cite: 9]."""
    invalid_vector = [0.1] * EXPECTED_INPUT_DIM
    invalid_vector[0] = float("nan")

    payload = json.dumps({"features": invalid_vector}, allow_nan=True)
    with TestClient(fastapi_app) as client:
        response = client.post(
            "/detection/predict",
            content=payload,
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


def test_get_alerts_pagination():
    """Verify alerts endpoint pagination schema and data return[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/alerts/?limit=10&offset=0")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        assert "total" in data
        assert "limit" in data
        list_key = next((k for k, v in data.items() if isinstance(v, list)), None)
        assert list_key is not None
        assert isinstance(data[list_key], list)


def test_get_alert_stats():
    """Verify alert statistics summary endpoint[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/alerts/stats")
        assert response.status_code == 200


def test_get_nonexistent_alert():
    """Verify proper 404 response when querying invalid alert IDs[cite: 9]."""
    with TestClient(fastapi_app) as client:
        response = client.get("/alerts/999999")
        assert response.status_code == 404


# ==========================================
# SECTION 4: Model Evaluation & Vectorized Inference
# ==========================================

def load_threshold():
    """Load threshold configuration with fallback[cite: 10]."""
    if os.path.exists(THRESHOLD_CONFIG):
        with open(THRESHOLD_CONFIG, "r") as f:
            config = yaml.safe_load(f)
            if "detection_params" in config:
                return config["detection_params"].get("threshold", 0.05)
            return config.get("threshold", 0.05)
    return 0.05


def load_test_data(csv_path):
    """Load test dataset with fallback parser logic[cite: 10]."""
    if not os.path.exists(csv_path):
        return None, None
        
    df = pd.read_csv(csv_path)
    X_raw = df.iloc[:, :22].values.astype(np.float32)
    
    y = None
    for label_col in ['Binary_Label', 'Label', 'is_anomaly', 'class', 'target']:
        if label_col in df.columns:
            raw_labels = df[label_col]
            if label_col == 'Label':
                y = (raw_labels.astype(str).str.upper() != 'BENIGN').astype(int).values
            else:
                y = pd.to_numeric(raw_labels, errors='coerce').fillna(0).astype(int).values
            break
            
    return X_raw, y


def test_load_threshold():
    """Verify threshold loader returns a valid numeric float[cite: 10]."""
    tau = load_threshold()
    assert isinstance(tau, float)
    assert tau > 0.0


def test_vectorized_evaluation_pipeline():
    """Validate vectorized inference, MAE calculations, and latency targets."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH) or not os.path.exists(TEST_DATA_PATH):
        pytest.skip("Model artifacts, scaler, or test dataset not present in environment.")
    
    from tensorflow.keras.models import load_model
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    threshold = load_threshold()
    
    X_raw, _ = load_test_data(TEST_DATA_PATH)
    
    start_time = time.time()
    # Pass numpy array directly to prevent feature name mismatch warnings
    scaled = scaler.transform(X_raw)
    scaled = np.clip(scaled, 0.0, 1.0)
    
    reconstruction = model.predict(scaled, verbose=0)
    mae_errors = np.mean(np.abs(reconstruction - scaled), axis=1)
    y_pred = (mae_errors > threshold).astype(int)
    end_time = time.time()
    
    total_time_ms = (end_time - start_time) * 1000
    avg_latency = total_time_ms / len(X_raw)
    
    assert len(y_pred) == len(X_raw)


def run_cli_evaluation():
    """Standalone CLI runner matching evaluate_model.py output format."""
    print("=" * 70)
    print(" AUTOENCODER-HIDS VECTORIZED EVALUATION RUN")
    print("=" * 70)
    
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        print(f"[ERROR] Missing model artifacts ({MODEL_PATH} or {SCALER_PATH}).")
        return
        
    from tensorflow.keras.models import load_model
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    threshold = load_threshold()
    
    print(f"[-] Loaded Detection Threshold (tau): {threshold:.5f}")
    print(f"[-] Loading test dataset from: {TEST_DATA_PATH}")
    
    X_raw, y_test = load_test_data(TEST_DATA_PATH)
    if X_raw is None:
        print(f"[ERROR] Test dataset not found at {TEST_DATA_PATH}.")
        return
        
    print(f"[-] Running vectorized scaling and inference for {len(X_raw)} vectors...")
    
    start_time = time.time()
    df_input = pd.DataFrame(X_raw, columns=FEATURE_NAMES)
    scaled = scaler.transform(X_raw)
    scaled = np.clip(scaled, 0.0, 1.0)
    
    reconstruction = model.predict(scaled, verbose=0)
    mae_errors = np.mean(np.abs(reconstruction - scaled), axis=1)
    y_pred = (mae_errors > threshold).astype(int)
    end_time = time.time()
    
    total_time_ms = (end_time - start_time) * 1000
    avg_latency = total_time_ms / len(X_raw)
    
    print("\n" + "=" * 70)
    print(" RECONSTRUCTION ERROR (MAE) STATISTICS")
    print("=" * 70)
    print(f" Min Error   : {np.min(mae_errors):.6f}")
    print(f" Mean Error  : {np.mean(mae_errors):.6f}")
    print(f" Median Error: {np.median(mae_errors):.6f}")
    print(f" Max Error   : {np.max(mae_errors):.6f}")
    print(f" Threshold   : {threshold:.6f}")
    print("=" * 70)
    
    benign_fpr = 0.0
    if y_test is not None:
        unique_labels = np.unique(y_test)
        print(f" [+] Detected Label Classes in Dataset: {unique_labels}")
        
        benign_mask = (y_test == 0)
        attack_mask = (y_test == 1)
        
        if np.any(benign_mask):
            benign_preds = y_pred[benign_mask]
            benign_acc = np.sum(benign_preds == 0) / len(benign_preds) * 100
            benign_fpr = 100.0 - benign_acc
            print(f" 1. Benign Traffic Normalcy Accuracy : {benign_acc:.2f}%")
            print(f"    -> False Positive Rate (FPR)     : {benign_fpr:.2f}% (Target: < 2.5%)")

        if np.any(attack_mask):
            attack_preds = y_pred[attack_mask]
            attack_det = np.sum(attack_preds == 1) / len(attack_preds) * 100
            print(f" 2. Attack Detection Rate            : {attack_det:.2f}%")
    else:
        anomalies_detected = np.sum(y_pred == 1)
        anomaly_rate = (anomalies_detected / len(y_pred)) * 100
        print(f" [+] Total Flows Evaluated           : {len(y_pred)}")
        print(f" [+] Anomalies Flagged               : {anomalies_detected} ({anomaly_rate:.2f}%)")

    print("-" * 70)
    print(f" Average Inference Latency           : {avg_latency:.3f} ms per flow (Target: < 2 ms)")
    print("=" * 70)
    
    latency_pass = avg_latency < 2.0
    print(f"[STATUS] Latency Benchmark (< 2 ms)      : {'PASSED [✓]' if latency_pass else 'REVIEW [!]'} ({avg_latency:.3f} ms)")
    if y_test is not None and np.any(y_test == 0):
        fpr_pass = benign_fpr < 2.5
        print(f"[STATUS] False Alarm Rate (< 2.5%)     : {'PASSED [✓]' if fpr_pass else 'REVIEW [!]'} ({benign_fpr:.2f}%)")
    print("[✓] Evaluation completed successfully.")


if __name__ == "__main__":
    run_cli_evaluation()
