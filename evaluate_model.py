#!/usr/bin/env python3
"""
AUTOENCODER-HIDS Vectorized High-Performance Evaluation Script
"""

import os
import sys
import time
import numpy as np
import pandas as pd
import yaml
import joblib
from tensorflow.keras.models import load_model

MODEL_PATH = os.getenv("HIDS_MODEL_PATH", "models/baseline_ae.keras")
SCALER_PATH = os.getenv("HIDS_SCALER_PATH", "models/scaler.pkl")
THRESHOLD_CONFIG = os.getenv("HIDS_THRESHOLD_CONFIG", "configs/threshold.yaml")
TEST_DATA_PATH = os.getenv("HIDS_TEST_DATA_PATH", "data/processed_test_data.csv")

def load_threshold():
    if os.path.exists(THRESHOLD_CONFIG):
        with open(THRESHOLD_CONFIG, "r") as f:
            config = yaml.safe_load(f)
            if "detection_params" in config:
                return config["detection_params"].get("threshold", 0.05)
            return config.get("threshold", 0.05)
    return 0.05

def load_test_data(csv_path):
    if not os.path.exists(csv_path):
        print(f"[ERROR] Test dataset not found at {csv_path}.")
        sys.exit(1)
        
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

def main():
    print("=" * 70)
    print(" AUTOENCODER-HIDS VECTORIZED EVALUATION RUN")
    print("=" * 70)
    
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        print(f"[ERROR] Missing model artifacts ({MODEL_PATH} or {SCALER_PATH}).")
        sys.exit(1)
        
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    threshold = load_threshold()
    
    print(f"[-] Loaded Detection Threshold (tau): {threshold:.5f}")
    print(f"[-] Loading test dataset from: {TEST_DATA_PATH}")
    
    X_raw, y_test = load_test_data(TEST_DATA_PATH)
    
    print(f"[-] Running vectorized scaling and inference for {len(X_raw)} vectors...")
    
    start_time = time.time()
    
    # 1. Vectorized scaling and clipping matching evaluator.py logic
    from src.ingestion.parser import FEATURE_NAMES
    df_input = pd.DataFrame(X_raw, columns=FEATURE_NAMES)
    scaled = scaler.transform(df_input)
    scaled = np.clip(scaled, 0.0, 1.0)
    
    # 2. Batch model prediction
    reconstruction = model.predict(scaled, verbose=0)
    
    # 3. Compute Mean Absolute Error per sample
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
    main()