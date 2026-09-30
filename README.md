# Autoencoder-HIDS

Autoencoder-HIDS v2.0 is a host-based network intrusion detection system powered by a symmetric autoencoder, developed as a final year project at UTAMU.

## Tech Stack & Badges
- Python 3.12[cite: 15]
- PySide6 / Qt6[cite: 15]
- FastAPI[cite: 15]
- SQLite[cite: 15]
- Keras / TensorFlow[cite: 15]
- Docker Compose[cite: 15]
- Scapy & psutil[cite: 15]

## 01: Overview
The Autoencoder-HIDS monitors network traffic on a chosen interface, extracts per-flow behavioral statistics, and runs them through a trained autoencoder to detect patterns deviating from a learned baseline of normal activity[cite: 15]. High reconstruction error indicates a potential intrusion[cite: 15].

The system utilizes a two-container architecture consisting of a FastAPI backend handling live capture, model inference, and database persistence, alongside a PySide6 dashboard that renders alerts, charts, and forensic details in real time over a shared SQLite volume[cite: 15].

## 02: Core Capabilities
* **Real-Time Detection**: Live packet capture via Scapy, per-connection flow feature extraction, and sub-second autoencoder inference[cite: 15].
* **Forensic Inspection**: Persistent SQLite storage for every alert with full 22-feature breakdowns, destination IP, protocol, encryption status, and analyst feedback fields[cite: 15].
* **Feedback Retraining**: Direct false-positive marking in the dashboard where accumulated flags feed a retraining pipeline that automatically recalibrates the threshold[cite: 15].
* **Compliance Reports**: One-click generation of structured plain-text forensic reports summarizing threats, per-incident breakdowns, and top anomalous flows[cite: 15].

## 03: System Architecture & Data Pipeline
- **Autoencoder Model**: Symmetric feed-forward autoencoder with topology `22 → 16 → 8 → 4 → 8 → 16 → 22`[cite: 15]. Trained on benign traffic; anomalies produce higher mean-squared reconstruction error (MSE)[cite: 15].
- **Data Pipeline**: 
  1. *Packet Capture*: Scapy sniffs raw packets on selected network interfaces using `NET_RAW`[cite: 15].
  2. *Feature Extraction*: 22 behavioral statistics computed per flow (timing, volume, rate, burstiness, session, protocol)[cite: 15].
  3. *Normalisation*: Scaled via saved `scaler.pkl` prior to inference[cite: 15].
  4. *Inference & Alert Routing*: Computes MSE; if \(\text{MSE} > \tau\), an alert is written to SQLite and emitted as a Qt signal[cite: 15].

## 04: Running the System

### Running Locally (Without Docker)
1. **Create and activate virtual environment**:
   ```bash
   python3.12 -m venv env
   source env/bin/activate
   pip install -r requirements.txt