# src/services/monitor_service.py
"""
Monitor Service — HIDS Sentinel v2.0[cite: 11]
Thread-safe bridge between the background HIDSSniffer and the PySide6 UI[cite: 11].
"""

import os
import time
import logging
from typing import Optional

import requests
from PySide6.QtCore import QObject, Signal
from dotenv import load_dotenv

from src.ingestion.sniffer import HIDSSniffer

load_dotenv()

logger = logging.getLogger("HIDS_MonitorService")

EXPECTED_INPUT_DIM = 22


class MonitorService(QObject):
    """
    Thread-safe bridge between the background HIDSSniffer and the PySide6 UI[cite: 11].
    """

    new_alert = Signal(dict)     # Emitted for every processed flow (benign + anomalous)[cite: 11]
    new_metrics = Signal(float)  # MAE reconstruction error — drives the live chart[cite: 11]
    engine_status = Signal(bool) # True = running, False = stopped[cite: 11]

    def __init__(self, interface: Optional[str] = None):
        super().__init__()

        self.current_iface = interface or os.getenv("SNIFFER_INTERFACE", "wlo1")

        api_host = os.getenv("API_HOST", "127.0.0.1")
        api_port = os.getenv("API_PORT", "9000")
        self.api_url = f"http://{api_host}:{api_port}/detection/predict"
        self.api_timeout = float(os.getenv("API_TIMEOUT", "2.0"))

        self.sniffer = HIDSSniffer(
            interface=self.current_iface,
            on_feature_extracted=self.handle_extracted_features,
        )

        logger.info(
            f"MonitorService ready — interface={self.current_iface} "
            f"api={self.api_url}"
        )

    def handle_extracted_features(self, features: list, meta: dict) -> None:
        """
        Receives the 22-feature vector and flow metadata, queries FastAPI inference,
        and emits the complete result for all traffic states to the UI[cite: 11].
        """
        if len(features) != EXPECTED_INPUT_DIM:
            logger.warning(
                f"Feature vector has {len(features)} elements, expected "
                f"{EXPECTED_INPUT_DIM}. Skipping[cite: 11]."
            )
            return

        result = self._post_to_api(features)
        if result is None:
            return

        mae = float(result.get("reconstruction_error", 0.0))
        self.new_metrics.emit(mae)

        src_ip = meta.get("src_ip", "unknown")
        dst_ip = meta.get("dst_ip", "unknown")
        src_port = meta.get("src_port")
        dst_port = meta.get("dst_port")
        protocol = meta.get("protocol", "IP")
        is_encrypted = meta.get("is_encrypted", False)

        result["src_ip"] = src_ip
        result["dst_ip"] = dst_ip
        result["src_port"] = src_port
        result["dst_port"] = dst_port
        result["protocol"] = protocol
        result["is_encrypted"] = is_encrypted
        result["timestamp"] = time.time()
        result["features"] = features

        from src.ingestion.parser import FEATURE_NAMES
        result.update(dict(zip(FEATURE_NAMES, features)))

        verdict = result.get("verdict", "BENIGN")
        severity = result.get("severity", "None")
        if verdict == "MALICIOUS":
            enc_tag = " [ENCRYPTED]" if is_encrypted else ""
            log_fn = logger.warning if severity in ("Critical", "High") else logger.info
            log_fn(
                f"ANOMALY DETECTED — {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"({protocol}){enc_tag} | severity={severity} MAE={mae:.6f}"
            )

        # Emit ALL evaluated flows (Normal, Low, Malicious) to the UI log table
        self.new_alert.emit(result)

        if verdict == "MALICIOUS":
            self._persist_alert(result)

    def _post_to_api(self, features: list, retries: int = 2) -> Optional[dict]:
        payload = {"features": features}

        for attempt in range(retries + 1):
            try:
                response = requests.post(
                    self.api_url,
                    json=payload,
                    timeout=self.api_timeout,
                )
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(f"API returned {response.status_code}: {response.text[:120]}")
                    return None
            except requests.exceptions.Timeout:
                logger.warning(f"API timeout (attempt {attempt + 1}/{retries + 1})")
            except requests.exceptions.ConnectionError:
                if attempt == 0:
                    logger.error(f"API connection refused — is FastAPI running on {self.api_url}?")
            except Exception as exc:
                logger.error(f"Unexpected API error: {exc}")
                return None

            if attempt < retries:
                time.sleep(0.5 * (2 ** attempt))

        return None

    def _persist_alert(self, result: dict) -> None:
        try:
            from src.database.connection import SessionLocal
            from src.database.crud import create_alert

            db = SessionLocal()
            try:
                create_alert(db, result)
            finally:
                db.close()
        except Exception as exc:
            logger.error(f"Failed to persist alert to database: {exc}")

    def start_engine(self) -> None:
        self.sniffer.start()
        self.engine_status.emit(True)
        logger.info(f"HIDS engine started on interface '{self.current_iface}'.")

    def stop_engine(self) -> None:
        self.sniffer.stop()
        self.engine_status.emit(False)
        logger.info("HIDS engine stopped.")

    def restart_with_new_interface(self, new_iface: str) -> None:
        logger.info(f"MonitorService: switching interface → '{new_iface}'")
        self.stop_engine()
        self.sniffer.interface = new_iface
        self.current_iface = new_iface
        self.sniffer.reset_parser()
        self.start_engine()
        logger.info(f"MonitorService: now monitoring '{new_iface}'.")