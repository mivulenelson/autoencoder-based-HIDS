# evaluator_3.py
import os
import logging
import warnings
from typing import Optional, Tuple, Dict, Any

import numpy as np
import pandas as pd
import yaml
import joblib

from src.detection.model import get_model, get_validation_metrics, EXPECTED_INPUT_DIM
from src.ingestion.parser import FEATURE_NAMES

logger = logging.getLogger("HIDS_Evaluator")

_DEFAULT_THRESHOLD = 0.5


class DetectionEvaluator:
    """
    Wraps Autoencoder reconstruction inference and threshold scoring for live flow telemetry.
    """

    def __init__(self):
        # ── 1. Load Model ─────────────────────────────────────────────────
        self.model = get_model()

        # ── 2. Load MinMaxScaler ──────────────────────────────────────────
        scaler_path = os.getenv("HIDS_SCALER_PATH", "models/scaler.pkl")
        if os.path.exists(scaler_path):
            try:
                self.scaler = joblib.load(scaler_path)
                logger.info(f"MinMaxScaler loaded successfully from {scaler_path}")
            except Exception as exc:
                logger.error(f"Failed to load scaler from {scaler_path}: {exc}")
                self.scaler = None
        else:
            logger.warning(
                f"Scaler not found at {scaler_path}. System running in fallback mode."
            )
            self.scaler = None

        # ── 3. Load Anomaly Threshold Config ──────────────────────────────
        self.config_path = os.getenv("HIDS_THRESHOLD_CONFIG", "configs/threshold.yaml")
        self.threshold: float = _DEFAULT_THRESHOLD
        self.mu: float = 0.0
        self.sigma: float = 0.0
        self._load_threshold_config()

    def _load_threshold_config(self) -> None:
        """
        Loads and validates threshold parameters (μ, σ, τ, feature ordering).
        """
        try:
            with open(self.config_path, "r") as fh:
                config = yaml.safe_load(fh)

            saved_dim = config.get("input_dim")
            if saved_dim is not None and int(saved_dim) != EXPECTED_INPUT_DIM:
                raise ValueError(
                    f"Config input_dim={saved_dim} does not match parser "
                    f"output dim={EXPECTED_INPUT_DIM}."
                )

            saved_feature_names = config.get("feature_names")
            if saved_feature_names is not None:
                if list(saved_feature_names) != list(FEATURE_NAMES):
                    mismatch_at = next(
                        (i for i, (a, b) in enumerate(zip(saved_feature_names, FEATURE_NAMES)) if a != b),
                        None,
                    )
                    raise ValueError(
                        f"Feature name/order mismatch between threshold.yaml and parser.py "
                        f"at index {mismatch_at}."
                    )

            self.threshold = float(config.get("threshold", _DEFAULT_THRESHOLD))
            self.mu = float(config.get("mu", 0.0))
            self.sigma = float(config.get("sigma", 0.0))

            logger.info(
                f"Threshold parameters active — τ={self.threshold:.6f} "
                f"(μ={self.mu:.6f}, σ={self.sigma:.6f})"
            )

        except FileNotFoundError:
            logger.warning(
                f"Threshold config file missing at {self.config_path}. Using fallback τ={_DEFAULT_THRESHOLD}"
            )
        except Exception as exc:
            logger.error(f"Failed parsing threshold configuration: {exc}. Using τ={_DEFAULT_THRESHOLD}")

    def reload_threshold(self) -> None:
        """Re-reads config parameters from disk dynamically."""
        self._load_threshold_config()

    def _compute_severity(self, mae_loss: float) -> str:
        """
        Calculates severity level based on loss margin relative to threshold,
        allowing sub-threshold and minor deviations to return 'Low' or 'Normal'.
        """
        if mae_loss <= self.threshold:
            if self.sigma > 0 and mae_loss >= (self.threshold - self.sigma):
                return "Low"
            return "Normal"

        delta = mae_loss - self.threshold

        # Step thresholds relative to sigma or ratio
        if self.sigma > 0:
            sigma_delta = delta / self.sigma
            if sigma_delta >= 6.0:
                return "Critical"
            if sigma_delta >= 3.0:
                return "High"
            if sigma_delta >= 1.0:
                return "Medium"
            return "Low"

        # Fallback ratio-based tiering if sigma is zero/missing
        ratio = mae_loss / self.threshold if self.threshold > 0 else 1.0
        if ratio >= 2.0:
            return "Critical"
        if ratio >= 1.4:
            return "High"
        if ratio >= 1.1:
            return "Medium"
        return "Low"

    def evaluate_flow(self, feature_vector: list) -> Dict[str, Any]:
        """
        Evaluates a 22-feature vector for anomaly detection.
        """
        n = len(feature_vector)
        if n != EXPECTED_INPUT_DIM:
            return {
                "is_anomaly": False,
                "score": 0.0,
                "threshold": self.threshold,
                "severity": "Normal",
                "feature_count": n,
                "error": f"Dimension mismatch: expected {EXPECTED_INPUT_DIM}, got {n}",
            }

        try:
            raw = np.array(feature_vector, dtype=np.float32).reshape(1, -1)

            # 1. Feature scaling with DataFrame wrapper to satisfy fitted feature names
            if self.scaler is not None:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=UserWarning)
                    df_input = pd.DataFrame(raw, columns=FEATURE_NAMES)
                    scaled = self.scaler.transform(df_input)
                scaled = np.clip(scaled, 0.0, 1.0)
            else:
                scaled = raw

            # 2. Model inference fallback check
            if self.model is None:
                return {
                    "is_anomaly": False,
                    "score": 0.0,
                    "threshold": self.threshold,
                    "severity": "Normal",
                    "feature_count": n,
                    "error": "Model weights unavailable",
                }

            # 3. Compute Autoencoder Loss
            reconstruction = self.model.predict(scaled, verbose=0)
            mae_loss = float(np.mean(np.abs(reconstruction - scaled)))

            # 4. Severity & Verdict
            is_anomaly = mae_loss > self.threshold
            severity = self._compute_severity(mae_loss)

            return {
                "is_anomaly": bool(is_anomaly),
                "score": mae_loss,
                "threshold": self.threshold,
                "severity": severity,
                "feature_count": n,
            }

        except Exception as exc:
            logger.error(f"Inference error during evaluation: {exc}")
            return {
                "is_anomaly": False,
                "score": 0.0,
                "threshold": self.threshold,
                "severity": "Normal",
                "feature_count": n,
                "error": str(exc),
            }

    def predict(self, feature_vector: list) -> Tuple[bool, float]:
        """Convenience method returning boolean verdict and raw score tuple."""
        result = self.evaluate_flow(feature_vector)
        return result["is_anomaly"], result["score"]

    def describe(self) -> Dict[str, Any]:
        """Returns diagnostic state metrics."""
        model_params = self.model.count_params() if self.model else 0
        return {
            "threshold": self.threshold,
            "mu": self.mu,
            "sigma": self.sigma,
            "expected_dim": EXPECTED_INPUT_DIM,
            "feature_names": FEATURE_NAMES,
            "scaler_path": os.getenv("HIDS_SCALER_PATH", "models/scaler.pkl"),
            "config_path": self.config_path,
            "model_params": model_params,
            "validation_metrics": get_validation_metrics(),
        }