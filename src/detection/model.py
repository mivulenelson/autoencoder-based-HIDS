import os
import json
import logging
import threading
from typing import Optional

import tensorflow as tf
from dotenv import load_dotenv

from src.detection.layers.dense_block import DetectionBlock

load_dotenv()

logger = logging.getLogger("HIDS_ModelLoader")

EXPECTED_INPUT_DIM = 22


class ModelRegistry:
    """
    Thread-safe singleton that loads and caches the Autoencoder model.
    """

    _instance = None
    _lock = threading.Lock()

    _validation_metrics: Optional[dict] = None
    _validation_metrics_loaded = False

    @classmethod
    def load_hids_model(cls) -> Optional[tf.keras.Model]:
        """
        Return the cached model, loading it from disk on first call.
        Returns None gracefully if the model file is missing.
        """
        if cls._instance is not None:
            return cls._instance

        with cls._lock:
            if cls._instance is not None:
                return cls._instance

            model_path = os.getenv("HIDS_MODEL_PATH", "models/baseline_ae.keras")

            if not os.path.exists(model_path):
                logger.warning(
                    f"Model file not found at {model_path}. "
                    "Inference will be disabled until baseline_ae.keras is provided."
                )
                return None

            try:
                model = tf.keras.models.load_model(
                    model_path,
                    custom_objects={"DetectionBlock": DetectionBlock},
                )
            except Exception as exc:
                logger.critical(f"Failed to deserialise model weights: {exc}")
                raise RuntimeError(
                    f"Model integrity error — could not load {model_path}: {exc}"
                ) from exc

            # Validate input shape
            try:
                actual_input_dim = model.input_shape[-1]
                if actual_input_dim != EXPECTED_INPUT_DIM:
                    raise ValueError(
                        f"Loaded model expects {actual_input_dim} input features but "
                        f"the parser produces {EXPECTED_INPUT_DIM}."
                    )
            except AttributeError:
                logger.warning("Could not verify model input dimension automatically.")

            # Validate output shape
            actual_output_dim = None
            try:
                actual_output_dim = model.output_shape[-1]
                if actual_output_dim != EXPECTED_INPUT_DIM:
                    raise ValueError(
                        f"Loaded model outputs {actual_output_dim} features but an "
                        f"autoencoder must reconstruct {EXPECTED_INPUT_DIM} inputs."
                    )
            except AttributeError:
                logger.warning("Could not verify model output dimension automatically.")

            detection_block_count = sum(
                1 for layer in model.layers if isinstance(layer, DetectionBlock)
            )
            if detection_block_count == 0:
                logger.info(
                    "Loaded model contains 0 DetectionBlock layers — built from plain Keras layers."
                )
            else:
                logger.info(
                    f"Loaded model contains {detection_block_count} DetectionBlock layer(s)."
                )

            cls._instance = model
            logger.info(
                f"AI Detection Engine ready — input: ({EXPECTED_INPUT_DIM},) output: ({actual_output_dim},)"
            )
            return cls._instance

    @classmethod
    def get_validation_metrics(cls) -> Optional[dict]:
        if cls._validation_metrics_loaded:
            return cls._validation_metrics

        with cls._lock:
            if cls._validation_metrics_loaded:
                return cls._validation_metrics

            metrics_path = os.getenv(
                "HIDS_VALIDATION_METRICS_PATH",
                os.path.join("experiments", "figures", "training", "validation_metrics.json"),
            )

            if not os.path.exists(metrics_path):
                logger.warning(f"validation_metrics.json not found at {metrics_path}.")
                cls._validation_metrics = None
            else:
                try:
                    with open(metrics_path, "r") as fh:
                        cls._validation_metrics = json.load(fh)
                    logger.info(f"Validation metrics loaded from {metrics_path}")
                except Exception as exc:
                    logger.error(f"Failed to parse validation_metrics.json: {exc}")
                    cls._validation_metrics = None

            cls._validation_metrics_loaded = True
            return cls._validation_metrics

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._instance = None
            cls._validation_metrics = None
            cls._validation_metrics_loaded = False


def get_model() -> Optional[tf.keras.Model]:
    return ModelRegistry.load_hids_model()


def get_validation_metrics() -> Optional[dict]:
    return ModelRegistry.get_validation_metrics()


AutoencoderProvider = ModelRegistry