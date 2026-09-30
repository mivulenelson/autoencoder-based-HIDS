import os
import threading
import logging
from typing import Optional

import joblib
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("HIDS_Dependencies")

# Thread-safe singleton locks
_evaluator_lock = threading.Lock()
_scaler_lock    = threading.Lock()

# Singleton caches
_evaluator = None
_scaler    = None


# DetectionEvaluator singleton 
def get_evaluator():
    """
    FastAPI dependency: returns the warm DetectionEvaluator singleton.

    The Autoencoder model and scaler are loaded from disk exactly once,
    on the first call, and reused for every subsequent inference request.

    Thread-safe: protected by _evaluator_lock so concurrent startup
    requests cannot trigger a double model load.

    Usage:
        @router.post("/predict")
        async def predict(evaluator = Depends(get_evaluator)):
            ...
    """
    global _evaluator

    if _evaluator is None:
        with _evaluator_lock:
            # Double-checked locking — re-check inside the lock because
            # another thread may have completed the init while we waited
            if _evaluator is None:
                logger.info("Loading DetectionEvaluator (first request)...")
                from src.detection.evaluator import DetectionEvaluator
                _evaluator = DetectionEvaluator()
                logger.info("DetectionEvaluator ready.")

    return _evaluator


# Scaler singleton 
def get_scaler():
    """
    Returns the fitted MinMaxScaler singleton.

    Shared between:
      - DetectionEvaluator (inference scaling)
      - POST /system/retrain (fine-tuning scaling)

    Prevents the scaler from being reloaded from disk on every retrain call.

    NEW: validates scaler.n_features_in_ against EXPECTED_INPUT_DIM
    immediately after loading — see module docstring's IMPROVEMENTS #1.
    Raises loudly at startup rather than allowing an incompatible scaler
    to silently corrupt every subsequent prediction or fine-tuning pass.

    Usage:
        @router.post("/system/retrain")
        async def retrain(scaler = Depends(get_scaler)):
            ...
    """
    global _scaler

    if _scaler is None:
        with _scaler_lock:
            if _scaler is None:
                scaler_path = os.getenv("HIDS_SCALER_PATH", "models/scaler.pkl")
                if not os.path.exists(scaler_path):
                    raise FileNotFoundError(
                        f"Scaler not found at '{scaler_path}'. "
                        "Set HIDS_SCALER_PATH in your .env file."
                    )
                logger.info(f"Loading scaler from {scaler_path}...")
                loaded_scaler = joblib.load(scaler_path)

                # NEW: fail loudly on a dimension mismatch 
                # sklearn scalers expose n_features_in_ after fitting. Import
                # here (not at module top) to avoid a hard TensorFlow import
                # dependency in dependencies.py just for this constant.
                from src.detection.model import EXPECTED_INPUT_DIM
                n_features = getattr(loaded_scaler, "n_features_in_", None)
                if n_features is not None and n_features != EXPECTED_INPUT_DIM:
                    raise ValueError(
                        f"Scaler at '{scaler_path}' was fitted on {n_features} "
                        f"features, but the parser produces {EXPECTED_INPUT_DIM}. "
                        "This scaler does not match the current feature schema — "
                        "re-run training_validated.ipynb to regenerate a matching "
                        "scaler.pkl before starting the API."
                    )
                elif n_features is None:
                    logger.warning(
                        f"Scaler at '{scaler_path}' has no n_features_in_ attribute "
                        "— could not verify its dimensionality automatically. "
                        "This is unusual for a fitted sklearn scaler; proceed with caution."
                    )

                _scaler = loaded_scaler
                logger.info(
                    f"Scaler loaded and verified ({n_features or '?'} features)."
                )

    return _scaler


# Database session dependency 
def get_db():
    """
    FastAPI dependency: yields a SQLAlchemy Session and guarantees
    it is closed after the request completes — regardless of success or error.

    Rolls back on exception so a failed request cannot leave dirty state
    in the session that would corrupt subsequent transactions on the same
    pooled connection.

    Usage:
        @router.get("/alerts")
        async def get_alerts(db: Session = Depends(get_db)):
            ...
    """
    from src.database.connection import SessionLocal
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()   # Bug fix: original had no rollback — dirty sessions
        raise
    finally:
        db.close()


# Singleton reset (testing only) 
def reset_singletons() -> None:
    """
    Clears all cached singletons — this file's (_evaluator, _scaler) AND
    ModelRegistry's own model/validation-metrics cache in model.py.

    NEW: previously only cleared the local references here, which did NOT
    force a fresh model reload — a new DetectionEvaluator() built right
    after "reset" would still fetch the SAME cached TensorFlow model object
    via get_model(), since that cache lives in ModelRegistry, not here.
    Now calls ModelRegistry.reset() too, so a full reset genuinely reloads
    everything from disk on next use — relevant since feedback_loop.py can
    overwrite baseline_ae.keras mid-session.

    Used in unit tests to force a fresh load between test cases.
    Never call this in production.
    """
    global _evaluator, _scaler

    with _evaluator_lock:
        _evaluator = None
    with _scaler_lock:
        _scaler = None

    try:
        from src.detection.model import ModelRegistry
        ModelRegistry.reset()
    except Exception as exc:
        logger.error(f"reset_singletons: failed to reset ModelRegistry: {exc}")

    logger.warning("Dependency singletons cleared (test mode) — model, scaler, "
                    "and evaluator will all reload fresh from disk on next use.")