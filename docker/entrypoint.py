"""
entrypoint.py  —  HIDS Backend startup  (SQLite edition)
Run as: python -m entrypoint

Sequence:
  1. Ensure DB directory and configs/ directory exist
  2. create_tables() + lightweight migrations
  3. Warm DetectionEvaluator (loads model + scaler + threshold.yaml)
  4. Start uvicorn on PORT 9000  with module path  api.main:app
"""
import logging
import os
import sys

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("HIDS_Entrypoint")

PORT    = int(os.getenv("API_PORT",  "9000"))
HOST    = os.getenv("API_HOST",      "0.0.0.0")
WORKERS = int(os.getenv("WORKERS",   "1"))


def ensure_dirs() -> None:
    """
    Create runtime directories that must exist before the app starts.

    /app/db      — SQLite database file (mounted volume)
    /app/configs — threshold.yaml lives here (mounted volume)
    /app/logs    — rotating log files
    """
    for d in ("db", "configs", "logs", "models"):
        os.makedirs(os.path.join("/app", d), exist_ok=True)

    # If threshold.yaml is supplied in /app/models (common volume mount),
    # symlink it into /app/configs so evaluator.py finds it at its default
    # path (HIDS_THRESHOLD_CONFIG = configs/threshold.yaml) without needing
    # an extra env override.
    model_thresh  = "/app/models/threshold.yaml"
    config_thresh = "/app/configs/threshold.yaml"
    if os.path.exists(model_thresh) and not os.path.exists(config_thresh):
        os.symlink(model_thresh, config_thresh)
        logger.info(f"Linked {model_thresh} → {config_thresh}")


def run_migrations() -> None:
    from src.database.connection import create_tables
    logger.info("Running schema bootstrap / migrations…")
    create_tables()
    logger.info("Schema ready.")


def warm_evaluator() -> None:
    """
    Load the model + scaler + threshold into memory before uvicorn forks
    workers, so every worker shares the already-loaded objects rather than
    each loading independently.
    """
    model_path = os.getenv("HIDS_MODEL_PATH", "models/baseline_ae.keras")
    if not os.path.exists(model_path):
        logger.warning(
            f"Model weights not found at {model_path}. "
            "/ready will return 503 until weights are placed in the volume."
        )
        return

    scaler_path = os.getenv("HIDS_SCALER_PATH", "models/scaler.pkl")
    if not os.path.exists(scaler_path):
        logger.warning(
            f"Scaler not found at {scaler_path}. "
            "/ready will return 503 until scaler.pkl is placed in the volume."
        )
        return

    try:
        from api.dependencies import get_evaluator
        get_evaluator()
        logger.info("DetectionEvaluator warmed successfully.")
    except Exception as exc:
        logger.error(f"Evaluator warm-up failed: {exc}. Server will start but /ready will return 503.")


def start_server() -> None:
    import uvicorn
    logger.info(f"Starting uvicorn  api.main:app  on {HOST}:{PORT} ({WORKERS} worker(s))…")
    uvicorn.run(
        "api.main:app",
        host=HOST,
        port=PORT,
        workers=WORKERS,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        access_log=True,
        log_config=None,   # let main.py's _configure_logging() own this
    )


if __name__ == "__main__":
    ensure_dirs()
    run_migrations()
    warm_evaluator()
    start_server()