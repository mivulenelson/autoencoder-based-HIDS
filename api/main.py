import os
import time
import json
import typing
import logging
from logging.handlers import RotatingFileHandler
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from api.routes import detection, alerts
from api.dependencies import get_db, get_evaluator, get_scaler
from src.detection.evaluator import DetectionEvaluator
from src.services.feedback_loop import FeedbackLoopService


# ── Safe JSON Response for NaN/Inf Support ────────────────────────────────────
class SafeJSONResponse(JSONResponse):
    """
    Custom JSONResponse that permits NaN, Infinity, and -Infinity values 
    to prevent serialization crashes during validation error handling of non-finite inputs.
    """
    def render(self, content: typing.Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=True,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")


# ── Logging Setup ─────────────────────────────────────────────────────────────
def _configure_logging():
    log_dir  = os.getenv("HIDS_LOG_DIR", "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_format = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler — 10 MB per file, keep last 5
    file_handler = RotatingFileHandler(
        filename=os.path.join(log_dir, "hids_api.log"),
        maxBytes=10 * 1024 * 1024,   # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(log_format)
    file_handler.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_format)
    console_handler.setLevel(logging.INFO)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(file_handler)
    root.addHandler(console_handler)


_configure_logging()
logger = logging.getLogger("HIDS_API")


# ── Application Lifespan ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs startup tasks before the app begins accepting requests,
    and shutdown tasks when the server is stopping.
    """
    # Startup 
    logger.info("=" * 60)
    logger.info("HIDS API starting up...")

    # 1. Bootstrap database schema
    try:
        from src.database.connection import create_tables
        create_tables()
        logger.info("Database schema verified.")
    except Exception as exc:
        logger.critical(f"Database init failed: {exc}")
        raise

    # 2. Warm the DetectionEvaluator
    try:
        get_evaluator()
        logger.info("DetectionEvaluator warmed successfully.")
    except Exception as exc:
        logger.critical(f"Model warm-up failed: {exc}")
        raise

    logger.info("HIDS API ready — accepting requests.")
    logger.info("=" * 60)

    yield   # ── app runs here ──

    # Shutdown
    logger.info("HIDS API shutting down.")


# ── FastAPI Application ───────────────────────────────────────────────────────
app = FastAPI(
    title="HIDS AI Detection Service",
    description=(
        "Real-time Autoencoder-based Intrusion Detection API.\n\n"
        "Accepts 22-feature flow vectors extracted from live network traffic "
        "and returns anomaly verdicts via MAE reconstruction error analysis.\n\n"
        "**Project:** An Autoencoder HIDS for Encrypted Network Traffic — UTAMU 2026"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ── CORS Middleware ───────────────────────────────────────────────────────────
_default_origins = "http://localhost:8501,http://localhost:3000"
_allowed_origins = os.getenv("HIDS_ALLOWED_ORIGINS", _default_origins).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)


# ── Request Timing Middleware ─────────────────────────────────────────────────
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Injects X-Process-Time header and logs all requests for performance audit."""
    start    = time.perf_counter()
    response = await call_next(request)
    elapsed  = time.perf_counter() - start

    response.headers["X-Process-Time"] = f"{elapsed * 1000:.2f}ms"

    if request.url.path in ("/health", "/ready"):
        logger.debug(f"{request.method} {request.url.path} {elapsed*1000:.2f}ms")
    else:
        logger.info(
            f"{request.method} {request.url.path} "
            f"status={response.status_code} {elapsed*1000:.2f}ms"
        )

    return response


# ── Route Registration ────────────────────────────────────────────────────────
app.include_router(detection.router)
app.include_router(alerts.router)


# ── System Endpoints ──────────────────────────────────────────────────────────
@app.get("/health", tags=["System"], summary="Liveness probe")
async def health_check():
    """Liveness probe for container orchestrators (Docker, Kubernetes)."""
    return {"status": "alive", "timestamp": time.time()}


@app.get("/ready", tags=["System"], summary="Readiness probe + model evidence")
async def readiness_check():
    """Readiness probe — returns 200 only when the DetectionEvaluator is loaded."""
    from api.dependencies import _evaluator
    from fastapi import Response

    if _evaluator is None:
        return Response(
            content='{"status":"loading","detail":"Model not yet initialised"}',
            status_code=503,
            media_type="application/json",
        )

    diagnostics = _evaluator.describe()

    return {
        "status":             "ready",
        "threshold":          round(diagnostics["threshold"], 6),
        "mu":                 round(diagnostics["mu"], 6),
        "sigma":              round(diagnostics["sigma"], 6),
        "expected_dim":       diagnostics["expected_dim"],
        "model_params":       diagnostics["model_params"],
        "validation_metrics": diagnostics["validation_metrics"],
        "timestamp":          time.time(),
    }


@app.get("/")
def read_root():
    return {"status": "healthy", "service": "Autoencoder HIDS API"}


@app.post("/system/retrain", tags=["System"], summary="Trigger adaptive feedback retraining")
async def trigger_retraining(
    db:       Session = Depends(get_db),
    evaluator: DetectionEvaluator = Depends(get_evaluator),
    scaler=   Depends(get_scaler),
):
    """Triggers the full adaptive feedback loop cycle."""
    logger.info("POST /system/retrain — starting feedback cycle...")
    result = FeedbackLoopService.run_feedback_cycle(db, scaler, evaluator)
    logger.info(f"Feedback cycle result: {result}")
    return result


@app.get("/docs", response_class=HTMLResponse)
async def serve_project_docs():
    docs_path = "/app/docs/hids_docs.html"
    if os.path.exists(docs_path):
        with open(docs_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<html><body><h1>Documentation not found</h1></body></html>"

@app.exception_handler(RequestValidationError)
async def custom_request_validation_handler(request: Request, exc: RequestValidationError):
    # Ensure all values in error 'ctx' dictionaries are JSON serializable (e.g., convert exceptions to strings)
    errors = []
    for error in exc.errors():
        err_copy = error.copy()
        if "ctx" in err_copy:
            err_copy["ctx"] = {
                k: str(v) if isinstance(v, Exception) else v 
                for k, v in err_copy["ctx"].items()
            }
        errors.append(err_copy)

    # Then pass the sanitized errors dictionary/list to your SafeJSONResponse
    return SafeJSONResponse(
        status_code=422,
        content={"detail": errors},
    )