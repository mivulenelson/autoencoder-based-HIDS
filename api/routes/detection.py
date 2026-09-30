import numpy as np
import uuid
import time
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from api.dependencies import get_evaluator, get_scaler
from src.detection.evaluator import DetectionEvaluator, EXPECTED_INPUT_DIM

logger = logging.getLogger("HIDS_Detection")

router = APIRouter(prefix="/detection", tags=["AI Inference"])

_EXAMPLE_VECTOR = [
    0.0520, 0.0087, 0.0031, 0.0011, 0.0214, 0.0435, 128.0, 18.4,
    64.0, 192.0, 640.0, 134.6, 16923.0, 338.6, 0.60, 96.2,
    5.0, 1.0, 64.0, 0.094, 0.0, 1.0
]


class FlowData(BaseModel):
    features: List[float] = Field(
        ...,
        min_length=EXPECTED_INPUT_DIM,
        max_length=EXPECTED_INPUT_DIM,
        description=f"Exactly {EXPECTED_INPUT_DIM} flow-based behavioral features.",
        examples=[_EXAMPLE_VECTOR],
    )

    @field_validator("features")
    @classmethod
    def check_no_nan_inf(cls, v: List[float]) -> List[float]:
        import math
        bad = [i for i, x in enumerate(v) if not math.isfinite(x)]
        if bad:
            raise ValueError(
                f"Feature vector contains non-finite values at indices {bad}."
            )
        return v


class BatchFlowData(BaseModel):
    flows: List[List[float]] = Field(
        ...,
        min_length=1,
        max_length=64,
        description=f"List of 1–64 flow vectors, each with {EXPECTED_INPUT_DIM} features.",
    )


@router.post("/predict")
async def analyze_flow(
    data: FlowData,
    evaluator: DetectionEvaluator = Depends(get_evaluator),
    scaler = Depends(get_scaler),
):
    t0 = time.perf_counter()

    try:
        # 1. Scale feature vector
        raw_scaled = scaler.transform([data.features])[0]
        
        # 2. Clip features to [0.0, 1.0] to prevent extreme outlier spikes from exploding MAE
        clipped_scaled = np.clip(raw_scaled, 0.0, 1.0).tolist()
    except Exception as e:
        logger.error(f"Scaler transformation failed: {e}")
        clipped_scaled = data.features

    result = evaluator.evaluate_flow(clipped_scaled)

    if "error" in result:
        logger.error(f"Inference failure: {result['error']}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["error"],
        )

    inference_ms = round((time.perf_counter() - t0) * 1000, 3)
    request_id   = str(uuid.uuid4())

    verdict = "MALICIOUS" if result["is_anomaly"] else "BENIGN"
    logger.info(
        f"[{request_id}] verdict={verdict} "
        f"MAE={result['score']:.6f} threshold={result['threshold']:.6f} "
        f"latency={inference_ms}ms"
    )

    return {
        "status":               "success",
        "request_id":           request_id,
        "verdict":              verdict,
        "reconstruction_error": round(result["score"], 6),
        "threshold_limit":      result["threshold"],
        "severity":             result.get("severity", "None"),
        "feature_count":        len(data.features),
        "inference_ms":         inference_ms,
    }


@router.post("/predict/batch")
async def analyze_batch(
    data: BatchFlowData,
    evaluator: DetectionEvaluator = Depends(get_evaluator),
    scaler = Depends(get_scaler),
):
    t0      = time.perf_counter()
    results = []

    try:
        raw_scaled = scaler.transform(data.flows)
        scaled_flows = np.clip(raw_scaled, 0.0, 1.0).tolist()
    except Exception as e:
        logger.error(f"Batch scaler transformation failed: {e}")
        scaled_flows = data.flows

    for i, scaled_vector in enumerate(scaled_flows):
        result = evaluator.evaluate_flow(scaled_vector)
        if "error" in result:
            results.append({
                "index":   i,
                "status":  "error",
                "detail":  result["error"],
            })
        else:
            results.append({
                "index":               i,
                "status":              "success",
                "verdict":             "MALICIOUS" if result["is_anomaly"] else "BENIGN",
                "reconstruction_error": round(result["score"], 6),
                "threshold_limit":     result["threshold"],
                "severity":            result.get("severity", "None"),
            })

    total_ms = round((time.perf_counter() - t0) * 1000, 3)
    batch_id = str(uuid.uuid4())

    malicious_count = sum(1 for r in results if r.get("verdict") == "MALICIOUS")

    return {
        "batch_id":       batch_id,
        "total":          len(results),
        "malicious_count": malicious_count,
        "total_ms":       total_ms,
        "results":        results,
    }