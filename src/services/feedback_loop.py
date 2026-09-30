import os
import logging
from typing import Optional

import numpy as np
import pandas as pd
import yaml
from sqlalchemy.orm import Session

from src.database import models
from src.database.crud import get_false_positives

logger = logging.getLogger("HIDS_FeedbackLoop")

# Must match parser.py FEATURE_NAMES length and evaluator.py EXPECTED_INPUT_DIM
EXPECTED_INPUT_DIM = 22

# Matches training_validated.ipynb's threshold calibration formula exactly:
# tau = mu + K_SIGMA * sigma. Keeping this as a named constant here (rather
# than a magic number inline) makes the fine-tune-time recalibration
# trivially auditable against the training notebook's methodology.
K_SIGMA = 2.0


class FeedbackLoopService:
    """
    Orchestrates the adaptive feedback cycle:

      1. extract_retraining_data()  — pull confirmed FP vectors from DB
      2. trigger_retraining()       — fine-tune Autoencoder on FP flows,
                                       recalibrate threshold, persist both
                                       the updated weights and the updated
                                       threshold config to disk

    All methods are @staticmethod / @classmethod so they can be called
    without instantiation from the FastAPI /system/retrain endpoint or
    from the PySide6 settings panel.
    """

    # ── Step 1: Data extraction ───────────────────────────────────────────────
    @staticmethod
    def extract_retraining_data(db: Session) -> Optional[pd.DataFrame]:
        """
        Queries all analyst-confirmed False Positive alerts and returns
        their 22-feature vectors as a DataFrame ready for fine-tuning.

        Returns None if no false positives exist yet.

        Feature vectors are stored in the DB as:
            {"vector": [f0, f1, ..., f21], "dim": 22}
        or as a plain list (legacy format from older MonitorService versions).
        """
        fps_all = get_false_positives(db)

        # Skip alerts already incorporated into a previous retraining pass
        fps = [a for a in fps_all
               if not (a.analyst_comment or "").startswith("[RETRAINED]")]

        if not fps:
            if fps_all:
                logger.info(
                    f"FeedbackLoop: {len(fps_all)} FP alert(s) found but all already "
                    "retrained — skipping. Submit new FP classifications to queue more."
                )
            else:
                logger.info("FeedbackLoop: no false positives found — skipping.")
            return None

        rows = []
        skipped = 0
        encrypted_count = 0
        plaintext_count = 0

        for alert in fps:
            features = alert.flow_features

            # Normalise storage format: {"vector": [...]} or plain list
            if isinstance(features, dict) and "vector" in features:
                vector = features["vector"]
            elif isinstance(features, list):
                vector = features
            else:
                logger.warning(
                    f"FeedbackLoop: alert id={alert.id} has unrecognised "
                    f"flow_features format ({type(features).__name__}) — skipping."
                )
                skipped += 1
                continue

            # Validate dimension before adding to training data
            if len(vector) != EXPECTED_INPUT_DIM:
                logger.warning(
                    f"FeedbackLoop: alert id={alert.id} has {len(vector)} features, "
                    f"expected {EXPECTED_INPUT_DIM} — skipping (likely a stale "
                    f"record from an earlier feature schema)."
                )
                skipped += 1
                continue

            rows.append(vector)

            # NEW: tally encrypted vs plaintext among the FP samples actually
            # used, purely for the audit-trail log below — does not affect
            # which samples are selected.
            if getattr(alert, "is_encrypted", False):
                encrypted_count += 1
            else:
                plaintext_count += 1

        if not rows:
            logger.warning(
                f"FeedbackLoop: {len(fps)} FP alert(s) found but 0 had valid "
                f"{EXPECTED_INPUT_DIM}-feature vectors. Nothing to retrain on."
            )
            return None

        df = pd.DataFrame(rows, columns=[f"f{i}" for i in range(EXPECTED_INPUT_DIM)])
        logger.info(
            f"FeedbackLoop: extracted {len(df)} valid FP samples "
            f"({encrypted_count} encrypted, {plaintext_count} plaintext, "
            f"{skipped} skipped due to format/dimension issues)."
        )
        return df

    # ── Step 2: Fine-tuning + recalibration + persistence ─────────────────────
    @staticmethod
    def trigger_retraining(
        data: pd.DataFrame,
        scaler,
        evaluator,
        epochs: int = 5,
        batch_size: int = 16,
    ) -> bool:
        """
        Fine-tunes the Autoencoder on confirmed benign (false-positive) flows,
        recalibrates the detection threshold, and persists BOTH the updated
        model weights and the updated threshold config to disk so this
        survives an API restart.

        This is incremental learning — we run a small number of additional
        training epochs on the misclassified benign samples so the model
        expands its reconstruction of "normal" to include these patterns.

        Args:
            data:       DataFrame of shape (N, 22) — FP flow feature vectors.
            scaler:     The fitted MinMaxScaler / StandardScaler used at inference.
                        Must have been fitted on the original training data.
            evaluator:  DetectionEvaluator instance — mu/sigma/threshold
                        updated in-place, then persisted to its config_path.
            epochs:     Fine-tuning epochs. Keep low (3–10) to avoid catastrophic
                        forgetting of the original normalcy manifold.
            batch_size: Mini-batch size. Keep small for limited GPU/CPU resources.

        Returns:
            True on success, False if an error occurred.
        """
        try:
            raw_array = data.values.astype(np.float64)

            # ── Validate dimensions before touching the model ─────────────────
            if raw_array.shape[1] != EXPECTED_INPUT_DIM:
                raise ValueError(
                    f"Feature dimension mismatch: DataFrame has {raw_array.shape[1]} "
                    f"columns, expected {EXPECTED_INPUT_DIM}. "
                    "Ensure extract_retraining_data() ran before trigger_retraining()."
                )

            # ── Scale the FP vectors using the SAME scaler used at inference ──
            # Pass a named DataFrame to silence sklearn's UserWarning —
            # the scaler was fitted on a DataFrame with named columns.
            import pandas as pd
            feature_cols = [f"f{i}" for i in range(EXPECTED_INPUT_DIM)]
            raw_df       = pd.DataFrame(raw_array, columns=feature_cols)
            scaled_array = scaler.transform(raw_df)

            # ── Get model from the singleton registry ─────────────────────────
            from src.detection.model import get_model
            model = get_model()

            logger.info(
                f"FeedbackLoop: fine-tuning on {len(scaled_array)} samples — "
                f"{epochs} epoch(s), batch_size={batch_size}."
            )

            # ── Autoencoder reconstruction task: target == input ──────────────
            history = model.fit(
                scaled_array,
                scaled_array,          # target = input for reconstruction
                epochs=epochs,
                batch_size=batch_size,
                verbose=0,
                shuffle=True,
            )

            final_loss = history.history["loss"][-1]
            logger.info(
                f"FeedbackLoop: fine-tuning complete. "
                f"Final reconstruction loss: {final_loss:.6f}"
            )

            # ── Recalibrate threshold using post-fine-tuning reconstruction ──
            # After fine-tuning, the model should reconstruct the FP (benign)
            # flows with LOWER error. We use these post-training errors to
            # set the new threshold boundary.
            #
            # Safety cap: new threshold cannot exceed 2x the pre-training
            # threshold — prevents runaway calibration when FP flows are
            # still anomalous-looking after limited fine-tuning epochs.
            old_threshold = evaluator.threshold

            reconstructions = model.predict(scaled_array, verbose=0)
            reconstruction_errors = np.mean(np.abs(reconstructions - scaled_array), axis=1)

            new_mu        = float(np.mean(reconstruction_errors))
            new_sigma     = float(np.std(reconstruction_errors))
            new_threshold = new_mu + K_SIGMA * new_sigma

            # Safety cap: never raise threshold beyond 2x the original
            # (protects against miscalibration when FP samples are few)
            MAX_THRESHOLD_MULTIPLIER = 2.0
            if new_threshold > old_threshold * MAX_THRESHOLD_MULTIPLIER:
                logger.warning(
                    f"FeedbackLoop: new threshold {new_threshold:.6f} exceeds "
                    f"{MAX_THRESHOLD_MULTIPLIER}x old threshold {old_threshold:.6f}. "
                    f"Capping at {old_threshold * MAX_THRESHOLD_MULTIPLIER:.6f}. "
                    "Consider running more fine-tuning epochs or adding more FP samples."
                )
                new_threshold = old_threshold * MAX_THRESHOLD_MULTIPLIER
                # Recalculate sigma to be consistent with capped threshold
                new_sigma = (new_threshold - new_mu) / K_SIGMA if K_SIGMA > 0 else new_sigma

            evaluator.mu        = new_mu
            evaluator.sigma     = new_sigma
            evaluator.threshold = new_threshold

            logger.info(
                f"FeedbackLoop: threshold recalibrated -> τ={new_threshold:.6f} "
                f"(μ={new_mu:.6f}, σ={new_sigma:.6f})"
            )

            # ── CRITICAL FIX #2: persist the fine-tuned WEIGHTS to disk.
            # Without this, model.fit() above only mutated the in-memory
            # model — an API restart would silently reload the original,
            # untuned checkpoint and discard this entire retraining pass.
            model_path = os.getenv("HIDS_MODEL_PATH", "models/baseline_ae.keras")
            try:
                model.save(model_path)
                logger.info(f"FeedbackLoop: fine-tuned weights saved to {model_path}")
            except Exception as exc:
                # Don't fail the whole retraining pass over a save error —
                # the in-memory model is still usable for this session, but
                # the operator needs to know it will NOT survive a restart.
                logger.error(
                    f"FeedbackLoop: fine-tuning succeeded but SAVING weights "
                    f"failed ({exc}). Updated weights will be LOST on restart "
                    f"until this is resolved."
                )

            # ── CRITICAL FIX #3: persist the recalibrated threshold config.
            # DetectionEvaluator only reads config_path at __init__ / explicit
            # reload_threshold() — nothing previously wrote back to it, so
            # even a successful in-memory recalibration was invisible to any
            # future process restart.
            FeedbackLoopService._persist_threshold_config(
                evaluator, new_mu, new_sigma, new_threshold
            )

            return True

        except Exception as e:
            logger.error(f"FeedbackLoop: retraining failed — {e}", exc_info=True)
            return False

    @staticmethod
    def _persist_threshold_config(
        evaluator, mu: float, sigma: float, threshold: float
    ) -> None:
        """
        Writes the recalibrated mu/sigma/threshold back to threshold.yaml at
        evaluator.config_path, in the same schema training_validated.ipynb
        writes (feature_names included, so evaluator.py's feature-order
        safety check on the NEXT load still has something to validate against).
        """
        from src.ingestion.parser import FEATURE_NAMES

        config = {
            "mu": mu,
            "sigma": sigma,
            "threshold": threshold,
            "feature_names": FEATURE_NAMES,
            "input_dim": EXPECTED_INPUT_DIM,
            "loss": "mae",
        }
        try:
            with open(evaluator.config_path, "w") as fh:
                yaml.safe_dump(config, fh)
            logger.info(
                f"FeedbackLoop: threshold config persisted to {evaluator.config_path}"
            )
        except Exception as exc:
            logger.error(
                f"FeedbackLoop: fine-tuning and in-memory recalibration succeeded, "
                f"but WRITING threshold.yaml failed ({exc}). The new threshold is "
                f"active for this session only and will revert to the stale value "
                f"on the next restart until this is resolved."
            )

    # ── Step 3: Full orchestration ────────────────────────────────────────────
    @classmethod
    def run_feedback_cycle(
        cls,
        db: Session,
        scaler,
        evaluator,
        epochs: int = 5,
        batch_size: int = 16,
    ) -> dict:
        """
        Convenience method that runs the complete feedback cycle:
            extract → validate → fine-tune → recalibrate → persist (model + config)

        Returns a status dict suitable for the FastAPI /system/retrain response:
            {
              "status": "complete" | "skipped" | "failed",
              "samples_used": int,
              "new_threshold": float | None,
              "reason": str | None,
            }
        """
        # ── Extract ───────────────────────────────────────────────────────────
        data = cls.extract_retraining_data(db)
        if data is None:
            return {
                "status": "skipped",
                "samples_used": 0,
                "new_threshold": None,
                "reason": "No false positive data available.",
            }

        # ── Fine-tune + recalibrate + persist ────────────────────────────────
        success = cls.trigger_retraining(
            data, scaler, evaluator,
            epochs=epochs, batch_size=batch_size
        )

        if success:
            # Mark the FP alerts as retrained so they are removed from
            # the pending queue. We stamp analyst_comment with a sentinel
            # value — no schema change required.
            try:
                fps_all = get_false_positives(db)
                for alert in fps_all:
                    if not (alert.analyst_comment or "").startswith("[RETRAINED]"):
                        alert.analyst_comment = (
                            "[RETRAINED] " + (alert.analyst_comment or "")
                        ).strip()
                db.commit()
                logger.info(
                    f"FeedbackLoop: marked {len(fps_all)} FP alert(s) as retrained."
                )
            except Exception as mark_exc:
                logger.warning(f"FeedbackLoop: could not mark alerts as retrained: {mark_exc}")

            return {
                "status": "complete",
                "samples_used": len(data),
                "new_threshold": round(evaluator.threshold, 6),
                "reason": None,
            }
        else:
            return {
                "status": "failed",
                "samples_used": 0,
                "new_threshold": None,
                "reason": "Fine-tuning raised an exception — check logs.",
            }