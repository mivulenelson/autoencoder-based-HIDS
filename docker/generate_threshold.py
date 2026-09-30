#!/usr/bin/env python3

import argparse
import os
import sys

import numpy as np
import yaml
import joblib

FEATURE_NAMES = [
    "flow_duration", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max",
    "fwd_iat_total", "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min",
    "fwd_pkt_len_max", "total_fwd_bytes", "flow_pkts_per_sec", "flow_bytes_per_sec",
    "pkt_len_variance", "burst_ratio", "active_time_ratio", "pkt_count",
    "unique_ttl_count", "ttl_mean", "tcp_flag_ratio", "has_udp", "has_tcp",
]
INPUT_DIM = 22
K_SIGMA   = 2.0


def main():
    parser = argparse.ArgumentParser(description="Generate threshold.yaml for HIDS")
    parser.add_argument("--model",  default="models/baseline_ae.keras",
                        help="Path to trained Keras model")
    parser.add_argument("--scaler", default="models/scaler.pkl",
                        help="Path to fitted MinMaxScaler")
    parser.add_argument("--mu",     type=float, default=None,
                        help="Override: known mu from notebook")
    parser.add_argument("--sigma",  type=float, default=None,
                        help="Override: known sigma from notebook")
    parser.add_argument("--n-samples", type=int, default=500,
                        help="Synthetic samples to estimate mu/sigma if not provided")
    args = parser.parse_args()

    # ── Validate paths ────────────────────────────────────────────────────────
    for path in (args.model, args.scaler):
        if not os.path.exists(path):
            print(f"ERROR: file not found: {path}", file=sys.stderr)
            sys.exit(1)

    print(f"Loading model   : {args.model}")
    print(f"Loading scaler  : {args.scaler}")

    import tensorflow as tf
    try:
        from src.detection.layers.dense_block import DetectionBlock
        custom = {"DetectionBlock": DetectionBlock}
    except ImportError:
        custom = {}

    model  = tf.keras.models.load_model(args.model, custom_objects=custom)
    scaler = joblib.load(args.scaler)

    # Verify dimensions
    actual_in  = model.input_shape[-1]
    actual_out = model.output_shape[-1]
    if actual_in != INPUT_DIM or actual_out != INPUT_DIM:
        print(f"ERROR: model shape {actual_in}→{actual_out}, expected {INPUT_DIM}→{INPUT_DIM}",
              file=sys.stderr)
        sys.exit(1)
    print(f"Model verified  : {actual_in}→{actual_out}  params={model.count_params():,}")

    if args.mu is not None and args.sigma is not None:
        # ── User supplied exact values from notebook ───────────────────────
        mu    = float(args.mu)
        sigma = float(args.sigma)
        print(f"Using supplied  : mu={mu:.6f}  sigma={sigma:.6f}")
    else:
        # ── Estimate from synthetic normal samples ─────────────────────────
        print(f"Estimating mu/sigma from {args.n_samples} synthetic samples…")

        # Generate samples at the scaler's fitted range boundaries
        # scaler.data_min_ and data_max_ give us the training data range
        try:
            lo = scaler.data_min_
            hi = scaler.data_max_
        except AttributeError:
            lo = np.zeros(INPUT_DIM)
            hi = np.ones(INPUT_DIM)

        rng     = np.random.default_rng(42)
        samples = rng.uniform(lo, hi, size=(args.n_samples, INPUT_DIM)).astype(np.float32)
        scaled  = scaler.transform(samples)

        recon   = model.predict(scaled, verbose=0)
        errors  = np.mean(np.abs(recon - scaled), axis=1)

        mu    = float(np.mean(errors))
        sigma = float(np.std(errors))
        print(f"Estimated       : mu={mu:.6f}  sigma={sigma:.6f}")

    threshold = mu + K_SIGMA * sigma
    print(f"Threshold (tau) : {threshold:.6f}  (= mu + {K_SIGMA}*sigma)")

    config = {
        "mu":            round(mu, 6),
        "sigma":         round(sigma, 6),
        "threshold":     round(threshold, 6),
        "feature_names": FEATURE_NAMES,
        "input_dim":     INPUT_DIM,
        "loss":          "mae",
    }

    # Write to both locations
    os.makedirs("configs", exist_ok=True)
    os.makedirs("models",  exist_ok=True)

    for out_path in ("configs/threshold.yaml", "models/threshold.yaml"):
        with open(out_path, "w") as f:
            yaml.safe_dump(config, f, default_flow_style=False)
        print(f"Written         : {out_path}")

    print("\n✓  threshold.yaml generated successfully.")
    print(f"   tau = {threshold:.6f}")
    print("   Copy both files into the Docker volume before running the container.")


if __name__ == "__main__":
    main()