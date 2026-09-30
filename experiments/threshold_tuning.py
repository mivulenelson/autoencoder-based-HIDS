import argparse
import os
import sys
import numpy as np
import pandas as pd
import yaml
import joblib
import matplotlib.pyplot as plt
import tensorflow as tf

# Add project root to path when running as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detection.layers.dense_block import DetectionBlock


def load_model(model_path: str) -> tf.keras.Model:
    return tf.keras.models.load_model(
        model_path,
        custom_objects={"DetectionBlock": DetectionBlock},
    )


def compute_mae_errors(model, scaled_data: np.ndarray) -> np.ndarray:
    """Vectorised MAE reconstruction error over the entire dataset."""
    reconstructions = model.predict(scaled_data, verbose=1, batch_size=256)
    return np.mean(np.abs(reconstructions - scaled_data), axis=1)


def plot_error_distribution(errors: np.ndarray, threshold: float, output_path: str = None):
    """Visualises the reconstruction error distribution and marks the threshold."""
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.hist(errors, bins=100, color="steelblue", edgecolor="white", alpha=0.85)
    ax.axvline(threshold, color="crimson", linewidth=2, linestyle="--",
               label=f"Threshold = {threshold:.6f}")
    ax.set_xlabel("MAE Reconstruction Error")
    ax.set_ylabel("Flow Count")
    ax.set_title("Autoencoder Reconstruction Error Distribution (Benign Traffic)")
    ax.legend()
    plt.tight_layout()
    if output_path:
        plt.savefig(output_path, dpi=150)
        print(f"Plot saved to {output_path}")
    plt.show()


def save_threshold(threshold: float, output_path: str, extra_stats: dict = None):
    """Writes the threshold (and optional diagnostics) to a YAML config file."""
    config = {
        "detection_params": {
            "threshold": round(float(threshold), 6),
            "calibration_stats": extra_stats or {},
        }
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    print(f"Threshold {threshold:.6f} saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Calibrate HIDS detection threshold.")
    parser.add_argument("--data",   required=True,  help="Path to benign flows CSV (22 features, no header row label issues)")
    parser.add_argument("--model",  default="models/baseline_ae.keras")
    parser.add_argument("--scaler", default="models/scaler.pkl")
    parser.add_argument("--k",      type=float, default=3.0,
                        help="Sensitivity multiplier: threshold = mean + k * std")
    parser.add_argument("--output", default="configs/threshold.yaml")
    parser.add_argument("--plot",   default="experiments/error_distribution.png")
    args = parser.parse_args()

    # ---- Load data ----
    print(f"Loading benign data from {args.data}...")
    df = pd.read_csv(args.data, header=None)
    assert df.shape[1] == 22, f"Expected 22 features, got {df.shape[1]}"
    raw = df.values.astype(np.float64)
    print(f"  {len(raw)} benign flows loaded.")

    # ---- Scale ----
    print(f"Loading scaler from {args.scaler}...")
    scaler = joblib.load(args.scaler)
    scaled = scaler.transform(raw)

    # ---- Model forward pass ----
    print(f"Loading model from {args.model}...")
    model = load_model(args.model)
    errors = compute_mae_errors(model, scaled)

    # ---- Compute threshold ----
    mean_err = float(np.mean(errors))
    std_err  = float(np.std(errors))
    p95      = float(np.percentile(errors, 95))
    p99      = float(np.percentile(errors, 99))
    threshold = mean_err + args.k * std_err

    print(f"\n--- Reconstruction Error Statistics ---")
    print(f"  Mean:       {mean_err:.6f}")
    print(f"  Std Dev:    {std_err:.6f}")
    print(f"  95th pct:   {p95:.6f}")
    print(f"  99th pct:   {p99:.6f}")
    print(f"  k={args.k}  =>  Threshold = {threshold:.6f}")

    # ---- Plot ----
    plot_error_distribution(errors, threshold, output_path=args.plot)

    # ---- Save ----
    save_threshold(threshold, args.output, extra_stats={
        "mean": round(mean_err, 6),
        "std":  round(std_err, 6),
        "p95":  round(p95, 6),
        "p99":  round(p99, 6),
        "k":    args.k,
        "n_samples": len(errors),
    })


if __name__ == "__main__":
    main()