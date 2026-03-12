"""
detect_unsupervised.py
----------------------
Unsupervised anomaly detection using Isolation Forest.
Designed to run without labelled data as a first-pass screening layer.

Improvements over the original:
  - Model persistence so it can score new events without re-training
  - Configurable contamination via CLI / env var
  - Returns results DataFrame and saved artefact
  - Optional matplotlib plot (skipped if display is unavailable)
"""

from __future__ import annotations

import logging
import os
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

DEFAULT_INPUT        = "engineered_features.csv"
DEFAULT_RESULTS      = "anomaly_detection_results.csv"
DEFAULT_MODEL_FILE   = "isolation_forest_model.pkl"
DEFAULT_CONTAMINATION = float(os.getenv("IDS_CONTAMINATION", "0.05"))


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_isolation_forest(
    input_file: str = DEFAULT_INPUT,
    model_file: str = DEFAULT_MODEL_FILE,
    contamination: float = DEFAULT_CONTAMINATION,
    n_estimators: int = 200,
    random_state: int = 42,
) -> IsolationForest:
    """Fit an Isolation Forest and persist the model."""
    df = pd.read_csv(input_file)
    if df.empty:
        raise ValueError(f"Feature file is empty: {input_file}")

    logger.info("Training Isolation Forest on %d samples …", len(df))
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples="auto",
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(df)

    with open(model_file, "wb") as fh:
        pickle.dump(model, fh)
    logger.info("Model saved → %s", model_file)
    return model


# ---------------------------------------------------------------------------
# Detection / scoring
# ---------------------------------------------------------------------------

def detect_anomalies(
    input_file: str = DEFAULT_INPUT,
    results_file: str = DEFAULT_RESULTS,
    model_file: str = DEFAULT_MODEL_FILE,
    contamination: float = DEFAULT_CONTAMINATION,
    save_plot: bool = True,
) -> pd.DataFrame:
    """
    Score all events in ``input_file`` and flag anomalies.

    Returns a DataFrame with ``anomaly_score`` and ``is_anomaly`` columns
    appended to the original features.
    """
    df = pd.read_csv(input_file)
    if df.empty:
        logger.warning("Input file is empty – nothing to score.")
        return pd.DataFrame()

    # Load or train model
    model_path = Path(model_file)
    if model_path.exists():
        with open(model_path, "rb") as fh:
            model: IsolationForest = pickle.load(fh)
        logger.info("Loaded model from %s", model_file)
    else:
        logger.info("No saved model found – training now.")
        model = train_isolation_forest(
            input_file, model_file, contamination=contamination
        )

    # Score
    raw_scores  = model.decision_function(df)   # lower = more anomalous
    predictions = model.predict(df)             # -1 = anomaly, 1 = normal

    results = df.copy()
    results["anomaly_score"] = np.round(raw_scores, 6)
    results["is_anomaly"]    = (predictions == -1).astype(int)

    n_anomalies = results["is_anomaly"].sum()
    logger.info(
        "Detected %d anomalies out of %d events (%.1f%%)",
        n_anomalies, len(results), 100 * n_anomalies / max(len(results), 1),
    )

    results.to_csv(results_file, index=False)
    logger.info("Results saved → %s", results_file)

    # Optional plot
    if save_plot:
        _save_plot(raw_scores)

    return results


def score_single_event(features: dict, model_file: str = DEFAULT_MODEL_FILE) -> float:
    """
    Score a single event dict.  Returns the raw anomaly score
    (negative = more anomalous; positive = normal).
    """
    with open(model_file, "rb") as fh:
        model: IsolationForest = pickle.load(fh)
    row = pd.DataFrame([features])
    return float(model.decision_function(row)[0])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _save_plot(scores: np.ndarray, path: str = "anomaly_scores_plot.png") -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.hist(scores, bins=40, edgecolor="black", alpha=0.7, color="#4A90D9")
        ax.axvline(0, color="#E74C3C", linestyle="--", linewidth=1.5, label="Approx. threshold")
        ax.set_title("Isolation Forest – Anomaly Score Distribution", fontsize=14)
        ax.set_xlabel("Score  (lower = more anomalous)")
        ax.set_ylabel("Event Count")
        ax.legend()
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(path, dpi=120)
        plt.close(fig)
        logger.info("Score distribution plot saved → %s", path)
    except Exception as exc:
        logger.debug("Could not save plot: %s", exc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    results = detect_anomalies()
    if not results.empty:
        print(f"\nAnomaly detection complete.")
        print(f"  Total events : {len(results)}")
        print(f"  Anomalies    : {results['is_anomaly'].sum()}")
        print(f"  Score range  : [{results['anomaly_score'].min():.4f}, "
              f"{results['anomaly_score'].max():.4f}]")
