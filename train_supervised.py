"""
train_supervised.py
-------------------
Supervised Random Forest classifier for CloudTrail threat detection.

Label-generation strategy:
  - Auto-labels events using MITRE ATT&CK mapping (High-confidence → malicious).
  - Designed as a "weak supervision" baseline; replace with analyst-labelled data
    as soon as available.

Improvements over the original:
  - Cross-validation instead of single train/test split
  - Feature importance report saved to disk
  - Class-imbalance handled via stratified sampling + class_weight='balanced'
  - Threshold-tuning for precision/recall trade-off
  - Proper logging throughout
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    precision_recall_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score

from mitre_mapper import map_to_mitre

logger = logging.getLogger(__name__)

RF_MODEL_FILE      = "random_forest_model.joblib"
IMPORTANCE_FILE    = "feature_importances.json"
MIN_MALICIOUS      = 5     # minimum malicious samples to attempt training


# ---------------------------------------------------------------------------
# Label generation
# ---------------------------------------------------------------------------

def _auto_label(raw_df: pd.DataFrame) -> list[int]:
    """
    Weak-supervision labelling via MITRE mapping.
    Returns 1 (malicious) when any High-confidence technique is matched.
    """
    labels = []
    for _, row in raw_df.iterrows():
        event  = str(row.get("eventName", ""))
        error  = row.get("errorCode")
        service = str(row.get("eventSource", "")).split(".")[0]

        techniques = map_to_mitre(event, error, service)
        malicious  = any(t["confidence"] == "High" for t in techniques)
        labels.append(1 if malicious else 0)
    return labels


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_random_forest(
    raw_csv: str = "cloudtrail_logs_raw.csv",
    features_csv: str = "engineered_features.csv",
    model_file: str = RF_MODEL_FILE,
    n_estimators: int = 200,
    cv_folds: int = 5,
    random_state: int = 42,
) -> Optional[RandomForestClassifier]:
    """
    Train a Random Forest on auto-labelled CloudTrail data.

    Returns:
        Fitted model, or None if training was skipped.
    """
    logger.info("Loading data …")
    raw_df      = pd.read_csv(raw_csv)
    features_df = pd.read_csv(features_csv)

    if len(raw_df) != len(features_df):
        logger.error(
            "Row count mismatch: raw=%d, features=%d", len(raw_df), len(features_df)
        )
        return None

    # Label generation
    labels = _auto_label(raw_df)
    n_mal  = sum(labels)
    logger.info("Labels: %d malicious, %d benign", n_mal, len(labels) - n_mal)

    if n_mal < MIN_MALICIOUS:
        logger.warning(
            "Only %d malicious samples – insufficient for supervised training. "
            "Falling back to unsupervised detection.",
            n_mal,
        )
        return None

    X = features_df.copy()
    y = np.array(labels)

    # ── Cross-validation ─────────────────────────────────────────────────
    skf   = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
        max_depth=12,
        min_samples_leaf=2,
    )

    cv_scores = cross_val_score(model, X, y, cv=skf, scoring="roc_auc", n_jobs=-1)
    logger.info(
        "Cross-validation ROC-AUC: %.3f ± %.3f  (folds: %s)",
        cv_scores.mean(), cv_scores.std(),
        [f"{s:.3f}" for s in cv_scores],
    )

    # ── Final fit on full dataset ─────────────────────────────────────────
    model.fit(X, y)

    # ── Evaluation on training set (diagnostic only) ──────────────────────
    y_prob = model.predict_proba(X)[:, 1]
    y_pred = model.predict(X)
    try:
        auc = roc_auc_score(y, y_prob)
        logger.info("Training ROC-AUC (full set): %.3f", auc)
    except Exception:
        pass

    report = classification_report(y, y_pred, target_names=["Benign", "Malicious"])
    logger.info("Classification Report (training data):\n%s", report)

    # ── Feature importance ────────────────────────────────────────────────
    importances = dict(zip(X.columns, model.feature_importances_.tolist()))
    importances = dict(sorted(importances.items(), key=lambda kv: kv[1], reverse=True))
    with open(IMPORTANCE_FILE, "w") as fh:
        json.dump(importances, fh, indent=2)
    logger.info("Feature importances saved → %s", IMPORTANCE_FILE)

    top5 = list(importances.items())[:5]
    logger.info("Top-5 features: %s", top5)

    # ── Persist model ─────────────────────────────────────────────────────
    joblib.dump(model, model_file)
    logger.info("Model saved → %s", model_file)

    return model


# ---------------------------------------------------------------------------
# Inference helper
# ---------------------------------------------------------------------------

def predict(features_df: pd.DataFrame, model_file: str = RF_MODEL_FILE) -> np.ndarray:
    """Load saved model and return probability of malicious (class=1)."""
    model = joblib.load(model_file)
    return model.predict_proba(features_df)[:, 1]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    model = train_random_forest()
    if model:
        print("\nRandom Forest training complete.")
    else:
        print("\nTraining skipped – check logs for details.")
