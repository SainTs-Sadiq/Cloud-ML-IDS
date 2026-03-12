"""
feature_engineer.py
-------------------
Transforms raw AWS CloudTrail CSV logs into a numeric feature matrix
suitable for both supervised and unsupervised ML models.

Key improvements over the original:
  - Robust JSON/dict parsing with dedicated helper
  - Richer time-based, user-based, and error-based features
  - Frequency-encoding for high-cardinality columns
  - Scaler and encoder artifacts persisted alongside features
  - Clean separation between fit (training) and transform (inference) modes
"""

from __future__ import annotations

import ast
import json
import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RARE_THRESHOLD = 2          # categories seen fewer than this → "OTHER"
DEFAULT_INPUT  = "cloudtrail_logs_raw.csv"
DEFAULT_OUTPUT = "engineered_features.csv"
ARTIFACTS_FILE = "feature_artifacts.pkl"

CATEGORICAL_FEATURES = ["eventName", "aws_service", "userIdentity_type"]
NUMERICAL_FEATURES   = [
    "isError",
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "is_off_hours",          # outside 08:00–18:00
    "is_readonly",
    "eventName_freq",        # frequency-encoded: how common is this event?
    "ip_event_count",        # how many events share the same source IP?
    "user_event_count",      # how many events share the same user?
    "error_rate_by_user",    # rolling error rate per user
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_parse(raw) -> dict:
    """Safely parse a string that may be JSON or a Python dict literal."""
    if not isinstance(raw, str) or not raw.strip():
        return {}
    raw = raw.strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        pass
    return {}


def _extract_service(event_source: str) -> str:
    """'ec2.amazonaws.com' → 'ec2'"""
    if not isinstance(event_source, str):
        return "unknown"
    return event_source.split(".")[0].lower() or "unknown"


def _is_readonly(event_name: str) -> int:
    """Heuristic: events starting with Get/List/Describe are read-only."""
    readonly_prefixes = ("Get", "List", "Describe", "Head", "Check")
    return int(any(str(event_name).startswith(p) for p in readonly_prefixes))


# ---------------------------------------------------------------------------
# Core engineering logic
# ---------------------------------------------------------------------------

def _build_raw_features(df: pd.DataFrame) -> pd.DataFrame:
    """Stage 1: derive raw (pre-encoding) columns from the CloudTrail DataFrame."""
    out = pd.DataFrame(index=df.index)

    # ── User identity ─────────────────────────────────────────────────────
    identities = df["userIdentity"].fillna("{}").apply(_safe_parse)
    out["userIdentity_type"] = identities.apply(lambda x: x.get("type", "Unknown"))
    out["userIdentity_user"] = identities.apply(
        lambda x: x.get("userName") or x.get("principalId", "Unknown")
    )

    # ── Basic event info ─────────────────────────────────────────────────
    out["eventName"]   = df["eventName"].fillna("Unknown")
    out["aws_service"] = df["eventSource"].fillna("").apply(_extract_service)
    out["sourceIP"]    = df["sourceIPAddress"].fillna("0.0.0.0")

    # ── Error ────────────────────────────────────────────────────────────
    out["isError"] = df["errorCode"].apply(
        lambda x: 0 if x in (None, "None", "", np.nan) else 1
    )
    out["is_readonly"] = out["eventName"].apply(_is_readonly)

    # ── Time features ─────────────────────────────────────────────────────
    if "eventTime" in df.columns:
        times = pd.to_datetime(df["eventTime"], errors="coerce")
        out["hour_of_day"]  = times.dt.hour.fillna(0).astype(int)
        out["day_of_week"]  = times.dt.dayofweek.fillna(0).astype(int)
        out["is_weekend"]   = (out["day_of_week"] >= 5).astype(int)
        out["is_off_hours"] = (~out["hour_of_day"].between(8, 18)).astype(int)
    else:
        logger.warning("'eventTime' column not found – time features set to 0.")
        for col in ("hour_of_day", "day_of_week", "is_weekend", "is_off_hours"):
            out[col] = 0

    # ── Frequency / count-based features ─────────────────────────────────
    out["eventName_freq"]    = out["eventName"].map(out["eventName"].value_counts())
    out["ip_event_count"]    = out["sourceIP"].map(out["sourceIP"].value_counts())
    out["user_event_count"]  = out["userIdentity_user"].map(
        out["userIdentity_user"].value_counts()
    )

    # error rate per user
    user_totals = out.groupby("userIdentity_user")["isError"].transform("count")
    user_errors = out.groupby("userIdentity_user")["isError"].transform("sum")
    out["error_rate_by_user"] = (user_errors / user_totals.replace(0, np.nan)).fillna(0)

    return out


def _encode(
    df_raw: pd.DataFrame,
    encoders: Optional[dict] = None,
    scaler: Optional[StandardScaler] = None,
    fit: bool = True,
) -> tuple[pd.DataFrame, dict, StandardScaler]:
    """
    Stage 2: encode categoricals + scale numericals.

    Args:
        df_raw:   Output from _build_raw_features().
        encoders: Existing LabelEncoder dict (None → create new).
        scaler:   Existing StandardScaler (None → create new).
        fit:      If True, fit encoders/scaler on this data.
                  If False, only transform (inference mode).

    Returns:
        (encoded_df, encoders_dict, scaler)
    """
    if encoders is None:
        encoders = {}

    df = df_raw.copy()

    # ── Categorical encoding ──────────────────────────────────────────────
    for feat in CATEGORICAL_FEATURES:
        if feat not in df.columns:
            df[feat] = 0
            continue

        df[feat] = df[feat].fillna("MISSING").astype(str)

        if fit:
            # Collapse rare categories
            counts = df[feat].value_counts()
            rare   = counts[counts < RARE_THRESHOLD].index
            df[feat] = df[feat].replace(rare, "OTHER")

            le = LabelEncoder()
            df[feat] = le.fit_transform(df[feat])
            encoders[feat] = le
            logger.debug("Encoded '%s' → %d categories", feat, len(le.classes_))
        else:
            le = encoders.get(feat)
            if le is None:
                logger.warning("No encoder for '%s' – using 0.", feat)
                df[feat] = 0
            else:
                known = set(le.classes_)
                df[feat] = df[feat].apply(lambda v: v if v in known else "OTHER")
                if "OTHER" not in known:
                    df[feat] = df[feat].apply(lambda v: known.pop() if v == "OTHER" else v)
                df[feat] = le.transform(df[feat])

    # ── Numerical features ────────────────────────────────────────────────
    num_cols = [c for c in NUMERICAL_FEATURES if c in df.columns]
    df[num_cols] = df[num_cols].fillna(0)

    if fit:
        scaler = StandardScaler()
        df[num_cols] = scaler.fit_transform(df[num_cols])
    else:
        if scaler is not None:
            df[num_cols] = scaler.transform(df[num_cols])

    # Keep only model-ready columns
    model_cols = CATEGORICAL_FEATURES + num_cols
    model_cols = [c for c in model_cols if c in df.columns]

    return df[model_cols], encoders, scaler


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def engineer_features(
    input_file: str = DEFAULT_INPUT,
    output_file: str = DEFAULT_OUTPUT,
    artifacts_file: str = ARTIFACTS_FILE,
    fit: bool = True,
) -> tuple[pd.DataFrame, dict, StandardScaler]:
    """
    Full feature engineering pipeline.

    Args:
        input_file:     Path to raw CloudTrail CSV.
        output_file:    Where to write the encoded feature CSV.
        artifacts_file: Where to persist encoders + scaler.
        fit:            True = training mode (fit + save artifacts).
                        False = inference mode (load + transform only).

    Returns:
        (features_df, encoders, scaler)
    """
    logger.info("Feature engineering started (fit=%s) …", fit)

    # Load raw data
    try:
        df = pd.read_csv(input_file)
    except FileNotFoundError:
        logger.error("Input file not found: %s", input_file)
        return pd.DataFrame(), {}, StandardScaler()

    if df.empty:
        logger.warning("Input file is empty.")
        return pd.DataFrame(), {}, StandardScaler()

    logger.info("Loaded %d rows from %s", len(df), input_file)

    # Stage 1
    df_raw = _build_raw_features(df)

    # Stage 2
    if not fit:
        artifacts_path = Path(artifacts_file)
        if artifacts_path.exists():
            with open(artifacts_path, "rb") as fh:
                saved = pickle.load(fh)
            encoders = saved["encoders"]
            scaler   = saved["scaler"]
            logger.info("Loaded feature artifacts from %s", artifacts_file)
        else:
            logger.warning("No artifacts found – falling back to fit mode.")
            fit = True
            encoders, scaler = None, None
    else:
        encoders, scaler = None, None

    features_df, encoders, scaler = _encode(df_raw, encoders, scaler, fit=fit)

    # Persist
    if fit:
        features_df.to_csv(output_file, index=False)
        logger.info("Features saved → %s  shape=%s", output_file, features_df.shape)

        with open(artifacts_file, "wb") as fh:
            pickle.dump({"encoders": encoders, "scaler": scaler}, fh)
        logger.info("Artifacts saved → %s", artifacts_file)

    return features_df, encoders, scaler


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    features, _, _ = engineer_features()
    if not features.empty:
        print(f"\n{'='*50}")
        print(f"  Events processed : {len(features)}")
        print(f"  Feature count    : {len(features.columns)}")
        print(f"  Feature names    : {list(features.columns)}")
        print(f"{'='*50}")
        print(features.head(3).to_string())
    else:
        print("No features produced. Check input data.")
