"""
generate_alerts.py
------------------
Merges Isolation Forest and Random Forest results, maps each flagged event
to MITRE ATT&CK techniques, assigns severity, and writes structured alerts.

Improvements over the original:
  - Single module (removes duplicate generate_enhanced_alerts.py)
  - Alert schema is fully structured with severity, tactic, and model metadata
  - Deduplication by (eventName, sourceIP, 5-minute window)
  - Alert ID generated deterministically for idempotent re-runs
  - Outputs both JSON (human-readable) and JSONL (streaming-friendly)
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd

from mitre_mapper import map_to_mitre, get_alert_level, get_highest_severity

logger = logging.getLogger(__name__)

ALERTS_JSON  = "alerts.json"
ALERTS_JSONL = "alerts.jsonl"
RF_MODEL     = "random_forest_model.joblib"
ISO_RESULTS  = "anomaly_detection_results.csv"


# ---------------------------------------------------------------------------
# Alert schema builder
# ---------------------------------------------------------------------------

def _alert_id(timestamp: str, event_name: str, source_ip: str) -> str:
    """Deterministic hex ID so re-runs don't produce duplicate rows in the SIEM."""
    raw = f"{timestamp}|{event_name}|{source_ip}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _build_alert(row: pd.Series, techniques: list[dict]) -> dict:
    ts = str(row.get("eventTime", datetime.now(timezone.utc).isoformat()))
    ev = str(row.get("eventName", "Unknown"))
    ip = str(row.get("sourceIPAddress", "N/A"))

    return {
        "alert_id":    _alert_id(ts, ev, ip),
        "timestamp":   ts,
        "event_name":  ev,
        "source_ip":   ip,
        "aws_region":  str(row.get("awsRegion", "N/A")),
        "user_identity": str(row.get("userIdentity", "N/A"))[:200],
        "event_source":  str(row.get("eventSource", "N/A")),
        "error_code":    str(row.get("errorCode", "")) or None,
        "anomaly_score": round(float(row.get("anomaly_score", 0.0)), 6),
        "rf_score":      round(float(row.get("rf_score", 0.0)), 6),
        "severity":      get_highest_severity(techniques),
        "alert_level":   get_alert_level(techniques),
        "mitre_techniques": techniques,
        "model_flags": {
            "isolation_forest": bool(row.get("is_anomaly_iso", 0)),
            "random_forest":    bool(row.get("is_anomaly_rf", 0)),
        },
        "raw_event": {
            k: _serialize(v)
            for k, v in row.items()
            if k not in {"anomaly_score", "is_anomaly_iso", "is_anomaly_rf",
                         "rf_score", "is_anomaly_combined"}
            and _is_meaningful(v)
        },
    }


def _serialize(v: Any) -> Any:
    if isinstance(v, float) and np.isnan(v):
        return None
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating,)):
        return float(v)
    return v


def _is_meaningful(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, float) and np.isnan(v):
        return False
    if v in ("", "nan", "None"):
        return False
    return True


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup(alerts: list[dict], window_minutes: int = 5) -> list[dict]:
    """
    Remove duplicate alerts for the same (event_name, source_ip) within
    a rolling time window.
    """
    seen: set[str] = set()
    unique: list[dict] = []
    for a in alerts:
        try:
            t   = pd.Timestamp(a["timestamp"]).floor(f"{window_minutes}min")
            key = f"{a['event_name']}|{a['source_ip']}|{t}"
        except Exception:
            key = a["alert_id"]
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_alerts(
    raw_csv: str = "cloudtrail_logs_raw.csv",
    iso_results_csv: str = ISO_RESULTS,
    features_csv: str = "engineered_features.csv",
    rf_model_file: str = RF_MODEL,
    output_json: str = ALERTS_JSON,
    output_jsonl: str = ALERTS_JSONL,
    dedup_window: int = 5,
    iso_threshold: float = -999.0,  # keep all iso-flagged events by default
) -> list[dict]:
    """
    Build the full alert list from detection results.

    Args:
        raw_csv:         Original CloudTrail CSV.
        iso_results_csv: Output of detect_unsupervised.py.
        features_csv:    Encoded feature matrix.
        rf_model_file:   Path to trained Random Forest (optional).
        output_json:     Human-readable alert file.
        output_jsonl:    Streaming JSONL alert file.
        dedup_window:    Minutes window for deduplication.
        iso_threshold:   Score cut-off for Isolation Forest (-inf keeps all).

    Returns:
        List of alert dicts.
    """
    logger.info("Loading data …")
    raw_df  = pd.read_csv(raw_csv)
    iso_df  = pd.read_csv(iso_results_csv)

    merged = raw_df.copy()
    merged["anomaly_score"]  = iso_df["anomaly_score"]
    merged["is_anomaly_iso"] = iso_df["is_anomaly"]
    merged["rf_score"]       = 0.0
    merged["is_anomaly_rf"]  = 0

    # ── Random Forest scoring (optional) ──────────────────────────────────
    try:
        rf      = joblib.load(rf_model_file)
        feat_df = pd.read_csv(features_csv)
        probs   = rf.predict_proba(feat_df)[:, 1]
        preds   = (probs >= 0.5).astype(int)
        merged["rf_score"]      = probs
        merged["is_anomaly_rf"] = preds
        logger.info("Random Forest predictions applied.")
    except FileNotFoundError:
        logger.info("No RF model found – using Isolation Forest only.")
    except Exception as exc:
        logger.warning("RF scoring failed: %s", exc)

    # ── Combined flag ─────────────────────────────────────────────────────
    merged["is_anomaly_combined"] = (
        (merged["is_anomaly_iso"] == 1) | (merged["is_anomaly_rf"] == 1)
    )
    flagged = merged[merged["is_anomaly_combined"]].copy()
    logger.info("%d / %d events flagged as anomalous.", len(flagged), len(merged))

    # ── Build alerts ──────────────────────────────────────────────────────
    alerts: list[dict] = []
    for _, row in flagged.iterrows():
        service    = str(row.get("eventSource", "")).split(".")[0]
        techniques = map_to_mitre(
            str(row.get("eventName", "")),
            row.get("errorCode"),
            service,
        )
        alerts.append(_build_alert(row, techniques))

    # Sort by severity descending, then timestamp
    alerts.sort(key=lambda a: (-a["severity"], a["timestamp"]))

    # Deduplication
    alerts = _dedup(alerts, window_minutes=dedup_window)
    logger.info("%d unique alerts after deduplication.", len(alerts))

    # ── Persist ───────────────────────────────────────────────────────────
    with open(output_json, "w") as fh:
        json.dump(alerts, fh, indent=2, default=str)

    with open(output_jsonl, "w") as fh:
        for a in alerts:
            fh.write(json.dumps(a, default=str) + "\n")

    logger.info("Alerts written → %s  |  %s", output_json, output_jsonl)
    _print_summary(alerts)
    return alerts


def _print_summary(alerts: list[dict]) -> None:
    from collections import Counter
    levels = Counter(a["alert_level"] for a in alerts)
    print("\n" + "=" * 50)
    print(f"  ALERT SUMMARY  ({len(alerts)} unique alerts)")
    print("=" * 50)
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if levels[level]:
            print(f"  {level:10s}  {levels[level]}")
    tactics = Counter(
        t["tactic"]
        for a in alerts
        for t in a.get("mitre_techniques", [])
    )
    if tactics:
        print("\n  Top Tactics:")
        for tac, cnt in tactics.most_common(5):
            print(f"    {tac:<35s} {cnt}")
    print("=" * 50)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    generate_alerts()
