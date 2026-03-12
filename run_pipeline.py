"""
scripts/run_pipeline.py
-----------------------
End-to-end IDS pipeline orchestrator.

Steps:
  1. Feature engineering  (feature_engineer.py)
  2. Unsupervised detection (detect_unsupervised.py)
  3. Supervised training    (train_supervised.py)   [optional]
  4. Alert generation       (generate_alerts.py)
  5. SOC dispatch           (wazuh_integration.py)  [optional]

Usage:
    python scripts/run_pipeline.py                  # full pipeline
    python scripts/run_pipeline.py --skip-train     # skip RF training
    python scripts/run_pipeline.py --skip-soc       # skip SOC dispatch
    python scripts/run_pipeline.py --input my_logs.csv
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# Ensure core modules are importable from any working directory
sys.path.insert(0, str(Path(__file__).parent.parent / "core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "soc"))

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------

def step(name: str):
    """Print a step banner."""
    print(f"\n{'─'*55}")
    print(f"  STEP: {name}")
    print(f"{'─'*55}")


def run_pipeline(
    input_csv: str = "cloudtrail_logs_raw.csv",
    skip_train: bool = False,
    skip_soc:   bool = False,
) -> bool:

    start = time.perf_counter()

    # ── 1. Feature engineering ────────────────────────────────────────────
    step("1/4  Feature Engineering")
    from feature_engineer import engineer_features
    features, encoders, scaler = engineer_features(input_file=input_csv)
    if features.empty:
        logger.error("Feature engineering produced no output. Aborting.")
        return False
    print(f"  ✓  {len(features)} events × {len(features.columns)} features")

    # ── 2. Unsupervised detection ─────────────────────────────────────────
    step("2/4  Isolation Forest – Anomaly Detection")
    from detect_unsupervised import detect_anomalies
    iso_results = detect_anomalies()
    if iso_results.empty:
        logger.error("Isolation Forest produced no results. Aborting.")
        return False
    n_anomalies = iso_results["is_anomaly"].sum()
    print(f"  ✓  {n_anomalies} anomalies detected ({len(iso_results)} total events)")

    # ── 3. Supervised training (optional) ─────────────────────────────────
    rf_model = None
    if not skip_train:
        step("3/4  Random Forest – Supervised Training")
        from train_supervised import train_random_forest
        rf_model = train_random_forest(raw_csv=input_csv)
        if rf_model:
            print("  ✓  Random Forest trained and saved")
        else:
            print("  ℹ  Training skipped (insufficient labelled samples) – using ISO only")
    else:
        print("\n  ⟳  Step 3/4 skipped (--skip-train)")

    # ── 4. Alert generation ───────────────────────────────────────────────
    step("4/4  Alert Generation")
    from generate_alerts import generate_alerts
    alerts = generate_alerts(raw_csv=input_csv)
    print(f"  ✓  {len(alerts)} alerts written to alerts.json / alerts.jsonl")

    # ── 5. SOC dispatch ───────────────────────────────────────────────────
    if not skip_soc and alerts:
        step("5/5  SOC Dispatch → Wazuh")
        from wazuh_integration import dispatch_alerts
        dispatch_alerts(alerts)
    elif skip_soc:
        print("\n  ⟳  SOC dispatch skipped (--skip-soc)")

    elapsed = time.perf_counter() - start
    print(f"\n{'='*55}")
    print(f"  ✅  Pipeline complete in {elapsed:.1f}s")
    print(f"  📁  alerts.json    → human-readable alerts")
    print(f"  📁  alerts.jsonl   → streaming format")
    print(f"  🌐  Dashboard      → python dashboard/server.py")
    print(f"{'='*55}\n")
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    parser = argparse.ArgumentParser(description="Cloud ML IDS Pipeline")
    parser.add_argument("--input",       default="cloudtrail_logs_raw.csv",
                        help="Path to raw CloudTrail CSV (default: cloudtrail_logs_raw.csv)")
    parser.add_argument("--skip-train",  action="store_true",
                        help="Skip Random Forest training step")
    parser.add_argument("--skip-soc",    action="store_true",
                        help="Skip SOC dispatch step")
    args = parser.parse_args()

    ok = run_pipeline(
        input_csv=args.input,
        skip_train=args.skip_train,
        skip_soc=args.skip_soc,
    )
    sys.exit(0 if ok else 1)
