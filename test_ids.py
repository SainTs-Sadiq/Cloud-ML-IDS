"""
tests/test_ids.py
-----------------
Unit and integration tests for the Cloud ML IDS system.
Run with:  pytest tests/test_ids.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

# Ensure core + soc are importable
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "soc"))


# ════════════════════════════════════════════════════════
# mitre_mapper
# ════════════════════════════════════════════════════════

from mitre_mapper import map_to_mitre, get_alert_level, get_highest_severity


class TestMitreMapper:

    def test_brute_force_detected(self):
        techs = map_to_mitre("ConsoleLogin", "Failed", "signin")
        ids = [t["technique_id"] for t in techs]
        assert "T1110.001" in ids

    def test_stop_logging_critical(self):
        techs = map_to_mitre("StopLogging", None, "cloudtrail")
        assert get_highest_severity(techs) >= 9

    def test_delete_trail_critical(self):
        techs = map_to_mitre("DeleteTrail", None, "cloudtrail")
        assert get_alert_level(techs) == "CRITICAL"

    def test_list_users_discovery(self):
        techs = map_to_mitre("ListUsers", None, "iam")
        assert any(t["tactic"] == "Discovery" for t in techs)

    def test_create_access_key_persistence(self):
        techs = map_to_mitre("CreateAccessKey", None, "iam")
        assert any(t["tactic"] == "Persistence" for t in techs)

    def test_s3_service_filter(self):
        # GetObject should trigger Exfiltration for s3, not for ec2
        techs_s3 = map_to_mitre("GetObject", None, "s3")
        techs_ec2 = map_to_mitre("GetObject", None, "ec2")
        s3_ids  = {t["technique_id"] for t in techs_s3}
        ec2_ids = {t["technique_id"] for t in techs_ec2}
        assert "T1530" in s3_ids
        assert "T1530" not in ec2_ids

    def test_empty_event_no_crash(self):
        techs = map_to_mitre("", None, "")
        assert isinstance(techs, list)

    def test_severity_sorted_descending(self):
        techs = map_to_mitre("StopLogging", None, "cloudtrail")
        if len(techs) > 1:
            sevs = [t["severity"] for t in techs]
            assert sevs == sorted(sevs, reverse=True)

    def test_alert_levels(self):
        assert get_alert_level([{"severity": 10}]) == "CRITICAL"
        assert get_alert_level([{"severity": 7}])  == "HIGH"
        assert get_alert_level([{"severity": 4}])  == "MEDIUM"
        assert get_alert_level([{"severity": 2}])  == "LOW"
        assert get_alert_level([])                 == "LOW"

    def test_no_duplicate_techniques(self):
        # ConsoleLogin with no error → multiple rules match, but IDs deduplicated
        techs = map_to_mitre("ConsoleLogin", None, "signin")
        ids   = [t["technique_id"] for t in techs]
        assert len(ids) == len(set(ids))


# ════════════════════════════════════════════════════════
# feature_engineer
# ════════════════════════════════════════════════════════

from feature_engineer import engineer_features, _safe_parse, _extract_service


class TestFeatureEngineer:

    def test_safe_parse_json(self):
        r = _safe_parse('{"type": "IAMUser"}')
        assert r["type"] == "IAMUser"

    def test_safe_parse_dict_literal(self):
        r = _safe_parse("{'type': 'Root'}")
        assert r["type"] == "Root"

    def test_safe_parse_empty(self):
        assert _safe_parse("") == {}
        assert _safe_parse(None) == {}
        assert _safe_parse("invalid {{{") == {}

    def test_extract_service(self):
        assert _extract_service("s3.amazonaws.com")     == "s3"
        assert _extract_service("iam.amazonaws.com")    == "iam"
        assert _extract_service("cloudtrail.amazonaws.com") == "cloudtrail"
        assert _extract_service("")                     == "unknown"
        assert _extract_service(None)                  == "unknown"

    def test_engineer_from_synthetic(self, tmp_path):
        """Run feature engineering on synthetic data without errors."""
        from scripts.simulate_attacks import generate_events, FIELDNAMES
        import csv

        events   = generate_events()
        csv_path = tmp_path / "test_logs.csv"
        with open(csv_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(events)

        feat_csv  = str(tmp_path / "features.csv")
        art_file  = str(tmp_path / "artifacts.pkl")
        features, encoders, scaler = engineer_features(
            input_file=str(csv_path),
            output_file=feat_csv,
            artifacts_file=art_file,
        )
        assert not features.empty
        assert len(features) == len(events)
        assert len(encoders) > 0


# ════════════════════════════════════════════════════════
# detect_unsupervised
# ════════════════════════════════════════════════════════

from detect_unsupervised import detect_anomalies, train_isolation_forest


class TestDetectUnsupervised:

    def test_detect_on_synthetic(self, tmp_path):
        """Isolation Forest should flag at least some events."""
        from scripts.simulate_attacks import generate_events, FIELDNAMES
        import csv

        events   = generate_events()
        csv_path = tmp_path / "logs.csv"
        with open(csv_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(events)

        # Feature engineer first
        feat_csv = str(tmp_path / "features.csv")
        art_file = str(tmp_path / "artifacts.pkl")
        from feature_engineer import engineer_features
        engineer_features(str(csv_path), feat_csv, art_file)

        model_file = str(tmp_path / "iso.pkl")
        results_file = str(tmp_path / "results.csv")
        results = detect_anomalies(
            input_file=feat_csv,
            results_file=results_file,
            model_file=model_file,
            save_plot=False,
        )
        assert not results.empty
        assert "is_anomaly" in results.columns
        assert results["is_anomaly"].sum() > 0


# ════════════════════════════════════════════════════════
# generate_alerts
# ════════════════════════════════════════════════════════

from generate_alerts import _alert_id, _dedup, _build_alert


class TestGenerateAlerts:

    def test_alert_id_deterministic(self):
        id1 = _alert_id("2026-01-01T00:00:00Z", "ConsoleLogin", "1.2.3.4")
        id2 = _alert_id("2026-01-01T00:00:00Z", "ConsoleLogin", "1.2.3.4")
        assert id1 == id2

    def test_alert_id_differs(self):
        id1 = _alert_id("2026-01-01T00:00:00Z", "ConsoleLogin", "1.2.3.4")
        id2 = _alert_id("2026-01-01T00:00:00Z", "ConsoleLogin", "5.6.7.8")
        assert id1 != id2

    def test_dedup_removes_duplicates(self):
        alerts = [
            {"alert_id": "a", "event_name": "ConsoleLogin", "source_ip": "1.2.3.4",
             "timestamp": "2026-01-01T10:00:00Z"},
            {"alert_id": "b", "event_name": "ConsoleLogin", "source_ip": "1.2.3.4",
             "timestamp": "2026-01-01T10:02:00Z"},   # same IP, same event, within 5 min
            {"alert_id": "c", "event_name": "ListUsers",   "source_ip": "1.2.3.4",
             "timestamp": "2026-01-01T10:00:00Z"},   # different event
        ]
        unique = _dedup(alerts, window_minutes=5)
        assert len(unique) == 2

    def test_build_alert_has_required_fields(self):
        row = pd.Series({
            "eventTime": "2026-01-01T10:00:00Z",
            "eventName": "StopLogging",
            "sourceIPAddress": "198.51.100.1",
            "awsRegion": "us-east-1",
            "eventSource": "cloudtrail.amazonaws.com",
            "anomaly_score": -0.3,
            "rf_score": 0.8,
            "is_anomaly_iso": 1,
            "is_anomaly_rf": 1,
        })
        from mitre_mapper import map_to_mitre
        techs = map_to_mitre("StopLogging", None, "cloudtrail")
        alert = _build_alert(row, techs)

        assert "alert_id"         in alert
        assert "timestamp"        in alert
        assert "event_name"       in alert
        assert "mitre_techniques" in alert
        assert "alert_level"      in alert
        assert alert["alert_level"] == "CRITICAL"


# ════════════════════════════════════════════════════════
# wazuh_integration
# ════════════════════════════════════════════════════════

from wazuh_integration import WazuhIntegrator, _wazuh_level


class TestWazuhIntegration:

    def test_severity_level_mapping(self):
        assert _wazuh_level(1) == 5
        assert _wazuh_level(5) == 8
        assert _wazuh_level(8) == 11
        assert _wazuh_level(10) == 14

    def test_health_check_fails_gracefully(self):
        """Should return False without raising when server is unreachable."""
        integrator = WazuhIntegrator(host="localhost", port=19999)
        result = integrator.health_check()
        assert result is False

    def test_send_alert_fails_gracefully(self):
        """Should return False without raising when server is unreachable."""
        integrator = WazuhIntegrator(host="localhost", port=19999)
        result = integrator.send_alert({"alert_id": "test", "event_name": "Test"})
        assert result is False

    def test_bulk_send_returns_counts(self):
        integrator = WazuhIntegrator(host="localhost", port=19999)
        alerts = [
            {"alert_id": "1", "event_name": "A"},
            {"alert_id": "2", "event_name": "B"},
        ]
        sent, failed = integrator.send_bulk(alerts, delay=0)
        assert sent + failed == 2
