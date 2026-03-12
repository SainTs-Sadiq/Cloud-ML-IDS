# Cloud ML IDS — MITRE ATT&CK + SOC Integration

A production-ready cloud intrusion detection system for AWS CloudTrail logs,
combining unsupervised and supervised ML with full MITRE ATT&CK for Cloud mapping
and Wazuh SIEM integration.

---

## Architecture

```
cloudtrail_logs_raw.csv
        │
        ▼
┌─────────────────────┐
│  feature_engineer   │  Parses CloudTrail JSON, extracts time/user/error
│  (core/)            │  features, encodes + scales → engineered_features.csv
└─────────┬───────────┘
          │
    ┌─────┴──────┐
    │            │
    ▼            ▼
┌─────────┐  ┌──────────────┐
│Isolation│  │ Random Forest │  (weak-supervised via MITRE labels)
│ Forest  │  │  Classifier   │
└────┬────┘  └──────┬───────┘
     │              │
     └──────┬───────┘
            │  combined flags
            ▼
┌─────────────────────┐
│  generate_alerts    │  MITRE mapping · severity scoring · dedup
│  (core/)            │  → alerts.json + alerts.jsonl
└─────────┬───────────┘
          │
    ┌─────┴──────┐
    │            │
    ▼            ▼
┌─────────┐  ┌──────────┐
│  Wazuh  │  │ Splunk / │
│  SIEM   │  │ Webhook  │
└─────────┘  └──────────┘
          │
          ▼
  SOC Dashboard (http://localhost:8000)
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate synthetic attack data (no AWS needed)
```bash
python scripts/simulate_attacks.py
```

### 3. Run the full pipeline
```bash
python scripts/run_pipeline.py
# Options:
#   --input <path>     custom CloudTrail CSV (default: cloudtrail_logs_raw.csv)
#   --skip-train       skip Random Forest training
#   --skip-soc         skip Wazuh dispatch
```

### 4. Start the mock Wazuh server (separate terminal)
```bash
python soc/mock_wazuh_server.py
```

### 5. Start the SOC dashboard (separate terminal)
```bash
python dashboard/server.py
# Open http://localhost:8000
```

---

## Module Reference

| File | Purpose |
|------|---------|
| `core/mitre_mapper.py`       | Maps CloudTrail events → MITRE ATT&CK techniques |
| `core/feature_engineer.py`   | Raw CSV → numeric feature matrix |
| `core/detect_unsupervised.py`| Isolation Forest anomaly detection |
| `core/train_supervised.py`   | Random Forest with weak supervision |
| `core/generate_alerts.py`    | Merge results, build structured alert JSON |
| `soc/wazuh_integration.py`   | Wazuh / Splunk / webhook dispatch |
| `soc/mock_wazuh_server.py`   | Local mock SIEM for development |
| `dashboard/index.html`       | SOC dashboard (dark theme, MITRE heatmap) |
| `dashboard/server.py`        | HTTP server for the dashboard |
| `scripts/run_pipeline.py`    | End-to-end orchestrator |
| `scripts/simulate_attacks.py`| Synthetic CloudTrail data generator |
| `tests/test_ids.py`          | pytest test suite |

---

## MITRE ATT&CK Coverage

| Tactic              | Techniques covered |
|---------------------|-------------------|
| Discovery           | T1526, T1580, T1613, T1033 |
| Credential Access   | T1110.001, T1110.003, T1550.001 |
| Defense Evasion     | T1562.008 |
| Persistence         | T1136.003, T1098.001, T1098.003 |
| Privilege Escalation| T1078.004, T1548 |
| Exfiltration        | T1530, T1537 |
| Lateral Movement    | T1550.001 |
| Impact              | T1485, T1529, T1486 |
| Initial Access      | T1078.004 |

---

## SOC Integration

### Wazuh
Set environment variables before running the pipeline:
```bash
export WAZUH_HOST=your-wazuh-host
export WAZUH_PORT=55000
export WAZUH_USER=wazuh
export WAZUH_PASS=your-password
```

### Splunk HEC
```bash
export SPLUNK_HEC_URL=https://splunk-host:8088/services/collector
export SPLUNK_HEC_TOKEN=your-hec-token
```

### Generic webhook (Slack, PagerDuty, etc.)
```bash
export IDS_WEBHOOK_URL=https://hooks.slack.com/services/...
```

---

## Running Tests
```bash
pytest tests/test_ids.py -v
```

---

## Alert Schema

```json
{
  "alert_id":    "a3f9b2c1d4e5",
  "timestamp":   "2026-03-12T10:00:00Z",
  "event_name":  "StopLogging",
  "source_ip":   "198.51.100.42",
  "aws_region":  "us-east-1",
  "alert_level": "CRITICAL",
  "severity":    10,
  "anomaly_score": -0.4132,
  "rf_score":    0.91,
  "mitre_techniques": [
    {
      "technique_id":   "T1562.008",
      "technique_name": "Impair Defenses: Disable Cloud Logs",
      "tactic":         "Defense Evasion",
      "confidence":     "High",
      "severity":       10
    }
  ],
  "model_flags": {
    "isolation_forest": true,
    "random_forest":    true
  }
}
```
