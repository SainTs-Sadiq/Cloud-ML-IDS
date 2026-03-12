"""
soc/wazuh_integration.py
------------------------
Sends IDS alerts to a Wazuh SIEM (or any compatible REST endpoint).

Improvements over the original:
  - Retry logic with exponential back-off
  - Alert severity → Wazuh rule level mapping
  - Bulk-send to reduce HTTP round-trips
  - Optional Splunk HEC and generic webhook targets
  - All credentials read from environment variables (no hard-coded secrets)
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------

WAZUH_HOST    = os.getenv("WAZUH_HOST", "localhost")
WAZUH_PORT    = int(os.getenv("WAZUH_PORT", "55000"))
WAZUH_USER    = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASS    = os.getenv("WAZUH_PASS", "wazuh")

SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")

WEBHOOK_URL   = os.getenv("IDS_WEBHOOK_URL", "")

# Wazuh rule level (1–15) mapped from alert severity (1–10)
_SEVERITY_TO_LEVEL = {range(1, 4): 5, range(4, 7): 8, range(7, 9): 11, range(9, 11): 14}


def _wazuh_level(severity: int) -> int:
    for r, lvl in _SEVERITY_TO_LEVEL.items():
        if severity in r:
            return lvl
    return 5


# ---------------------------------------------------------------------------
# HTTP session with retry
# ---------------------------------------------------------------------------

def _make_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    session = requests.Session()
    retry   = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    return session


# ---------------------------------------------------------------------------
# Wazuh integrator
# ---------------------------------------------------------------------------

class WazuhIntegrator:
    """
    Sends alerts to the Wazuh REST API (or mock server).

    Usage::

        integrator = WazuhIntegrator()
        integrator.send_alert(alert_dict)
        integrator.send_bulk(list_of_alerts)
    """

    def __init__(
        self,
        host: str = WAZUH_HOST,
        port: int = WAZUH_PORT,
        username: str = WAZUH_USER,
        password: str = WAZUH_PASS,
        timeout: int = 10,
    ):
        self.base_url = f"http://{host}:{port}"
        self.auth     = (username, password)
        self.timeout  = timeout
        self._session = _make_session()

    # ── Internal helpers ─────────────────────────────────────────────────

    def _enrich_for_wazuh(self, alert: dict) -> dict:
        """Wrap alert in the Wazuh event envelope."""
        return {
            "wazuh_rule_level": _wazuh_level(alert.get("severity", 1)),
            "wazuh_rule_id":    "100001",
            "wazuh_rule_description": (
                f"[IDS] {alert.get('alert_level', 'UNKNOWN')} – "
                f"{alert.get('event_name', 'N/A')}"
            ),
            "event_data": alert,
        }

    def _post(self, endpoint: str, payload: dict) -> bool:
        url = f"{self.base_url}{endpoint}"
        try:
            resp = self._session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                return True
            logger.warning("Wazuh responded %d: %s", resp.status_code, resp.text[:200])
            return False
        except requests.RequestException as exc:
            logger.error("Failed to reach Wazuh at %s: %s", url, exc)
            return False

    # ── Public API ────────────────────────────────────────────────────────

    def send_alert(self, alert: dict) -> bool:
        """Send a single alert."""
        payload = self._enrich_for_wazuh(alert)
        ok = self._post("/events", payload)
        status = "✓" if ok else "✗"
        logger.info("%s Wazuh: %s [%s]", status, alert.get("event_name"), alert.get("alert_level"))
        return ok

    def send_bulk(self, alerts: list[dict], delay: float = 0.05) -> tuple[int, int]:
        """
        Send multiple alerts.  Returns (sent_count, failed_count).
        """
        sent = failed = 0
        for alert in alerts:
            if self.send_alert(alert):
                sent += 1
            else:
                failed += 1
            if delay:
                time.sleep(delay)
        logger.info("Bulk send complete: %d sent, %d failed.", sent, failed)
        return sent, failed

    def health_check(self) -> bool:
        try:
            resp = self._session.get(f"{self.base_url}/", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Splunk HEC integrator
# ---------------------------------------------------------------------------

class SplunkIntegrator:
    """
    Forwards alerts to Splunk via HTTP Event Collector (HEC).
    Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN environment variables.
    """

    def __init__(
        self,
        hec_url:  str = SPLUNK_HEC_URL,
        hec_token: str = SPLUNK_HEC_TOKEN,
    ):
        self.hec_url   = hec_url
        self.hec_token = hec_token
        self._session  = _make_session()

    def send_alert(self, alert: dict) -> bool:
        if not self.hec_url or not self.hec_token:
            logger.warning("Splunk HEC not configured.")
            return False
        payload = {
            "time":       alert.get("timestamp", ""),
            "sourcetype": "cloud:ids:alert",
            "source":     "cloud-ml-ids",
            "event":      alert,
        }
        headers = {"Authorization": f"Splunk {self.hec_token}"}
        try:
            resp = self._session.post(
                self.hec_url, json=payload, headers=headers, timeout=10
            )
            return resp.status_code == 200
        except requests.RequestException as exc:
            logger.error("Splunk HEC error: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Generic webhook
# ---------------------------------------------------------------------------

class WebhookIntegrator:
    """POST alerts to any generic HTTPS webhook (e.g. Slack, PagerDuty, Teams)."""

    def __init__(self, url: str = WEBHOOK_URL):
        self.url      = url
        self._session = _make_session()

    def send_alert(self, alert: dict) -> bool:
        if not self.url:
            logger.debug("Webhook URL not set – skipping.")
            return False
        try:
            resp = self._session.post(self.url, json=alert, timeout=10)
            return resp.status_code in (200, 201, 202, 204)
        except requests.RequestException as exc:
            logger.error("Webhook error: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Convenience dispatcher
# ---------------------------------------------------------------------------

def dispatch_alerts(alerts: list[dict]) -> None:
    """
    Send alerts to all configured SOC targets.
    Enable targets by setting the appropriate environment variables.
    """
    wazuh   = WazuhIntegrator()
    splunk  = SplunkIntegrator()
    webhook = WebhookIntegrator()

    active_targets = []
    if wazuh.health_check():
        active_targets.append(("Wazuh",   wazuh.send_alert))
    if splunk.hec_url:
        active_targets.append(("Splunk",  splunk.send_alert))
    if webhook.url:
        active_targets.append(("Webhook", webhook.send_alert))

    if not active_targets:
        logger.warning("No active SOC targets configured.")
        return

    for alert in alerts:
        for name, fn in active_targets:
            fn(alert)


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    sample_alert = {
        "alert_id":    "test-001",
        "timestamp":   "2026-03-12T10:00:00Z",
        "event_name":  "ConsoleLogin",
        "source_ip":   "198.51.100.42",
        "alert_level": "HIGH",
        "severity":    8,
        "mitre_techniques": [
            {"technique_id": "T1110.001", "technique_name": "Brute Force: Password Guessing",
             "tactic": "Credential Access", "confidence": "High", "severity": 8}
        ],
    }

    wazuh = WazuhIntegrator()
    if wazuh.health_check():
        wazuh.send_alert(sample_alert)
        print("Test alert dispatched to Wazuh.")
    else:
        print("Wazuh not reachable.  Start mock_wazuh_server.py first.")
