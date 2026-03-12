"""
soc/mock_wazuh_server.py
------------------------
A lightweight mock Wazuh API server for local development and testing.
Stores alerts in SQLite and exposes them via a REST API consumed by the dashboard.

Endpoints:
  GET  /              → health check
  POST /events        → ingest an alert
  GET  /alerts        → list alerts (supports ?limit=N&level=HIGH)
  GET  /alerts/<id>   → retrieve single alert by alert_id
  GET  /stats         → aggregate counts by level and tactic
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

DB_FILE   = "wazuh_alerts.db"
HOST      = "0.0.0.0"
PORT      = 55000

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _get_conn(db: str = DB_FILE) -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db(db: str = DB_FILE) -> None:
    with _get_conn(db) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id        TEXT UNIQUE,
                received_at     TEXT NOT NULL,
                timestamp       TEXT,
                event_name      TEXT,
                source_ip       TEXT,
                alert_level     TEXT,
                severity        INTEGER DEFAULT 0,
                mitre_techniques TEXT,
                raw_alert       TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_level ON alerts(alert_level)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_received ON alerts(received_at)")


def _save_alert(alert: dict, db: str = DB_FILE) -> None:
    techniques = json.dumps(alert.get("mitre_techniques", []))
    now        = datetime.now(timezone.utc).isoformat()
    with _get_conn(db) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO alerts
                (alert_id, received_at, timestamp, event_name, source_ip,
                 alert_level, severity, mitre_techniques, raw_alert)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("alert_id", ""),
            now,
            alert.get("timestamp", now),
            alert.get("event_name", "Unknown"),
            alert.get("source_ip", "N/A"),
            alert.get("alert_level", "LOW"),
            int(alert.get("severity", 0)),
            techniques,
            json.dumps(alert),
        ))


def _query_alerts(
    limit: int = 50,
    level: Optional[str] = None,
    db: str = DB_FILE,
) -> list[dict]:
    where = "WHERE alert_level = ?" if level else ""
    params: list = [level] if level else []
    params.append(limit)
    with _get_conn(db) as conn:
        rows = conn.execute(
            f"SELECT raw_alert FROM alerts {where} ORDER BY severity DESC, received_at DESC LIMIT ?",
            params,
        ).fetchall()
    return [json.loads(r["raw_alert"]) for r in rows]


def _get_stats(db: str = DB_FILE) -> dict:
    with _get_conn(db) as conn:
        total = conn.execute("SELECT COUNT(*) as n FROM alerts").fetchone()["n"]
        by_level = {
            row["alert_level"]: row["cnt"]
            for row in conn.execute(
                "SELECT alert_level, COUNT(*) as cnt FROM alerts GROUP BY alert_level"
            ).fetchall()
        }
    return {"total": total, "by_level": by_level}


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class WazuhHandler(BaseHTTPRequestHandler):
    server_version = "MockWazuh/1.0"

    # ── Helpers ──────────────────────────────────────────────────────────

    def _send_json(self, data, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json({"error": message}, status)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _qs(self) -> dict:
        return parse_qs(urlparse(self.path).query)

    def log_message(self, fmt, *args):  # silence default access log
        logger.debug(fmt, *args)

    # ── OPTIONS (CORS pre-flight) ─────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── GET ──────────────────────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            self._send_json({"status": "ok", "service": "Mock Wazuh API", "version": "4.x"})

        elif path == "/alerts":
            qs    = self._qs()
            limit = int(qs.get("limit", ["50"])[0])
            level = qs.get("level", [None])[0]
            alerts = _query_alerts(limit=min(limit, 500), level=level)
            self._send_json(alerts)

        elif re.match(r"^/alerts/[a-f0-9]+$", path):
            alert_id = path.split("/")[-1]
            with _get_conn() as conn:
                row = conn.execute(
                    "SELECT raw_alert FROM alerts WHERE alert_id = ?", (alert_id,)
                ).fetchone()
            if row:
                self._send_json(json.loads(row["raw_alert"]))
            else:
                self._send_error_json(404, "Alert not found")

        elif path == "/stats":
            self._send_json(_get_stats())

        else:
            self._send_error_json(404, f"Unknown endpoint: {path}")

    # ── POST ─────────────────────────────────────────────────────────────

    def do_POST(self):
        path = urlparse(self.path).path

        if path != "/events":
            self._send_error_json(404, "Unknown endpoint")
            return

        body = self._read_body()
        if not body:
            self._send_error_json(400, "Empty body")
            return

        try:
            payload = json.loads(body.decode())
        except json.JSONDecodeError as exc:
            self._send_error_json(400, f"Invalid JSON: {exc}")
            return

        # Unwrap Wazuh envelope if present
        alert = payload.get("event_data", payload)
        _save_alert(alert)
        logger.info("Alert stored: %s [%s]", alert.get("event_name"), alert.get("alert_level"))
        self._send_json({"status": "ok", "alert_id": alert.get("alert_id", "")})


# ---------------------------------------------------------------------------
# Server runner
# ---------------------------------------------------------------------------

def run_server(host: str = HOST, port: int = PORT) -> None:
    _init_db()
    server = HTTPServer((host, port), WazuhHandler)
    print(f"🚀  Mock Wazuh API  →  http://{host}:{port}")
    print(f"    POST /events      ingest alerts")
    print(f"    GET  /alerts      list alerts  (?limit=N&level=HIGH)")
    print(f"    GET  /stats       aggregate stats")
    print(f"    GET  /            health check")
    print("    Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down …")
        server.shutdown()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    run_server()
