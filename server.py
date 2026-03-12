"""
dashboard/server.py
-------------------
Serves the IDS dashboard HTML and proxies /alerts requests to the
Wazuh server (or falls back to reading alerts.json directly).

Usage:
    python server.py                  # default port 8000
    python server.py --port 9000
    python server.py --alerts-file ../alerts.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

logger = logging.getLogger(__name__)

WAZUH_URL     = os.getenv("WAZUH_URL", "http://localhost:55000")
DEFAULT_FILE  = Path(__file__).parent.parent / "alerts.json"


class DashboardHandler(SimpleHTTPRequestHandler):
    """Serves the dashboard and exposes /alerts for the frontend."""

    alerts_file: Path = DEFAULT_FILE
    wazuh_url: str    = WAZUH_URL

    # ── Request routing ───────────────────────────────────────────────────

    def do_GET(self):
        if self.path.startswith("/alerts"):
            self._serve_alerts()
        else:
            super().do_GET()

    # ── Alert source (live server → file fallback) ───────────────────────

    def _serve_alerts(self):
        alerts = self._from_wazuh() or self._from_file()

        body = json.dumps(alerts, default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _from_wazuh(self) -> list | None:
        try:
            with urlopen(f"{self.wazuh_url}/alerts?limit=200", timeout=3) as resp:
                return json.loads(resp.read())
        except (URLError, Exception):
            return None

    def _from_file(self) -> list:
        path = self.alerts_file
        if not path.exists():
            return []
        try:
            with open(path) as fh:
                return json.load(fh)
        except Exception as exc:
            logger.warning("Could not read alerts file: %s", exc)
            return []

    def log_message(self, fmt, *args):
        logger.debug(fmt, *args)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(port: int = 8000, alerts_file: Path = DEFAULT_FILE) -> None:
    # Serve from dashboard directory so index.html is at /
    web_root = Path(__file__).parent
    os.chdir(web_root)

    DashboardHandler.alerts_file = alerts_file
    server = HTTPServer(("0.0.0.0", port), DashboardHandler)
    print(f"📊  Dashboard  →  http://localhost:{port}")
    print(f"    Alert source: Wazuh ({WAZUH_URL}) → {alerts_file}")
    print("    Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        server.shutdown()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    parser = argparse.ArgumentParser(description="IDS Dashboard Server")
    parser.add_argument("--port",         type=int,  default=8000)
    parser.add_argument("--alerts-file",  type=Path, default=DEFAULT_FILE)
    args = parser.parse_args()

    run(port=args.port, alerts_file=args.alerts_file)
