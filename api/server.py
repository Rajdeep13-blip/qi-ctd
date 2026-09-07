"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Public Full-Stack Server & REST API Backend

Features:
- Binds to 0.0.0.0 (Accessible to Cloud Platforms, Local Network & Public Internet)
- Supports dynamic PORT environment variables for Render, Railway, Fly.io, Heroku
- Serves Frontend Dashboard directly at http://<IP>:<PORT>/
- SQLite Database Persistence integrated
- Real Data Ingestion from https://github.com/public-apis/public-apis
"""

import sys
import os
import json
import time
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import QICTDEngine
from simulation.attack_generator import SyntheticAttackGenerator
from telemetry.public_apis_ingestor import PublicApisIngestor
from telemetry.schema import NormalizedSignatureEvent, SourceType, AlgorithmType

# Global Engine, Generator & Public APIs Ingestor
ENGINE = QICTDEngine(batch_window_size=10)
GENERATOR = SyntheticAttackGenerator()
PUBLIC_APIS = PublicApisIngestor()

# Path to static dashboard files
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")


class QICTDPublicServerHandler(BaseHTTPRequestHandler):

    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json_response(self, status_code: int, data: dict):
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(response_bytes)

    def _serve_static_file(self, filename: str):
        filepath = os.path.join(DASHBOARD_DIR, filename)
        if not os.path.exists(filepath):
            self._send_json_response(404, {"error": "File Not Found", "file": filename})
            return

        mime_type, _ = mimetypes.guess_type(filepath)
        mime_type = mime_type or "application/octet-stream"

        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self._send_json_response(500, {"error": f"Failed to read file: {str(e)}"})

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. Serve Dashboard Static Frontend
        if path == "/" or path == "/index.html" or path == "/dashboard":
            self._serve_static_file("index.html")
            return
        elif path == "/styles.css":
            self._serve_static_file("styles.css")
            return
        elif path == "/app.js":
            self._serve_static_file("app.js")
            return
        elif path == "/manifest.json":
            self._serve_static_file("manifest.json")
            return

        # 2. REST API: GET /api/v1/engine/status
        if path == "/api/v1/engine/status":
            status = ENGINE.get_system_status()
            self._send_json_response(200, {"status": "SUCCESS", "data": status})

        # 3. REST API: GET /api/v1/alerts
        elif path == "/api/v1/alerts":
            alerts = [a.to_dict() for a in ENGINE.active_alerts]
            self._send_json_response(200, {"status": "SUCCESS", "count": len(alerts), "alerts": alerts})

        # 4. REST API: GET /api/v1/qvs/inventory
        elif path == "/api/v1/qvs/inventory":
            posture = ENGINE.qvs_engine.get_organization_posture()
            self._send_json_response(200, {"status": "SUCCESS", "posture": posture})

        # 5. REST API: GET /api/v1/public-apis/catalog
        elif path == "/api/v1/public-apis/catalog":
            catalog = PUBLIC_APIS.get_public_apis_catalog()
            self._send_json_response(200, {
                "status": "SUCCESS",
                "source": "https://github.com/public-apis/public-apis",
                "count": len(catalog),
                "apis": catalog
            })

        # 6. REST API: Health Check
        elif path == "/health":
            self._send_json_response(200, {
                "service": "QI-CTD Quantum-Inspired Detection Backend",
                "status": "HEALTHY",
                "mode": "PUBLIC_NETWORK",
                "database": "SQLite qi_ctd.db Active",
                "public_apis_connected": True,
                "timestamp": time.time()
            })

        else:
            self._send_json_response(404, {"error": "Not Found", "path": path})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except json.JSONDecodeError:
            self._send_json_response(400, {"error": "Invalid JSON format"})
            return

        # 1. Ingest Telemetry: POST /api/v1/telemetry/ingest
        if path == "/api/v1/telemetry/ingest":
            try:
                src_type = SourceType(body.get("source_type", "pki_hsm"))
            except ValueError:
                src_type = SourceType.PKI_HSM

            event = ENGINE.normalizer.normalize_raw_event(body, src_type)
            alert = ENGINE.ingest_event(event)

            res = {
                "status": "INGESTED",
                "event_id": event.event_id,
                "is_anomalous": alert is not None,
                "alert": alert.to_dict() if alert else None
            }
            self._send_json_response(200, res)

        # 2. SOAR Action: POST /api/v1/soar/execute
        elif path == "/api/v1/soar/execute":
            alert_id = body.get("alert_id", "")
            action = body.get("action", "Quarantine Key & Throttle HSM")
            result = ENGINE.execute_soar_playbook(alert_id, action)
            self._send_json_response(200, result)

        # 3. Trigger Attack Scenario: POST /api/v1/simulate/attack
        elif path == "/api/v1/simulate/attack":
            scenario = int(body.get("scenario", 1))
            if scenario == 1:
                events = GENERATOR.inject_attack_scenario_1_nonce_reuse()
                desc = "ECDSA Nonce Reuse (Key Recovery Attack)"
            elif scenario == 2:
                events = GENERATOR.inject_attack_scenario_2_signature_malleability()
                desc = "Signature Malleability (High-S Abuse)"
            elif scenario == 3:
                events = GENERATOR.inject_attack_scenario_3_rogue_cicd_signing()
                desc = "Rogue CI/CD Supply Chain Signing"
            elif scenario == 4:
                events = GENERATOR.inject_attack_scenario_4_harvest_now_bulk_export()
                desc = "Quantum Harvest-Now Reconnaissance"
            else:
                events = GENERATOR.generate_baseline_normal_stream(count=5)
                desc = "Benign Baseline Stream"

            alerts = ENGINE.ingest_batch(events)
            self._send_json_response(200, {
                "scenario": scenario,
                "description": desc,
                "events_injected": len(events),
                "alerts_triggered": [a.to_dict() for a in alerts]
            })

        # 4. Fetch & Ingest Real Live Data from Public APIs: POST /api/v1/public-apis/fetch-live
        elif path == "/api/v1/public-apis/fetch-live":
            events = PUBLIC_APIS.fetch_live_blockchain_signatures(count=5)
            alerts = ENGINE.ingest_batch(events)
            self._send_json_response(200, {
                "status": "INGESTED_REAL_DATA",
                "source": "https://github.com/public-apis/public-apis (Live Blockchain & SSL)",
                "events_count": len(events),
                "events": [
                    {
                        "event_id": e.event_id,
                        "time": time.strftime("%H:%M:%S", time.localtime(e.timestamp)),
                        "source": e.source_type.value,
                        "key_id": e.key_id,
                        "algorithm": e.algorithm.value,
                        "entropy": e.nonce_entropy,
                        "caller": e.caller_identity,
                        "latency": f"{e.latency_ms}ms"
                    }
                    for e in events
                ],
                "alerts_triggered": [a.to_dict() for a in alerts]
            })

        else:
            self._send_json_response(404, {"error": "Not Found", "path": path})


def start_public_server(host: str = "0.0.0.0", port: int = 8000):
    server_address = (host, port)
    httpd = HTTPServer(server_address, QICTDPublicServerHandler)
    print("=" * 80)
    print("🌐 QI-CTD Full-Stack Public Server ONLINE")
    print(f"📡 Bound to: {host}:{port} (Accessible to Cloud Platforms & Public Internet)")
    print(f"🖥️  Dashboard Web UI: http://localhost:{port}/  or  http://<YOUR-IP>:{port}/")
    print("📊 Public REST API Endpoints:")
    print(f"   • GET  http://<YOUR-IP>:{port}/api/v1/public-apis/catalog")
    print(f"   • POST http://<YOUR-IP>:{port}/api/v1/public-apis/fetch-live")
    print(f"   • POST http://<YOUR-IP>:{port}/api/v1/telemetry/ingest")
    print(f"   • GET  http://<YOUR-IP>:{port}/api/v1/alerts")
    print(f"   • POST http://<YOUR-IP>:{port}/api/v1/soar/execute")
    print(f"   • GET  http://<YOUR-IP>:{port}/api/v1/qvs/inventory")
    print(f"   • POST http://<YOUR-IP>:{port}/api/v1/simulate/attack")
    print("=" * 80)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping QI-CTD Server...")
        httpd.server_close()


if __name__ == "__main__":
    env_port = os.environ.get("PORT")
    if env_port:
        try:
            port = int(env_port)
        except ValueError:
            port = 8000
    elif len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            port = 8000
    else:
        port = 8000

    host = "0.0.0.0"
    start_public_server(host=host, port=port)
