"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
SQLite Database Manager & Persistent Storage Engine
"""

import sqlite3
import os
import time
import json
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "qi_ctd.db")


class DatabaseManager:
    """Manages SQLite database connections and persistent storage for QI-CTD."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_tables()

    def _get_connection(self):
        return self._conn

    def _init_tables(self):
        """Initializes database schema if tables do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Telemetry Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_events (
                event_id TEXT PRIMARY KEY,
                timestamp_ns INTEGER,
                source_type TEXT,
                key_id TEXT,
                algorithm TEXT,
                key_length_bits INTEGER,
                requester_identity TEXT,
                client_ip TEXT,
                geo_location TEXT,
                operation TEXT,
                nonce_entropy_bits REAL,
                signing_latency_ms REAL,
                is_anomaly INTEGER DEFAULT 0,
                metadata_json TEXT
            )
            """)

            # 2. Threat Alerts Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp REAL,
                event_id TEXT,
                key_id TEXT,
                severity TEXT,
                confidence_score REAL,
                attack_type TEXT,
                mitre_ttp TEXT,
                detection_engine TEXT,
                summary TEXT,
                recommended_playbook TEXT,
                soar_status TEXT,
                feature_attribution_json TEXT
            )
            """)

            # 3. Cryptographic Asset Inventory Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS quantum_assets (
                asset_id TEXT PRIMARY KEY,
                asset_name TEXT,
                key_id TEXT,
                algorithm TEXT,
                key_length INTEGER,
                data_shelf_life_years INTEGER,
                asset_criticality REAL,
                exposure_level TEXT,
                qvs_score REAL,
                pqc_recommended_target TEXT,
                status TEXT
            )
            """)

            # 4. SOAR Execution Audit Logs
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS soar_audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT,
                action_executed TEXT,
                target_key TEXT,
                timestamp REAL,
                status TEXT
            )
            """)
            conn.commit()

    def save_event(self, event_dict: Dict[str, Any], is_anomaly: bool = False):
        """Saves a normalized telemetry event to the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO telemetry_events (
                event_id, timestamp_ns, source_type, key_id, algorithm,
                key_length_bits, requester_identity, client_ip, geo_location,
                operation, nonce_entropy_bits, signing_latency_ms, is_anomaly, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_dict.get("event_id"),
                event_dict.get("timestamp_ns", int(time.time() * 1e9)),
                event_dict.get("source_type"),
                event_dict.get("key_id"),
                event_dict.get("algorithm"),
                event_dict.get("key_length_bits", 2048),
                event_dict.get("requester_identity"),
                event_dict.get("client_ip"),
                event_dict.get("geo_location"),
                event_dict.get("operation"),
                event_dict.get("nonce_entropy_bits", 7.95),
                event_dict.get("signing_latency_ms", 4.0),
                1 if is_anomaly else 0,
                json.dumps(event_dict.get("metadata", {}))
            ))
            conn.commit()

    def save_alert(self, alert_dict: Dict[str, Any]):
        """Saves a threat alert to the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO threat_alerts (
                alert_id, timestamp, event_id, key_id, severity, confidence_score,
                attack_type, mitre_ttp, detection_engine, summary,
                recommended_playbook, soar_status, feature_attribution_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_dict.get("alert_id"),
                alert_dict.get("timestamp", time.time()),
                alert_dict.get("event_id"),
                alert_dict.get("key_id"),
                alert_dict.get("severity"),
                alert_dict.get("confidence_score"),
                alert_dict.get("attack_type"),
                alert_dict.get("mitre_ttp"),
                alert_dict.get("detection_engine"),
                alert_dict.get("summary"),
                alert_dict.get("recommended_playbook"),
                alert_dict.get("soar_status"),
                json.dumps(alert_dict.get("feature_attribution", {}))
            ))
            conn.commit()

    def update_soar_status(self, alert_id: str, action: str, target_key: str):
        """Updates alert SOAR status and creates an audit log entry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE threat_alerts SET soar_status = 'EXECUTED' WHERE alert_id = ?", (alert_id,))
            cursor.execute("""
            INSERT INTO soar_audit_logs (alert_id, action_executed, target_key, timestamp, status)
            VALUES (?, ?, ?, ?, 'SUCCESS')
            """, (alert_id, action, target_key, time.time()))
            conn.commit()

    def get_all_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetches latest alerts from database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            alerts = []
            for r in rows:
                d = dict(r)
                if d.get("feature_attribution_json"):
                    try:
                        d["feature_attribution"] = json.loads(d["feature_attribution_json"])
                    except Exception:
                        d["feature_attribution"] = {}
                alerts.append(d)
            return alerts
