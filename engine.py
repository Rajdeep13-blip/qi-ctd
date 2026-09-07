"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Master Engine & Real-Time Orchestration Pipeline (with SQLite Database Persistence)
"""

import time
from typing import List, Dict, Any, Optional
from telemetry.schema import (
    NormalizedSignatureEvent,
    AnomalyFeatureVector,
    ThreatAlert,
    SOARStatus,
    SourceType
)
from telemetry.normalizer import TelemetryNormalizer
from core.qubo_engine import QUBOAnomalySolver
from core.tensor_network import MPSTensorNetworkClassifier
from core.grover_search import GroverCorrelationSearch
from core.qvs_engine import QuantumRiskEngine
from database.db import DatabaseManager


class QICTDEngine:
    """
    Master Orchestration Engine combining all Quantum-Inspired modules + SQLite Persistence:
    1. Normalizes raw streaming telemetry.
    2. Runs QUBO Simulated Annealing for unsupervised outlier clustering.
    3. Runs MPS Tensor Network Classifier for multi-feature quantum entanglement analysis.
    4. Runs Grover Amplitude Amplification for correlation graph searching.
    5. Evaluates Quantum Vulnerability Scores (QVS).
    6. Dispatches MITRE-mapped alerts and handles SOAR automated playbooks.
    7. Persists all events, alerts, and audit records into SQLite database.
    """

    def __init__(self, batch_window_size: int = 15):
        self.batch_window_size = batch_window_size
        self.normalizer = TelemetryNormalizer()
        self.qubo_solver = QUBOAnomalySolver(temperature_initial=12.0, num_sweeps=200)
        self.mps_classifier = MPSTensorNetworkClassifier(feature_dim=8, bond_dim=4, threshold=0.68)
        self.grover_search = GroverCorrelationSearch(max_iterations=12)
        self.qvs_engine = QuantumRiskEngine(crqc_horizon_years=6.5)
        self.db = DatabaseManager()

        # In-memory streaming state
        self._event_buffer: List[NormalizedSignatureEvent] = []
        self._feature_buffer: List[AnomalyFeatureVector] = []
        self.active_alerts: List[ThreatAlert] = []
        self.processed_events_count: int = 0
        self.total_anomalies_detected: int = 0
        self.detection_latencies_ms: List[float] = []

        # Load existing alerts from DB
        self._load_persisted_alerts()

    def _load_persisted_alerts(self):
        """Loads previous alerts from SQLite on startup."""
        try:
            persisted = self.db.get_all_alerts(limit=20)
            for p in persisted:
                alert = ThreatAlert(
                    alert_id=p["alert_id"],
                    timestamp=p["timestamp"],
                    event_id=p.get("event_id", ""),
                    key_id=p.get("key_id", ""),
                    severity=p.get("severity", "HIGH"),
                    confidence_score=p.get("confidence_score", 0.95),
                    attack_type=p.get("attack_type", "Unknown Anomaly"),
                    mitre_ttp=p.get("mitre_ttp", "T1552.004"),
                    detection_engine=p.get("detection_engine", "QUBO Engine"),
                    summary=p.get("summary", ""),
                    recommended_playbook=p.get("recommended_playbook", "Quarantine Key"),
                    soar_status=p.get("soar_status", "PENDING_APPROVAL"),
                    feature_attribution=p.get("feature_attribution", {})
                )
                self.active_alerts.append(alert)
        except Exception:
            pass

    def ingest_event(self, event: NormalizedSignatureEvent) -> Optional[ThreatAlert]:
        """
        Ingests a single streaming event, processes it through fast MPS classifier,
        persists to SQLite, and adds it to sliding batch window for QUBO analysis.
        """
        t0 = time.perf_counter()
        self.processed_events_count += 1
        self._event_buffer.append(event)

        # 1. Feature extraction
        feature_vector = self.normalizer.extract_feature_vector(event)
        self._feature_buffer.append(feature_vector)

        # 2. Fast Streaming Inference via MPS Tensor Network
        mps_alert, mps_telemetry = self.mps_classifier.classify(feature_vector)

        # 3. Save event to SQLite DB
        self.db.save_event(event.to_dict(), is_anomaly=mps_alert is not None)

        # 4. If batch window full, trigger batch QUBO Annealer and Grover Graph Search
        if len(self._event_buffer) >= self.batch_window_size:
            self._flush_batch_window()

        t_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.detection_latencies_ms.append(t_elapsed_ms)
        if len(self.detection_latencies_ms) > 500:
            self.detection_latencies_ms = self.detection_latencies_ms[-500:]

        if mps_alert:
            self._register_alert(mps_alert)
            return mps_alert

        return None

    def ingest_batch(self, events: List[NormalizedSignatureEvent]) -> List[ThreatAlert]:
        """Ingests a batch of events and runs complete detection ensemble."""
        batch_alerts: List[ThreatAlert] = []
        for ev in events:
            alert = self.ingest_event(ev)
            if alert:
                batch_alerts.append(alert)

        if self._event_buffer:
            batch_alerts.extend(self._flush_batch_window())

        return batch_alerts

    def _flush_batch_window(self) -> List[ThreatAlert]:
        """Executes QUBO Annealing and Grover Correlation Search over the current buffer."""
        if not self._feature_buffer:
            return []

        qubo_alerts, qubo_telemetry = self.qubo_solver.detect_anomalies(self._feature_buffer)
        grover_alerts = self.grover_search.correlate_nonce_reuse_distributed(self._event_buffer)

        flushed_alerts = []
        for alert in qubo_alerts + grover_alerts:
            self._register_alert(alert)
            flushed_alerts.append(alert)

        self._event_buffer.clear()
        self._feature_buffer.clear()
        return flushed_alerts

    def _register_alert(self, alert: ThreatAlert):
        """Deduplicates, registers in active queue, and saves to SQLite."""
        for existing in self.active_alerts:
            if existing.event_id == alert.event_id and existing.attack_type == alert.attack_type:
                return

        self.active_alerts.insert(0, alert) 
        self.total_anomalies_detected += 1
        if len(self.active_alerts) > 100:
            self.active_alerts = self.active_alerts[:100]

        # Persist alert to SQLite Database
        self.db.save_alert(alert.to_dict())

    def execute_soar_playbook(self, alert_id: str, action: str) -> Dict[str, Any]:
        """Executes SOAR playbooks and records audit log in SQLite."""
        for alert in self.active_alerts:
            if alert.alert_id == alert_id:
                alert.soar_status = SOARStatus.EXECUTED
                for asset in self.qvs_engine.inventory.values():
                    if asset.key_id == alert.key_id:
                        asset.status = "QUARANTINED" if "Quarantine" in action else "REVOKED"

                # Persist in SQLite
                self.db.update_soar_status(alert_id, action, alert.key_id)

                return {
                    "status": "SUCCESS",
                    "alert_id": alert_id,
                    "action_executed": action,
                    "target_key": alert.key_id,
                    "timestamp": time.time(),
                    "message": f"Successfully executed SOAR action '{action}' on key '{alert.key_id}'. Logged to database."
                }
        return {"status": "ERROR", "message": f"Alert {alert_id} not found."}

    def get_system_status(self) -> Dict[str, Any]:
        """Returns real-time engine telemetry, metrics, and risk posture."""
        avg_latency = (
            sum(self.detection_latencies_ms) / len(self.detection_latencies_ms)
            if self.detection_latencies_ms else 0.0
        )

        return {
            "engine_state": "HEALTHY / ONLINE",
            "database": "SQLite (qi_ctd.db Persistent)",
            "processed_events_total": self.processed_events_count,
            "anomalies_detected_total": self.total_anomalies_detected,
            "mean_detection_latency_ms": round(avg_latency, 2),
            "active_unresolved_alerts": len([a for a in self.active_alerts if a.soar_status == SOARStatus.PENDING_APPROVAL]),
            "quantum_risk_posture": self.qvs_engine.get_organization_posture(),
            "latest_alerts": [a.to_dict() for a in self.active_alerts[:10]]
        }
