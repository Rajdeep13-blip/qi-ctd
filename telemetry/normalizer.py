"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Telemetry Normalizer & Feature Extraction Engine
"""

import math
from typing import Dict, Any, List
from .schema import (
    NormalizedSignatureEvent,
    AnomalyFeatureVector,
    SourceType,
    AlgorithmType
)


class TelemetryNormalizer:
    """
    Normalizes logs from PKI/HSM, TLS/mTLS, CI/CD, and Blockchain sources
    into a standardized schema and produces normalized feature vectors for quantum-inspired solvers.
    """

    FEATURE_NAMES = [
        "nonce_entropy_inv",    # 1.0 - (entropy / 8.0) -> high value = low entropy (anomaly)
        "latency_deviation",    # normalized latency deviation from baseline
        "geo_risk_score",       # known anomalous geo score [0, 1]
        "hour_of_day_anomaly",  # deviation from standard business hours [0, 1]
        "key_frequency_burst",  # signing rate burst score [0, 1]
        "malleability_indicator", # binary 1.0 if s > (curve_order / 2) or malleable flag
        "cert_depth_risk",      # chain depth irregularity [0, 1]
        "requester_privilege_mismatch" # 1.0 if untrusted caller signed with tier-1 key
    ]

    def __init__(self):
        self._key_invocation_history: Dict[str, List[float]] = {}
        self._trusted_callers = {
            "prod-release-bot@infra.internal",
            "pki-signer-svc@corp.internal",
            "tls-terminator-01@edge.internal",
            "blockchain-validator-node-01"
        }

    @staticmethod
    def calculate_shannon_entropy(hex_str: str) -> float:
        """Calculates Shannon entropy in bits for a hex string."""
        if not hex_str:
            return 8.0
        try:
            byte_data = bytes.fromhex(hex_str)
        except ValueError:
            byte_data = hex_str.encode("utf-8")
        
        if not byte_data:
            return 8.0
        
        length = len(byte_data)
        freq: Dict[int, int] = {}
        for b in byte_data:
            freq[b] = freq.get(b, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def normalize_raw_event(self, raw_data: Dict[str, Any], source_type: SourceType) -> NormalizedSignatureEvent:
        """Converts raw log dictionary to a NormalizedSignatureEvent."""
        nonce_hex = raw_data.get("nonce_hex") or raw_data.get("k_value") or raw_data.get("nonce")
        if nonce_hex:
            nonce_entropy = self.calculate_shannon_entropy(nonce_hex)
        else:
            nonce_entropy = raw_data.get("nonce_entropy_bits", 7.95)

        algo_str = raw_data.get("algorithm", "RSA-2048")
        try:
            algo_enum = AlgorithmType(algo_str)
        except ValueError:
            algo_enum = AlgorithmType.RSA_2048

        event = NormalizedSignatureEvent(
            event_id=raw_data.get("event_id", ""),
            timestamp_ns=raw_data.get("timestamp_ns", 0),
            source_type=source_type,
            key_id=raw_data.get("key_id", "key-unknown"),
            algorithm=algo_enum,
            key_length_bits=int(raw_data.get("key_length_bits", 2048)),
            requester_identity=raw_data.get("requester_identity", "unknown_user"),
            client_ip=raw_data.get("client_ip", "127.0.0.1"),
            geo_location=raw_data.get("geo_location", "US-EAST"),
            operation=raw_data.get("operation", "sign"),
            payload_hash=raw_data.get("payload_hash", "0" * 64),
            sig_r_s_length=int(raw_data.get("sig_r_s_length", 512)),
            nonce_hex=nonce_hex,
            nonce_entropy_bits=nonce_entropy,
            signing_latency_ms=float(raw_data.get("signing_latency_ms", 4.0)),
            cert_chain_depth=int(raw_data.get("cert_chain_depth", 3)),
            is_malleable_candidate=bool(raw_data.get("is_malleable_candidate", False)),
            metadata=raw_data.get("metadata", {})
        )
        return event

    def extract_feature_vector(self, event: NormalizedSignatureEvent) -> AnomalyFeatureVector:
        """
        Transforms a NormalizedSignatureEvent into an 8-dimensional normalized [0.0, 1.0] feature vector.
        """
        # 1. Nonce entropy inversion (8.0 is perfect entropy, <6.0 is dangerously biased)
        entropy = max(0.0, min(8.0, event.nonce_entropy_bits))
        nonce_entropy_inv = max(0.0, min(1.0, (8.0 - entropy) / 8.0))

        # 2. Latency deviation (baseline ~4ms; >50ms or <0.5ms is suspicious)
        baseline_latency = 4.0
        lat_diff = abs(event.signing_latency_ms - baseline_latency)
        latency_dev = max(0.0, min(1.0, lat_diff / 50.0))

        # 3. Geo risk score
        geo_risk_map = {
            "US-EAST": 0.05, "US-WEST": 0.05, "EU-CENTRAL": 0.05, "AP-SOUTH": 0.08,
            "TOR-EXIT": 0.95, "ANON-VPN": 0.85, "UNKNOWN-GEO": 0.70
        }
        geo_risk = geo_risk_map.get(event.geo_location.upper(), 0.3)

        # 4. Hour of day anomaly (assumes timestamps in ns)
        hour = (event.timestamp_ns // (3600 * 1_000_000_000)) % 24
        # Standard business hours 08:00 - 18:00
        if 8 <= hour <= 18:
            hour_anomaly = 0.05
        elif 6 <= hour < 8 or 18 < hour <= 22:
            hour_anomaly = 0.35
        else:
            hour_anomaly = 0.85

        # 5. Key frequency burst
        now_sec = event.timestamp_ns / 1e9
        history = self._key_invocation_history.setdefault(event.key_id, [])
        history.append(now_sec)
        # Keep last 60 seconds
        history = [t for t in history if now_sec - t <= 60]
        self._key_invocation_history[event.key_id] = history
        burst_rate = len(history)
        freq_burst = max(0.0, min(1.0, (burst_rate - 5) / 50.0)) if burst_rate > 5 else 0.02

        # 6. Malleability indicator
        malleability_score = 1.0 if event.is_malleable_candidate else 0.0

        # 7. Cert depth risk (normal: 2-3, root: 1, abnormal: >5)
        depth_risk = 0.0
        if event.cert_chain_depth > 4:
            depth_risk = min(1.0, (event.cert_chain_depth - 4) * 0.3)
        elif event.cert_chain_depth == 0:
            depth_risk = 0.9

        # 8. Requester privilege mismatch
        priv_mismatch = 0.05
        if event.key_length_bits >= 4096 or "root" in event.key_id.lower() or "master" in event.key_id.lower():
            if event.requester_identity not in self._trusted_callers:
                priv_mismatch = 0.95

        features = [
            round(nonce_entropy_inv, 4),
            round(latency_dev, 4),
            round(geo_risk, 4),
            round(hour_anomaly, 4),
            round(freq_burst, 4),
            round(malleability_score, 4),
            round(depth_risk, 4),
            round(priv_mismatch, 4)
        ]

        return AnomalyFeatureVector(
            event_id=event.event_id,
            key_id=event.key_id,
            features=features,
            feature_names=self.FEATURE_NAMES,
            raw_event=event
        )
