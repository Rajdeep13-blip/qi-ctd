"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Telemetry Schema & Data Models
"""

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any


class SourceType(str, Enum):
    PKI_HSM = "pki_hsm"
    TLS_MTLS = "tls_mtls"
    CICD_SIGNING = "cicd_signing"
    BLOCKCHAIN = "blockchain"
    DOC_SIGNING = "doc_signing"
    CERT_AUTHORITY = "cert_authority"


class AlgorithmType(str, Enum):
    # Classical / Quantum-Vulnerable
    RSA_1024 = "RSA-1024"
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"
    ECDSA_P256 = "ECDSA-P256"
    ECDSA_SECP256K1 = "ECDSA-secp256k1"
    ED25519 = "Ed25519"
    # Post-Quantum Cryptography (PQC)
    ML_DSA_44 = "ML-DSA-44"      # Dilithium2 (FIPS 204)
    ML_DSA_65 = "ML-DSA-65"      # Dilithium3 (FIPS 204)
    ML_DSA_87 = "ML-DSA-87"      # Dilithium5 (FIPS 204)
    SLH_DSA_128 = "SLH-DSA-128"  # SPHINCS+ (FIPS 205)
    FN_DSA_512 = "FN-DSA-512"    # Falcon-512
    HYBRID_RSA_MLDSA = "Hybrid-RSA-MLDSA"


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SOARStatus(str, Enum):
    IDLE = "IDLE"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTED = "EXECUTED"
    REVERTED = "REVERTED"


@dataclass
class NormalizedSignatureEvent:
    event_id: str = field(default_factory=lambda: f"ev-{uuid.uuid4().hex[:10]}")
    timestamp_ns: int = field(default_factory=lambda: int(time.time() * 1e9))
    source_type: SourceType = SourceType.PKI_HSM
    key_id: str = "key-default"
    algorithm: AlgorithmType = AlgorithmType.RSA_2048
    key_length_bits: int = 2048
    requester_identity: str = "service_account_default"
    client_ip: str = "10.0.1.50"
    geo_location: str = "US-EAST"
    operation: str = "sign"  # sign, verify, key_export, cert_issue
    payload_hash: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sig_r_s_length: int = 512
    nonce_hex: Optional[str] = None
    nonce_entropy_bits: float = 7.95  # ~8.0 is ideal high-entropy
    signing_latency_ms: float = 4.2
    cert_chain_depth: int = 3
    is_malleable_candidate: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source_type"] = self.source_type.value if isinstance(self.source_type, SourceType) else self.source_type
        d["algorithm"] = self.algorithm.value if isinstance(self.algorithm, AlgorithmType) else self.algorithm
        return d


@dataclass
class AnomalyFeatureVector:
    event_id: str
    key_id: str
    features: List[float]  # normalized [0, 1] numerical vector
    feature_names: List[str]
    raw_event: NormalizedSignatureEvent


@dataclass
class ThreatAlert:
    alert_id: str = field(default_factory=lambda: f"alt-{uuid.uuid4().hex[:8]}")
    timestamp: float = field(default_factory=time.time)
    event_id: str = ""
    key_id: str = ""
    severity: AlertSeverity = AlertSeverity.HIGH
    confidence_score: float = 0.95  # [0.0, 1.0]
    attack_type: str = "Unknown Anomaly"
    mitre_ttp: str = "T1552.004"
    detection_engine: str = "QUBO + Tensor Network Hybrid"
    summary: str = ""
    feature_attribution: Dict[str, float] = field(default_factory=dict)  # SHAP-like attribution
    recommended_playbook: str = "Quarantine Key & Throttle HSM"
    soar_status: SOARStatus = SOARStatus.PENDING_APPROVAL
    affected_asset: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["soar_status"] = self.soar_status.value
        return d


@dataclass
class QuantumRiskAsset:
    asset_id: str
    asset_name: str
    key_id: str
    algorithm: AlgorithmType
    key_length: int
    data_shelf_life_years: int
    asset_criticality: float  # [0.5, 2.0]
    exposure_level: str       # PUBLIC, INTERNAL, AIR_GAPPED
    qvs_score: float          # [0, 100]
    pqc_recommended_target: AlgorithmType = AlgorithmType.ML_DSA_65
    migration_urgency: str = "MODERATE"
    status: str = "ACTIVE"    # ACTIVE, QUARANTINED, REVOKED, MIGRATED

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["algorithm"] = self.algorithm.value
        d["pqc_recommended_target"] = self.pqc_recommended_target.value
        return d
