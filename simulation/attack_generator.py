"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Simulation Engine: Normal Baseline & Synthetic Attack Scenarios Generator
"""

import time
import random
import uuid
import hashlib
from typing import List, Dict, Any
from telemetry.schema import (
    NormalizedSignatureEvent,
    SourceType,
    AlgorithmType
)


class SyntheticAttackGenerator:
    """
    Generates realistic normal baseline digital signature telemetry and injects
    targeted cryptographic attack scenarios to benchmark QI-CTD detection recall.
    """

    def __init__(self):
        self._seq = 1000

    def _next_event_id(self) -> str:
        self._seq += 1
        return f"ev-{self._seq}"

    @staticmethod
    def _random_hash() -> str:
        return hashlib.sha256(f"{random.random()}-{time.time_ns()}".encode()).hexdigest()

    def generate_baseline_normal_stream(self, count: int = 15) -> List[NormalizedSignatureEvent]:
        """Generates regular benign telemetry across all sources."""
        events: List[NormalizedSignatureEvent] = []
        normal_sources = [
            (SourceType.TLS_MTLS, AlgorithmType.RSA_2048, 2048, "tls-terminator-01@edge.internal", "US-EAST", 3.8),
            (SourceType.PKI_HSM, AlgorithmType.ECDSA_P256, 256, "pki-signer-svc@corp.internal", "US-EAST", 4.1),
            (SourceType.CICD_SIGNING, AlgorithmType.ML_DSA_65, 1536, "prod-release-bot@infra.internal", "US-WEST", 5.2),
            (SourceType.BLOCKCHAIN, AlgorithmType.ECDSA_SECP256K1, 256, "blockchain-validator-node-01", "EU-CENTRAL", 2.9),
            (SourceType.DOC_SIGNING, AlgorithmType.RSA_2048, 2048, "doc-sign-daemon@corp.internal", "US-EAST", 4.5)
        ]

        now_ns = int(time.time() * 1e9)
        for i in range(count):
            src, algo, bits, requester, geo, base_lat = random.choice(normal_sources)
            # High-entropy random nonce
            nonce_bytes = bytes([random.randint(0, 255) for _ in range(32)])
            event = NormalizedSignatureEvent(
                event_id=self._next_event_id(),
                timestamp_ns=now_ns + i * 50_000_000,
                source_type=src,
                key_id=f"key-{src.value}-norm-{random.randint(1, 4)}",
                algorithm=algo,
                key_length_bits=bits,
                requester_identity=requester,
                client_ip=f"10.100.{random.randint(1, 10)}.{random.randint(10, 200)}",
                geo_location=geo,
                operation="sign",
                payload_hash=self._random_hash(),
                sig_r_s_length=512 if "RSA" in algo.value else (64 if "ECDSA" in algo.value else 128),
                nonce_hex=nonce_bytes.hex(),
                nonce_entropy_bits=round(7.85 + random.random() * 0.14, 3),
                signing_latency_ms=round(base_lat + (random.random() - 0.5) * 1.2, 2),
                cert_chain_depth=random.randint(2, 3),
                is_malleable_candidate=False,
                metadata={"status": "SUCCESS", "tls_version": "TLSv1.3"}
            )
            events.append(event)

        return events

    def inject_attack_scenario_1_nonce_reuse(self) -> List[NormalizedSignatureEvent]:
        """
        Scenario 1: ECDSA Nonce Reuse / Weak PRNG (Enables Catastrophic Private Key Recovery)
        Two distinct signatures generated with the IDENTICAL nonce k-value.
        """
        fixed_nonce = "a8f3c1d94b7e20684f5a11c08e3321557ba8d34091c5e9a4f216789bde014432"
        key_id = "key-ecdsa-treasury-master"
        now_ns = int(time.time() * 1e9)

        ev1 = NormalizedSignatureEvent(
            event_id=self._next_event_id(),
            timestamp_ns=now_ns,
            source_type=SourceType.BLOCKCHAIN,
            key_id=key_id,
            algorithm=AlgorithmType.ECDSA_SECP256K1,
            key_length_bits=256,
            requester_identity="treasury-signer-node-a",
            client_ip="192.168.1.101",
            geo_location="EU-CENTRAL",
            operation="sign_tx",
            payload_hash=self._random_hash(),
            sig_r_s_length=64,
            nonce_hex=fixed_nonce,
            nonce_entropy_bits=2.15, # severely degraded entropy
            signing_latency_ms=3.1,
            cert_chain_depth=2,
            is_malleable_candidate=False,
            metadata={"tx_id": "0x4f8a...12", "attack_tag": "NONCE_REUSE_A"}
        )

        ev2 = NormalizedSignatureEvent(
            event_id=self._next_event_id(),
            timestamp_ns=now_ns + 120_000_000,
            source_type=SourceType.BLOCKCHAIN,
            key_id=key_id,
            algorithm=AlgorithmType.ECDSA_SECP256K1,
            key_length_bits=256,
            requester_identity="treasury-signer-node-b",
            client_ip="45.33.32.156", # anomalous external IP
            geo_location="TOR-EXIT",
            operation="sign_tx",
            payload_hash=self._random_hash(),
            sig_r_s_length=64,
            nonce_hex=fixed_nonce, # EXACT SAME NONCE!
            nonce_entropy_bits=2.15,
            signing_latency_ms=3.2,
            cert_chain_depth=2,
            is_malleable_candidate=False,
            metadata={"tx_id": "0x9c3e...88", "attack_tag": "NONCE_REUSE_B"}
        )

        return [ev1, ev2]

    def inject_attack_scenario_2_signature_malleability(self) -> List[NormalizedSignatureEvent]:
        """
        Scenario 2: Digital Signature Malleability & Low-S Violation (Tx Mutability Abuse)
        """
        now_ns = int(time.time() * 1e9)
        ev = NormalizedSignatureEvent(
            event_id=self._next_event_id(),
            timestamp_ns=now_ns,
            source_type=SourceType.BLOCKCHAIN,
            key_id="key-eth-smart-contract",
            algorithm=AlgorithmType.ECDSA_SECP256K1,
            key_length_bits=256,
            requester_identity="unauthenticated-relayer",
            client_ip="185.220.101.5",
            geo_location="TOR-EXIT",
            operation="relay_signature",
            payload_hash=self._random_hash(),
            sig_r_s_length=65,
            nonce_hex=self._random_hash()[:32],
            nonce_entropy_bits=7.8,
            signing_latency_ms=18.5,
            cert_chain_depth=1,
            is_malleable_candidate=True, # high-s / malleable signature detected
            metadata={"malleability_flag": "HIGH_S_DETECTED", "curve": "secp256k1"}
        )
        return [ev]

    def inject_attack_scenario_3_rogue_cicd_signing(self) -> List[NormalizedSignatureEvent]:
        """
        Scenario 3: Rogue CI/CD Supply Chain Signing Anomaly (SolarWinds style)
        Unauthorized runner signs binary with tier-1 master production key at abnormal hours.
        """
        now_ns = int(time.time() * 1e9)
        ev = NormalizedSignatureEvent(
            event_id=self._next_event_id(),
            timestamp_ns=now_ns, # 02:45 AM timestamp
            source_type=SourceType.CICD_SIGNING,
            key_id="key-cicd-master-release",
            algorithm=AlgorithmType.RSA_4096,
            key_length_bits=4096,
            requester_identity="unauthorized_runner_vm_9823", # untrusted caller
            client_ip="198.51.100.42",
            geo_location="UNKNOWN-GEO",
            operation="sign_release_artifact",
            payload_hash=self._random_hash(),
            sig_r_s_length=512,
            nonce_hex=None,
            nonce_entropy_bits=7.9,
            signing_latency_ms=92.4, # abnormal HSM latency
            cert_chain_depth=6, # anomalous deep chain
            is_malleable_candidate=False,
            metadata={"pipeline_id": "nightly-shadow-build-09", "artifact_name": "update_agent.dll"}
        )
        return [ev]

    def inject_attack_scenario_4_harvest_now_bulk_export(self) -> List[NormalizedSignatureEvent]:
        """
        Scenario 4: Quantum "Harvest Now, Decrypt/Forge Later" Bulk Export
        High burst rate of key export and public certificate cataloging on long-term RSA-4096 roots.
        """
        events: List[NormalizedSignatureEvent] = []
        now_ns = int(time.time() * 1e9)
        for i in range(8):
            ev = NormalizedSignatureEvent(
                event_id=self._next_event_id(),
                timestamp_ns=now_ns + (i * 10_000_000),
                source_type=SourceType.PKI_HSM,
                key_id="key-root-ca-01",
                algorithm=AlgorithmType.RSA_4096,
                key_length_bits=4096,
                requester_identity="suspicious-recon-service",
                client_ip="103.245.236.1",
                geo_location="ANON-VPN",
                operation="key_export_metadata",
                payload_hash=self._random_hash(),
                sig_r_s_length=512,
                nonce_hex=None,
                nonce_entropy_bits=7.9,
                signing_latency_ms=1.1,
                cert_chain_depth=1,
                is_malleable_candidate=False,
                metadata={"batch_export_flag": True, "target_lifetime_years": 25}
            )
            events.append(ev)
        return events
