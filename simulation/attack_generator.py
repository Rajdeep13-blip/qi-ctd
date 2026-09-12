"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Simulation Engine: Normal Baseline & Dynamic Synthetic Attack Scenarios Generator
(Fully randomized cryptographic parameters on every invocation)
"""

import time
import random
import hashlib
from typing import List, Dict, Any
from telemetry.schema import NormalizedSignatureEvent, SourceType, AlgorithmType
from core.ecdsa_recovery import ECDSANonceRecoveryEngine, SECP256K1_N


class SyntheticAttackGenerator:
    """
    Generates realistic normal baseline digital signature telemetry and injects
    targeted cryptographic attack scenarios to benchmark QI-CTD detection recall.
    All parameters are dynamically randomized per execution.
    """

    def __init__(self):
        self._seq = int(time.time()) % 100000

    def _next_event_id(self) -> str:
        self._seq += 1
        return f"ev-{self._seq}"

    @staticmethod
    def _random_hash() -> str:
        return hashlib.sha256(f"{random.random()}-{time.time_ns()}".encode()).hexdigest()

    @staticmethod
    def _random_ip(internal: bool = True) -> str:
        if internal:
            return f"10.{random.randint(10, 100)}.{random.randint(1, 20)}.{random.randint(10, 250)}"
        return f"{random.randint(30, 210)}.{random.randint(10, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"

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
            nonce_bytes = bytes([random.randint(0, 255) for _ in range(32)])
            event = NormalizedSignatureEvent(
                event_id=self._next_event_id(),
                timestamp_ns=now_ns + i * 50_000_000,
                source_type=src,
                key_id=f"key-{src.value}-norm-{random.randint(1, 10)}",
                algorithm=algo,
                key_length_bits=bits,
                requester_identity=requester,
                client_ip=self._random_ip(internal=True),
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
        Scenario 1: Dynamic ECDSA Nonce Reuse (Real mathematical private key recovery)
        Generates genuine secp256k1 signatures sharing the EXACT same nonce k.
        """
        priv_key = random.randint(1, SECP256K1_N - 1)
        reused_k = random.randint(1, SECP256K1_N - 1)
        key_id = f"key-ecdsa-treasury-{random.randint(100, 999)}"
        now_ns = int(time.time() * 1e9)

        tx1_msg = f"Transfer {random.randint(10, 500)} BTC to Treasury Vault 0x{self._random_hash()[:10]}"
        tx2_msg = f"Transfer {random.randint(1, 50)} BTC to Cold Storage 0x{self._random_hash()[:10]}"

        sig1 = ECDSANonceRecoveryEngine.sign_message(priv_key, tx1_msg, fixed_nonce=reused_k)
        sig2 = ECDSANonceRecoveryEngine.sign_message(priv_key, tx2_msg, fixed_nonce=reused_k)

        # Pre-verify mathematical private key recovery
        recovery_proof = ECDSANonceRecoveryEngine.recover_private_key(sig1, sig2)

        ev1 = NormalizedSignatureEvent(
            event_id=self._next_event_id(),
            timestamp_ns=now_ns,
            source_type=SourceType.BLOCKCHAIN,
            key_id=key_id,
            algorithm=AlgorithmType.ECDSA_SECP256K1,
            key_length_bits=256,
            requester_identity=f"treasury-signer-node-{random.choice(['a', 'primary', 'eu-1'])}",
            client_ip=self._random_ip(internal=True),
            geo_location="EU-CENTRAL",
            operation="sign_tx",
            payload_hash=sig1["hash_z"],
            sig_r_s_length=64,
            nonce_hex=sig1["nonce_k"],
            nonce_entropy_bits=2.15,
            signing_latency_ms=round(2.8 + random.random() * 0.6, 2),
            cert_chain_depth=2,
            is_malleable_candidate=False,
            metadata={
                "tx_id": f"0x{self._random_hash()[:16]}",
                "attack_tag": "NONCE_REUSE_COLLISION",
                "sig_r": sig1["r"],
                "sig_s": sig1["s"],
                "recovery_proof": recovery_proof
            }
        )

        ev2 = NormalizedSignatureEvent(
            event_id=self._next_event_id(),
            timestamp_ns=now_ns + random.randint(50_000_000, 200_000_000),
            source_type=SourceType.BLOCKCHAIN,
            key_id=key_id,
            algorithm=AlgorithmType.ECDSA_SECP256K1,
            key_length_bits=256,
            requester_identity=f"untrusted-proxy-worker-{random.randint(10, 99)}",
            client_ip=self._random_ip(internal=False), # external anomalous IP
            geo_location="TOR-EXIT",
            operation="sign_tx",
            payload_hash=sig2["hash_z"],
            sig_r_s_length=64,
            nonce_hex=sig2["nonce_k"], # IDENTICAL NONCE
            nonce_entropy_bits=2.15,
            signing_latency_ms=round(3.1 + random.random() * 0.8, 2),
            cert_chain_depth=2,
            is_malleable_candidate=False,
            metadata={
                "tx_id": f"0x{self._random_hash()[:16]}",
                "attack_tag": "NONCE_REUSE_COLLISION",
                "sig_r": sig2["r"],
                "sig_s": sig2["s"],
                "recovery_proof": recovery_proof
            }
        )

        return [ev1, ev2]

    def inject_attack_scenario_2_signature_malleability(self) -> List[NormalizedSignatureEvent]:
        """Scenario 2: Digital Signature Malleability & Low-S Violation (Tx Mutability Abuse)."""
        now_ns = int(time.time() * 1e9)
        ev = NormalizedSignatureEvent(
            event_id=self._next_event_id(),
            timestamp_ns=now_ns,
            source_type=SourceType.BLOCKCHAIN,
            key_id=f"key-eth-smart-contract-{random.randint(10, 99)}",
            algorithm=AlgorithmType.ECDSA_SECP256K1,
            key_length_bits=256,
            requester_identity=f"unauthenticated-relayer-{random.randint(100, 999)}",
            client_ip=self._random_ip(internal=False),
            geo_location="ANON-VPN",
            operation="relay_signature",
            payload_hash=self._random_hash(),
            sig_r_s_length=65,
            nonce_hex=self._random_hash()[:32],
            nonce_entropy_bits=7.8,
            signing_latency_ms=round(16.5 + random.random() * 4.0, 2),
            cert_chain_depth=1,
            is_malleable_candidate=True,
            metadata={"malleability_flag": "HIGH_S_VIOLATION", "curve": "secp256k1", "bip62_rule": "FAILED"}
        )
        return [ev]

    def inject_attack_scenario_3_rogue_cicd_signing(self) -> List[NormalizedSignatureEvent]:
        """Scenario 3: Rogue CI/CD Supply Chain Signing Anomaly (SolarWinds style)."""
        now_ns = int(time.time() * 1e9)
        ev = NormalizedSignatureEvent(
            event_id=self._next_event_id(),
            timestamp_ns=now_ns,
            source_type=SourceType.CICD_SIGNING,
            key_id=f"key-cicd-master-release-{random.randint(1, 5)}",
            algorithm=AlgorithmType.RSA_4096,
            key_length_bits=4096,
            requester_identity=f"unauthorized_runner_vm_{random.randint(1000, 9999)}",
            client_ip=self._random_ip(internal=False),
            geo_location="UNKNOWN-HOST",
            operation="sign_release_artifact",
            payload_hash=self._random_hash(),
            sig_r_s_length=512,
            nonce_hex=None,
            nonce_entropy_bits=7.92,
            signing_latency_ms=round(85.0 + random.random() * 20.0, 2),
            cert_chain_depth=random.randint(5, 7),
            is_malleable_candidate=False,
            metadata={
                "pipeline_id": f"shadow-build-job-{random.randint(100, 999)}",
                "artifact_name": random.choice(["update_agent.dll", "kernel_patch.bin", "auth_helper.so"])
            }
        )
        return [ev]

    def inject_attack_scenario_4_harvest_now_bulk_export(self) -> List[NormalizedSignatureEvent]:
        """Scenario 4: Quantum 'Harvest Now, Decrypt Later' (HNDL) Bulk Exfiltration."""
        events: List[NormalizedSignatureEvent] = []
        now_ns = int(time.time() * 1e9)
        burst_size = random.randint(6, 10)
        target_key = f"key-root-ca-{random.randint(1, 4)}"
        suspicious_ip = self._random_ip(internal=False)

        for i in range(burst_size):
            ev = NormalizedSignatureEvent(
                event_id=self._next_event_id(),
                timestamp_ns=now_ns + (i * 12_000_000),
                source_type=SourceType.PKI_HSM,
                key_id=target_key,
                algorithm=AlgorithmType.RSA_4096,
                key_length_bits=4096,
                requester_identity=f"recon-scraper-daemon-{random.randint(1, 20)}",
                client_ip=suspicious_ip,
                geo_location="ANON-TOR",
                operation="bulk_key_export_handshake",
                payload_hash=self._random_hash(),
                sig_r_s_length=512,
                nonce_hex=None,
                nonce_entropy_bits=7.98,
                signing_latency_ms=round(1.2 + random.random() * 0.5, 2),
                cert_chain_depth=1,
                is_malleable_candidate=False,
                metadata={"hndl_bulk_flag": True, "target_shelf_life_years": 25}
            )
            events.append(ev)
        return events
