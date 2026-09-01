"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Core Algorithm 4: Quantum Vulnerability Scoring (QVS) & PQC Migration Engine
"""

from typing import List, Dict, Any, Tuple
from telemetry.schema import QuantumRiskAsset, AlgorithmType


class QuantumRiskEngine:
    """
    Computes Quantum Vulnerability Scores (QVS in [0, 100]) based on the Mosca Theorem:
        If Shelf_Life (X) + Migration_Time (Y) > Time_to_CRQC (Z), then system is at immediate risk.

    Evaluates:
        - Base algorithm vulnerability to Shor's algorithm (discrete log / integer factorization)
        - Data / Signature shelf-life (years)
        - Asset criticality weight (Root CA, CI/CD, TLS, Blockchain)
        - Exposure factor (Public Internet vs Air-gapped)
        - PQC Migration target recommendation (NIST FIPS 204 ML-DSA, FIPS 205 SLH-DSA)
    """

    # Estimated years until Cryptographically Relevant Quantum Computer (CRQC) consensus
    CRQC_TIMELINE_YEARS = 6.5

    # Algorithm Vulnerability Coefficients S_algo in [0.0, 1.0]
    ALGORITHM_VULNERABILITY_MAP = {
        AlgorithmType.RSA_1024: 1.00,
        AlgorithmType.RSA_2048: 0.88,
        AlgorithmType.RSA_4096: 0.75,
        AlgorithmType.ECDSA_P256: 0.92,
        AlgorithmType.ECDSA_SECP256K1: 0.92,
        AlgorithmType.ED25519: 0.90,
        AlgorithmType.HYBRID_RSA_MLDSA: 0.15,
        AlgorithmType.ML_DSA_44: 0.05,
        AlgorithmType.ML_DSA_65: 0.03,
        AlgorithmType.ML_DSA_87: 0.02,
        AlgorithmType.SLH_DSA_128: 0.02,
        AlgorithmType.FN_DSA_512: 0.04
    }

    # Recommended PQC Migration Targets
    PQC_REPLACEMENT_TARGETS = {
        AlgorithmType.RSA_1024: AlgorithmType.ML_DSA_65,
        AlgorithmType.RSA_2048: AlgorithmType.ML_DSA_65,
        AlgorithmType.RSA_4096: AlgorithmType.ML_DSA_87,
        AlgorithmType.ECDSA_P256: AlgorithmType.ML_DSA_44,
        AlgorithmType.ECDSA_SECP256K1: AlgorithmType.ML_DSA_65,
        AlgorithmType.ED25519: AlgorithmType.ML_DSA_44,
        AlgorithmType.HYBRID_RSA_MLDSA: AlgorithmType.ML_DSA_65,
        AlgorithmType.ML_DSA_44: AlgorithmType.ML_DSA_44,
        AlgorithmType.ML_DSA_65: AlgorithmType.ML_DSA_65,
        AlgorithmType.ML_DSA_87: AlgorithmType.ML_DSA_87,
        AlgorithmType.SLH_DSA_128: AlgorithmType.SLH_DSA_128,
        AlgorithmType.FN_DSA_512: AlgorithmType.FN_DSA_512
    }

    def __init__(self, crqc_horizon_years: float = 6.5):
        self.crqc_horizon_years = crqc_horizon_years
        self.inventory: Dict[str, QuantumRiskAsset] = {}
        self._init_default_inventory()

    def _init_default_inventory(self):
        """Initializes a representative enterprise digital signature inventory."""
        sample_assets = [
            QuantumRiskAsset(
                asset_id="AST-001",
                asset_name="Corporate Enterprise Root CA",
                key_id="key-root-ca-01",
                algorithm=AlgorithmType.RSA_4096,
                key_length=4096,
                data_shelf_life_years=15,
                asset_criticality=2.0,
                exposure_level="INTERNAL",
                qvs_score=0.0
            ),
            QuantumRiskAsset(
                asset_id="AST-002",
                asset_name="Master CI/CD Production Release Signer",
                key_id="key-cicd-master",
                algorithm=AlgorithmType.ECDSA_P256,
                key_length=256,
                data_shelf_life_years=10,
                asset_criticality=1.9,
                exposure_level="INTERNAL",
                qvs_score=0.0
            ),
            QuantumRiskAsset(
                asset_id="AST-003",
                asset_name="Edge TLS Wildcard Gateway (*.corp.com)",
                key_id="key-edge-tls-wildcard",
                algorithm=AlgorithmType.RSA_2048,
                key_length=2048,
                data_shelf_life_years=1,
                asset_criticality=1.4,
                exposure_level="PUBLIC",
                qvs_score=0.0
            ),
            QuantumRiskAsset(
                asset_id="AST-004",
                asset_name="Treasury Blockchain Cold Multisig Validator",
                key_id="key-eth-cold-treasury",
                algorithm=AlgorithmType.ECDSA_SECP256K1,
                key_length=256,
                data_shelf_life_years=20,
                asset_criticality=2.0,
                exposure_level="PUBLIC",
                qvs_score=0.0
            ),
            QuantumRiskAsset(
                asset_id="AST-005",
                asset_name="Executive PDF Legal Contract Signer",
                key_id="key-doc-exec-signer",
                algorithm=AlgorithmType.RSA_2048,
                key_length=2048,
                data_shelf_life_years=25,
                asset_criticality=1.7,
                exposure_level="INTERNAL",
                qvs_score=0.0
            ),
            QuantumRiskAsset(
                asset_id="AST-006",
                asset_name="PQC Next-Gen Artifact Signer (Pilot)",
                key_id="key-pqc-dilithium-01",
                algorithm=AlgorithmType.ML_DSA_65,
                key_length=1536,
                data_shelf_life_years=10,
                asset_criticality=1.5,
                exposure_level="INTERNAL",
                qvs_score=0.0
            )
        ]
        for a in sample_assets:
            a.qvs_score = self.calculate_qvs(a)
            a.migration_urgency = self._determine_urgency(a.qvs_score)
            a.pqc_recommended_target = self.PQC_REPLACEMENT_TARGETS.get(a.algorithm, AlgorithmType.ML_DSA_65)
            self.inventory[a.asset_id] = a

    def calculate_qvs(self, asset: QuantumRiskAsset) -> float:
        """
        Calculates Quantum Vulnerability Score in range [0, 100].
        Formula:
            Base = S_algo(algo) * 35.0
            Time_Factor = min(30.0, (Shelf_Life / CRQC_Horizon) * 15.0)
            Criticality_Factor = (Criticality / 2.0) * 20.0
            Exposure_Factor = 15.0 if PUBLIC else (10.0 if INTERNAL else 3.0)
            QVS = min(100.0, Base + Time_Factor + Criticality_Factor + Exposure_Factor)
        """
        s_algo = self.ALGORITHM_VULNERABILITY_MAP.get(asset.algorithm, 0.85)

        # If already post-quantum, score is minimal (residual implementation/side-channel risk)
        if s_algo <= 0.05:
            return round(s_algo * 100.0, 1)

        base = s_algo * 35.0
        time_factor = min(30.0, (asset.data_shelf_life_years / self.crqc_horizon_years) * 12.0)
        crit_factor = (asset.asset_criticality / 2.0) * 20.0
        exp_map = {"PUBLIC": 15.0, "INTERNAL": 10.0, "AIR_GAPPED": 3.0}
        exp_factor = exp_map.get(asset.exposure_level, 10.0)

        total_qvs = min(100.0, base + time_factor + crit_factor + exp_factor)
        return round(total_qvs, 1)

    @staticmethod
    def _determine_urgency(qvs: float) -> str:
        if qvs >= 80.0:
            return "CRITICAL (Immediate PQC Migration Mandated)"
        elif qvs >= 60.0:
            return "HIGH (Plan Migration within 6 Months)"
        elif qvs >= 40.0:
            return "MODERATE (Phase 2 Migration Target)"
        return "LOW / QUANTUM SAFE"

    def get_organization_posture(self) -> Dict[str, Any]:
        """
        Calculates org-wide quantum risk posture, algorithm distributions, and compliance readiness.
        """
        assets = list(self.inventory.values())
        if not assets:
            return {}

        total_assets = len(assets)
        avg_qvs = sum(a.qvs_score for a in assets) / total_assets
        high_risk_count = sum(1 for a in assets if a.qvs_score >= 60.0)
        pqc_ready_count = sum(1 for a in assets if self.ALGORITHM_VULNERABILITY_MAP.get(a.algorithm, 1.0) <= 0.05)

        algo_breakdown: Dict[str, int] = {}
        for a in assets:
            algo_breakdown[a.algorithm.value] = algo_breakdown.get(a.algorithm.value, 0) + 1

        # Sorted by QVS descending
        prioritized = sorted(assets, key=lambda a: a.qvs_score, reverse=True)

        return {
            "total_monitored_signing_assets": total_assets,
            "average_qvs_score": round(avg_qvs, 1),
            "high_risk_assets_count": high_risk_count,
            "pqc_migration_progress_pct": round((pqc_ready_count / total_assets) * 100.0, 1),
            "crqc_estimated_years": self.crqc_horizon_years,
            "algorithm_distribution": algo_breakdown,
            "prioritized_inventory": [a.to_dict() for a in prioritized],
            "compliance_frameworks": {
                "NIST_FIPS_204_205": f"{round((pqc_ready_count / total_assets) * 100)}% Compliant",
                "CNSA_2_0_Timeline": "Phase 1 Transition Active",
                "NIS2_Quantum_Readiness": "Action Required on 3 Critical Keys"
            }
        }

    def update_asset_status(self, asset_id: str, new_status: str) -> bool:
        if asset_id in self.inventory:
            self.inventory[asset_id].status = new_status
            return True
        return False
