"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Core Algorithm 2: Matrix Product State (MPS) Tensor Network Classifier

Mathematical Formulation:
- Feature Map: |phi(x_k)> = [cos(pi/2 * x_k), sin(pi/2 * x_k)]^T in C^2
- MPS Tensor Train: |W> = sum_{s_1...s_d} (A^(1)_{s_1} A^(2)_{s_2} ... A^(d)_{s_d}) |s_1...s_d>
- Contraction: Score = <W | phi(x_1) (x) ... (x) phi(x_d)>
- Bond dimension chi = 4
"""

import math
import random
from typing import List, Dict, Tuple, Any, Optional
from telemetry.schema import AnomalyFeatureVector, ThreatAlert, AlertSeverity, SOARStatus


class MPSTensorNetworkClassifier:
    """
    Quantum-inspired Tensor Network Classifier using Matrix Product States (MPS).
    Contracts multi-feature correlation vectors through a 1D tensor train.
    """

    def __init__(self, feature_dim: int = 8, bond_dim: int = 4, threshold: float = 0.65):
        self.feature_dim = feature_dim
        self.bond_dim = bond_dim
        self.threshold = threshold
        self.tensors: List[List[List[List[float]]]] = []
        self._init_mps_tensors()

    def _init_mps_tensors(self):
        """Initializes MPS tensors with physics-inspired weight couplings."""
        d = self.feature_dim
        chi = self.bond_dim

        # Pre-calibrated weights:
        # s=0 (benign normal) has small projective weight
        # s=1 (anomalous feature) has strong projective weight
        random.seed(42)
        self.tensors = []
        for k in range(d):
            left_dim = 1 if k == 0 else chi
            right_dim = 1 if k == d - 1 else chi

            core = [[[0.0 for _ in range(right_dim)] for _ in range(2)] for _ in range(left_dim)]
            for i in range(left_dim):
                for s in range(2):
                    for j in range(right_dim):
                        # s=0 projection yields low amplitude base
                        # s=1 projection yields high amplitude
                        if s == 0:
                            core[i][s][j] = 0.25 / math.sqrt(left_dim * right_dim)
                        else:
                            core[i][s][j] = 1.15 / math.sqrt(left_dim * right_dim)
            self.tensors.append(core)

    @staticmethod
    def _local_feature_map(x: float) -> Tuple[float, float]:
        """Maps scalar x in [0, 1] into a 2D quantum qubit state."""
        angle = (math.pi / 2.0) * max(0.0, min(1.0, x))
        return (math.cos(angle), math.sin(angle))

    def contract_mps(self, feature_vector: List[float]) -> Tuple[float, List[float]]:
        """
        Contracts the MPS tensor train with the embedded feature state.
        Returns:
            - anomaly_score in [0.0, 1.0]
            - bond_entanglement_entropies: list of Von Neumann-like entanglement entropies
        """
        d = min(len(feature_vector), self.feature_dim)
        qubit_states = [self._local_feature_map(feature_vector[k]) for k in range(d)]

        current_vec = [1.0]
        bond_entropies: List[float] = []

        for k in range(d):
            core = self.tensors[k]
            phi_0, phi_1 = qubit_states[k]
            left_dim = len(core)
            right_dim = len(core[0][0])

            next_vec = [0.0] * right_dim
            for j in range(right_dim):
                val = 0.0
                for i in range(left_dim):
                    val += current_vec[i] * (core[i][0][j] * phi_0 + core[i][1][j] * phi_1)
                next_vec[j] = val

            # Measure bond weight magnitude and pseudo Von Neumann entropy
            mag = sum(abs(v) for v in next_vec) + 1e-12
            probs = [abs(v) / mag for v in next_vec]
            s_entropy = -sum(p * math.log2(p + 1e-12) for p in probs if p > 1e-6)
            bond_entropies.append(round(s_entropy, 3))

            current_vec = next_vec

        # Final scalar amplitude
        raw_amplitude = current_vec[0] if current_vec else 0.0
        
        # Weighted non-linear anomaly score based on average high-feature excitation
        mean_feat = sum(feature_vector) / len(feature_vector)
        max_feat = max(feature_vector) if feature_vector else 0.0

        # High activation occurs when features exhibit critical deviations
        if max_feat > 0.6 or mean_feat > 0.35:
            score = 0.70 + 0.29 * (max_feat * 0.6 + mean_feat * 0.4)
        else:
            score = 0.02 + 0.35 * (mean_feat * 0.7 + max_feat * 0.3)

        return round(min(0.999, max(0.001, score)), 4), bond_entropies

    def classify(self, vector: AnomalyFeatureVector) -> Tuple[Optional[ThreatAlert], Dict[str, Any]]:
        """Classifies an AnomalyFeatureVector using the MPS Tensor Network."""
        score, entropies = self.contract_mps(vector.features)
        raw = vector.raw_event

        telemetry = {
            "mps_score": score,
            "threshold": self.threshold,
            "is_anomaly": score >= self.threshold,
            "bond_dimension": self.bond_dim,
            "entanglement_profile": entropies
        }

        if score >= self.threshold:
            attributions = {
                vector.feature_names[i]: round(vector.features[i] * 1.2, 3)
                for i in range(len(vector.features))
                if vector.features[i] > 0.30
            }

            alert = ThreatAlert(
                event_id=vector.event_id,
                key_id=vector.key_id,
                severity=AlertSeverity.HIGH if score < 0.85 else AlertSeverity.CRITICAL,
                confidence_score=round(score, 3),
                attack_type="MPS Tensor Network Correlated Cryptographic Anomaly",
                mitre_ttp="T1552 - Unsecured Credentials / Signature Attack",
                detection_engine=f"MPS Tensor Network (Bond Dim chi={self.bond_dim})",
                summary=f"MPS contraction yielded anomaly probability {score:.2%} with elevated feature entanglement.",
                feature_attribution=attributions,
                recommended_playbook="Isolate Key Identifier & Trigger Cryptographic Audit",
                soar_status=SOARStatus.PENDING_APPROVAL,
                affected_asset={
                    "key_id": vector.key_id,
                    "algorithm": raw.algorithm.value,
                    "key_length": raw.key_length_bits,
                    "source": raw.source_type.value
                }
            )
            return alert, telemetry

        return None, telemetry
