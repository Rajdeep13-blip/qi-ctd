"""
Quantum-Inspired Cyber Threat Detection (QI-CTD)
Core Algorithm 1: QUBO & Simulated Annealing Anomaly Detector
"""

import math
import random
from typing import List, Dict, Tuple, Any, Optional
from telemetry.schema import AnomalyFeatureVector, ThreatAlert, AlertSeverity, SOARStatus


class QUBOAnomalySolver:
    """
    Formulates high-dimensional signature anomaly detection as a Quadratic Unconstrained
    Binary Optimization (QUBO) problem:
        min x^T Q x, where x in {0, 1}^N

    Where:
        - N is the batch window of signature events.
        - x_i = 1 designates event i as an anomaly/outlier.
        - Linear diagonal terms Q_ii represent individual event unary anomaly potential (derived from feature distance).
        - Off-diagonal terms Q_ij represent pairwise coherence / mutual consistency between events (penalizes co-clustering unrelated noise).
        - Capacity penalty lambda * (sum(x_i) - K)^2 enforces sparsity / expected anomaly prior.
    """

    def __init__(
        self,
        temperature_initial: float = 10.0,
        cooling_rate: float = 0.95,
        num_sweeps: int = 250,
        anomaly_prior_k: int = 1,
        penalty_lambda: float = 2.5
    ):
        self.t_init = temperature_initial
        self.cooling_rate = cooling_rate
        self.num_sweeps = num_sweeps
        self.anomaly_prior_k = anomaly_prior_k
        self.penalty_lambda = penalty_lambda

    @staticmethod
    def _euclidean_distance(v1: List[float], v2: List[float]) -> float:
        return math.sqrt(sum((a - b) ** 2 for a, b in zip(v1, v2)))

    @staticmethod
    def _cosine_similarity(v1: List[float], v2: List[float]) -> float:
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot / (norm1 * norm2)

    def build_qubo_matrix(self, vectors: List[AnomalyFeatureVector]) -> List[List[float]]:
        """
        Constructs the N x N QUBO matrix Q from a batch of feature vectors.
        """
        N = len(vectors)
        if N == 0:
            return []

        # 1. Compute centroid of the batch (representing the baseline normal operating point)
        dim = len(vectors[0].features)
        centroid = [0.0] * dim
        for v in vectors:
            for d in range(dim):
                centroid[d] += v.features[d]
        centroid = [c / N for c in centroid]

        # 2. Build Q matrix
        Q = [[0.0 for _ in range(N)] for _ in range(N)]

        # Linear unary potential (diagonal): distance from centroid + feature weight penalties
        for i in range(N):
            dist_to_centroid = self._euclidean_distance(vectors[i].features, centroid)
            # High values in specific critical features (like low nonce entropy or malleability)
            critical_penalty = (
                vectors[i].features[0] * 3.0 +   # nonce entropy inv
                vectors[i].features[5] * 2.5 +   # malleability
                vectors[i].features[7] * 2.0     # privilege mismatch
            )
            # In QUBO, we MINIMIZE energy. To make anomalies have x_i = 1, we make Q_ii negative for high anomaly scores.
            Q[i][i] = -(dist_to_centroid + critical_penalty)

        # Off-diagonal terms: pairwise similarity coupling
        for i in range(N):
            for j in range(i + 1, N):
                sim = self._cosine_similarity(vectors[i].features, vectors[j].features)
                # If two events are very similar, coupling encourages them to share the same state
                coupling = -0.5 * sim
                Q[i][j] = coupling
                Q[j][i] = coupling

        # Add capacity constraint penalty: lambda * (sum(x) - K)^2
        # Expansion: lambda * sum(x_i^2) + 2*lambda * sum(x_i * x_j) - 2*lambda*K * sum(x_i) + lambda*K^2
        # Since x_i in {0,1}, x_i^2 = x_i.
        for i in range(N):
            Q[i][i] += self.penalty_lambda * (1.0 - 2.0 * self.anomaly_prior_k)
            for j in range(i + 1, N):
                coupling_penalty = 2.0 * self.penalty_lambda
                Q[i][j] += coupling_penalty
                Q[j][i] += coupling_penalty

        return Q

    def compute_energy(self, state: List[int], Q: List[List[float]]) -> float:
        """Computes QUBO Hamiltonian energy E = x^T Q x."""
        N = len(state)
        energy = 0.0
        for i in range(N):
            if state[i] == 1:
                for j in range(N):
                    if state[j] == 1:
                        energy += Q[i][j]
        return energy

    def solve_simulated_annealing(
        self, Q: List[List[float]]
    ) -> Tuple[List[int], float, List[float], List[List[int]]]:
        """
        Solves QUBO via Simulated Annealing.
        Returns:
            - best_state: binary state vector {0, 1}^N
            - best_energy: minimum energy achieved
            - energy_trace: progression of energy over annealing sweeps
            - state_history: sample of spin states for visualizer
        """
        N = len(Q)
        if N == 0:
            return [], 0.0, [], []

        # Initialize random binary state
        current_state = [1 if random.random() < 0.1 else 0 for _ in range(N)]
        current_energy = self.compute_energy(current_state, Q)

        best_state = list(current_state)
        best_energy = current_energy

        temp = self.t_init
        energy_trace: List[float] = [current_energy]
        state_history: List[List[int]] = [list(current_state)]

        for sweep in range(self.num_sweeps):
            # Pick a random spin to flip
            flip_idx = random.randint(0, N - 1)
            candidate_state = list(current_state)
            candidate_state[flip_idx] = 1 - candidate_state[flip_idx]

            candidate_energy = self.compute_energy(candidate_state, Q)
            delta_e = candidate_energy - current_energy

            # Metropolis-Hastings acceptance criterion
            if delta_e < 0 or (temp > 1e-6 and random.random() < math.exp(-delta_e / temp)):
                current_state = candidate_state
                current_energy = candidate_energy

                if current_energy < best_energy:
                    best_energy = current_energy
                    best_state = list(current_state)

            # Cool temperature
            temp *= self.cooling_rate
            if sweep % 5 == 0:
                energy_trace.append(round(current_energy, 4))
                state_history.append(list(current_state))

        return best_state, round(best_energy, 4), energy_trace, state_history

    def detect_anomalies(
        self, vectors: List[AnomalyFeatureVector]
    ) -> Tuple[List[ThreatAlert], Dict[str, Any]]:
        """
        Runs the full QUBO Anomaly Pipeline on a batch of telemetry events.
        """
        if not vectors:
            return [], {}

        Q = self.build_qubo_matrix(vectors)
        best_state, best_energy, energy_trace, state_history = self.solve_simulated_annealing(Q)

        alerts: List[ThreatAlert] = []

        for idx, is_anomaly in enumerate(best_state):
            if is_anomaly == 1:
                v = vectors[idx]
                raw = v.raw_event

                # Calculate feature attributions (SHAP-style)
                attributions: Dict[str, float] = {}
                for f_idx, f_name in enumerate(v.feature_names):
                    val = v.features[f_idx]
                    if val > 0.3:
                        attributions[f_name] = round(val * (1.5 if "entropy" in f_name or "malleability" in f_name else 1.0), 3)

                # Determine Attack Type & MITRE Mapping
                if v.features[0] > 0.4:  # low nonce entropy
                    attack_type = "ECDSA Nonce Bias / Weak PRNG (Key Recovery Setup)"
                    mitre_ttp = "T1552.004 - Private Key Recovery"
                    severity = AlertSeverity.CRITICAL
                    playbook = "Quarantine Key & Revoke Subverted Certificates"
                elif v.features[5] > 0.5: # malleability
                    attack_type = "Digital Signature Malleability Abuse (Low-S Violation)"
                    mitre_ttp = "T1565.002 - Transmitted Data Manipulation"
                    severity = AlertSeverity.HIGH
                    playbook = "Enforce Low-S Canonical Verification Rule"
                elif v.features[7] > 0.6: # privilege mismatch
                    attack_type = "Rogue CI/CD Supply Chain Signing Anomaly"
                    mitre_ttp = "T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain"
                    severity = AlertSeverity.CRITICAL
                    playbook = "Quarantine CI/CD Signing Certificate & Terminate Build Pipeline"
                elif v.features[4] > 0.6: # frequency burst
                    attack_type = "Automated Key Harvesting / Rapid Replay Attack"
                    mitre_ttp = "T1110 - Brute Force / Token Harvesting"
                    severity = AlertSeverity.MEDIUM
                    playbook = "Apply HSM Rate-Limiting & Alert On-Call Engineer"
                else:
                    attack_type = "Cryptographic Telemetry Behavioral Outlier"
                    mitre_ttp = "T1078 - Valid Accounts Misuse"
                    severity = AlertSeverity.MEDIUM
                    playbook = "Trigger SOC Analyst Deep-Dive Triage"

                # Calculate confidence based on energy gap and attribution magnitude
                total_attr = sum(attributions.values())
                confidence = min(0.99, max(0.85, 0.70 + (total_attr * 0.1)))

                alert = ThreatAlert(
                    event_id=v.event_id,
                    key_id=v.key_id,
                    severity=severity,
                    confidence_score=round(confidence, 3),
                    attack_type=attack_type,
                    mitre_ttp=mitre_ttp,
                    detection_engine="QUBO Simulated Annealing Solver",
                    summary=f"QUBO energy state minimized with outlier partition x_{idx}=1 on key {v.key_id} ({raw.algorithm.value}).",
                    feature_attribution=attributions,
                    recommended_playbook=playbook,
                    soar_status=SOARStatus.PENDING_APPROVAL,
                    affected_asset={
                        "key_id": v.key_id,
                        "algorithm": raw.algorithm.value,
                        "key_length": raw.key_length_bits,
                        "source": raw.source_type.value,
                        "client_ip": raw.client_ip
                    }
                )
                alerts.append(alert)

        solver_telemetry = {
            "num_events": len(vectors),
            "qubo_dim": f"{len(vectors)}x{len(vectors)}",
            "min_energy": best_energy,
            "energy_trace": energy_trace,
            "spin_history": state_history[:15],
            "anomalies_detected": len(alerts),
            "convergence_sweeps": self.num_sweeps
        }

        return alerts, solver_telemetry
