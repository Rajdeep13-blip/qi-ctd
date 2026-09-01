# Quantum-Inspired Cyber Threat Detection (QI-CTD)

> **Quantum-Inspired Cyber Threat Detection for Digital Signature Security**
> A detection and monitoring layer using simulated annealing / QUBO optimization, Matrix Product State (MPS) tensor networks, and Grover-inspired amplitude amplification search heuristics run on classical hardware to detect anomalous, forged, or quantum-attack-precursor activity around digital signature operations in real time.

---

## 🌟 Key Architecture & Capabilities

1. **QUBO / Simulated Annealing Anomaly Solver (`core/qubo_engine.py`)**:
   - Formulates high-dimensional signature telemetry clustering into a Quadratic Unconstrained Binary Optimization (QUBO) Hamiltonian: $\min \mathbf{x}^T \mathbf{Q} \mathbf{x}$.
   - Partitions baseline normal signing behavior from subtle attack outliers.
   - Built to run on classical GPUs/CPUs, with an abstraction layer for D-Wave Advantage and cloud QPU backends (AWS Braket / Azure Quantum).

2. **Matrix Product State (MPS) Tensor Network Classifier (`core/tensor_network.py`)**:
   - Maps multi-dimensional cryptographic features into product states of 2-level quantum spin states.
   - Captures high-order, multi-feature cryptographic correlations (such as subtle biased nonce generators in ECDSA/EdDSA) with linear parameter scaling $O(d \cdot \chi^2)$.

3. **Grover-Inspired Amplitude Amplification Search (`core/grover_search.py`)**:
   - Accelerates correlation search queries over historic signature graphs for complex multi-stage attack footprints.
   - Quadratic speedup $O(\sqrt{N/M})$ in isolating rare cross-IP nonce collisions and key harvesting patterns.

4. **Quantum Vulnerability Scoring (QVS) Engine (`core/qvs_engine.py`)**:
   - Evaluates Mosca Theorem conditions ($X + Y > Z$) and generates prioritized PQC migration roadmaps.
   - Tracks NIST FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and CNSA 2.0 readiness.

5. **Interactive SOC & CISO Quantum Posture Dashboard (`dashboard/`)**:
   - **SOC Real-Time Stream**: Live telemetry feed, alert queue, MITRE ATT&CK TTP mapping, and 1-Click SOAR playbooks.
   - **Quantum-Inspired Visualizers**: Live canvas animations for QUBO energy minimization, MPS tensor contraction with Von Neumann entanglement entropy meters, and Grover probability distributions.
   - **CISO Quantum Posture**: Org-wide QVS score, Mosca countdown clock, and interactive PQC migration planner.
   - **Attack Injection Suite**: Interactive triggers for Nonce Reuse, Signature Malleability, Rogue CI/CD Signing, and Quantum HNDL Bulk Reconnaissance.

---

## 📁 Project Structure

```
qi_ctd/
├── core/
│   ├── qubo_engine.py          # QUBO Hamiltonian matrix constructor & Simulated Annealing Solver
│   ├── tensor_network.py       # Matrix Product State (MPS) Feature Correlation Classifier
│   ├── grover_search.py        # Grover-Inspired Amplitude Amplification Search Heuristic
│   ├── qvs_engine.py           # Quantum Vulnerability Scoring & PQC Migration Engine
│   └── __init__.py
├── telemetry/
│   ├── schema.py               # Normalized Cryptographic Telemetry Schema
│   ├── normalizer.py           # Ingestion from PKI, TLS, CI/CD, and Blockchain logs
│   └── __init__.py
├── simulation/
│   ├── attack_generator.py     # Attack scenarios: Nonce Reuse, Malleability, Rogue CI/CD, HNDL
│   └── __init__.py
├── engine.py                   # Master QI-CTD Detection Engine & Event Pipeline
├── dashboard/
│   ├── index.html              # Interactive SOC/CISO Cyber & Quantum Posture Dashboard
│   ├── styles.css              # Cyber-security dark theme styling & neon accents
│   └── app.js                  # Dynamic streaming & quantum visualizers
├── run_demo.py                 # Standalone CLI demo runner and test verification suite
└── README.md                   # System documentation
```

---

## 🚀 Getting Started

### 1. Interactive Web Dashboard
Open the standalone dashboard directly in any modern browser:
```
file:///C:/Users/sande/.gemini/antigravity/scratch/qi_ctd/dashboard/index.html
```
- Toggle the **SOC Real-Time Triage**, **Quantum-Inspired Core**, and **CISO Quantum Posture** tabs.
- Click any of the **Simulate Cryptographic Attacks** buttons in the top toolbar to inject attack scenarios in real time.
- Click **🔍 View Explainability** to inspect SHAP-style feature attributions and execute 1-click SOAR playbooks.

### 2. Standalone Python CLI Engine
Run the end-to-end CLI demonstration:
```bash
python run_demo.py
```
This executes:
1. Normal baseline traffic ingestion.
2. ECDSA Nonce Reuse attack injection & Grover detection.
3. Signature Malleability injection & QUBO detection.
4. Rogue CI/CD supply chain signing injection & MPS classification.
5. Automated SOAR playbook execution.
6. Quantum Vulnerability Scoring (QVS) inventory calculation.
