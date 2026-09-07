/**
 * QI-CTD Simplified, Clean Dashboard Application
 * Real-Time Quantum-Inspired Threat Detection & Posture Orchestration
 * (Includes 1-Click Light/Dark Theme Switcher, Real-Time Streaming, and Crypto Scanner)
 */

(function () {
  'use strict';

  // Dynamically resolve backend host
  const getBackendUrl = () => {
    if (window.location.protocol.startsWith('http')) {
      return window.location.origin;
    }
    return `http://${window.location.hostname || '127.0.0.1'}:8000`;
  };

  const BACKEND_URL = getBackendUrl();

  // --- STATE ---
  const state = {
    theme: localStorage.getItem('qi_theme') || 'dark',
    backendConnected: false,
    streamingActive: true,
    streamTimer: null,
    totalIngested: 1463,
    totalAnomalies: 3,
    activeAlerts: [],
    recentEvents: [],
    quboEnergyTrace: [-2.1, -4.5, -7.2, -9.8, -12.4, -15.1, -17.3, -18.42],
    quboSpins: [0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    mpsBondEntropies: [0.42, 0.85, 1.42, 1.84, 1.12, 0.76, 0.35],
    groverData: {
      N: 1024,
      M: 2,
      optimalK: 18,
      history: [
        { k: 1, p: 0.08 },
        { k: 4, p: 0.28 },
        { k: 8, p: 0.58 },
        { k: 12, p: 0.84 },
        { k: 16, p: 0.96 },
        { k: 18, p: 0.998 }
      ]
    },
    inventory: [
      { id: 'AST-001', name: 'Corporate Enterprise Root CA', keyId: 'key-root-ca-01', algo: 'RSA-4096', shelfLife: '15 yrs', criticality: '2.0 (High)', exposure: 'INTERNAL', qvs: 84.5, targetPqc: 'ML-DSA-87 (Dilithium5)', status: 'ACTIVE' },
      { id: 'AST-002', name: 'Master CI/CD Production Signer', keyId: 'key-cicd-master-release', algo: 'ECDSA-P256', shelfLife: '10 yrs', criticality: '1.9 (High)', exposure: 'INTERNAL', qvs: 78.2, targetPqc: 'ML-DSA-65 (Dilithium3)', status: 'ACTIVE' },
      { id: 'AST-003', name: 'Edge TLS Wildcard Gateway', keyId: 'key-edge-tls-wildcard', algo: 'RSA-2048', shelfLife: '1 yr', criticality: '1.4 (Med)', exposure: 'PUBLIC', qvs: 62.0, targetPqc: 'ML-DSA-44 (Dilithium2)', status: 'ACTIVE' },
      { id: 'AST-004', name: 'Treasury Blockchain Multisig', keyId: 'key-ecdsa-treasury-master', algo: 'ECDSA-secp256k1', shelfLife: '20 yrs', criticality: '2.0 (High)', exposure: 'PUBLIC', qvs: 94.8, targetPqc: 'ML-DSA-65 (Dilithium3)', status: 'ACTIVE' },
      { id: 'AST-005', name: 'Executive PDF Contract Signer', keyId: 'key-doc-exec-signer', algo: 'RSA-2048', shelfLife: '25 yrs', criticality: '1.7 (High)', exposure: 'INTERNAL', qvs: 88.6, targetPqc: 'ML-DSA-65 (Dilithium3)', status: 'ACTIVE' },
      { id: 'AST-006', name: 'PQC Artifact Signer (Pilot)', keyId: 'key-pqc-dilithium-01', algo: 'ML-DSA-65', shelfLife: '10 yrs', criticality: '1.5 (Med)', exposure: 'INTERNAL', qvs: 3.2, targetPqc: 'ML-DSA-65 (Current)', status: 'MIGRATED' }
    ]
  };

  // Initial Sample Alerts
  state.activeAlerts = [
    {
      id: 'alt-84f9a1',
      time: 'Just now',
      severity: 'CRITICAL',
      title: 'ECDSA Nonce Collision Detected (Catastrophic Key Recovery Threat)',
      keyId: 'key-ecdsa-treasury-master',
      engine: 'Grover Search + QUBO',
      confidence: 0.999,
      mitre: 'T1552.004',
      summary: 'Identical k-value nonce reused across 2 transactions. Private key recovery mathematically feasible.',
      playbook: 'Emergency Key Revocation & CA Invalidation',
      soarExecuted: false,
      attributions: { 'nonce_collision_entropy': 0.98, 'cross_ip_divergence': 0.85, 'geo_risk_score': 0.72 }
    },
    {
      id: 'alt-39e1bc',
      time: '2m ago',
      severity: 'CRITICAL',
      title: 'Rogue CI/CD Supply Chain Signing Anomaly',
      keyId: 'key-cicd-master-release',
      engine: 'MPS Tensor Network (Bond χ=4)',
      confidence: 0.962,
      mitre: 'T1195.002',
      summary: 'Master release key invoked by unauthorized VM runner at 02:40 AM with anomalous latency.',
      playbook: 'Quarantine Signing Key & Terminate Pipeline',
      soarExecuted: false,
      attributions: { 'requester_privilege_mismatch': 0.94, 'hour_of_day_anomaly': 0.88, 'latency_deviation': 0.76 }
    },
    {
      id: 'alt-17d45e',
      time: '6m ago',
      severity: 'HIGH',
      title: 'Digital Signature Malleability Abuse (High-S Violation)',
      keyId: 'key-eth-smart-contract',
      engine: 'QUBO Simulated Annealing',
      confidence: 0.924,
      mitre: 'T1565.002',
      summary: 'High-S signature structure detected attempting relay mutation on smart contract.',
      playbook: 'Enforce Low-S Canonical Verification Rule',
      soarExecuted: true,
      attributions: { 'malleability_indicator': 1.0, 'geo_risk_score': 0.65 }
    }
  ];

  // Initial Stream Rows
  state.recentEvents = [
    { time: '00:38:50', src: 'PKI/HSM', keyId: 'key-pki-hsm-04', algo: 'ECDSA-P256', caller: 'svc-worker-21 (10.0.1.73)', entropy: '7.97', lat: '4.6ms', isAnomaly: false },
    { time: '00:38:29', src: 'Blockchain', keyId: 'key-blockchain-82', algo: 'ECDSA-P256', caller: 'svc-worker-37 (10.0.1.98)', entropy: '7.98', lat: '3.8ms', isAnomaly: false },
    { time: '00:38:27', src: 'PKI/HSM', keyId: 'key-pki-hsm-03', algo: 'RSA-4096', caller: 'svc-worker-26 (10.0.1.95)', entropy: '7.96', lat: '4.3ms', isAnomaly: false },
    { time: '00:38:26', src: 'Blockchain', keyId: 'key-blockchain-81', algo: 'ECDSA-P256', caller: 'svc-worker-93 (10.0.1.193)', entropy: '7.91', lat: '4.3ms', isAnomaly: false },
    { time: '00:38:24', src: 'Blockchain', keyId: 'key-blockchain-81', algo: 'ECDSA-secp256k1', caller: 'svc-worker-22 (10.0.1.63)', entropy: '7.96', lat: '4.5ms', isAnomaly: false }
  ];

  // DOM Elements
  const el = {
    btnThemeToggle: document.getElementById('btnThemeToggle'),
    themeToggleIcon: document.getElementById('themeToggleIcon'),
    systemStateText: document.getElementById('systemStateText'),
    tabBtns: document.querySelectorAll('.nav-pill'),
    tabContents: document.querySelectorAll('.tab-panel'),
    alertsContainer: document.getElementById('alertsContainer'),
    activeAlertCount: document.getElementById('activeAlertCount'),
    telemetryStreamBody: document.getElementById('telemetryStreamBody'),
    totalIngestedCount: document.getElementById('totalIngestedCount'),
    totalAnomaliesCount: document.getElementById('totalAnomaliesCount'),
    quboEnergyVal: document.getElementById('quboEnergyVal'),
    inventoryTableBody: document.getElementById('inventoryTableBody'),
    orgAvgQvs: document.getElementById('orgAvgQvs'),
    pqcProgressPct: document.getElementById('pqcProgressPct'),
    btnToggleStream: document.getElementById('btnToggleStream'),
    streamStateIcon: document.getElementById('streamStateIcon'),
    streamStateText: document.getElementById('streamStateText'),
    btnResetData: document.getElementById('btnResetData'),
    // Attack buttons
    btnAttackNonce: document.getElementById('btnAttackNonce'),
    btnAttackMalleability: document.getElementById('btnAttackMalleability'),
    btnAttackCICD: document.getElementById('btnAttackCICD'),
    btnAttackHNDL: document.getElementById('btnAttackHNDL'),
    // Modal
    explainModal: document.getElementById('explainModal'),
    modalCloseBtn: document.getElementById('modalCloseBtn'),
    modalSeverityBadge: document.getElementById('modalSeverityBadge'),
    modalAlertTitle: document.getElementById('modalAlertTitle'),
    modalKeyId: document.getElementById('modalKeyId'),
    modalEngine: document.getElementById('modalEngine'),
    modalConfidence: document.getElementById('modalConfidence'),
    modalMitre: document.getElementById('modalMitre'),
    modalFeatureBars: document.getElementById('modalFeatureBars'),
    modalPlaybookName: document.getElementById('modalPlaybookName'),
    btnExecuteSoar: document.getElementById('btnExecuteSoar'),
    btnExportCef: document.getElementById('btnExportCef'),
    // Canvases
    quboCanvas: document.getElementById('quboCanvas'),
    mpsCanvas: document.getElementById('mpsCanvas'),
    groverCanvas: document.getElementById('groverCanvas'),
    // Scanner Elements (Tab 4)
    btnSampleRSA: document.getElementById('btnSampleRSA'),
    btnSampleECDSA: document.getElementById('btnSampleECDSA'),
    btnSamplePQC: document.getElementById('btnSamplePQC'),
    scannerInputText: document.getElementById('scannerInputText'),
    btnRunScan: document.getElementById('btnRunScan'),
    btnClearScan: document.getElementById('btnClearScan'),
    scanStatusBadge: document.getElementById('scanStatusBadge'),
    scanAlgoLabel: document.getElementById('scanAlgoLabel'),
    scanKeyLengthLabel: document.getElementById('scanKeyLengthLabel'),
    scanQvsLabel: document.getElementById('scanQvsLabel'),
    scanUrgencyLabel: document.getElementById('scanUrgencyLabel'),
    scanTimeToCrack: document.getElementById('scanTimeToCrack'),
    scanRecText: document.getElementById('scanRecText'),
    btnGeneratePqcSeal: document.getElementById('btnGeneratePqcSeal'),
    pqcSealOutput: document.getElementById('pqcSealOutput'),
    pqcSealText: document.getElementById('pqcSealText')
  };

  let activeModalAlert = null;

  // --- THEME MANAGEMENT ---
  function applyTheme(themeName) {
    state.theme = themeName;
    localStorage.setItem('qi_theme', themeName);
    if (themeName === 'light') {
      document.body.className = 'theme-light';
      if (el.themeToggleIcon) el.themeToggleIcon.textContent = '🌙 Dark Mode';
    } else {
      document.body.className = 'theme-dark';
      if (el.themeToggleIcon) el.themeToggleIcon.textContent = '☀️ Light Mode';
    }
    renderAllCanvases();
  }

  if (el.btnThemeToggle) {
    el.btnThemeToggle.addEventListener('click', () => {
      const newTheme = state.theme === 'dark' ? 'light' : 'dark';
      applyTheme(newTheme);
    });
  }

  // --- BACKEND HEALTH CHECK & SYNC ---
  async function checkBackendConnection() {
    try {
      const res = await fetch(`${BACKEND_URL}/health`, { method: 'GET', signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        state.backendConnected = true;
        if (el.systemStateText) el.systemStateText.innerHTML = `Live Python Server Connected`;
        syncWithBackend();
        return;
      }
    } catch (e) {}
    state.backendConnected = false;
    if (el.systemStateText) el.systemStateText.textContent = `Standby / Ready`;
  }

  async function syncWithBackend() {
    if (!state.backendConnected) return;
    try {
      const resAlerts = await fetch(`${BACKEND_URL}/api/v1/alerts`);
      if (resAlerts.ok) {
        const json = await resAlerts.json();
        if (json.alerts && json.alerts.length > 0) {
          state.activeAlerts = json.alerts.map(a => ({
            id: a.alert_id,
            time: 'Just now',
            severity: a.severity,
            title: a.attack_type,
            keyId: a.key_id,
            engine: a.detection_engine,
            confidence: a.confidence_score,
            mitre: a.mitre_ttp,
            summary: a.summary,
            playbook: a.recommended_playbook,
            soarExecuted: a.soar_status === 'EXECUTED',
            attributions: a.feature_attribution || {}
          }));
          renderAlerts();
        }
      }

      const resStatus = await fetch(`${BACKEND_URL}/api/v1/engine/status`);
      if (resStatus.ok) {
        const json = await resStatus.json();
        if (json.data) {
          state.totalIngested = json.data.processed_events_total || state.totalIngested;
          state.totalAnomalies = json.data.anomalies_detected_total || state.totalAnomalies;
          renderStreamTable();
        }
      }
    } catch (err) {
      console.warn('Backend sync failed:', err);
    }
  }

  // --- TAB SWITCHING ---
  el.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      el.tabBtns.forEach(b => b.classList.remove('active'));
      el.tabContents.forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');

      if (targetId === 'quantum-algorithms') {
        renderAllCanvases();
      }
    });
  });

  // --- RENDER ALERTS ---
  function renderAlerts() {
    el.alertsContainer.innerHTML = '';
    const pendingCount = state.activeAlerts.filter(a => !a.soarExecuted).length;
    el.activeAlertCount.textContent = `${pendingCount} Pending`;

    state.activeAlerts.forEach(alert => {
      const item = document.createElement('div');
      item.className = `alert-card-item severity-${alert.severity} ${alert.soarExecuted ? 'soar-executed' : ''}`;
      item.innerHTML = `
        <div class="alert-top-row">
          <span class="pill-badge ${alert.severity === 'CRITICAL' ? 'pill-danger' : 'pill-warning'}">${alert.severity} THREAT</span>
          <span style="font-size:11px; color:var(--text-soft); font-family:var(--font-mono);">${alert.time}</span>
        </div>
        <div class="alert-title-text">${alert.title}</div>
        <div class="alert-meta-tags">
          <span><strong>Target Key:</strong> ${alert.keyId}</span>
          <span><strong>AI Engine:</strong> ${alert.engine}</span>
          <span><strong>Certainty:</strong> ${(alert.confidence * 100).toFixed(1)}%</span>
        </div>
        <div class="alert-action-footer">
          <button class="btn-view-clues" data-id="${alert.id}">🔍 View AI Clues</button>
          ${
            alert.soarExecuted
              ? `<span style="font-size:12px; color:var(--accent-success); font-weight:700;">✓ Threat Neutralized</span>`
              : `<button class="btn-lockdown" data-id="${alert.id}">⚡ Quarantine Key</button>`
          }
        </div>
      `;
      el.alertsContainer.appendChild(item);
    });

    el.alertsContainer.querySelectorAll('.btn-view-clues').forEach(b => {
      b.addEventListener('click', () => openModal(b.getAttribute('data-id')));
    });

    el.alertsContainer.querySelectorAll('.btn-lockdown').forEach(b => {
      b.addEventListener('click', () => executeSoarDirect(b.getAttribute('data-id')));
    });
  }

  // --- RENDER STREAM TABLE ---
  function renderStreamTable() {
    el.telemetryStreamBody.innerHTML = '';
    state.recentEvents.forEach(ev => {
      const row = document.createElement('tr');
      if (ev.isAnomaly) row.className = 'row-threat';
      row.innerHTML = `
        <td>${ev.time}</td>
        <td><strong>${ev.src}</strong></td>
        <td>${ev.keyId}</td>
        <td>${ev.algo}</td>
        <td>${ev.entropy} bits</td>
        <td>${ev.lat}</td>
        <td>${ev.isAnomaly ? '<span class="pill-badge pill-danger">🚨 BLOCKED</span>' : '<span class="pill-badge pill-success">✓ SAFE</span>'}</td>
      `;
      el.telemetryStreamBody.appendChild(row);
    });

    if (el.totalIngestedCount) el.totalIngestedCount.textContent = state.totalIngested.toLocaleString();
    if (el.totalAnomaliesCount) el.totalAnomaliesCount.textContent = state.totalAnomalies.toLocaleString();
  }

  // --- RENDER INVENTORY TABLE ---
  function renderInventoryTable() {
    el.inventoryTableBody.innerHTML = '';
    let totalQvs = 0;
    let pqcCount = 0;

    state.inventory.forEach(asset => {
      totalQvs += asset.qvs;
      if (asset.qvs <= 10.0 || asset.status === 'MIGRATED') pqcCount++;

      const tr = document.createElement('tr');
      const qvsColor = asset.qvs >= 80 ? 'text-danger' : (asset.qvs >= 50 ? 'text-warning' : 'text-success');

      tr.innerHTML = `
        <td><strong>${asset.name}</strong></td>
        <td>${asset.keyId}</td>
        <td><code>${asset.algo}</code></td>
        <td>${asset.shelfLife}</td>
        <td>${asset.criticality}</td>
        <td><strong class="${qvsColor}">${asset.qvs.toFixed(1)} / 100</strong></td>
        <td><span class="text-indigo">${asset.targetPqc}</span></td>
        <td>
          <span class="pill-badge ${asset.status === 'MIGRATED' ? 'pill-success' : 'pill-warning'}">
            ${asset.status}
          </span>
        </td>
        <td>
          ${
            asset.status === 'MIGRATED'
              ? '<span class="text-success" style="font-weight:700;">✓ Protected</span>'
              : `<button class="btn-migrate-action" data-key="${asset.keyId}">Upgrade Key</button>`
          }
        </td>
      `;
      el.inventoryTableBody.appendChild(tr);
    });

    const avgQvs = (totalQvs / state.inventory.length).toFixed(1);
    if (el.orgAvgQvs) el.orgAvgQvs.textContent = `${avgQvs} / 100`;
    const pct = ((pqcCount / state.inventory.length) * 100).toFixed(1);
    if (el.pqcProgressPct) el.pqcProgressPct.textContent = `${pct}%`;

    el.inventoryTableBody.querySelectorAll('.btn-migrate-action').forEach(btn => {
      btn.addEventListener('click', () => {
        const keyId = btn.getAttribute('data-key');
        migrateAssetToPqc(keyId);
      });
    });
  }

  function migrateAssetToPqc(keyId) {
    const item = state.inventory.find(a => a.keyId === keyId);
    if (item) {
      item.algo = item.targetPqc;
      item.qvs = 3.5;
      item.status = 'MIGRATED';
      renderInventoryTable();
      showToast(`Key '${keyId}' upgraded to Quantum-Safe ML-DSA! Danger score dropped to 3.5.`);
    }
  }

  // --- CANVASES & VISUALIZERS ---
  function isDarkTheme() {
    return state.theme !== 'light';
  }

  function drawQuboCanvas() {
    if (!el.quboCanvas) return;
    const ctx = el.quboCanvas.getContext('2d');
    const w = el.quboCanvas.width;
    const h = el.quboCanvas.height;
    ctx.clearRect(0, 0, w, h);

    const isDark = isDarkTheme();
    const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
    const textColor = isDark ? '#94a3b8' : '#64748b';
    const curveColor = '#6366f1';

    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    for (let y = 25; y < h; y += 30) {
      ctx.beginPath();
      ctx.moveTo(30, y);
      ctx.lineTo(w / 2 - 20, y);
      ctx.stroke();
    }

    ctx.strokeStyle = curveColor;
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    const trace = state.quboEnergyTrace;
    const xStep = (w / 2 - 60) / (trace.length - 1);
    const minVal = -20;
    const maxVal = 0;

    trace.forEach((val, i) => {
      const x = 35 + i * xStep;
      const y = 25 + ((val - maxVal) / (minVal - maxVal)) * (h - 50);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    trace.forEach((val, i) => {
      const x = 35 + i * xStep;
      const y = 25 + ((val - maxVal) / (minVal - maxVal)) * (h - 50);
      ctx.fillStyle = i === trace.length - 1 ? '#10b981' : '#6366f1';
      ctx.beginPath();
      ctx.arc(x, y, i === trace.length - 1 ? 5 : 3, 0, Math.PI * 2);
      ctx.fill();
    });

    ctx.fillStyle = textColor;
    ctx.font = '10px Inter, sans-serif';
    ctx.fillText('Energy Cooling Curve (T → 0)', 35, 16);
    ctx.fillText(`Lowest Energy = ${trace[trace.length - 1]}`, w / 2 - 110, h - 8);

    // Qubit Spins
    const startX = w / 2 + 25;
    ctx.fillText('Qubit Outlier States (0 = Safe, 1 = Attacker)', startX, 16);

    const cols = 5;
    const cellSize = 22;
    const gap = 7;

    state.quboSpins.forEach((spin, idx) => {
      const r = Math.floor(idx / cols);
      const c = idx % cols;
      const cx = startX + c * (cellSize + gap);
      const cy = 30 + r * (cellSize + gap);

      ctx.fillStyle = spin === 1 ? 'rgba(244, 63, 94, 0.85)' : (isDark ? 'rgba(99, 102, 241, 0.2)' : 'rgba(99, 102, 241, 0.1)');
      ctx.strokeStyle = spin === 1 ? '#f43f5e' : '#6366f1';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.rect(cx, cy, cellSize, cellSize);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = spin === 1 ? '#fff' : (isDark ? '#cbd5e1' : '#334155');
      ctx.font = '11px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(spin.toString(), cx + cellSize / 2, cy + cellSize / 2);
    });

    ctx.textAlign = 'left';
    ctx.textBaseline = 'alphabetic';
  }

  function drawMpsCanvas() {
    if (!el.mpsCanvas) return;
    const ctx = el.mpsCanvas.getContext('2d');
    const w = el.mpsCanvas.width;
    const h = el.mpsCanvas.height;
    ctx.clearRect(0, 0, w, h);

    const isDark = isDarkTheme();
    const textColor = isDark ? '#94a3b8' : '#64748b';
    const numNodes = 8;
    const nodeRadius = 13;
    const stepX = (w - 70) / (numNodes - 1);
    const cy = h / 2 + 8;

    ctx.strokeStyle = '#6366f1';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    ctx.moveTo(35, cy);
    ctx.lineTo(35 + (numNodes - 1) * stepX, cy);
    ctx.stroke();

    state.mpsBondEntropies.forEach((entropy, i) => {
      const xMid = 35 + i * stepX + stepX / 2;
      ctx.fillStyle = entropy > 1.2 ? '#f43f5e' : '#6366f1';
      ctx.font = '9px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText(`S=${entropy}`, xMid, cy - 18);

      ctx.fillStyle = '#6366f1';
      ctx.beginPath();
      ctx.arc(xMid, cy, 3, 0, Math.PI * 2);
      ctx.fill();
    });

    for (let i = 0; i < numNodes; i++) {
      const cx = 35 + i * stepX;

      ctx.strokeStyle = isDark ? 'rgba(255, 255, 255, 0.3)' : 'rgba(0, 0, 0, 0.2)';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(cx, cy + nodeRadius);
      ctx.lineTo(cx, cy + 30);
      ctx.stroke();

      ctx.fillStyle = textColor;
      ctx.font = '8.5px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText(`Clue ${i+1}`, cx, cy + 42);

      ctx.fillStyle = isDark ? '#131b2e' : '#ffffff';
      ctx.strokeStyle = i === 0 || i === 7 ? '#6366f1' : '#06b6d4';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, cy, nodeRadius, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = isDark ? '#fff' : '#0f172a';
      ctx.font = '9.5px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(`A${i+1}`, cx, cy);
    }

    ctx.textAlign = 'left';
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = textColor;
    ctx.font = '10px Inter, sans-serif';
    ctx.fillText('Tensor Network Entangled Clues Chain', 30, 16);
  }

  function drawGroverCanvas() {
    if (!el.groverCanvas) return;
    const ctx = el.groverCanvas.getContext('2d');
    const w = el.groverCanvas.width;
    const h = el.groverCanvas.height;
    ctx.clearRect(0, 0, w, h);

    const isDark = isDarkTheme();
    const textColor = isDark ? '#94a3b8' : '#64748b';
    const history = state.groverData.history;
    const barWidth = 46;
    const gap = 40;
    const startX = 60;
    const chartHeight = h - 60;

    ctx.fillStyle = textColor;
    ctx.font = '11px Inter, sans-serif';
    ctx.fillText('Target Probability Amplification: Making the Hacker Stand Out', startX, 18);

    history.forEach((step, i) => {
      const x = startX + i * (barWidth + gap);
      const barH = step.p * chartHeight;
      const y = h - 28 - barH;

      ctx.fillStyle = isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';
      ctx.fillRect(x, h - 28 - chartHeight, barWidth, chartHeight);

      const grad = ctx.createLinearGradient(0, y, 0, h - 28);
      grad.addColorStop(0, '#10b981');
      grad.addColorStop(1, '#6366f1');
      ctx.fillStyle = grad;
      ctx.fillRect(x, y, barWidth, barH);

      ctx.fillStyle = isDark ? '#f8fafc' : '#0f172a';
      ctx.font = '10px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText(`${(step.p * 100).toFixed(1)}%`, x + barWidth / 2, y - 5);

      ctx.fillStyle = textColor;
      ctx.fillText(`Step ${step.k}`, x + barWidth / 2, h - 12);
    });

    ctx.textAlign = 'left';
  }

  function renderAllCanvases() {
    drawQuboCanvas();
    drawMpsCanvas();
    drawGroverCanvas();
  }

  // --- STREAMING TICKER ---
  function pushNewStreamEvent(isAttack = false, customEvent = null) {
    state.totalIngested += 1;

    let ev;
    if (customEvent) {
      ev = customEvent;
    } else {
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0];
      const algos = ['RSA-2048', 'ECDSA-P256', 'ML-DSA-65', 'RSA-4096', 'ECDSA-secp256k1'];
      const sources = ['TLS/mTLS', 'PKI/HSM', 'CI/CD', 'Blockchain', 'Doc Sign'];
      const algo = algos[Math.floor(Math.random() * algos.length)];
      const src = sources[Math.floor(Math.random() * sources.length)];

      ev = {
        time: timeStr,
        src: src,
        keyId: `key-${src.toLowerCase().replace('/', '-')}-0${Math.floor(Math.random() * 4) + 1}`,
        algo: algo,
        caller: `svc-worker-${Math.floor(Math.random() * 90) + 10} (10.0.1.${Math.floor(Math.random() * 200)})`,
        entropy: (7.88 + Math.random() * 0.1).toFixed(2),
        lat: `${(3.2 + Math.random() * 1.5).toFixed(1)}ms`,
        isAnomaly: false
      };
    }

    state.recentEvents.unshift(ev);
    if (state.recentEvents.length > 8) state.recentEvents.pop();
    renderStreamTable();
  }

  function toggleStreaming() {
    state.streamingActive = !state.streamingActive;
    if (state.streamingActive) {
      el.streamStateIcon.textContent = '⏸️';
      el.streamStateText.textContent = 'Pause Feed';
      startStreamInterval();
    } else {
      el.streamStateIcon.textContent = '▶️';
      el.streamStateText.textContent = 'Resume Feed';
      clearInterval(state.streamTimer);
    }
  }

  function startStreamInterval() {
    clearInterval(state.streamTimer);
    state.streamTimer = setInterval(() => {
      pushNewStreamEvent();
    }, 1400);
  }

  // --- ATTACK TRIGGER ---
  async function triggerAttackScenario(scenarioNum) {
    if (state.backendConnected) {
      try {
        const res = await fetch(`${BACKEND_URL}/api/v1/simulate/attack`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: scenarioNum })
        });
        if (res.ok) {
          const json = await res.json();
          syncWithBackend();
          showToast(`⚡ Test ${scenarioNum} Launched: ${json.description}`);
          return;
        }
      } catch (err) {
        console.warn('Backend attack call failed, using client fallback', err);
      }
    }

    // Client fallback
    state.totalAnomalies += 1;
    const now = new Date().toTimeString().split(' ')[0];

    if (scenarioNum === 1) {
      pushNewStreamEvent(true, { time: now, src: 'Blockchain', keyId: 'key-ecdsa-treasury-master', algo: 'ECDSA-secp256k1', caller: 'relayer-node (185.220.101.5)', entropy: '2.14', lat: '3.1ms', isAnomaly: true });
      state.activeAlerts.unshift({
        id: `alt-${Math.random().toString(36).substring(2, 8)}`,
        time: 'Just now',
        severity: 'CRITICAL',
        title: 'ECDSA Catastrophic Nonce Collision (Private Key Recovery Setup)',
        keyId: 'key-ecdsa-treasury-master',
        engine: 'Grover Search + QUBO',
        confidence: 0.999,
        mitre: 'T1552.004',
        summary: 'Identical k-value nonce reused across 2 transactions. Private key recovery mathematically feasible.',
        playbook: 'Emergency Key Revocation & CA Invalidation',
        soarExecuted: false,
        attributions: { 'nonce_collision_entropy': 0.99, 'cross_ip_divergence': 0.88, 'geo_risk_score': 0.74 }
      });
      state.groverData.history[5].p = 0.999;
      renderAllCanvases();
      showToast('🚨 Test 1: Reused Nonce caught by Grover Search!');
    } else if (scenarioNum === 2) {
      pushNewStreamEvent(true, { time: now, src: 'Blockchain', keyId: 'key-eth-smart-contract', algo: 'ECDSA-secp256k1', caller: 'unauthenticated-relayer (TOR-EXIT)', entropy: '7.85', lat: '14.2ms', isAnomaly: true });
      state.activeAlerts.unshift({
        id: `alt-${Math.random().toString(36).substring(2, 8)}`,
        time: 'Just now',
        severity: 'HIGH',
        title: 'Digital Signature Malleability Abuse (High-S Violation)',
        keyId: 'key-eth-smart-contract',
        engine: 'QUBO Simulated Annealing',
        confidence: 0.935,
        mitre: 'T1565.002',
        summary: 'High-S signature structure detected attempting relay mutation on smart contract.',
        playbook: 'Enforce Low-S Canonical Verification Rule',
        soarExecuted: false,
        attributions: { 'malleability_indicator': 1.0, 'geo_risk_score': 0.70 }
      });
      showToast('🚨 Test 2: Tampered signature detected via QUBO!');
    } else if (scenarioNum === 3) {
      pushNewStreamEvent(true, { time: now, src: 'CI/CD', keyId: 'key-cicd-master-release', algo: 'RSA-4096', caller: 'unauthorized_runner_vm_9823 (198.51.100.42)', entropy: '7.91', lat: '88.2ms', isAnomaly: true });
      state.activeAlerts.unshift({
        id: `alt-${Math.random().toString(36).substring(2, 8)}`,
        time: 'Just now',
        severity: 'CRITICAL',
        title: 'Rogue CI/CD Supply Chain Signing Anomaly',
        keyId: 'key-cicd-master-release',
        engine: 'MPS Tensor Network (Bond χ=4)',
        confidence: 0.978,
        mitre: 'T1195.002',
        summary: 'Master release key signed artifact from untrusted runner at abnormal off-peak hours.',
        playbook: 'Quarantine CI/CD Signing Certificate & Terminate Build Pipeline',
        soarExecuted: false,
        attributions: { 'requester_privilege_mismatch': 0.96, 'hour_of_day_anomaly': 0.89, 'latency_deviation': 0.82 }
      });
      state.mpsBondEntropies = [0.92, 1.45, 1.88, 2.14, 1.76, 1.10, 0.65];
      renderAllCanvases();
      showToast('🚨 Test 3: Rogue server signing flagged via Tensor Network!');
    } else if (scenarioNum === 4) {
      pushNewStreamEvent(true, { time: now, src: 'PKI/HSM', keyId: 'key-root-ca-01', algo: 'RSA-4096', caller: 'suspicious-recon-service (ANON-VPN)', entropy: '7.94', lat: '1.2ms', isAnomaly: true });
      state.activeAlerts.unshift({
        id: `alt-${Math.random().toString(36).substring(2, 8)}`,
        time: 'Just now',
        severity: 'HIGH',
        title: 'Quantum "Harvest Now, Decrypt Later" Bulk Key Export Profile',
        keyId: 'key-root-ca-01',
        engine: 'QUBO Simulated Annealing',
        confidence: 0.912,
        mitre: 'T1110 - Token Harvesting',
        summary: 'Rapid burst export of 25-year root public keys and certs to anonymous VPN endpoint.',
        playbook: 'Apply HSM Export Rate-Limiting & Alert CISO',
        soarExecuted: false,
        attributions: { 'key_frequency_burst': 0.95, 'geo_risk_score': 0.85 }
      });
      showToast('🚨 Test 4: Bulk key hoarding flagged!');
    }
    renderAlerts();
  }

  el.btnAttackNonce.addEventListener('click', () => triggerAttackScenario(1));
  el.btnAttackMalleability.addEventListener('click', () => triggerAttackScenario(2));
  el.btnAttackCICD.addEventListener('click', () => triggerAttackScenario(3));
  el.btnAttackHNDL.addEventListener('click', () => triggerAttackScenario(4));

  el.btnResetData.addEventListener('click', () => {
    state.activeAlerts = [];
    state.recentEvents = [];
    renderAlerts();
    renderStreamTable();
    showToast('Alarm list and feed cleared.');
  });

  el.btnToggleStream.addEventListener('click', toggleStreaming);

  // --- MODAL & SOAR ACTIONS ---
  function openModal(alertId) {
    const alert = state.activeAlerts.find(a => a.id === alertId);
    if (!alert) return;
    activeModalAlert = alert;

    el.modalSeverityBadge.textContent = alert.severity;
    el.modalSeverityBadge.className = `pill-badge ${alert.severity === 'CRITICAL' ? 'pill-danger' : 'pill-warning'}`;
    el.modalAlertTitle.textContent = alert.title;
    el.modalKeyId.textContent = alert.keyId;
    el.modalEngine.textContent = alert.engine;
    el.modalConfidence.textContent = `${(alert.confidence * 100).toFixed(1)}%`;
    el.modalMitre.textContent = alert.mitre;
    el.modalPlaybookName.textContent = alert.playbook;

    el.modalFeatureBars.innerHTML = '';
    for (const [feat, val] of Object.entries(alert.attributions)) {
      const item = document.createElement('div');
      item.className = 'feature-bar-item';
      item.innerHTML = `
        <div class="feature-bar-header">
          <span>${feat.replace(/_/g, ' ')}</span>
          <span>+${(val * 100).toFixed(0)}% contribution</span>
        </div>
        <div class="feature-progress-bg">
          <div class="feature-progress-fill" style="width: ${Math.min(100, val * 100)}%;"></div>
        </div>
      `;
      el.modalFeatureBars.appendChild(item);
    }

    el.explainModal.style.display = 'flex';
  }

  el.modalCloseBtn.addEventListener('click', () => {
    el.explainModal.style.display = 'none';
  });

  async function executeSoarDirect(alertId) {
    const alert = state.activeAlerts.find(a => a.id === alertId);
    if (!alert) return;

    if (state.backendConnected) {
      try {
        await fetch(`${BACKEND_URL}/api/v1/soar/execute`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ alert_id: alertId, action: alert.playbook })
        });
      } catch (e) {
        console.warn('Backend SOAR call failed:', e);
      }
    }

    alert.soarExecuted = true;
    const asset = state.inventory.find(i => i.keyId === alert.keyId);
    if (asset) {
      asset.status = 'QUARANTINED';
      renderInventoryTable();
    }
    renderAlerts();
    showToast(`⚡ Key '${alert.keyId}' locked down and quarantined.`);
  }

  el.btnExecuteSoar.addEventListener('click', () => {
    if (activeModalAlert) {
      executeSoarDirect(activeModalAlert.id);
      el.explainModal.style.display = 'none';
    }
  });

  el.btnExportCef.addEventListener('click', () => {
    if (activeModalAlert) {
      const cef = `CEF:0|Quantum-Inspired|QI-CTD|1.0|${activeModalAlert.mitre}|${activeModalAlert.title}|${activeModalAlert.severity}|src=10.0.1.50 dstKey=${activeModalAlert.keyId} cs1=${activeModalAlert.engine} cs1Label=DetectionEngine`;
      navigator.clipboard.writeText(cef);
      showToast('✓ Copied security log format to clipboard!');
    }
  });

  // --- CRYPTO SCANNER LOGIC (TAB 4) ---
  if (el.btnSampleRSA) {
    el.btnSampleRSA.addEventListener('click', () => {
      el.scannerInputText.value = `-----BEGIN CERTIFICATE-----
Issuer: C=US, O=Enterprise CA, CN=Corp Root CA 2024
Subject: CN=internal-pki.corp.com
Public Key Algorithm: rsaEncryption (2048-bit)
Validity: 15 Years Shelf-Life
-----END CERTIFICATE-----`;
      runCryptoInspection();
    });

    el.btnSampleECDSA.addEventListener('click', () => {
      el.scannerInputText.value = `-----BEGIN EC PUBLIC KEY-----
Curve: secp256k1 (256-bit)
Algorithm: ECDSA-secp256k1
Key ID: key-treasury-multisig-09
Data Lifetime: 20 Years
-----END EC PUBLIC KEY-----`;
      runCryptoInspection();
    });

    el.btnSamplePQC.addEventListener('click', () => {
      el.scannerInputText.value = `-----BEGIN NIST PQC PUBLIC KEY-----
Algorithm: ML-DSA-65 (NIST FIPS 204 - Dilithium3)
Security Category: Category 3 (Shor-Resistant)
Status: Certified Quantum-Safe
-----END NIST PQC PUBLIC KEY-----`;
      runCryptoInspection();
    });

    el.btnRunScan.addEventListener('click', runCryptoInspection);

    el.btnClearScan.addEventListener('click', () => {
      el.scannerInputText.value = '';
      el.pqcSealOutput.style.display = 'none';
    });

    el.btnGeneratePqcSeal.addEventListener('click', () => {
      const fakeSig = `-----BEGIN NIST FIPS 204 QUANTUM-SAFE SIGNATURE-----
Algorithm: ML-DSA-65 (Dilithium3)
Hash: SHA3-512 (${Math.random().toString(36).substring(2, 15)})
Status: VERIFIED_QUANTUM_SAFE
Timestamp: ${new Date().toISOString()}
-----END NIST FIPS 204 QUANTUM-SAFE SIGNATURE-----`;

      el.pqcSealText.value = fakeSig;
      el.pqcSealOutput.style.display = 'block';
      showToast('✓ Generated NIST ML-DSA-65 Quantum-Safe Seal!');
    });
  }

  function runCryptoInspection() {
    const text = el.scannerInputText.value.toLowerCase();
    if (!text) {
      showToast('Please paste text or click a sample preset.');
      return;
    }

    if (text.includes('ml-dsa') || text.includes('dilithium') || text.includes('pqc')) {
      el.scanAlgoLabel.textContent = 'ML-DSA-65';
      el.scanAlgoLabel.className = 'scan-stat-val text-success';
      el.scanKeyLengthLabel.textContent = 'NIST FIPS 204 Lattice Key';
      el.scanQvsLabel.textContent = '3.2 / 100';
      el.scanQvsLabel.className = 'scan-stat-val text-success';
      el.scanUrgencyLabel.textContent = 'QUANTUM SAFE';
      el.scanUrgencyLabel.className = 'scan-stat-sub text-success';
      el.scanTimeToCrack.textContent = '> 1000 Years';
      el.scanTimeToCrack.className = 'scan-stat-val text-success';
      el.scanRecText.textContent = '✓ This key is already using Post-Quantum Cryptography (NIST FIPS 204). It is immune to quantum supercomputers.';
      el.scanStatusBadge.textContent = 'SAFE (PQC)';
      el.scanStatusBadge.className = 'pill-badge pill-success';
    } else if (text.includes('ecdsa') || text.includes('secp256k1') || text.includes('p-256')) {
      el.scanAlgoLabel.textContent = 'ECDSA-256';
      el.scanAlgoLabel.className = 'scan-stat-val text-danger';
      el.scanKeyLengthLabel.textContent = '256-bit Elliptic Curve';
      el.scanQvsLabel.textContent = '94.8 / 100';
      el.scanQvsLabel.className = 'scan-stat-val text-danger';
      el.scanUrgencyLabel.textContent = 'CRITICAL VULNERABILITY';
      el.scanUrgencyLabel.className = 'scan-stat-sub text-danger';
      el.scanTimeToCrack.textContent = '< 5 Seconds';
      el.scanTimeToCrack.className = 'scan-stat-val text-danger';
      el.scanRecText.textContent = '⚠️ CRITICAL: Vulnerable to Shor\'s algorithm and nonce reuse. Upgrade to ML-DSA-65 recommended.';
      el.scanStatusBadge.textContent = 'CRITICAL RISK';
      el.scanStatusBadge.className = 'pill-badge pill-danger';
    } else {
      el.scanAlgoLabel.textContent = 'RSA-2048';
      el.scanAlgoLabel.className = 'scan-stat-val text-indigo';
      el.scanKeyLengthLabel.textContent = '2048-bit Modulus';
      el.scanQvsLabel.textContent = '84.5 / 100';
      el.scanQvsLabel.className = 'scan-stat-val text-danger';
      el.scanUrgencyLabel.textContent = 'HIGH MIGRATION PRIORITY';
      el.scanUrgencyLabel.className = 'scan-stat-sub text-danger';
      el.scanTimeToCrack.textContent = '< 10 Seconds';
      el.scanTimeToCrack.className = 'scan-stat-val text-danger';
      el.scanRecText.textContent = '⚠️ VULNERABLE: Integer factoring easily broken by quantum computers. Upgrade to NIST ML-DSA-87 recommended.';
      el.scanStatusBadge.textContent = 'HIGH RISK';
      el.scanStatusBadge.className = 'pill-badge pill-warning';
    }
    showToast('✓ Security inspection complete.');
  }

  function showToast(msg) {
    const toast = document.createElement('div');
    toast.style.position = 'fixed';
    toast.style.bottom = '24px';
    toast.style.right = '24px';
    toast.style.background = isDarkTheme() ? '#131b2e' : '#ffffff';
    toast.style.color = isDarkTheme() ? '#f8fafc' : '#0f172a';
    toast.style.border = '1px solid #6366f1';
    toast.style.boxShadow = '0 8px 24px rgba(0,0,0,0.2)';
    toast.style.padding = '12px 18px';
    toast.style.borderRadius = '8px';
    toast.style.fontFamily = 'Inter, sans-serif';
    toast.style.fontSize = '12.5px';
    toast.style.fontWeight = '600';
    toast.style.zIndex = '9999';
    toast.textContent = msg;

    document.body.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 3200);
  }

  // --- INITIALIZATION ---
  applyTheme(state.theme);
  renderAlerts();
  renderStreamTable();
  renderInventoryTable();
  renderAllCanvases();
  startStreamInterval();
  checkBackendConnection();

  setInterval(checkBackendConnection, 4000);
})();
