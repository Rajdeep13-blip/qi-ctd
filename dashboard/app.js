/**
 * QI-CTD Interactive Dashboard Application
 * Real-Time Quantum-Inspired Threat Detection & Posture Orchestration
 * (Dynamically resolves Backend URL for Localhost, LAN IP, and Public Domains)
 */

(function () {
  'use strict';

  // Dynamically resolve backend host based on where the browser is accessing the page
  const getBackendUrl = () => {
    if (window.location.protocol.startsWith('http')) {
      return window.location.origin;
    }
    return `http://${window.location.hostname || '127.0.0.1'}:8000`;
  };

  const BACKEND_URL = getBackendUrl();

  // --- STATE ---
  const state = {
    backendConnected: false,
    streamingActive: true,
    streamTimer: null,
    totalIngested: 1420,
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
      { id: 'AST-006', name: 'PQC Artifact Signer (Pilot)', keyId: 'key-pqc-dilithium-01', algo: 'ML-DSA-65 (FIPS 204)', shelfLife: '10 yrs', criticality: '1.5 (Med)', exposure: 'INTERNAL', qvs: 3.2, targetPqc: 'ML-DSA-65 (Current)', status: 'MIGRATED' }
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
      engine: 'Grover Amplitude Search + QUBO',
      confidence: 0.999,
      mitre: 'T1552.004',
      summary: 'Identical k-value nonce reused across 2 blockchain transactions from differing IP origins.',
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
    { time: '20:34:12', src: 'TLS/mTLS', keyId: 'key-edge-tls-wildcard', algo: 'RSA-2048', caller: 'tls-edge-01 (10.0.1.4)', entropy: 7.94, lat: '3.8ms', isAnomaly: false },
    { time: '20:34:12', src: 'PKI/HSM', keyId: 'key-root-ca-01', algo: 'RSA-4096', caller: 'pki-signer-svc (10.0.4.12)', entropy: 7.96, lat: '4.1ms', isAnomaly: false },
    { time: '20:34:13', src: 'CI/CD', keyId: 'key-pqc-dilithium-01', algo: 'ML-DSA-65', caller: 'prod-release-bot (10.2.1.8)', entropy: 7.92, lat: '5.2ms', isAnomaly: false },
    { time: '20:34:14', src: 'Blockchain', keyId: 'key-ecdsa-treasury-master', algo: 'ECDSA-secp256k1', caller: 'validator-node (45.33.32.156)', entropy: 2.15, lat: '3.2ms', isAnomaly: true }
  ];

  // DOM Elements
  const el = {
    systemStateText: document.getElementById('systemStateText'),
    tabBtns: document.querySelectorAll('.tab-btn'),
    tabContents: document.querySelectorAll('.tab-content'),
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
    groverCanvas: document.getElementById('groverCanvas')
  };

  let activeModalAlert = null;

  // --- BACKEND HEALTH CHECK & SYNC ---
  async function checkBackendConnection() {
    try {
      const res = await fetch(`${BACKEND_URL}/health`, { method: 'GET', signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        state.backendConnected = true;
        el.systemStateText.innerHTML = `ONLINE (Bound to ${BACKEND_URL})`;
        syncWithBackend();
        return;
      }
    } catch (e) {
      // Backend not running
    }
    state.backendConnected = false;
    el.systemStateText.textContent = `STANDALONE CLIENT MODE (Run 'python api/server.py' for Live Server)`;
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
      item.className = `alert-item severity-${alert.severity} ${alert.soarExecuted ? 'soar-executed' : ''}`;
      item.innerHTML = `
        <div class="alert-header">
          <span class="alert-badge ${alert.severity}">${alert.severity}</span>
          <span class="alert-time">${alert.time}</span>
        </div>
        <div class="alert-title">${alert.title}</div>
        <div class="alert-meta-row">
          <span><strong>Key:</strong> ${alert.keyId}</span>
          <span><strong>Engine:</strong> ${alert.engine}</span>
          <span><strong>Confidence:</strong> ${(alert.confidence * 100).toFixed(1)}%</span>
          <span><strong>MITRE:</strong> ${alert.mitre}</span>
        </div>
        <div class="alert-actions">
          <button class="btn-triage" data-id="${alert.id}">🔍 View Explainability</button>
          ${
            alert.soarExecuted
              ? `<span class="soar-status-tag">✓ SOAR Playbook Executed</span>`
              : `<button class="btn-soar-action" data-id="${alert.id}">⚡ Execute: ${alert.playbook.split('&')[0]}</button>`
          }
        </div>
      `;
      el.alertsContainer.appendChild(item);
    });

    el.alertsContainer.querySelectorAll('.btn-triage').forEach(b => {
      b.addEventListener('click', () => openModal(b.getAttribute('data-id')));
    });

    el.alertsContainer.querySelectorAll('.btn-soar-action').forEach(b => {
      b.addEventListener('click', () => executeSoarDirect(b.getAttribute('data-id')));
    });
  }

  // --- RENDER STREAM TABLE ---
  function renderStreamTable() {
    el.telemetryStreamBody.innerHTML = '';
    state.recentEvents.forEach(ev => {
      const row = document.createElement('tr');
      if (ev.isAnomaly) row.className = 'stream-row-anomaly';
      row.innerHTML = `
        <td>${ev.time}</td>
        <td>${ev.src}</td>
        <td>${ev.keyId}</td>
        <td>${ev.algo}</td>
        <td>${ev.caller}</td>
        <td>${ev.entropy} bits</td>
        <td>${ev.lat}</td>
        <td>${ev.isAnomaly ? '<span class="text-alert">🚨 ANOMALY</span>' : '<span class="text-success">✓ VALID</span>'}</td>
      `;
      el.telemetryStreamBody.appendChild(row);
    });

    el.totalIngestedCount.textContent = state.totalIngested.toLocaleString();
    el.totalAnomaliesCount.textContent = state.totalAnomalies.toLocaleString();
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
      const qvsColor = asset.qvs >= 80 ? 'text-alert' : (asset.qvs >= 50 ? 'text-purple' : 'text-success');

      tr.innerHTML = `
        <td><strong>${asset.name}</strong></td>
        <td>${asset.keyId}</td>
        <td><span class="formula-pill">${asset.algo}</span></td>
        <td>${asset.shelfLife}</td>
        <td>${asset.criticality}</td>
        <td>${asset.exposure}</td>
        <td><strong class="${qvsColor}">${asset.qvs.toFixed(1)}</strong></td>
        <td><span class="text-cyan">${asset.targetPqc}</span></td>
        <td>
          <span class="comp-badge ${asset.status === 'MIGRATED' ? 'pass' : (asset.status === 'QUARANTINED' ? 'warn' : 'warn')}">
            ${asset.status}
          </span>
        </td>
        <td>
          ${
            asset.status === 'MIGRATED'
              ? '<span class="text-success">✓ Protected</span>'
              : `<button class="btn-triage btn-migrate" data-key="${asset.keyId}">Migrate to PQC</button>`
          }
        </td>
      `;
      el.inventoryTableBody.appendChild(tr);
    });

    const avgQvs = (totalQvs / state.inventory.length).toFixed(1);
    el.orgAvgQvs.textContent = avgQvs;
    const pct = ((pqcCount / state.inventory.length) * 100).toFixed(1);
    el.pqcProgressPct.textContent = `${pct}%`;

    el.inventoryTableBody.querySelectorAll('.btn-migrate').forEach(btn => {
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
      showToast(`Key '${keyId}' migrated to ${item.targetPqc} (QVS reduced to 3.5).`);
    }
  }

  // --- CANVASES & VISUALIZERS ---
  function drawQuboCanvas() {
    if (!el.quboCanvas) return;
    const ctx = el.quboCanvas.getContext('2d');
    const w = el.quboCanvas.width;
    const h = el.quboCanvas.height;
    ctx.clearRect(0, 0, w, h);

    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    ctx.lineWidth = 1;
    for (let y = 30; y < h; y += 35) {
      ctx.beginPath();
      ctx.moveTo(30, y);
      ctx.lineTo(w / 2 - 20, y);
      ctx.stroke();
    }

    ctx.strokeStyle = '#a855f7';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    const trace = state.quboEnergyTrace;
    const xStep = (w / 2 - 60) / (trace.length - 1);
    const minVal = -20;
    const maxVal = 0;

    trace.forEach((val, i) => {
      const x = 40 + i * xStep;
      const y = 30 + ((val - maxVal) / (minVal - maxVal)) * (h - 60);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    trace.forEach((val, i) => {
      const x = 40 + i * xStep;
      const y = 30 + ((val - maxVal) / (minVal - maxVal)) * (h - 60);
      ctx.fillStyle = i === trace.length - 1 ? '#00f0ff' : '#a855f7';
      ctx.beginPath();
      ctx.arc(x, y, i === trace.length - 1 ? 5 : 3, 0, Math.PI * 2);
      ctx.fill();
    });

    ctx.fillStyle = '#8b9bb4';
    ctx.font = '10px JetBrains Mono';
    ctx.fillText('Simulated Annealing Energy E(t)', 40, 20);
    ctx.fillText(`E_min = ${trace[trace.length - 1]}`, w / 2 - 90, h - 10);

    const startX = w / 2 + 30;
    ctx.fillText('Qubit Spin State Vector x ∈ {0, 1}^N', startX, 20);

    const cols = 5;
    const cellSize = 24;
    const gap = 8;

    state.quboSpins.forEach((spin, idx) => {
      const r = Math.floor(idx / cols);
      const c = idx % cols;
      const cx = startX + c * (cellSize + gap);
      const cy = 40 + r * (cellSize + gap);

      ctx.fillStyle = spin === 1 ? 'rgba(239, 68, 68, 0.85)' : 'rgba(0, 240, 255, 0.2)';
      ctx.strokeStyle = spin === 1 ? '#ef4444' : '#00f0ff';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.rect(cx, cy, cellSize, cellSize);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = spin === 1 ? '#fff' : '#8b9bb4';
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

    const numNodes = 8;
    const nodeRadius = 14;
    const stepX = (w - 80) / (numNodes - 1);
    const cy = h / 2 + 10;

    ctx.strokeStyle = '#00f0ff';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    ctx.moveTo(40, cy);
    ctx.lineTo(40 + (numNodes - 1) * stepX, cy);
    ctx.stroke();

    state.mpsBondEntropies.forEach((entropy, i) => {
      const xMid = 40 + i * stepX + stepX / 2;
      ctx.fillStyle = entropy > 1.2 ? '#ef4444' : '#a855f7';
      ctx.font = '9px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText(`χ=4 (S=${entropy})`, xMid, cy - 22);

      ctx.fillStyle = '#00f0ff';
      ctx.beginPath();
      ctx.arc(xMid, cy, 3, 0, Math.PI * 2);
      ctx.fill();
    });

    for (let i = 0; i < numNodes; i++) {
      const cx = 40 + i * stepX;
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.4)';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(cx, cy + nodeRadius);
      ctx.lineTo(cx, cy + 36);
      ctx.stroke();

      ctx.fillStyle = '#8b9bb4';
      ctx.font = '8px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText(`|φ(${i+1})⟩`, cx, cy + 48);

      ctx.fillStyle = '#111724';
      ctx.strokeStyle = i === 0 || i === 7 ? '#a855f7' : '#00f0ff';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, cy, nodeRadius, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#fff';
      ctx.font = '10px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(`A^(${i+1})`, cx, cy);
    }

    ctx.textAlign = 'left';
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#8b9bb4';
    ctx.font = '10px JetBrains Mono';
    ctx.fillText('MPS Tensor Train Contraction ⟨W | Ψ(v)⟩', 30, 20);
  }

  function drawGroverCanvas() {
    if (!el.groverCanvas) return;
    const ctx = el.groverCanvas.getContext('2d');
    const w = el.groverCanvas.width;
    const h = el.groverCanvas.height;
    ctx.clearRect(0, 0, w, h);

    const history = state.groverData.history;
    const barWidth = 40;
    const gap = 35;
    const startX = 50;
    const chartHeight = h - 70;

    ctx.fillStyle = '#8b9bb4';
    ctx.font = '11px JetBrains Mono';
    ctx.fillText('Target State Probability Amplification P(target) = |⟨target | Ψ(k)⟩|²', startX, 22);

    history.forEach((step, i) => {
      const x = startX + i * (barWidth + gap);
      const barH = step.p * chartHeight;
      const y = h - 35 - barH;

      ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.fillRect(x, h - 35 - chartHeight, barWidth, chartHeight);

      const grad = ctx.createLinearGradient(0, y, 0, h - 35);
      grad.addColorStop(0, '#10b981');
      grad.addColorStop(1, '#00f0ff');
      ctx.fillStyle = grad;
      ctx.fillRect(x, y, barWidth, barH);

      ctx.fillStyle = '#fff';
      ctx.font = '10px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText(`${(step.p * 100).toFixed(1)}%`, x + barWidth / 2, y - 6);

      ctx.fillStyle = '#8b9bb4';
      ctx.fillText(`k=${step.k}`, x + barWidth / 2, h - 18);
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
    if (state.recentEvents.length > 10) state.recentEvents.pop();
    renderStreamTable();
  }

  function toggleStreaming() {
    state.streamingActive = !state.streamingActive;
    if (state.streamingActive) {
      el.streamStateIcon.textContent = '⏸️';
      el.streamStateText.textContent = 'Pause Telemetry';
      startStreamInterval();
    } else {
      el.streamStateIcon.textContent = '▶️';
      el.streamStateText.textContent = 'Resume Telemetry';
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
          showToast(`⚡ Backend Processed Scenario ${scenarioNum}: ${json.description}`);
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
        engine: 'Grover Amplitude Amplification Search',
        confidence: 0.999,
        mitre: 'T1552.004',
        summary: 'Identical k-value nonce reused across 2 transactions. Private key recovery mathematically feasible.',
        playbook: 'Emergency Key Revocation & CA Invalidation',
        soarExecuted: false,
        attributions: { 'nonce_collision_entropy': 0.99, 'cross_ip_divergence': 0.88, 'geo_risk_score': 0.74 }
      });
      state.groverData.history[5].p = 0.999;
      renderAllCanvases();
      showToast('🚨 Scenario 1: Nonce Reuse flagged via Grover Search!');
    } else if (scenarioNum === 2) {
      pushNewStreamEvent(true, { time: now, src: 'Blockchain', keyId: 'key-eth-smart-contract', algo: 'ECDSA-secp256k1', caller: 'unauthenticated-relayer (TOR-EXIT)', entropy: '7.85', lat: '14.2ms', isAnomaly: true });
      state.activeAlerts.unshift({
        id: `alt-${Math.random().toString(36).substring(2, 8)}`,
        time: 'Just now',
        severity: 'HIGH',
        title: 'Digital Signature Malleability Abuse (High-S Violation)',
        keyId: 'key-eth-smart-contract',
        engine: 'QUBO Simulated Annealing Solver',
        confidence: 0.935,
        mitre: 'T1565.002',
        summary: 'High-S signature structure detected attempting relay mutation on smart contract.',
        playbook: 'Enforce Low-S Canonical Verification Rule',
        soarExecuted: false,
        attributions: { 'malleability_indicator': 1.0, 'geo_risk_score': 0.70 }
      });
      showToast('🚨 Scenario 2: Signature Malleability flagged via QUBO!');
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
      showToast('🚨 Scenario 3: Rogue CI/CD Signing flagged via MPS!');
    } else if (scenarioNum === 4) {
      pushNewStreamEvent(true, { time: now, src: 'PKI/HSM', keyId: 'key-root-ca-01', algo: 'RSA-4096', caller: 'suspicious-recon-service (ANON-VPN)', entropy: '7.94', lat: '1.2ms', isAnomaly: true });
      state.activeAlerts.unshift({
        id: `alt-${Math.random().toString(36).substring(2, 8)}`,
        time: 'Just now',
        severity: 'HIGH',
        title: 'Quantum "Harvest Now, Decrypt Later" Bulk Key Export Profile',
        keyId: 'key-root-ca-01',
        engine: 'QUBO Simulated Annealing Solver',
        confidence: 0.912,
        mitre: 'T1110 - Token Harvesting',
        summary: 'Rapid burst export of 25-year root public keys and certs to anonymous VPN endpoint.',
        playbook: 'Apply HSM Export Rate-Limiting & Alert CISO',
        soarExecuted: false,
        attributions: { 'key_frequency_burst': 0.95, 'geo_risk_score': 0.85 }
      });
      showToast('🚨 Scenario 4: Quantum Harvest-Now reconnaissance flagged!');
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
    showToast('Alert queue and stream history reset.');
  });

  el.btnToggleStream.addEventListener('click', toggleStreaming);

  // --- MODAL & SOAR ACTIONS ---
  function openModal(alertId) {
    const alert = state.activeAlerts.find(a => a.id === alertId);
    if (!alert) return;
    activeModalAlert = alert;

    el.modalSeverityBadge.textContent = alert.severity;
    el.modalSeverityBadge.className = `modal-badge ${alert.severity}`;
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
          <span>+${(val * 100).toFixed(0)}% weight</span>
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
    showToast(`⚡ Executed: ${alert.playbook} on key '${alert.keyId}'.`);
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
      showToast('✓ Copied CEF Log format to clipboard!');
    }
  });

  function showToast(msg) {
    const toast = document.createElement('div');
    toast.style.position = 'fixed';
    toast.style.bottom = '24px';
    toast.style.right = '24px';
    toast.style.background = 'rgba(18, 24, 38, 0.95)';
    toast.style.color = '#00f0ff';
    toast.style.border = '1px solid #00f0ff';
    toast.style.boxShadow = '0 0 16px rgba(0, 240, 255, 0.3)';
    toast.style.padding = '12px 18px';
    toast.style.borderRadius = '8px';
    toast.style.fontFamily = 'JetBrains Mono, monospace';
    toast.style.fontSize = '12px';
    toast.style.zIndex = '9999';
    toast.textContent = msg;

    document.body.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 3200);
  }

  // --- INITIALIZATION ---
  renderAlerts();
  renderStreamTable();
  renderInventoryTable();
  renderAllCanvases();
  startStreamInterval();
  checkBackendConnection();

  setInterval(checkBackendConnection, 4000);
})();
