const deviceCatalog = [
  { name: 'Internet', ip: '203.0.113.1', kind: 'gateway' },
  { name: 'Router', ip: '10.0.0.1', kind: 'router' },
  { name: 'Firewall', ip: '10.0.0.2', kind: 'firewall' },
  { name: 'Server', ip: '10.0.0.10', kind: 'server' },
  { name: 'PC-01', ip: '10.0.0.20', kind: 'pc' },
  { name: 'PC-02', ip: '10.0.0.21', kind: 'pc' },
  { name: 'PC-03', ip: '10.0.0.22', kind: 'pc' },
  { name: 'PC-04', ip: '10.0.0.23', kind: 'pc' },
  { name: 'PC-05', ip: '10.0.0.24', kind: 'pc' }
];

const state = {
  packetId: 0,
  paused: false,
  stats: { created: 0, delivered: 0, blocked: 0, dropped: 0 },
  rules: [{ action: 'BLOCK', protocol: 'TCP', port: 23, enabled: true }],
  events: [],
  demoTimers: []
};

const elements = {
  created: document.querySelector('#createdMetric'),
  delivered: document.querySelector('#deliveredMetric'),
  blocked: document.querySelector('#blockedMetric'),
  deliveryMeta: document.querySelector('#deliveryMeta'),
  blockedMeta: document.querySelector('#blockedMeta'),
  onlineMetric: document.querySelector('#onlineMetric'),
  ruleList: document.querySelector('#ruleList'),
  ruleCount: document.querySelector('#ruleCount'),
  eventList: document.querySelector('#eventList'),
  packetOrb: document.querySelector('#packetOrb'),
  sourceSelect: document.querySelector('#sourceSelect'),
  destinationSelect: document.querySelector('#destinationSelect')
};

function now() {
  return new Date().toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

function populateEndpointOptions() {
  const endpoints = deviceCatalog.filter(device => device.kind === 'server' || device.kind === 'pc');
  const options = endpoints
    .map(device => `<option value="${device.name}">${device.name} · ${device.ip}</option>`)
    .join('');

  elements.sourceSelect.innerHTML = options;
  elements.destinationSelect.innerHTML = options;
  elements.sourceSelect.value = 'PC-01';
  elements.destinationSelect.value = 'Server';
}

function addEvent(message, type = '') {
  state.events.unshift({ time: now(), message, type });
  state.events = state.events.slice(0, 12);

  elements.eventList.innerHTML = state.events
    .map(event => `<div class="event-row ${event.type}"><span class="event-time">${event.time}</span><span class="event-message">${event.message}</span></div>`)
    .join('');
}

function renderStats() {
  elements.onlineMetric.textContent = String(deviceCatalog.length);
  elements.created.textContent = String(state.stats.created);
  elements.delivered.textContent = String(state.stats.delivered);
  elements.blocked.textContent = String(state.stats.blocked);

  elements.deliveryMeta.textContent = state.stats.created
    ? `${Math.round((state.stats.delivered / state.stats.created) * 100)}% delivery rate`
    : 'Awaiting traffic';

  elements.blockedMeta.textContent = state.stats.blocked
    ? `${state.stats.blocked} policy decision${state.stats.blocked === 1 ? '' : 's'}`
    : 'Firewall clear';
}

function renderRules() {
  const activeRules = state.rules.filter(rule => rule.enabled).length;
  elements.ruleCount.textContent = `${activeRules} active`;

  elements.ruleList.innerHTML = state.rules.map((rule, index) => `
    <div class="rule-row">
      <span class="rule-action ${rule.action.toLowerCase()}">${rule.action}</span>
      <span class="rule-condition">${rule.protocol} destination port ${rule.port}</span>
      <button class="rule-toggle" data-rule="${index}" title="Toggle rule">${rule.enabled ? 'ON' : 'OFF'}</button>
    </div>
  `).join('');

  document.querySelectorAll('.rule-toggle').forEach(button => {
    button.addEventListener('click', () => {
      const ruleIndex = Number(button.dataset.rule);
      const rule = state.rules[ruleIndex];
      if (!rule) return;

      rule.enabled = !rule.enabled;
      renderRules();
      addEvent(`<strong>Firewall rule updated</strong> · rule ${ruleIndex} is now ${rule.enabled ? 'active' : 'disabled'}`);
    });
  });
}

function animatePacket(result) {
  const orb = elements.packetOrb;
  orb.classList.remove('animate');
  void orb.offsetWidth;
  orb.style.background = result === 'BLOCKED' ? 'var(--red)' : 'var(--cyan)';
  orb.style.boxShadow = result === 'BLOCKED'
    ? '0 0 0 5px rgba(255,125,123,.14), 0 0 20px rgba(255,125,123,.9)'
    : '0 0 0 5px rgba(97,232,218,.14), 0 0 24px rgba(97,232,218,.9)';
  orb.classList.add('animate');
}

function routePacket({ source, destination, protocol, port, size }, quiet = false) {
  const packetId = ++state.packetId;
  state.stats.created += 1;

  const matchingRule = state.rules.find(rule =>
    rule.enabled &&
    rule.protocol === protocol &&
    Number(rule.port) === Number(port)
  );

  const result = matchingRule?.action === 'BLOCK' ? 'BLOCKED' : 'DELIVERED';
  state.stats[result.toLowerCase()] += 1;

  renderStats();
  animatePacket(result);

  if (result === 'BLOCKED') {
    addEvent(`<strong>Packet #${packetId} blocked</strong> · ${source} → ${destination} · ${protocol}:${port}`, 'blocked');
  } else {
    addEvent(`<strong>Packet #${packetId} delivered</strong> · ${source} → ${destination} · ${protocol}:${port}`, 'delivered');
  }

  if (!quiet) {
    document.querySelector('#events').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  return result;
}

function cancelDemoSequence() {
  state.demoTimers.forEach(timerId => clearTimeout(timerId));
  state.demoTimers = [];
}

function seedDemoSequence() {
  cancelDemoSequence();
  const sequence = [
    { source: 'PC-01', destination: 'Server', protocol: 'TCP', port: 80, size: 512 },
    { source: 'PC-03', destination: 'Server', protocol: 'UDP', port: 53, size: 384 },
    { source: 'PC-05', destination: 'Server', protocol: 'TCP', port: 23, size: 512 },
    { source: 'PC-02', destination: 'PC-04', protocol: 'ICMP', port: 8, size: 256 },
    { source: 'PC-04', destination: 'PC-01', protocol: 'TCP', port: 443, size: 768 }
  ];

  state.demoTimers = sequence.map((packet, index) => setTimeout(() => {
    routePacket(packet, true);
    if (index === sequence.length - 1) state.demoTimers = [];
  }, index * 650));

  addEvent('<strong>Demo sequence started</strong> · traffic routed across five workstations');
}

document.querySelector('#packetForm').addEventListener('submit', event => {
  event.preventDefault();
  const source = document.querySelector('#sourceSelect').value;
  const destination = document.querySelector('#destinationSelect').value;
  const protocol = document.querySelector('#protocolSelect').value;
  const port = Number(document.querySelector('#portInput').value);
  const size = Number(document.querySelector('#sizeInput').value);

  if (!port || port < 1 || port > 65535 || !size || size < 1) return;

  routePacket({ source, destination, protocol, port, size });
});

document.querySelector('#ruleForm').addEventListener('submit', event => {
  event.preventDefault();

  const rule = {
    action: document.querySelector('#ruleAction').value,
    protocol: document.querySelector('#ruleProtocol').value,
    port: Number(document.querySelector('#rulePort').value),
    enabled: true
  };

  if (!rule.port || rule.port > 65535) return;

  state.rules.push(rule);
  renderRules();
  addEvent(`<strong>Firewall rule added</strong> · ${rule.action} ${rule.protocol}:${rule.port}`);
});

document.querySelector('#pauseButton').addEventListener('click', event => {
  state.paused = !state.paused;
  if (state.paused) cancelDemoSequence();
  event.currentTarget.innerHTML = state.paused ? '<span>▶</span>Resume stream' : '<span>Ⅱ</span>Pause stream';
  addEvent(`<strong>Simulation ${state.paused ? 'paused' : 'resumed'}</strong> · manual controls remain available`);
});

document.querySelector('#demoButton').addEventListener('click', () => {
  if (state.paused) return;
  seedDemoSequence();
});

document.querySelector('#resetButton').addEventListener('click', () => {
  cancelDemoSequence();
  state.packetId = 0;
  state.stats = { created: 0, delivered: 0, blocked: 0, dropped: 0 };
  state.rules = [{ action: 'BLOCK', protocol: 'TCP', port: 23, enabled: true }];
  state.events = [];

  renderStats();
  renderRules();
  elements.eventList.innerHTML = '';
  addEvent('<strong>Simulation reset</strong> · network ready for traffic');
});

populateEndpointOptions();
renderStats();
renderRules();
addEvent('<strong>Engine initialized</strong> · nine devices online');
addEvent('<strong>Firewall ready</strong> · TCP destination port 23 blocked');


const incidentElements = {
  list: document.querySelector('#incidentList'),
  summary: document.querySelector('#incidentSummary'),
  filter: document.querySelector('#incidentStatusFilter'),
  refresh: document.querySelector('#refreshIncidents'),
  demo: document.querySelector('#generateIncidentDemo'),
  simulate: document.querySelector('#runCppSimulation'),
  message: document.querySelector('#incidentMessage')
};

function setIncidentMessage(message, isError = false) {
  incidentElements.message.textContent = message;
  incidentElements.message.classList.toggle('error', isError);
}

function makeIncidentNode(incident) {
  const card = document.createElement('article');
  card.className = 'incident-card';
  const top = document.createElement('div');
  top.className = 'incident-card-top';
  const title = document.createElement('strong');
  title.textContent = incident.title;
  const severity = document.createElement('span');
  severity.className = 'severity-pill severity-' + incident.severity;
  severity.textContent = incident.severity;
  top.append(title, severity);

  const summary = document.createElement('p');
  summary.className = 'incident-summary';
  summary.textContent = incident.summary;
  const meta = document.createElement('div');
  meta.className = 'incident-meta';
  meta.textContent = incident.source_ip + (incident.destination_ip ? ' → ' + incident.destination_ip : '') +
    (incident.destination_port ? ' · port ' + incident.destination_port : '') +
    ' · risk ' + incident.risk_score + '/100 · ' + incident.occurrence_count + ' signal(s)';

  const controls = document.createElement('div');
  controls.className = 'incident-controls';
  const status = document.createElement('select');
  status.setAttribute('aria-label', 'Update incident status');
  ['new', 'acknowledged', 'investigating', 'resolved', 'false_positive'].forEach(value => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = value.replace('_', ' ');
    option.selected = value === incident.status;
    status.append(option);
  });
  status.addEventListener('change', async () => {
    try {
      const response = await fetch('/api/incidents/' + encodeURIComponent(incident.id) + '/status', {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: status.value })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Status update failed');
      setIncidentMessage('Incident ' + incident.id + ' updated.');
      await loadIncidents();
    } catch (error) {
      setIncidentMessage(error.message, true);
      status.value = incident.status;
    }
  });

  const evidence = document.createElement('details');
  evidence.className = 'incident-evidence';
  const evidenceSummary = document.createElement('summary');
  evidenceSummary.textContent = 'View evidence';
  const evidenceBody = document.createElement('pre');
  evidenceBody.textContent = JSON.stringify(incident.evidence, null, 2);
  evidence.append(evidenceSummary, evidenceBody);
  evidence.addEventListener('toggle', async () => {
    if (!evidence.open) return;
    try {
      const response = await fetch('/api/incidents/' + encodeURIComponent(incident.id));
      const detail = await response.json();
      if (!response.ok) throw new Error(detail.error || 'Unable to load incident timeline');
      evidenceBody.textContent = JSON.stringify({ evidence: detail.incident.evidence, timeline: detail.incident.timeline }, null, 2);
    } catch (error) {
      evidenceBody.textContent = error.message;
    }
  });
  const inspect = document.createElement('button');
  inspect.className = 'incident-inspect';
  inspect.type = 'button';
  inspect.textContent = 'Evidence';
  inspect.addEventListener('click', () => { evidence.open = !evidence.open; });
  controls.append(status, inspect);
  card.append(top, summary, meta, controls, evidence);
  return card;
}

async function loadIncidents() {
  try {
    const status = incidentElements.filter.value;
    const response = await fetch('/api/incidents' + (status ? '?status=' + encodeURIComponent(status) : ''));
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to load incidents');
    incidentElements.summary.textContent = result.summary.open + ' open · ' +
      result.summary.critical + ' critical · ' + result.summary.total + ' total';
    incidentElements.list.replaceChildren();
    if (!result.incidents.length) {
      const empty = document.createElement('p');
      empty.className = 'incident-empty';
      empty.textContent = 'No incidents match this view. Generate local demo detections to explore the workflow.';
      incidentElements.list.append(empty);
    } else {
      result.incidents.forEach(incident => incidentElements.list.append(makeIncidentNode(incident)));
    }
    setIncidentMessage('SQLite incident store connected.');
  } catch (error) {
    incidentElements.summary.textContent = 'API unavailable';
    incidentElements.list.replaceChildren();
    setIncidentMessage(error.message + ' · Start with python backend/server.py.', true);
  }
}

async function generateIncidentDemo() {
  const samples = [
    { type: 'port_scan', source_ip: '10.0.0.20', destination_ip: '10.0.0.10', destination_port: 443, protocol: 'TCP', summary: 'PC-01 contacted many service ports on the server', evidence: { distinct_ports: 12, threshold: 10, window_seconds: 60, source: 'local-demo' } },
    { type: 'brute_force', source_ip: '10.0.0.21', destination_ip: '10.0.0.10', destination_port: 22, protocol: 'TCP', summary: 'Repeated failed connection attempts to SSH service', evidence: { failed_attempts: 8, threshold: 5, window_seconds: 60, source: 'local-demo' } },
    { type: 'dos', source_ip: '10.0.0.22', destination_ip: '10.0.0.10', destination_port: 80, protocol: 'TCP', summary: 'High-volume packet burst against the web server', evidence: { packet_count: 180, threshold: 100, window_seconds: 10, source: 'local-demo' } },
    { type: 'lateral_movement', source_ip: '10.0.0.23', destination_ip: '10.0.0.24', destination_port: 445, protocol: 'TCP', summary: 'Internal workstation contacted multiple private hosts', evidence: { distinct_internal_destinations: 5, threshold: 3, window_seconds: 60, source: 'local-demo' } }
  ];
  incidentElements.demo.disabled = true;
  try {
    for (const sample of samples) {
      const response = await fetch('/api/detections', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sample)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Detection ingestion failed');
    }
    setIncidentMessage('Four local demo detections submitted and persisted in SQLite.');
    await loadIncidents();
  } catch (error) {
    setIncidentMessage(error.message, true);
  } finally {
    incidentElements.demo.disabled = false;
  }
}

incidentElements.refresh.addEventListener('click', loadIncidents);
incidentElements.filter.addEventListener('change', loadIncidents);
incidentElements.demo.addEventListener('click', generateIncidentDemo);
incidentElements.simulate.addEventListener('click', async () => {
  incidentElements.simulate.disabled = true;
  setIncidentMessage('Running native C++ simulator and importing detections…');
  try {
    const response = await fetch('/api/simulate', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Native simulation failed');
    setIncidentMessage(result.detections_received + ' native detections imported · ' +
      result.incidents_created + ' new incidents · ' + result.detections_correlated + ' correlated.');
    await loadIncidents();
  } catch (error) {
    setIncidentMessage(error.message, true);
  } finally {
    incidentElements.simulate.disabled = false;
  }
});
loadIncidents();

const liveElements = {
  state: document.querySelector('#liveCaptureState'),
  interface: document.querySelector('#liveInterfaceSelect'),
  start: document.querySelector('#startLiveCapture'),
  stop: document.querySelector('#stopLiveCapture'),
  refresh: document.querySelector('#refreshLiveCapture'),
  message: document.querySelector('#liveMonitorMessage'),
  packets: document.querySelector('#livePacketsSeen'),
  detections: document.querySelector('#liveDetectionsCreated'),
  errors: document.querySelector('#liveCaptureErrors')
};

function liveMessage(message, isError = false) {
  liveElements.message.textContent = message;
  liveElements.message.classList.toggle('error', isError);
}

async function refreshLiveInterfaces() {
  liveElements.refresh.disabled = true;
  try {
    const response = await fetch('/api/live/interfaces');
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Live capture is unavailable');
    liveElements.interface.replaceChildren();
    result.interfaces.forEach(item => {
      const option = document.createElement('option');
      option.value = item.name;
      option.textContent = item.description === item.name ? item.name : item.description + ' · ' + item.name;
      liveElements.interface.append(option);
    });
    liveElements.interface.disabled = result.interfaces.length === 0;
    liveElements.start.disabled = result.interfaces.length === 0;
    liveMessage(result.interfaces.length
      ? 'Choose the interface connected to the network you are authorized to monitor.'
      : 'No capture interfaces are available on this machine.');
    if (!result.interfaces.length) liveElements.interface.innerHTML = '<option value="">No interfaces found</option>';
  } catch (error) {
    liveElements.interface.replaceChildren();
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'Live capture unavailable';
    liveElements.interface.append(option);
    liveElements.interface.disabled = true;
    liveElements.start.disabled = true;
    liveMessage(error.message + ' · Install optional capture support and check Npcap/libpcap.', true);
  } finally {
    liveElements.refresh.disabled = false;
    await refreshLiveStatus();
  }
}

async let lastLiveDetectionCount = -1;

async function refreshLiveStatus() {
  try {
    const response = await fetch('/api/live/status');
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to read capture status');
    liveElements.state.textContent = result.running ? 'Capture running' : (result.available ? 'Capture stopped' : 'Capture unavailable');
    liveElements.state.classList.toggle('is-running', result.running);
    liveElements.packets.textContent = String(result.packets_seen || 0);
    liveElements.detections.textContent = String(result.detections_created || 0);
    liveElements.errors.textContent = String(result.ingest_errors || 0);
    const detectionCount = Number(result.detections_created || 0);
    if (lastLiveDetectionCount >= 0 && detectionCount > lastLiveDetectionCount) {
      await loadIncidents();
      setIncidentMessage('New live-monitoring detections were added to the incident list.');
    }
    lastLiveDetectionCount = detectionCount;
    liveElements.start.disabled = !result.available || result.running || !liveElements.interface.value;
    liveElements.stop.disabled = !result.running;
    if (result.last_error) liveMessage(result.last_error, true);
  } catch (error) {
    liveElements.state.textContent = 'API unavailable';
    liveMessage(error.message, true);
  }
}

liveElements.start.addEventListener('click', async () => {
  liveElements.start.disabled = true;
  liveMessage('Starting passive packet capture…');
  try {
    const response = await fetch('/api/live/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: liveElements.interface.value })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to start packet capture');
    liveMessage('Capture started on ' + result.interface + '. Incoming metadata will be analyzed locally.');
    await refreshLiveStatus();
  } catch (error) {
    liveMessage(error.message, true);
    await refreshLiveStatus();
  }
});

liveElements.stop.addEventListener('click', async () => {
  liveElements.stop.disabled = true;
  try {
    const response = await fetch('/api/live/stop', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to stop packet capture');
    liveMessage('Live packet capture stopped.');
    await refreshLiveStatus();
  } catch (error) {
    liveMessage(error.message, true);
    await refreshLiveStatus();
  }
});

liveElements.refresh.addEventListener('click', refreshLiveInterfaces);
refreshLiveInterfaces();
window.setInterval(refreshLiveStatus, 3000);
