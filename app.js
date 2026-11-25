class NetworkSimulatorController {
  constructor() {
this.deviceCatalog = [
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

this.state = {
  packetId: 0,
  paused: false,
  stats: { created: 0, delivered: 0, blocked: 0, dropped: 0 },
  rules: [{ action: 'BLOCK', protocol: 'TCP', port: 23, enabled: true }],
  events: [],
  demoTimers: []
};

this.elements = {
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
    for (const name of Object.getOwnPropertyNames(Object.getPrototypeOf(this))) {
      if (name !== 'constructor') this[name] = this[name].bind(this);
    }
    this.initialize();
  }

now() {
  return new Date().toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

populateEndpointOptions() {
  const endpoints = this.deviceCatalog.filter(device => device.kind === 'server' || device.kind === 'pc');
  const options = endpoints
    .map(device => `<option value="${device.name}">${device.name} · ${device.ip}</option>`)
    .join('');

  this.elements.sourceSelect.innerHTML = options;
  this.elements.destinationSelect.innerHTML = options;
  this.elements.sourceSelect.value = 'PC-01';
  this.elements.destinationSelect.value = 'Server';
}

addEvent(message, type = '') {
  this.state.events.unshift({ time: this.now(), message, type });
  this.state.events = this.state.events.slice(0, 12);

  this.elements.eventList.innerHTML = this.state.events
    .map(event => `<div class="event-row ${event.type}"><span class="event-time">${event.time}</span><span class="event-message">${event.message}</span></div>`)
    .join('');
}

renderStats() {
  this.elements.onlineMetric.textContent = String(this.deviceCatalog.length);
  this.elements.created.textContent = String(this.state.stats.created);
  this.elements.delivered.textContent = String(this.state.stats.delivered);
  this.elements.blocked.textContent = String(this.state.stats.blocked);

  this.elements.deliveryMeta.textContent = this.state.stats.created
    ? `${Math.round((this.state.stats.delivered / this.state.stats.created) * 100)}% delivery rate`
    : 'Awaiting traffic';

  this.elements.blockedMeta.textContent = this.state.stats.blocked
    ? `${this.state.stats.blocked} policy decision${this.state.stats.blocked === 1 ? '' : 's'}`
    : 'Firewall clear';
}

renderRules() {
  const activeRules = this.state.rules.filter(rule => rule.enabled).length;
  this.elements.ruleCount.textContent = `${activeRules} active`;

  this.elements.ruleList.innerHTML = this.state.rules.map((rule, index) => `
    <div class="rule-row">
      <span class="rule-action ${rule.action.toLowerCase()}">${rule.action}</span>
      <span class="rule-condition">${rule.protocol} destination port ${rule.port}</span>
      <button class="rule-toggle" data-rule="${index}" title="Toggle rule">${rule.enabled ? 'ON' : 'OFF'}</button>
    </div>
  `).join('');

  document.querySelectorAll('.rule-toggle').forEach(button => {
    button.addEventListener('click', () => {
      const ruleIndex = Number(button.dataset.rule);
      const rule = this.state.rules[ruleIndex];
      if (!rule) return;

      rule.enabled = !rule.enabled;
      this.renderRules();
      this.addEvent(`<strong>Firewall rule updated</strong> · rule ${ruleIndex} is now ${rule.enabled ? 'active' : 'disabled'}`);
    });
  });
}

animatePacket(result) {
  const orb = this.elements.packetOrb;
  orb.classList.remove('animate');
  void orb.offsetWidth;
  orb.style.background = result === 'BLOCKED' ? 'var(--red)' : 'var(--cyan)';
  orb.style.boxShadow = result === 'BLOCKED'
    ? '0 0 0 5px rgba(255,125,123,.14), 0 0 20px rgba(255,125,123,.9)'
    : '0 0 0 5px rgba(97,232,218,.14), 0 0 24px rgba(97,232,218,.9)';
  orb.classList.add('animate');
}

routePacket({ source, destination, protocol, port, size }, quiet = false) {
  const packetId = ++this.state.packetId;
  this.state.stats.created += 1;

  const matchingRule = this.state.rules.find(rule =>
    rule.enabled &&
    rule.protocol === protocol &&
    Number(rule.port) === Number(port)
  );

  const result = matchingRule?.action === 'BLOCK' ? 'BLOCKED' : 'DELIVERED';
  this.state.stats[result.toLowerCase()] += 1;

  this.renderStats();
  this.animatePacket(result);

  if (result === 'BLOCKED') {
    this.addEvent(`<strong>Packet #${packetId} blocked</strong> · ${source} → ${destination} · ${protocol}:${port}`, 'blocked');
  } else {
    this.addEvent(`<strong>Packet #${packetId} delivered</strong> · ${source} → ${destination} · ${protocol}:${port}`, 'delivered');
  }

  if (!quiet) {
    document.querySelector('#events').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  return result;
}

cancelDemoSequence() {
  this.state.demoTimers.forEach(timerId => clearTimeout(timerId));
  this.state.demoTimers = [];
}

seedDemoSequence() {
  this.cancelDemoSequence();
  const sequence = [
    { source: 'PC-01', destination: 'Server', protocol: 'TCP', port: 80, size: 512 },
    { source: 'PC-03', destination: 'Server', protocol: 'UDP', port: 53, size: 384 },
    { source: 'PC-05', destination: 'Server', protocol: 'TCP', port: 23, size: 512 },
    { source: 'PC-02', destination: 'PC-04', protocol: 'ICMP', port: 8, size: 256 },
    { source: 'PC-04', destination: 'PC-01', protocol: 'TCP', port: 443, size: 768 }
  ];

  this.state.demoTimers = sequence.map((packet, index) => setTimeout(() => {
    this.routePacket(packet, true);
    if (index === sequence.length - 1) this.state.demoTimers = [];
  }, index * 650));

  this.addEvent('<strong>Demo sequence started</strong> · traffic routed across five workstations');
}

  initialize() {
document.querySelector('#packetForm').addEventListener('submit', event => {
  event.preventDefault();
  const source = document.querySelector('#sourceSelect').value;
  const destination = document.querySelector('#destinationSelect').value;
  const protocol = document.querySelector('#protocolSelect').value;
  const port = Number(document.querySelector('#portInput').value);
  const size = Number(document.querySelector('#sizeInput').value);

  if (!port || port < 1 || port > 65535 || !size || size < 1) return;

  this.routePacket({ source, destination, protocol, port, size });
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

  this.state.rules.push(rule);
  this.renderRules();
  this.addEvent(`<strong>Firewall rule added</strong> · ${rule.action} ${rule.protocol}:${rule.port}`);
});

document.querySelector('#pauseButton').addEventListener('click', event => {
  this.state.paused = !this.state.paused;
  if (this.state.paused) this.cancelDemoSequence();
  event.currentTarget.innerHTML = this.state.paused ? '<span>▶</span>Resume stream' : '<span>Ⅱ</span>Pause stream';
  this.addEvent(`<strong>Simulation ${this.state.paused ? 'paused' : 'resumed'}</strong> · manual controls remain available`);
});

document.querySelector('#demoButton').addEventListener('click', () => {
  if (this.state.paused) return;
  this.seedDemoSequence();
});

document.querySelector('#resetButton').addEventListener('click', () => {
  this.cancelDemoSequence();
  this.state.packetId = 0;
  this.state.stats = { created: 0, delivered: 0, blocked: 0, dropped: 0 };
  this.state.rules = [{ action: 'BLOCK', protocol: 'TCP', port: 23, enabled: true }];
  this.state.events = [];

  this.renderStats();
  this.renderRules();
  this.elements.eventList.innerHTML = '';
  this.addEvent('<strong>Simulation reset</strong> · network ready for traffic');
});

this.populateEndpointOptions();
this.renderStats();
this.renderRules();
this.addEvent('<strong>Engine initialized</strong> · nine devices online');
this.addEvent('<strong>Firewall ready</strong> · TCP destination port 23 blocked');
  }
}

class IncidentDashboardController {
  constructor() {
this.incidentElements = {
  list: document.querySelector('#incidentList'),
  summary: document.querySelector('#incidentSummary'),
  filter: document.querySelector('#incidentStatusFilter'),
  refresh: document.querySelector('#refreshIncidents'),
  demo: document.querySelector('#generateIncidentDemo'),
  simulate: document.querySelector('#runCppSimulation'),
  message: document.querySelector('#incidentMessage')
};
    for (const name of Object.getOwnPropertyNames(Object.getPrototypeOf(this))) {
      if (name !== 'constructor') this[name] = this[name].bind(this);
    }
    this.initialize();
  }

setIncidentMessage(message, isError = false) {
  this.incidentElements.message.textContent = message;
  this.incidentElements.message.classList.toggle('error', isError);
}

makeIncidentNode(incident) {
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
      this.setIncidentMessage('Incident ' + incident.id + ' updated.');
      await this.loadIncidents();
    } catch (error) {
      this.setIncidentMessage(error.message, true);
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
      evidenceBody.textContent = JSON.stringify({ evidence: detail.incident.evidence, timeline: detail.incident.timeline, threat_intel_matches: detail.incident.threat_intel_matches, analyst_notes: detail.incident.analyst_notes }, null, 2);
    } catch (error) {
      evidenceBody.textContent = error.message;
    }
  });
  const inspect = document.createElement('button');
  inspect.className = 'incident-inspect';
  inspect.type = 'button';
  inspect.textContent = 'Evidence';
  inspect.addEventListener('click', () => { evidence.open = !evidence.open; });
  const noteForm = document.createElement('form');
  noteForm.className = 'incident-note-form';
  const noteInput = document.createElement('input');
  noteInput.type = 'text';
  noteInput.maxLength = 2000;
  noteInput.placeholder = 'Add an investigation note…';
  noteInput.setAttribute('aria-label', 'Investigation note');
  const noteButton = document.createElement('button');
  noteButton.type = 'submit';
  noteButton.textContent = 'Add note';
  noteForm.append(noteInput, noteButton);
  noteForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (!noteInput.value.trim()) return;
    noteButton.disabled = true;
    try {
      const response = await fetch('/api/incidents/' + encodeURIComponent(incident.id) + '/notes', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: noteInput.value.trim() })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Unable to save investigation note');
      this.setIncidentMessage('Investigation note saved for ' + incident.id + '.');
      noteInput.value = '';
      evidence.open = true;
      evidence.dispatchEvent(new Event('toggle'));
    } catch (error) {
      this.setIncidentMessage(error.message, true);
    } finally {
      noteButton.disabled = false;
    }
  });
  controls.append(status, inspect);
  card.append(top, summary, meta, controls, noteForm, evidence);
  return card;
}

async loadIncidents() {
  try {
    const status = this.incidentElements.filter.value;
    const response = await fetch('/api/incidents' + (status ? '?status=' + encodeURIComponent(status) : ''));
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to load incidents');
    this.incidentElements.summary.textContent = result.summary.open + ' open · ' +
      result.summary.critical + ' critical · ' + result.summary.total + ' total';
    this.incidentElements.list.replaceChildren();
    if (!result.incidents.length) {
      const empty = document.createElement('p');
      empty.className = 'incident-empty';
      empty.textContent = 'No incidents match this view. Generate local demo detections to explore the workflow.';
      this.incidentElements.list.append(empty);
    } else {
      result.incidents.forEach(incident => this.incidentElements.list.append(this.makeIncidentNode(incident)));
    }
    this.setIncidentMessage('SQLite incident store connected.');
  } catch (error) {
    this.incidentElements.summary.textContent = 'API unavailable';
    this.incidentElements.list.replaceChildren();
    this.setIncidentMessage(error.message + ' · Start with python backend/server.py.', true);
  }
}

async generateIncidentDemo() {
  const samples = [
    { type: 'port_scan', source_ip: '10.0.0.20', destination_ip: '10.0.0.10', destination_port: 443, protocol: 'TCP', summary: 'PC-01 contacted many service ports on the server', evidence: { distinct_ports: 12, threshold: 10, window_seconds: 60, source: 'local-demo' } },
    { type: 'brute_force', source_ip: '10.0.0.21', destination_ip: '10.0.0.10', destination_port: 22, protocol: 'TCP', summary: 'Repeated failed connection attempts to SSH service', evidence: { failed_attempts: 8, threshold: 5, window_seconds: 60, source: 'local-demo' } },
    { type: 'dos', source_ip: '10.0.0.22', destination_ip: '10.0.0.10', destination_port: 80, protocol: 'TCP', summary: 'High-volume packet burst against the web server', evidence: { packet_count: 180, threshold: 100, window_seconds: 10, source: 'local-demo' } },
    { type: 'lateral_movement', source_ip: '10.0.0.23', destination_ip: '10.0.0.24', destination_port: 445, protocol: 'TCP', summary: 'Internal workstation contacted multiple private hosts', evidence: { distinct_internal_destinations: 5, threshold: 3, window_seconds: 60, source: 'local-demo' } }
  ];
  this.incidentElements.demo.disabled = true;
  try {
    for (const sample of samples) {
      const response = await fetch('/api/detections', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sample)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Detection ingestion failed');
    }
    this.setIncidentMessage('Four local demo detections submitted and persisted in SQLite.');
    await this.loadIncidents();
  } catch (error) {
    this.setIncidentMessage(error.message, true);
  } finally {
    this.incidentElements.demo.disabled = false;
  }
}

  initialize() {
this.incidentElements.refresh.addEventListener('click', this.loadIncidents);
this.incidentElements.filter.addEventListener('change', this.loadIncidents);
this.incidentElements.demo.addEventListener('click', this.generateIncidentDemo);
this.incidentElements.simulate.addEventListener('click', async () => {
  this.incidentElements.simulate.disabled = true;
  this.setIncidentMessage('Running native C++ simulator and importing detections…');
  try {
    const response = await fetch('/api/simulate', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Native simulation failed');
    this.setIncidentMessage(result.detections_received + ' native detections imported · ' +
      result.incidents_created + ' new incidents · ' + result.detections_correlated + ' correlated.');
    await this.loadIncidents();
  } catch (error) {
    this.setIncidentMessage(error.message, true);
  } finally {
    this.incidentElements.simulate.disabled = false;
  }
});
this.loadIncidents();
  }
}

class LiveMonitorController {
  constructor(incidentController) {
    this.incidentController = incidentController;
this.liveElements = {
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
    this.lastLiveDetectionCount = -1;
    for (const name of Object.getOwnPropertyNames(Object.getPrototypeOf(this))) {
      if (name !== 'constructor') this[name] = this[name].bind(this);
    }
    this.initialize();
  }

liveMessage(message, isError = false) {
  this.liveElements.message.textContent = message;
  this.liveElements.message.classList.toggle('error', isError);
}

async refreshLiveInterfaces() {
  this.liveElements.refresh.disabled = true;
  try {
    const response = await fetch('/api/live/interfaces');
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Live capture is unavailable');
    this.liveElements.interface.replaceChildren();
    result.interfaces.forEach(item => {
      const option = document.createElement('option');
      option.value = item.name;
      option.textContent = item.description === item.name ? item.name : item.description + ' · ' + item.name;
      this.liveElements.interface.append(option);
    });
    this.liveElements.interface.disabled = result.interfaces.length === 0;
    this.liveElements.start.disabled = result.interfaces.length === 0;
    this.liveMessage(result.interfaces.length
      ? 'Choose the interface connected to the network you are authorized to monitor.'
      : 'No capture interfaces are available on this machine.');
    if (!result.interfaces.length) this.liveElements.interface.innerHTML = '<option value="">No interfaces found</option>';
  } catch (error) {
    this.liveElements.interface.replaceChildren();
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'Live capture unavailable';
    this.liveElements.interface.append(option);
    this.liveElements.interface.disabled = true;
    this.liveElements.start.disabled = true;
    this.liveMessage(error.message + ' · Install optional capture support and check Npcap/libpcap.', true);
  } finally {
    this.liveElements.refresh.disabled = false;
    await this.refreshLiveStatus();
  }
}



async refreshLiveStatus() {
  try {
    const response = await fetch('/api/live/status');
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to read capture status');
    this.liveElements.state.textContent = result.running ? 'Capture running' : (result.available ? 'Capture stopped' : 'Capture unavailable');
    this.liveElements.state.classList.toggle('is-running', result.running);
    this.liveElements.packets.textContent = String(result.packets_seen || 0);
    this.liveElements.detections.textContent = String(result.detections_created || 0);
    this.liveElements.errors.textContent = String(result.ingest_errors || 0);
    const detectionCount = Number(result.detections_created || 0);
    if (this.lastLiveDetectionCount >= 0 && detectionCount > this.lastLiveDetectionCount) {
      await this.incidentController.loadIncidents();
      this.incidentController.setIncidentMessage('New live-monitoring detections were added to the incident list.');
    }
    this.lastLiveDetectionCount = detectionCount;
    this.liveElements.start.disabled = !result.available || result.running || !this.liveElements.interface.value;
    this.liveElements.stop.disabled = !result.running;
    if (result.last_error) this.liveMessage(result.last_error, true);
  } catch (error) {
    this.liveElements.state.textContent = 'API unavailable';
    this.liveMessage(error.message, true);
  }
}

  initialize() {
this.liveElements.start.addEventListener('click', async () => {
  this.liveElements.start.disabled = true;
  this.liveMessage('Starting passive packet capture…');
  try {
    const response = await fetch('/api/live/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: this.liveElements.interface.value })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to start packet capture');
    this.liveMessage('Capture started on ' + result.interface + '. Incoming metadata will be analyzed locally.');
    await this.refreshLiveStatus();
  } catch (error) {
    this.liveMessage(error.message, true);
    await this.refreshLiveStatus();
  }
});

this.liveElements.stop.addEventListener('click', async () => {
  this.liveElements.stop.disabled = true;
  try {
    const response = await fetch('/api/live/stop', { method: 'POST' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to stop packet capture');
    this.liveMessage('Live packet capture stopped.');
    await this.refreshLiveStatus();
  } catch (error) {
    this.liveMessage(error.message, true);
    await this.refreshLiveStatus();
  }
});

this.liveElements.refresh.addEventListener('click', this.refreshLiveInterfaces);
this.refreshLiveInterfaces();
window.setInterval(this.refreshLiveStatus, 3000);
  }
}

class ThreatIntelController {
  constructor(incidentController) {
    this.incidentController = incidentController;
    this.input = document.querySelector('#threatIntelInput');
    this.importButton = document.querySelector('#importThreatIntel');
    this.syncButton = document.querySelector('#syncThreatFox');
    this.syncDays = document.querySelector('#threatFoxDays');
    this.message = document.querySelector('#threatIntelMessage');
    this.initialize();
  }

  initialize() {
    if (this.importButton) this.importButton.addEventListener('click', () => this.importIndicators());
    if (this.syncButton) this.syncButton.addEventListener('click', () => this.syncThreatFox());
  }

  async syncThreatFox() {
    const days = Number(this.syncDays?.value || 3);
    if (!Number.isInteger(days) || days < 1 || days > 7) {
      this.message.textContent = 'Choose a recent window from 1 to 7 days.';
      return;
    }
    this.syncButton.disabled = true;
    this.message.textContent = 'Fetching ThreatFox community indicators…';
    try {
      const response = await fetch('/api/threat-intel/sync', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ days })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'ThreatFox sync failed');
      this.message.textContent = `ThreatFox: ${result.inserted} new, ${result.updated} updated, ${result.skipped} skipped.`;
      await this.incidentController.loadIncidents();
    } catch (error) {
      this.message.textContent = error.message;
    } finally {
      this.syncButton.disabled = false;
    }
  }

  async importIndicators() {
    this.importButton.disabled = true;
    try {
      const payload = JSON.parse(this.input.value);
      const response = await fetch('/api/threat-intel/import', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Threat-intelligence import failed');
      this.message.textContent = result.inserted + ' new · ' + result.updated + ' updated indicators.';
      await this.incidentController.loadIncidents();
    } catch (error) {
      this.message.textContent = error instanceof SyntaxError ? 'Enter valid JSON before importing.' : error.message;
    } finally {
      this.importButton.disabled = false;
    }
  }
}

class AnomalyDashboardController {
  constructor() {
    this.featuresInput = document.querySelector('#anomalyFeaturesInput');
    this.scoreButton = document.querySelector('#scoreAnomaly');
    this.message = document.querySelector('#anomalyMessage');
    this.result = document.querySelector('#anomalyResult');
    this.initialize();
  }

  initialize() {
    if (!this.scoreButton) return;
    this.scoreButton.addEventListener('click', () => this.score());
  }

  async score() {
    this.scoreButton.disabled = true;
    this.message.textContent = 'Scoring locally…';
    try {
      const payload = JSON.parse(this.featuresInput.value);
      const response = await fetch('/api/anomaly/score', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Anomaly scoring failed');
      this.result.textContent = JSON.stringify(result.result, null, 2);
      this.message.textContent = result.result.anomalous
        ? 'Unusual telemetry flagged for analyst review.'
        : 'No anomaly flagged by this model.';
    } catch (error) {
      this.message.textContent = error instanceof SyntaxError ? 'Enter valid JSON before scoring.' : error.message;
      this.result.textContent = 'No score available.';
    } finally {
      this.scoreButton.disabled = false;
    }
  }
}

const networkSimulator = new NetworkSimulatorController();
const incidentDashboard = new IncidentDashboardController();
const liveMonitor = new LiveMonitorController(incidentDashboard);
const threatIntel = new ThreatIntelController(incidentDashboard);
const anomalyDashboard = new AnomalyDashboardController();
