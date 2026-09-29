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
  events: []
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

function seedDemoSequence() {
  const sequence = [
    { source: 'PC-01', destination: 'Server', protocol: 'TCP', port: 80, size: 512 },
    { source: 'PC-03', destination: 'Server', protocol: 'UDP', port: 53, size: 384 },
    { source: 'PC-05', destination: 'Server', protocol: 'TCP', port: 23, size: 512 },
    { source: 'PC-02', destination: 'PC-04', protocol: 'ICMP', port: 8, size: 256 },
    { source: 'PC-04', destination: 'PC-01', protocol: 'TCP', port: 443, size: 768 }
  ];

  sequence.forEach((packet, index) => {
    setTimeout(() => routePacket(packet, true), index * 650);
  });

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
  event.currentTarget.innerHTML = state.paused ? '<span>▶</span>Resume stream' : '<span>Ⅱ</span>Pause stream';
  addEvent(`<strong>Simulation ${state.paused ? 'paused' : 'resumed'}</strong> · manual controls remain available`);
});

document.querySelector('#demoButton').addEventListener('click', () => {
  if (state.paused) return;
  seedDemoSequence();
});

document.querySelector('#resetButton').addEventListener('click', () => {
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
