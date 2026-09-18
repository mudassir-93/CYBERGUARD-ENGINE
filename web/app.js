const state = {
  packetId: 0,
  paused: false,
  stats: { created: 0, delivered: 0, blocked: 0, dropped: 0 },
  rules: [{ action: 'BLOCK', protocol: 'TCP', port: 23, enabled: true }],
  events: []
};

const devices = {
  'PC-01': { ip: '10.0.0.20' },
  'PC-02': { ip: '10.0.0.21' },
  Server: { ip: '10.0.0.10' }
};

const elements = {
  created: document.querySelector('#createdMetric'),
  delivered: document.querySelector('#deliveredMetric'),
  blocked: document.querySelector('#blockedMetric'),
  deliveryMeta: document.querySelector('#deliveryMeta'),
  blockedMeta: document.querySelector('#blockedMeta'),
  ruleList: document.querySelector('#ruleList'),
  ruleCount: document.querySelector('#ruleCount'),
  eventList: document.querySelector('#eventList'),
  packetOrb: document.querySelector('#packetOrb')
};

function now() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function addEvent(message, type = '') {
  state.events.unshift({ time: now(), message, type });
  state.events = state.events.slice(0, 12);
  elements.eventList.innerHTML = state.events.map(event =>
    `<div class="event-row ${event.type}"><span class="event-time">${event.time}</span><span class="event-message">${event.message}</span></div>`
  ).join('');
}

function renderStats() {
  elements.created.textContent = state.stats.created;
  elements.delivered.textContent = state.stats.delivered;
  elements.blocked.textContent = state.stats.blocked;
  elements.deliveryMeta.textContent = state.stats.delivered ? `${Math.round((state.stats.delivered / state.stats.created) * 100)}% delivery rate` : 'Awaiting traffic';
  elements.blockedMeta.textContent = state.stats.blocked ? `${state.stats.blocked} policy decision${state.stats.blocked === 1 ? '' : 's'}` : 'Firewall clear';
}

function renderRules() {
  elements.ruleCount.textContent = `${state.rules.filter(rule => rule.enabled).length} active`;
  elements.ruleList.innerHTML = state.rules.map((rule, index) => `
    <div class="rule-row">
      <span class="rule-action ${rule.action.toLowerCase()}">${rule.action}</span>
      <span class="rule-condition">${rule.protocol} destination port ${rule.port}</span>
      <button class="rule-toggle" data-rule="${index}" title="Toggle rule">${rule.enabled ? 'ON' : 'OFF'}</button>
    </div>`).join('');
  document.querySelectorAll('.rule-toggle').forEach(button => button.addEventListener('click', () => {
    state.rules[Number(button.dataset.rule)].enabled = !state.rules[Number(button.dataset.rule)].enabled;
    renderRules();
    addEvent(`<strong>Firewall rule updated</strong> · rule ${button.dataset.rule} is now ${state.rules[Number(button.dataset.rule)].enabled ? 'active' : 'disabled'}`);
  }));
}

function animatePacket(result) {
  elements.packetOrb.classList.remove('animate');
  void elements.packetOrb.offsetWidth;
  elements.packetOrb.style.background = result === 'BLOCKED' ? 'var(--red)' : 'var(--cyan)';
  elements.packetOrb.style.boxShadow = result === 'BLOCKED' ? '0 0 0 5px rgba(255,124,133,.14), 0 0 20px var(--red)' : '0 0 0 5px rgba(94,231,210,.13), 0 0 20px var(--cyan)';
  elements.packetOrb.classList.add('animate');
}

function routePacket({ source, destination, protocol, port, size }, quiet = false) {
  const packetId = ++state.packetId;
  state.stats.created += 1;
  const matchingRule = state.rules.find(rule => rule.enabled && rule.protocol === protocol && Number(rule.port) === Number(port));
  const result = matchingRule?.action === 'BLOCK' ? 'BLOCKED' : 'DELIVERED';
  state.stats[result.toLowerCase()] += 1;
  renderStats();
  animatePacket(result);
  if (result === 'BLOCKED') {
    addEvent(`<strong>Packet #${packetId} blocked</strong> · ${source} → ${destination} · ${protocol}:${port}`, 'blocked');
  } else {
    addEvent(`<strong>Packet #${packetId} delivered</strong> · ${source} → ${destination} · ${protocol}:${port}`, 'delivered');
  }
  if (!quiet) document.querySelector('#events').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  return result;
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
  const rule = { action: document.querySelector('#ruleAction').value, protocol: document.querySelector('#ruleProtocol').value, port: Number(document.querySelector('#rulePort').value), enabled: true };
  if (!rule.port || rule.port > 65535) return;
  state.rules.push(rule);
  renderRules();
  addEvent(`<strong>Firewall rule added</strong> · ${rule.action} ${rule.protocol}:${rule.port}`);
});

document.querySelector('#pauseButton').addEventListener('click', event => {
  state.paused = !state.paused;
  event.currentTarget.innerHTML = state.paused ? '<span>▶</span> Resume stream' : '<span>Ⅱ</span> Pause stream';
  addEvent(`<strong>Simulation ${state.paused ? 'paused' : 'resumed'}</strong> · manual controls remain available`);
});

document.querySelector('#demoButton').addEventListener('click', () => {
  if (state.paused) return;
  const sequence = [
    { source: 'PC-01', destination: 'Server', protocol: 'TCP', port: 80, size: 512 },
    { source: 'PC-02', destination: 'Server', protocol: 'TCP', port: 443, size: 512 },
    { source: 'PC-01', destination: 'Server', protocol: 'TCP', port: 23, size: 512 }
  ];
  sequence.forEach((packet, index) => setTimeout(() => routePacket(packet, true), index * 650));
  addEvent('<strong>Demo sequence started</strong> · three deterministic packets queued');
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

renderStats();
renderRules();
addEvent('<strong>Engine initialized</strong> · five devices online');
addEvent('<strong>Firewall ready</strong> · TCP destination port 23 blocked');