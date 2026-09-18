const state = { devices: [], status: {}, filter: 'all', query: '', activeDevice: null };

const $ = (selector) => document.querySelector(selector);
const rows = $('#deviceRows');
const notice = $('#notice');

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
}

function timeAgo(value) {
  if (!value) return null;
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)} days ago`;
  return new Date(value).toLocaleDateString();
}

function seenText(device) {
  if (!device.last_seen) return 'Not observed online yet';
  const seen = new Date(device.last_seen);
  if (Number.isNaN(seen.getTime())) return 'Last seen time unavailable';
  if (device.online) return `Seen ${timeAgo(device.last_seen)}`;
  return `Last seen ${seen.toLocaleString()}`;
}

function showNotice(message, error = false) {
  notice.textContent = message;
  notice.classList.toggle('error', error);
  notice.classList.remove('hidden');
  window.clearTimeout(showNotice.timer);
  showNotice.timer = window.setTimeout(() => notice.classList.add('hidden'), 6500);
}

async function api(path, options = {}) {
  const response = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...options});
  const data = await response.json().catch(() => ({message: 'The server returned an unreadable response.'}));
  if (!response.ok) throw new Error(data.message || `Request failed (${response.status})`);
  return data;
}

async function loadDevices() {
  try {
    const data = await api('/api/devices');
    state.devices = data.devices;
    state.status = data.status;
    render();
  } catch (error) { showNotice(error.message, true); }
}

function filteredDevices() {
  const query = state.query.trim().toLowerCase();
  return state.devices.filter(device => {
    if (state.filter === 'online' && !device.online) return false;
    if (state.filter === 'offline' && device.online) return false;
    if (state.filter === 'reserved' && !device.reserved_ip) return false;
    if (state.filter === 'unknown' && (device.friendly_name || device.device_identity || device.ha_name || device.eero_reservation_name || device.eero_name || device.eero_hostname || device.hostname)) return false;
    if (!query) return true;
    return JSON.stringify(device).toLowerCase().includes(query);
  });
}

function render() {
  const devices = filteredDevices();
  $('#knownCount').textContent = state.devices.length;
  $('#onlineCount').textContent = state.devices.filter(d => d.online).length;
  $('#reservationCount').textContent = state.devices.filter(d => d.reserved_ip).length;
  const latest = state.status.last_ha_sync || state.status.last_eero_sync || state.status.last_lan_scan;
  $('#lastUpdated').textContent = latest ? timeAgo(latest) : 'Not scanned yet';
  $('#eeroButton').textContent = state.status.eero_connected ? 'eero connected' : 'Connect eero';
  $('#eeroButton').classList.toggle('connected', !!state.status.eero_connected);
  $('#haButton').textContent = state.status.ha_connected ? 'Home Assistant connected' : 'Connect Home Assistant';
  $('#haButton').classList.toggle('connected', !!state.status.ha_connected);
  $('#piholeButton').textContent = state.status.pihole_connected ? 'Pi-hole connected' : 'Connect Pi-hole';
  $('#piholeButton').classList.toggle('connected', !!state.status.pihole_connected);

  rows.innerHTML = devices.map(device => {
    const subtitle = [device.device_type, device.device_identity && device.device_identity !== device.display_name ? device.device_identity : null, device.ha_name && device.ha_name !== device.display_name ? `HA: ${device.ha_name}` : null, device.eero_reservation_name && device.eero_reservation_name !== device.display_name ? `eero reservation: ${device.eero_reservation_name}` : null, device.eero_name && device.eero_name !== device.display_name ? `eero: ${device.eero_name}` : null, device.eero_hostname && device.eero_hostname !== device.eero_name ? device.eero_hostname : null].filter(Boolean).join(' · ') || ((device.ha_name || device.eero_reservation_name || device.eero_name || device.eero_hostname || device.hostname) ? 'Identified by network data' : 'Needs identification');
    const vendor = device.manufacturer || device.online_lookup || 'Unknown manufacturer';
    const location = [device.location || device.ha_area, device.eero_node ? `via ${device.eero_node}` : null].filter(Boolean).join(' · ') || '—';
    return `<tr>
      <td><div class="device-cell"><div class="device-icon"><svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="13" rx="2"/><path d="M8 21h8M12 18v3"/></svg></div><div><div class="device-name">${escapeHtml(device.display_name)}</div><div class="subtext">${escapeHtml(subtitle)}</div></div></div></td>
      <td><div class="ip-wrap"><span class="mono">${escapeHtml(device.ip || 'No current IP')}</span>${device.reserved_ip ? `<span class="reservation-tag">Reserved ${escapeHtml(device.reserved_ip)}</span>` : ''}</div></td>
      <td><div class="mono">${escapeHtml(device.mac)}${device.is_private_mac ? '<span class="private-tag" title="Private or randomized MAC">private</span>' : ''}</div><div class="subtext">${escapeHtml(vendor)}</div></td>
      <td><div class="location-text">${escapeHtml(location)}</div>${device.connection_type ? `<div class="subtext">${escapeHtml([device.connection_type, device.frequency].filter(Boolean).join(' · '))}</div>` : ''}</td>
      <td><div class="status ${device.online ? 'online' : ''}">${device.online ? 'Online' : 'Offline'}</div><div class="status-meta">${escapeHtml(seenText(device))}</div>${device.ports_scanned_at ? `<div class="status-meta port-count">${device.open_ports.length} open port${device.open_ports.length === 1 ? '' : 's'}</div>` : ''}</td>
      <td><button class="row-action" data-edit="${device.id}" aria-label="Edit ${escapeHtml(device.display_name)}">•••</button></td>
    </tr>`;
  }).join('');
  $('#emptyState').classList.toggle('hidden', devices.length !== 0);
}

function openDevice(device) {
  state.activeDevice = device;
  $('#deviceId').value = device.id;
  $('#deviceDialogTitle').textContent = device.display_name;
  $('#friendlyName').value = device.friendly_name || '';
  $('#deviceType').value = device.device_type || '';
  $('#location').value = device.location || '';
  $('#notes').value = device.notes || '';
  $('#reservationIp').value = device.reserved_ip || device.ip || '';
  $('#reserveButton').textContent = device.reserved_ip ? 'Update reservation' : 'Add reservation';
  $('#reserveButton').disabled = !state.status.eero_connected;
  $('#reservationHelp').textContent = state.status.eero_connected
    ? (device.reserved_ip ? `Currently reserved as ${device.reserved_ip}.` : 'This will add a DHCP reservation in eero.')
    : 'Connect eero to manage reservations.';
  $('#lookupButton').disabled = device.is_private_mac;
  $('#lookupButton').textContent = device.is_private_mac ? 'Private MAC — lookup unavailable' : 'Look up MAC online';
  $('#scanPortsButton').disabled = !device.ip;
  $('#deepScanButton').disabled = !device.ip;
  $('#dnsAnalyzeButton').disabled = !state.status.pihole_connected || !(device.ip || device.reserved_ip);
  renderIdentity(device);
  renderDnsAnalysis(device);
  renderHaMatch(device);
  renderPorts(device);
  const facts = [
    ['Current IP', device.ip || '—'], ['MAC address', device.mac],
    ['eero reservation name', device.eero_reservation_name || '—'], ['eero friendly name', device.eero_name || '—'],
    ['eero hostname', device.eero_hostname || '—'], ['Manufacturer', device.manufacturer || device.online_lookup || '—'],
    ['First seen', new Date(device.first_seen).toLocaleString()], ['Last seen', device.last_seen ? new Date(device.last_seen).toLocaleString() : 'Not observed online yet']
  ];
  $('#deviceFacts').innerHTML = facts.map(([label,value]) => `<div class="fact"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
  if (!$('#deviceDialog').open) $('#deviceDialog').showModal();
}

function renderDnsAnalysis(device) {
  const result = $('#dnsResult');
  if (!state.status.pihole_connected && !device.dns_scanned_at) {
    result.classList.add('hidden');
    $('#dnsHelp').textContent = 'Connect Pi-hole to identify this device from its DNS destinations and request patterns.';
    return;
  }
  if (!device.dns_scanned_at) {
    result.classList.add('hidden');
    $('#dnsHelp').textContent = state.status.pihole_connected
      ? 'No saved DNS report yet. Choose a history period and analyze this device.'
      : 'Pi-hole is disconnected; no saved DNS report is available.';
    return;
  }
  result.classList.remove('hidden');
  $('#dnsHelp').textContent = `Analyzed ${timeAgo(device.dns_scanned_at)} · ${Number(device.dns_query_count || 0).toLocaleString()} requests · ${device.dns_lookback_hours || 24}-hour lookback.`;
  $('#dnsLookback').value = String(device.dns_lookback_hours || 24);
  $('#dnsIdentity').textContent = device.dns_identity || 'DNS analysis';
  $('#dnsConfidence').textContent = `${device.dns_confidence || 'low'} confidence`;
  $('#dnsConfidence').className = `confidence-tag ${device.dns_confidence || 'low'}`;
  $('#dnsSummary').textContent = device.dns_summary || '';
  $('#dnsEvidence').innerHTML = (device.dns_evidence || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  $('#dnsSources').innerHTML = (device.dns_source_summary || []).map(source => {
    const detail = source.error ? `error: ${source.error}` : `${Number(source.count || 0).toLocaleString()} unique requests${source.truncated ? ' (limited)' : ''}`;
    return `<span class="${source.error ? 'source-error' : ''}">${escapeHtml(source.name)}: ${escapeHtml(detail)}</span>`;
  }).join('');
  $('#dnsDomains').innerHTML = (device.dns_domains || []).map(item => `<div class="dns-domain-row"><span>${escapeHtml(item.domain)}</span><strong>${Number(item.count || 0).toLocaleString()}</strong><small>${escapeHtml((item.sources || []).join(', '))}${item.blocked ? ` · ${Number(item.blocked).toLocaleString()} blocked` : ''}</small></div>`).join('');
}

function renderHaMatch(device) {
  const result = $('#haMatchResult');
  const directEntities = device.esphome_entities || [];
  const hasDirectDetails = directEntities.length || Object.keys(device.esphome_device_info || {}).length;
  if (!state.status.ha_connected && !hasDirectDetails) {
    result.classList.add('hidden');
    $('#haMatchHelp').textContent = 'Connect Home Assistant to match this MAC address with its device and entities.';
    return;
  }
  if (!device.ha_device_id && !hasDirectDetails) {
    result.classList.add('hidden');
    $('#haMatchHelp').textContent = 'No Home Assistant device currently matches this MAC address.';
    return;
  }
  const directInfo = device.esphome_device_info || {};
  const details = [device.ha_model || directInfo.model, device.ha_manufacturer || directInfo.manufacturer, (device.ha_sw_version || directInfo.esphome_version) ? `firmware ${device.ha_sw_version || directInfo.esphome_version}` : null, device.ha_area ? `area: ${device.ha_area}` : null].filter(Boolean).join(' · ');
  const entitySource = device.ha_device_id ? (device.ha_entities || []) : directEntities;
  const entities = entitySource.map(entity => {
    const value = [entity.state, entity.unit].filter(Boolean).join(' ');
    const identifier = entity.entity_id || entity.object_id || entity.type || '';
    return `<div class="ha-entity"><span>${escapeHtml(entity.name || identifier)}</span><small>${escapeHtml(identifier)}</small><strong>${escapeHtml(value || entity.device_class || '—')}</strong></div>`;
  }).join('');
  $('#haMatchHelp').textContent = device.ha_device_id ? `Matched ${timeAgo(device.ha_synced_at)}.` : (device.esphome_api_status || 'Read directly from ESPHome.');
  const title = device.ha_name || directInfo.friendly_name || directInfo.name || 'ESPHome device';
  result.innerHTML = `<div class="ha-device-title"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(details || (device.ha_device_id ? 'Matched by MAC address' : 'Read from ESPHome API'))}</span></div><div class="ha-entities">${entities || '<p>No enabled entities were returned.</p>'}</div>`;
  result.classList.remove('hidden');
}

function renderIdentity(device) {
  const result = $('#identityResult');
  if (!device.device_identity) {
    result.classList.add('hidden');
    $('#identityHelp').textContent = 'Combine MAC manufacturer, host information, ports, service fingerprints, and operating-system hints.';
    return;
  }
  result.classList.remove('hidden');
  $('#identityName').textContent = device.device_identity;
  $('#identityConfidence').textContent = `${device.identity_confidence || 'low'} confidence`;
  $('#identityConfidence').className = `confidence-tag ${device.identity_confidence || 'low'}`;
  $('#identitySummary').textContent = device.identity_summary || '';
  $('#identityHelp').textContent = `Deep scanned ${timeAgo(device.deep_scanned_at)}.`;
  $('#osHint').textContent = device.os_hint ? `OS hint: ${device.os_hint}` : '';
  $('#osHint').classList.toggle('hidden', !device.os_hint);
  $('#identityEvidence').innerHTML = (device.identity_evidence || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
}

function renderPorts(device) {
  const ports = device.open_ports || [];
  if (device.ports_scanned_at) {
    $('#portsHelp').textContent = `${ports.length} open TCP port${ports.length === 1 ? '' : 's'} found · scanned ${timeAgo(device.ports_scanned_at)}.`;
  } else {
    $('#portsHelp').textContent = 'Not scanned yet. Checks 5,000 common ports plus home-network services.';
  }
  $('#portsList').innerHTML = ports.map(port => {
    const product = [port.product, port.version, port.extra].filter(Boolean).join(' ') || 'No additional service details';
    const scripts = (port.scripts || []).map(item => `${item.name}: ${item.output}`).join(' · ');
    return `<div class="port-row"><span class="port-number">${escapeHtml(port.port)}/${escapeHtml(port.protocol)}</span><span class="port-service">${escapeHtml(port.service || 'unknown')}</span><span class="port-product">${escapeHtml(product)}${scripts ? `<small>${escapeHtml(scripts)}</small>` : ''}</span></div>`;
  }).join('');
}

rows.addEventListener('click', event => {
  const button = event.target.closest('[data-edit]');
  if (!button) return;
  const device = state.devices.find(item => item.id === Number(button.dataset.edit));
  if (device) openDevice(device);
});

$('#searchInput').addEventListener('input', event => { state.query = event.target.value; render(); });
document.addEventListener('keydown', event => {
  if (event.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) {
    event.preventDefault(); $('#searchInput').focus();
  }
});
document.querySelectorAll('.filter').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.filter').forEach(item => item.classList.remove('active'));
  button.classList.add('active'); state.filter = button.dataset.filter; render();
}));

$('#scanButton').addEventListener('click', async () => {
  const button = $('#scanButton'); button.disabled = true; button.textContent = 'Scanning…';
  try { const data = await api('/api/scan', {method:'POST'}); showNotice(data.message); await loadDevices(); }
  catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6"/></svg>Scan network'; }
});

$('#deviceForm').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await api(`/api/devices/${$('#deviceId').value}`, {method:'PUT', body:JSON.stringify({friendly_name:$('#friendlyName').value, device_type:$('#deviceType').value, location:$('#location').value, notes:$('#notes').value})});
    $('#deviceDialog').close(); showNotice('Device details saved.'); await loadDevices();
  } catch (error) { showNotice(error.message, true); }
});

$('#lookupButton').addEventListener('click', async () => {
  const button = $('#lookupButton'); button.disabled = true; button.textContent = 'Looking up…';
  try { const data = await api(`/api/devices/${state.activeDevice.id}/mac-lookup`, {method:'POST'}); showNotice(`Manufacturer found: ${data.vendor}`); await loadDevices(); const updated = state.devices.find(d => d.id === state.activeDevice.id); openDevice(updated); }
  catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Look up MAC online'; }
});

$('#scanPortsButton').addEventListener('click', async () => {
  const button = $('#scanPortsButton');
  button.disabled = true;
  button.textContent = 'Scanning…';
  $('#portsHelp').textContent = 'Scanning a broad list of common TCP ports. This can take a minute or two.';
  try {
    const data = await api(`/api/devices/${state.activeDevice.id}/ports/scan`, {method:'POST'});
    showNotice(`${data.message} Checked ${data.ports_checked.toLocaleString()} ports.`);
    await loadDevices();
    const updated = state.devices.find(device => device.id === state.activeDevice.id);
    if (updated) openDevice(updated);
  } catch (error) {
    showNotice(error.message, true);
    $('#portsHelp').textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = 'Scan ports';
  }
});

$('#deepScanButton').addEventListener('click', async () => {
  const button = $('#deepScanButton');
  button.disabled = true;
  button.textContent = 'Deep scanning…';
  $('#identityHelp').textContent = 'Checking MAC ownership, services, mDNS, Home Assistant, and operating-system clues. This may take two or three minutes.';
  try {
    const data = await api(`/api/devices/${state.activeDevice.id}/deep-scan`, {method:'POST'});
    showNotice(`${data.message} Identification report updated.`);
    await loadDevices();
    const updated = state.devices.find(device => device.id === state.activeDevice.id);
    if (updated) openDevice(updated);
  } catch (error) {
    showNotice(error.message, true);
    $('#identityHelp').textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = 'Deep scan';
  }
});

$('#dnsAnalyzeButton').addEventListener('click', async () => {
  const button = $('#dnsAnalyzeButton');
  button.disabled = true;
  button.textContent = 'Analyzing…';
  $('#dnsHelp').textContent = 'Reading and comparing DNS history from both Pi-hole servers. Longer periods may take a minute.';
  try {
    const data = await api(`/api/devices/${state.activeDevice.id}/dns-analysis`, {method:'POST', body:JSON.stringify({hours:Number($('#dnsLookback').value)})});
    showNotice(data.message);
    await loadDevices();
    const updated = state.devices.find(device => device.id === state.activeDevice.id);
    if (updated) openDevice(updated);
  } catch (error) {
    showNotice(error.message, true);
    $('#dnsHelp').textContent = error.message;
  } finally {
    button.disabled = !state.status.pihole_connected;
    button.textContent = 'Analyze DNS';
  }
});

$('#reserveButton').addEventListener('click', async () => {
  const ip = $('#reservationIp').value.trim();
  const name = state.activeDevice.display_name;
  if (!window.confirm(`Reserve ${ip} for ${name} in eero?\n\nThe device may need to reconnect before it receives this address.`)) return;
  const button = $('#reserveButton'); button.disabled = true; button.textContent = 'Saving…';
  try { const data = await api(`/api/devices/${state.activeDevice.id}/reserve`, {method:'POST', body:JSON.stringify({ip})}); $('#deviceDialog').close(); showNotice(data.message); await loadDevices(); }
  catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Add reservation'; }
});

function renderHaDialog() {
  const connected = !!state.status.ha_connected;
  $('#haDisconnected').classList.toggle('hidden', connected);
  $('#haConnected').classList.toggle('hidden', !connected);
  $('#haUrl').value = state.status.ha_url || 'http://homeassistant.local:8123';
  $('#haConnectionStatus').textContent = state.status.last_ha_sync
    ? `Last synchronized ${timeAgo(state.status.last_ha_sync)}.`
    : 'Device and entity information can now be matched by MAC address.';
}

$('#haButton').addEventListener('click', () => { renderHaDialog(); $('#haDialog').showModal(); });
$('#haConnectButton').addEventListener('click', async () => {
  const button = $('#haConnectButton'); button.disabled = true; button.textContent = 'Connecting…';
  try {
    const data = await api('/api/home-assistant/connect', {method:'POST', body:JSON.stringify({url:$('#haUrl').value, token:$('#haToken').value})});
    $('#haToken').value = '';
    showNotice(data.message);
    await loadDevices();
    renderHaDialog();
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Connect and match devices'; }
});
$('#haSyncButton').addEventListener('click', async () => {
  const button = $('#haSyncButton'); button.disabled = true; button.textContent = 'Synchronizing…';
  try { const data = await api('/api/home-assistant/sync', {method:'POST'}); showNotice(data.message); await loadDevices(); renderHaDialog(); }
  catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Sync Home Assistant now'; }
});
$('#haDisconnectButton').addEventListener('click', async () => {
  if (!window.confirm('Disconnect this site from Home Assistant? Previously imported device information will remain.')) return;
  try { const data = await api('/api/home-assistant/disconnect', {method:'POST'}); showNotice(data.message); await loadDevices(); renderHaDialog(); }
  catch (error) { showNotice(error.message, true); }
});

function renderPiholeDialog() {
  const connected = !!state.status.pihole_connected;
  $('#piholeDisconnected').classList.toggle('hidden', connected);
  $('#piholeConnected').classList.toggle('hidden', !connected);
  $('#piholeConnectionStatus').textContent = state.status.last_pihole_test
    ? `Last tested ${timeAgo(state.status.last_pihole_test)}. DNS query history is available for device analysis.`
    : 'DNS query history is available for device analysis.';
  $('#piholeSources').innerHTML = (state.status.pihole_sources || []).map(source => `<div><strong>${escapeHtml(source.name)}</strong><span>${escapeHtml(source.url)}</span></div>`).join('');
}

$('#piholeButton').addEventListener('click', () => { renderPiholeDialog(); $('#piholeDialog').showModal(); });
$('#piholeConnectButton').addEventListener('click', async () => {
  const button = $('#piholeConnectButton'); button.disabled = true; button.textContent = 'Testing…';
  const sources = [
    {name:'DNS1', url:$('#piholeUrl1').value, password:$('#piholePassword1').value},
    {name:'DNS2', url:$('#piholeUrl2').value, password:$('#piholePassword2').value},
  ];
  try {
    const data = await api('/api/pihole/connect', {method:'POST', body:JSON.stringify({sources})});
    $('#piholePassword1').value = ''; $('#piholePassword2').value = '';
    showNotice(data.message); await loadDevices(); renderPiholeDialog();
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Connect and test both'; }
});
$('#piholeTestButton').addEventListener('click', async () => {
  const button = $('#piholeTestButton'); button.disabled = true; button.textContent = 'Testing…';
  try { const data = await api('/api/pihole/test', {method:'POST'}); showNotice(data.message); await loadDevices(); renderPiholeDialog(); }
  catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Test connections'; }
});
$('#piholeDisconnectButton').addEventListener('click', async () => {
  if (!window.confirm('Disconnect both Pi-hole servers? Saved DNS analysis reports will remain.')) return;
  try { const data = await api('/api/pihole/disconnect', {method:'POST'}); showNotice(data.message); await loadDevices(); renderPiholeDialog(); }
  catch (error) { showNotice(error.message, true); }
});

function renderEeroDialog() {
  const connected = !!state.status.eero_connected;
  $('#eeroDisconnected').classList.toggle('hidden', connected);
  $('#eeroConnected').classList.toggle('hidden', !connected);
  $('#eeroNetworkName').textContent = state.status.eero_network_name ? `Connected to ${state.status.eero_network_name}. Device names and reservations can be synchronized.` : 'Your device names and reservations can now be synchronized.';
}
$('#eeroButton').addEventListener('click', () => { renderEeroDialog(); $('#eeroDialog').showModal(); });
$('#sendCodeButton').addEventListener('click', async () => {
  const button = $('#sendCodeButton'); button.disabled = true; button.textContent = 'Sending…';
  try { const data = await api('/api/eero/login', {method:'POST', body:JSON.stringify({identifier:$('#eeroIdentifier').value})}); $('#verifyArea').classList.remove('hidden'); $('#eeroCode').focus(); showNotice(data.message); }
  catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Send verification code'; }
});
$('#verifyButton').addEventListener('click', async () => {
  const button = $('#verifyButton'); button.disabled = true; button.textContent = 'Verifying…';
  try { const data = await api('/api/eero/verify', {method:'POST', body:JSON.stringify({code:$('#eeroCode').value})}); showNotice(data.message); await loadDevices(); renderEeroDialog(); }
  catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Verify and import devices'; }
});
$('#syncButton').addEventListener('click', async () => {
  const button = $('#syncButton'); button.disabled = true; button.textContent = 'Synchronizing…';
  try { const data = await api('/api/eero/sync', {method:'POST'}); showNotice(data.message); await loadDevices(); }
  catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Sync eero now'; }
});
$('#disconnectButton').addEventListener('click', async () => {
  if (!window.confirm('Disconnect this site from eero? Existing imported device information will remain.')) return;
  try { const data = await api('/api/eero/logout', {method:'POST'}); showNotice(data.message); await loadDevices(); renderEeroDialog(); }
  catch (error) { showNotice(error.message, true); }
});

$('#addButton').addEventListener('click', () => $('#manualDialog').showModal());
$('#manualForm').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await api('/api/devices/manual', {method:'POST', body:JSON.stringify({mac:$('#manualMac').value, ip:$('#manualIp').value, friendly_name:$('#manualName').value})});
    $('#manualDialog').close(); $('#manualForm').reset(); showNotice('Device added.'); await loadDevices();
  } catch (error) { showNotice(error.message, true); }
});

loadDevices();
window.setInterval(loadDevices, 60000);
