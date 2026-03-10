<script>
  import { openInspector, activeResult, activeSessionId } from '../stores/session.js';

  export let senders = [];
  export let receivers = [];

  function fmt(bytes) {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
  }

  function maxBytes(list) {
    return Math.max(...list.map(t => t.total_bytes), 1);
  }

  function deviceName(t) {
    if (t.vendor) return t.vendor;
    if (t.mac) return t.mac.substring(0, 8) + '…';
    return t.ip;
  }

  function viewHost(ip) {
    const packets = $activeResult?.packets || [];
    const indices = packets
      .filter(p => p.src_ip === ip || p.dst_ip === ip)
      .map(p => p.index);
    openInspector(indices, $activeSessionId);
  }
</script>

<div class="card">
  <div class="card-header">Top Talkers <span class="hint">· click row to inspect</span></div>
  <div class="tables">
    <div class="table-wrap">
      <div class="table-label">Top Senders</div>
      <table>
        <thead>
          <tr>
            <th>Device</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each senders.slice(0, 10) as t}
            <tr class="clickable" on:click={() => viewHost(t.ip)} title="Inspect {t.ip}">
              <td class="device-cell">
                <span class="device-name">{deviceName(t)}</span>
                <span class="device-ip">{t.ip}</span>
              </td>
              <td>{t.packets_sent.toLocaleString()}</td>
              <td>{fmt(t.bytes_sent)}</td>
              <td class="bar-cell">
                <div class="bar" style="width: {Math.round(t.bytes_sent / maxBytes(senders) * 100)}%"></div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <div class="table-wrap">
      <div class="table-label">Top Receivers</div>
      <table>
        <thead>
          <tr>
            <th>Device</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each receivers.slice(0, 10) as t}
            <tr class="clickable" on:click={() => viewHost(t.ip)} title="Inspect {t.ip}">
              <td class="device-cell">
                <span class="device-name">{deviceName(t)}</span>
                <span class="device-ip">{t.ip}</span>
              </td>
              <td>{t.packets_received.toLocaleString()}</td>
              <td>{fmt(t.bytes_received)}</td>
              <td class="bar-cell">
                <div class="bar" style="width: {Math.round(t.bytes_received / maxBytes(receivers) * 100)}%"></div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
</div>

<style>
  .card {
    background: #111111;
    border: 1px solid rgba(200, 216, 240, 0.18);
    
    border-radius: 2px;
    padding: 1.25rem;
    overflow: hidden;
  }
  .card-header {
    font-size: 0.75rem;
    font-weight: 600;
    color: #c8d8f0;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
    
  }
  .hint {
    color: #606060;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 400;
    font-size: 0.68rem;
  }
  .tables {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
  }
  .table-label {
    font-size: 0.72rem;
    font-weight: 600;
    color: #f0f0f0;
    margin-bottom: 0.5rem;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.76rem;
  }
  th {
    color: #606060;
    font-weight: 500;
    text-align: left;
    padding: 0.3rem 0.4rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
  }
  td {
    padding: 0.32rem 0.4rem;
    color: #f0f0f0;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    white-space: nowrap;
  }
  tr.clickable {
    cursor: pointer;
    transition: background 0.1s;
  }
  tr.clickable:hover td {
    background: rgba(255,255,255,0.04);
  }
  tr.clickable:hover .device-name {
    
  }
  .device-cell {
    display: flex;
    flex-direction: column;
    gap: 0.05rem;
  }
  .device-name {
    color: #c8d8f0;
    font-size: 0.76rem;
    transition: text-shadow 0.15s;
  }
  .device-ip {
    font-family: monospace;
    font-size: 0.68rem;
    color: #606060;
  }
  .bar-cell { width: 60px; }
  .bar {
    height: 3px;
    background: linear-gradient(90deg, #c8d8f088, #c8d8f022);
    border-radius: 2px;
    min-width: 2px;
  }
  @media (max-width: 600px) {
    .tables { grid-template-columns: 1fr; }
  }
</style>
