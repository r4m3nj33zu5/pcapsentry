<script>
  import { openInspector, activeSessionId } from '../stores/session.js';

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
</script>

<div class="card">
  <div class="card-header">Top Talkers</div>
  <div class="tables">
    <div class="table-wrap">
      <div class="table-label">Top Senders</div>
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each senders.slice(0, 10) as t}
            <tr>
              <td class="ip">{t.ip}</td>
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
            <th>IP</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each receivers.slice(0, 10) as t}
            <tr>
              <td class="ip">{t.ip}</td>
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
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1.25rem;
    overflow: hidden;
  }
  .card-header {
    font-size: 0.8rem;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 1rem;
  }
  .tables {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
  }
  .table-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 0.5rem;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.78rem;
  }
  th {
    color: #8b949e;
    font-weight: 500;
    text-align: left;
    padding: 0.3rem 0.4rem;
    border-bottom: 1px solid #21262d;
  }
  td {
    padding: 0.35rem 0.4rem;
    color: #c9d1d9;
    border-bottom: 1px solid #21262d11;
    white-space: nowrap;
  }
  .ip {
    font-family: monospace;
    font-size: 0.75rem;
    color: #58a6ff;
  }
  .bar-cell {
    width: 60px;
  }
  .bar {
    height: 4px;
    background: #58a6ff44;
    border-radius: 2px;
    min-width: 2px;
  }
  @media (max-width: 600px) {
    .tables { grid-template-columns: 1fr; }
  }
</style>
