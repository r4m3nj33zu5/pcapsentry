<script>
  import { openInspector, activeResult, activeSessionId } from '../stores/session.js';

  export let flows = [];

  const SUSPICIOUS_PORTS = new Set([4444, 31337, 23, 12345, 6666, 6667, 1337]);
  const NOTABLE_PORTS = new Set([8080, 25, 21, 587, 143, 110, 3306, 5432, 3389, 22]);

  let sortKey = 'bytes';
  let sortAsc = false;
  let filter = '';
  let showCount = 50;

  $: filtered = flows.filter(f => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    // Null-guard each field — L2-only flows may lack src/dst IP or protocol.
    return (f.src_ip || '').includes(q) ||
           (f.dst_ip || '').includes(q) ||
           (f.protocol || '').toLowerCase().includes(q) ||
           String(f.dst_port || '').includes(q);
  });

  $: sorted = [...filtered].sort((a, b) => {
    const va = a[sortKey] ?? 0;
    const vb = b[sortKey] ?? 0;
    return sortAsc ? (va > vb ? 1 : -1) : (va < vb ? 1 : -1);
  });

  $: visible = sorted.slice(0, showCount);

  function setSort(key) {
    if (sortKey === key) sortAsc = !sortAsc;
    else { sortKey = key; sortAsc = false; }
  }

  function portClass(port) {
    if (!port) return '';
    if (SUSPICIOUS_PORTS.has(port)) return 'magenta';
    if (NOTABLE_PORTS.has(port)) return 'amber';
    return 'cyan';
  }

  function fmt(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
    if (b >= 1048576)    return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024)       return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  function fmtDuration(f) {
    const d = f.last_seen - f.first_seen;
    if (d < 1) return d.toFixed(2) + 's';
    if (d < 60) return d.toFixed(1) + 's';
    return (d / 60).toFixed(1) + 'm';
  }

  function viewFlow(f) {
    const packets = $activeResult?.packets || [];
    const indices = packets
      .filter(p =>
        (p.src_ip === f.src_ip && p.dst_ip === f.dst_ip && p.dst_port === f.dst_port && p.protocol === f.protocol) ||
        (p.src_ip === f.dst_ip && p.dst_ip === f.src_ip && p.src_port === f.dst_port && p.protocol === f.protocol)
      )
      .map(p => p.index);
    openInspector(indices, $activeSessionId);
  }

  function sortIcon(key) {
    if (sortKey !== key) return '⇅';
    return sortAsc ? '↑' : '↓';
  }
</script>

<div class="card">
  <div class="card-header">
    <span>Connection Flows</span>
    <span class="count-badge">{flows.length} flows</span>
    <input class="filter-input" bind:value={filter} placeholder="Filter by IP, protocol, port…" />
  </div>

  <div class="table-scroll">
    <table>
      <thead>
        <tr>
          <th class="sortable" on:click={() => setSort('protocol')}>Protocol {sortIcon('protocol')}</th>
          <th>Source IP</th>
          <th>Dst IP</th>
          <th class="port-col">Dst Port</th>
          <th class="sortable" on:click={() => setSort('packets')}>Pkts {sortIcon('packets')}</th>
          <th class="sortable" on:click={() => setSort('bytes')}>Bytes {sortIcon('bytes')}</th>
          <th>Duration</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each visible as f}
          <tr class:suspicious={SUSPICIOUS_PORTS.has(f.dst_port)}>
            <td><span class="proto-tag proto-{f.protocol.toLowerCase()}">{f.protocol}</span></td>
            <td class="mono">{f.src_ip}</td>
            <td class="mono">{f.dst_ip}</td>
            <td class="mono port-{portClass(f.dst_port)}">{f.dst_port ?? '—'}</td>
            <td class="num">{f.packets.toLocaleString()}</td>
            <td class="num bytes-col">{fmt(f.bytes)}</td>
            <td class="num muted">{fmtDuration(f)}</td>
            <td>
              <button class="inspect-btn" on:click={() => viewFlow(f)} title="Inspect packets">⬡</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  {#if sorted.length > showCount}
    <button class="load-more" on:click={() => showCount += 50}>
      Show more ({sorted.length - showCount} remaining)
    </button>
  {/if}
</div>

<style>
  .card {
    background: #111111;
    border: 1px solid rgba(255,255,255,0.08);
    
    border-radius: 2px;
    padding: 1.25rem;
  }
  .card-header {
    font-size: 0.75rem;
    font-weight: 600;
    color: #c8d8f0;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
    
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
  }
  .count-badge {
    background: rgba(255,255,255,0.07);
    border-radius: 999px;
    padding: 0.1rem 0.5rem;
    font-size: 0.68rem;
    color: #606060;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 400;
  }
  .filter-input {
    margin-left: auto;
    background: rgba(0,0,0,0.4);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 2px;
    padding: 0.3rem 0.65rem;
    color: #f0f0f0;
    font-size: 0.78rem;
    outline: none;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 400;
    width: 240px;
  }
  .filter-input:focus {
    border-color: #c8d8f0;
    
  }
  .table-scroll {
    max-height: 340px;
    overflow-y: auto;
    overflow-x: auto;
  }
  table { width: 100%; border-collapse: collapse; font-size: 0.75rem; min-width: 640px; }
  th {
    color: #606060;
    font-weight: 500;
    text-align: left;
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
    position: sticky;
    top: 0;
    background: #111111;
    user-select: none;
  }
  th.sortable { cursor: pointer; }
  th.sortable:hover { color: #c8d8f0; }
  td {
    padding: 0.28rem 0.5rem;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    color: #f0f0f0;
    white-space: nowrap;
  }
  tr.suspicious td { background: rgba(255,32,121,0.04); }
  tr:hover td { background: rgba(255,255,255,0.03); }
  .mono { font-family: monospace; font-size: 0.71rem; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .muted { color: #606060; }
  .bytes-col { color: #4ade80; }
  .port-col { text-align: right; }
  .port-cyan    { color: #c8d8f0; }
  .port-amber   { color: #ffb700; }
  .port-magenta { color: #e03e5a; font-weight: 600; }
  .proto-tag {
    display: inline-block;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .proto-tcp  { background: rgba(255,255,255,0.08); color: #c8d8f0; }
  .proto-udp  { background: rgba(57,255,20,0.12);  color: #4ade80; }
  .proto-icmp { background: rgba(255,183,0,0.12);  color: #ffb700; }
  .proto-dns  { background: rgba(167,139,250,0.12);color: #a78bfa; }
  .proto-http { background: rgba(249,115,22,0.12); color: #f97316; }
  .proto-arp  { background: rgba(6,182,212,0.12);  color: #06b6d4; }
  .inspect-btn {
    background: none;
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 4px;
    color: #606060;
    cursor: pointer;
    padding: 0.15rem 0.35rem;
    font-size: 0.7rem;
    transition: all 0.15s;
  }
  .inspect-btn:hover {
    border-color: #c8d8f0;
    color: #c8d8f0;
    
  }
  .load-more {
    margin-top: 0.75rem;
    width: 100%;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.09);
    border-radius: 2px;
    color: #606060;
    padding: 0.4rem;
    cursor: pointer;
    font-size: 0.78rem;
    transition: all 0.15s;
  }
  .load-more:hover { color: #c8d8f0; border-color: rgba(255,255,255,0.15); }
</style>
