<script>
  import { investigationFilter, markPacket } from '../../stores/investigation.js';
  export let result;

  $: packets = result?.packets || [];
  $: filter = $investigationFilter;

  let search = '';
  let protoFilter = 'All';
  let showMarkedOnly = false;
  let page = 0;
  const PAGE = 50;

  // Collect unique protocols
  $: protocols = ['All', ...new Set(packets.map(p => p.protocol || 'OTHER'))];

  $: filtered = packets.filter((p, i) => {
    if (filter.focusIp && p.src_ip !== filter.focusIp && p.dst_ip !== filter.focusIp) return false;
    if (showMarkedOnly && !filter.markedPackets?.has(i)) return false;
    if (protoFilter !== 'All' && (p.protocol || 'OTHER') !== protoFilter) return false;
    if (filter.focusTimeRange) {
      const { start, end } = filter.focusTimeRange;
      if (p.timestamp < start || p.timestamp > end) return false;
    }
    if (search) {
      const q = search.toLowerCase();
      return (p.src_ip||'').includes(q) || (p.dst_ip||'').includes(q)
        || (p.info||'').toLowerCase().includes(q)
        || String(p.src_port||'').includes(q)
        || String(p.dst_port||'').includes(q);
    }
    return true;
  });

  $: paged = filtered.slice(page * PAGE, (page + 1) * PAGE);
  $: totalPages = Math.ceil(filtered.length / PAGE);

  // Store original indices for marking
  $: filteredWithIdx = packets.reduce((acc, p, i) => {
    if (filtered.includes(p)) acc.push({ ...p, _orig_idx: i });
    return acc;
  }, []);
  $: pagedWithIdx = filteredWithIdx.slice(page * PAGE, (page + 1) * PAGE);

  let selected = null;

  function protoColor(proto) {
    const map = { TCP:'#c8d8f0', UDP:'#bf5fff', DNS:'#c8920a', TLS:'#4ade80', HTTP:'#d4622c', ICMP:'#606060', ARP:'#787878' };
    return map[proto] || '#888888';
  }

  function lenColor(len) {
    if (len > 1400) return '#e03e5a';
    if (len > 500) return '#c8920a';
    return '#888888';
  }
</script>

<div class="packet-module">
  <div class="toolbar">
    <div class="proto-tabs">
      {#each protocols.slice(0,8) as p}
        <button class="pt" class:active={protoFilter===p} on:click={() => { protoFilter=p; page=0; }}>{p}</button>
      {/each}
    </div>
    <input class="search" type="text" bind:value={search} placeholder="IP, port, info…" on:input={() => page=0} />
    <label class="toggle">
      <input type="checkbox" bind:checked={showMarkedOnly} on:change={() => page=0} />
      Marked only
    </label>
    <span class="count">{filtered.length.toLocaleString()} / {packets.length.toLocaleString()} packets</span>
  </div>

  <div class="table-wrap">
    <table class="pkt-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Time</th>
          <th>Src IP</th>
          <th>Src Port</th>
          <th>Dst IP</th>
          <th>Dst Port</th>
          <th>Proto</th>
          <th>Len</th>
          <th>Info</th>
          <th>★</th>
        </tr>
      </thead>
      <tbody>
        {#each pagedWithIdx as pkt}
          <tr
            class:selected={selected === pkt._orig_idx}
            class:marked={filter.markedPackets?.has(pkt._orig_idx)}
            on:click={() => selected = selected === pkt._orig_idx ? null : pkt._orig_idx}
          >
            <td class="idx">{pkt._orig_idx + 1}</td>
            <td class="ts">{new Date(pkt.timestamp * 1000).toLocaleTimeString()}</td>
            <td class="ip">{pkt.src_ip || '—'}</td>
            <td class="port">{pkt.src_port ?? '—'}</td>
            <td class="ip">{pkt.dst_ip || '—'}</td>
            <td class="port">{pkt.dst_port ?? '—'}</td>
            <td class="proto" style="color:{protoColor(pkt.protocol)}">{pkt.protocol || '?'}</td>
            <td class="len" style="color:{lenColor(pkt.length || 0)}">{pkt.length}</td>
            <td class="info" title={pkt.info}>{(pkt.info||'').substring(0,60)}</td>
            <td class="mark-cell">
              <button class="mark-btn" class:active={filter.markedPackets?.has(pkt._orig_idx)}
                on:click|stopPropagation={() => markPacket(pkt._orig_idx)}>
                ★
              </button>
            </td>
          </tr>
          {#if selected === pkt._orig_idx}
            <tr class="detail-row">
              <td colspan="10">
                <div class="detail-grid">
                  <div><span class="dl">Timestamp</span><span class="dv">{pkt.timestamp}</span></div>
                  <div><span class="dl">Length</span><span class="dv">{pkt.length} bytes</span></div>
                  <div><span class="dl">Protocol</span><span class="dv">{pkt.protocol}</span></div>
                  {#if pkt.tcp_flags}
                    <div><span class="dl">TCP Flags</span><span class="dv mono">{pkt.tcp_flags}</span></div>
                  {/if}
                  {#if pkt.ttl !== undefined}
                    <div><span class="dl">TTL</span><span class="dv">{pkt.ttl}</span></div>
                  {/if}
                  {#if pkt.app_payload_preview}
                    <div class="full-width"><span class="dl">Payload (hex)</span><code class="payload">{pkt.app_payload_preview}</code></div>
                  {/if}
                  {#if pkt.info}
                    <div class="full-width"><span class="dl">Info</span><span class="dv">{pkt.info}</span></div>
                  {/if}
                </div>
              </td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
  </div>

  {#if totalPages > 1}
    <div class="pagination">
      <button on:click={() => page=0} disabled={page===0}>««</button>
      <button on:click={() => page--} disabled={page===0}>‹</button>
      <span>Page {page+1} / {totalPages} &nbsp;({filtered.length.toLocaleString()} packets)</span>
      <button on:click={() => page++} disabled={page>=totalPages-1}>›</button>
      <button on:click={() => page=totalPages-1} disabled={page>=totalPages-1}>»»</button>
    </div>
  {/if}
</div>

<style>
  .packet-module { display:flex; flex-direction:column; height:100%; }
  .toolbar { display:flex; align-items:center; gap:0.5rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); flex-wrap:wrap; }
  .proto-tabs { display:flex; gap:3px; }
  .pt { background:none; border:1px solid rgba(255,255,255,0.07); color:#606060; padding:3px 7px; border-radius:4px; font-size:0.7rem; cursor:pointer; }
  .pt.active { color:#c8d8f0; border-color:rgba(255,255,255,0.2); }
  .search { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#f0f0f0; padding:5px 10px; border-radius:5px; font-size:0.8rem; width:200px; }
  .search:focus { outline:none; border-color:rgba(255,255,255,0.15); }
  .toggle { display:flex; align-items:center; gap:6px; font-size:0.78rem; color:#787878; cursor:pointer; }
  .count { margin-left:auto; color:#606060; font-size:0.78rem; }
  .table-wrap { flex:1; overflow:auto; }
  .pkt-table { width:100%; border-collapse:collapse; font-size:0.75rem; }
  thead th { position:sticky; top:0; background:#0a0a0a; color:#606060; text-align:left; padding:5px 8px; border-bottom:1px solid rgba(255,255,255,0.07); font-size:0.68rem; text-transform:uppercase; }
  tbody tr { border-bottom:1px solid rgba(255,255,255,0.02); cursor:pointer; }
  tbody tr:hover { background:rgba(200,216,240,0.02); }
  tbody tr.selected { background:rgba(255,255,255,0.04); }
  tbody tr.marked { background:rgba(255,215,0,0.04); }
  td { padding:3px 8px; color:#888888; }
  .idx { color:#606060; font-family:monospace; width:50px; }
  .ts { color:#606060; font-family:monospace; white-space:nowrap; }
  .ip { color:#c8d8f0; font-family:monospace; font-size:0.72rem; }
  .port { color:#bf5fff; font-family:monospace; font-size:0.72rem; }
  .proto { font-weight:700; font-size:0.72rem; }
  .len { font-family:monospace; font-size:0.72rem; }
  .info { color:#787878; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:0.7rem; }
  .mark-cell { width:30px; text-align:center; }
  .mark-btn { background:none; border:none; color:#606060; cursor:pointer; font-size:0.85rem; padding:0; }
  .mark-btn.active { color:#ffd700; }
  .mark-btn:hover { color:#ffd700; }
  .detail-row td { padding:6px 10px 10px 20px; }
  .detail-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:6px; }
  .full-width { grid-column:1/-1; }
  .dl { display:block; color:#606060; font-size:0.65rem; text-transform:uppercase; }
  .dv { color:#f0f0f0; font-size:0.75rem; }
  .dv.mono { font-family:monospace; }
  .payload { display:block; font-family:monospace; font-size:0.68rem; color:#4ade80; word-break:break-all; margin-top:2px; max-height:80px; overflow:auto; }
  .pagination { display:flex; align-items:center; gap:0.4rem; justify-content:center; padding:0.5rem; border-top:1px solid rgba(255,255,255,0.05); }
  .pagination button { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#c8d8f0; padding:3px 7px; border-radius:4px; cursor:pointer; font-size:0.78rem; }
  .pagination button:disabled { opacity:0.3; cursor:not-allowed; }
  .pagination span { color:#606060; font-size:0.78rem; }
</style>
