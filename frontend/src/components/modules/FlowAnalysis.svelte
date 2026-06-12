<script>
  import { activeSessionId } from '../../stores/session.js';
  import { investigationFilter, focusOnIp, focusOnFlow, openIpPivot } from '../../stores/investigation.js';
  import StreamViewer from '../StreamViewer.svelte';

  let streamFlow = null; // flow to show in stream viewer

  export let result;

  $: allFlows = result?.flows || [];
  $: filter = $investigationFilter;

  let search = '';
  let sortKey = 'bytes';
  let sortDir = -1;
  let page = 0;
  const PAGE_SIZE = 50;

  $: filtered = allFlows.filter(f => {
    if (filter.focusIp) {
      if (f.src_ip !== filter.focusIp && f.dst_ip !== filter.focusIp) return false;
    }
    if (search) {
      const s = search.toLowerCase();
      return f.src_ip.includes(s) || f.dst_ip.includes(s) || f.protocol.toLowerCase().includes(s)
        || f.service_guess.toLowerCase().includes(s);
    }
    return true;
  });

  $: sorted = [...filtered].sort((a, b) => {
    const av = a[sortKey] ?? 0, bv = b[sortKey] ?? 0;
    return typeof av === 'string' ? av.localeCompare(bv) * sortDir : (av - bv) * sortDir;
  });

  $: paged = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  $: totalPages = Math.ceil(sorted.length / PAGE_SIZE);

  function sort(key) {
    if (sortKey === key) sortDir *= -1;
    else { sortKey = key; sortDir = -1; }
    page = 0;
  }

  function fmt(b) {
    if (b >= 1e9) return (b/1e9).toFixed(1)+'G';
    if (b >= 1e6) return (b/1e6).toFixed(1)+'M';
    if (b >= 1e3) return (b/1e3).toFixed(1)+'K';
    return b+'';
  }

  function fmtDur(s) {
    if (s >= 3600) return (s/3600).toFixed(1)+'h';
    if (s >= 60) return (s/60).toFixed(1)+'m';
    return s.toFixed(1)+'s';
  }

  function stateColor(s) {
    return {established:'#4ade80',scan:'#d4622c',reset:'#e03e5a',stateless:'#606060'}[s]||'#606060';
  }

  let expandedFlow = null;
  function toggleFlow(f) {
    expandedFlow = expandedFlow?.flow_id === f.flow_id ? null : f;
  }
</script>

<div class="flow-module">
  <div class="toolbar">
    <span class="count">{sorted.length} flows</span>
    <input class="search" type="text" bind:value={search} placeholder="Filter by IP, protocol, service…" on:input={() => page=0} />
  </div>

  <div class="table-wrap">
    <table class="flow-table">
      <thead>
        <tr>
          <th on:click={() => sort('src_ip')}>Src IP {sortKey==='src_ip'?'⇅':''}</th>
          <th>Port</th>
          <th on:click={() => sort('dst_ip')}>Dst IP {sortKey==='dst_ip'?'⇅':''}</th>
          <th>Port</th>
          <th on:click={() => sort('protocol')}>Proto</th>
          <th on:click={() => sort('service_guess')}>Service</th>
          <th on:click={() => sort('bytes')}>Bytes {sortKey==='bytes'?'⇅':''}</th>
          <th on:click={() => sort('packets')}>Pkts</th>
          <th on:click={() => sort('duration_secs')}>Duration</th>
          <th>State</th>
        </tr>
      </thead>
      <tbody>
        {#each paged as flow (flow.flow_id)}
          <tr class="flow-row"
            class:suspicious={flow.is_suspicious}
            on:click={() => toggleFlow(flow)}
          >
            <td class="ip" on:click|stopPropagation={(e) => openIpPivot(flow.src_ip, e)}>{flow.src_ip}</td>
            <td class="port">{flow.src_port ?? '—'}</td>
            <td class="ip" on:click|stopPropagation={(e) => openIpPivot(flow.dst_ip, e)}>{flow.dst_ip}</td>
            <td class="port">{flow.dst_port ?? '—'}</td>
            <td class="proto">{flow.protocol}</td>
            <td class="svc">{flow.service_guess}</td>
            <td class="bytes">{fmt(flow.bytes)}</td>
            <td>{flow.packets}</td>
            <td>{fmtDur(flow.duration_secs)}</td>
            <td><span class="state-dot" style="color:{stateColor(flow.state)}">{flow.state}</span></td>
          </tr>
          {#if expandedFlow?.flow_id === flow.flow_id}
            <tr class="detail-row">
              <td colspan="10">
                <div class="flow-detail">
                  <div class="detail-grid">
                    <div><span class="dl">Flow ID</span><span class="dv mono">{flow.flow_id}</span></div>
                    <div><span class="dl">BPS</span><span class="dv">{fmt(Math.round(flow.bytes_per_second))}/s</span></div>
                    <div><span class="dl">TCP Flags</span><span class="dv mono">{flow.tcp_flags_seen || '—'}</span></div>
                    <div><span class="dl">First Seen</span><span class="dv">{new Date(flow.first_seen*1000).toLocaleTimeString()}</span></div>
                  </div>
                  {#if flow.payload_preview}
                    <div class="payload">
                      <span class="dl">Payload Preview</span>
                      <code class="payload-hex">{flow.payload_preview}</code>
                    </div>
                  {/if}
                  <div class="detail-actions">
                    <button class="focus-btn" on:click={() => focusOnFlow(flow.flow_id)}>
                      ⇌ Focus on Flow
                    </button>
                    {#if flow.protocol === 'TCP'}
                      <button class="stream-btn" on:click|stopPropagation={() => streamFlow = flow}>
                        ⊞ View Stream
                      </button>
                    {/if}
                  </div>
                </div>
              </td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
  </div>

  {#if streamFlow}
    <StreamViewer flow={streamFlow} onclose={() => streamFlow = null} />
  {/if}

  {#if totalPages > 1}
    <div class="pagination">
      <button on:click={() => page=0} disabled={page===0}>«</button>
      <button on:click={() => page--} disabled={page===0}>‹</button>
      <span>Page {page+1} / {totalPages}</span>
      <button on:click={() => page++} disabled={page>=totalPages-1}>›</button>
      <button on:click={() => page=totalPages-1} disabled={page>=totalPages-1}>»</button>
    </div>
  {/if}
</div>

<style>
  .flow-module { display:flex; flex-direction:column; height:100%; overflow:hidden; }
  .toolbar { display:flex; align-items:center; gap:0.75rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); }
  .count { color:#606060; font-size:0.8rem; }
  .search { margin-left:auto; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#f0f0f0; padding:5px 10px; border-radius:5px; font-size:0.8rem; width:280px; }
  .search:focus { outline:none; border-color:rgba(255,255,255,0.15); }
  .table-wrap { flex:1; overflow:auto; }
  .flow-table { width:100%; border-collapse:collapse; font-size:0.78rem; }
  thead th { position:sticky; top:0; background:#0a0a0a; color:#606060; text-align:left; padding:6px 10px; border-bottom:1px solid rgba(255,255,255,0.07); cursor:pointer; white-space:nowrap; user-select:none; }
  thead th:hover { color:#909090; }
  tbody tr { border-bottom:1px solid rgba(255,255,255,0.03); cursor:pointer; }
  tbody tr:hover { background:rgba(255,255,255,0.02); }
  .flow-row.suspicious { background:rgba(255,107,53,0.04); }
  td { padding:5px 10px; color:#888888; }
  .ip { color:#c8d8f0; font-family:monospace; cursor:pointer !important; }
  .ip:hover { text-decoration:underline; }
  .port { color:#606060; font-family:monospace; }
  .proto { color:#bf5fff; font-weight:600; }
  .svc { color:#909090; }
  .bytes { font-weight:600; color:#f0f0f0; }
  .state-dot { font-size:0.72rem; font-weight:600; }
  .detail-row { background:rgba(200,216,240,0.02); }
  .flow-detail { padding:0.75rem 1rem; }
  .detail-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:0.5rem; margin-bottom:0.75rem; }
  .detail-grid > div { display:flex; flex-direction:column; gap:2px; }
  .dl { color:#606060; font-size:0.7rem; text-transform:uppercase; }
  .dv { color:#f0f0f0; font-size:0.8rem; }
  .mono { font-family:monospace; }
  .payload { margin-bottom:0.75rem; }
  .payload-hex { display:block; font-family:monospace; font-size:0.72rem; color:#4ade80; word-break:break-all; margin-top:4px; }
  .detail-actions { display:flex; gap:0.5rem; flex-wrap:wrap; }
  .focus-btn { background:rgba(10,40,80,0.15); border:1px solid rgba(200,216,240,0.12); color:var(--accent); padding:4px 12px; border-radius:2px; font-size:0.65rem; font-family:var(--font-ui); letter-spacing:0.07em; text-transform:uppercase; cursor:pointer; transition:background 0.2s,color 0.2s,border-color 0.2s; }
  .focus-btn:hover { background:var(--text); color:#000; border-color:var(--text); }
  .stream-btn { background:rgba(74,222,128,0.05); border:1px solid rgba(74,222,128,0.18); color:var(--low); padding:4px 12px; border-radius:2px; font-size:0.65rem; font-family:var(--font-ui); letter-spacing:0.07em; text-transform:uppercase; cursor:pointer; transition:background 0.2s,color 0.2s,border-color 0.2s; }
  .stream-btn:hover { background:var(--low); color:#000; border-color:var(--low); }
  .pagination { display:flex; align-items:center; gap:0.5rem; justify-content:center; padding:0.5rem; border-top:1px solid rgba(255,255,255,0.05); }
  .pagination button { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#c8d8f0; padding:3px 8px; border-radius:4px; cursor:pointer; font-size:0.8rem; }
  .pagination button:disabled { opacity:0.3; cursor:not-allowed; }
  .pagination span { color:#606060; font-size:0.8rem; }
</style>
