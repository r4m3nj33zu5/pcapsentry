<script>
  import ProtocolHierarchy from '../ProtocolHierarchy.svelte';
  export let result;

  $: proto = result?.proto_hierarchy || [];
  $: overview = result?.overview;
  $: flows = result?.flows || [];
  $: packets = result?.packets || [];

  // Top talkers by bytes
  $: topTalkers = (() => {
    const m = {};
    for (const f of flows) {
      if (!m[f.src_ip]) m[f.src_ip] = { ip: f.src_ip, bytes: 0, packets: 0, flows: 0 };
      if (!m[f.dst_ip]) m[f.dst_ip] = { ip: f.dst_ip, bytes: 0, packets: 0, flows: 0 };
      m[f.src_ip].bytes += f.bytes_src_to_dst || f.bytes || 0;
      m[f.src_ip].packets += f.packets_src_to_dst || 0;
      m[f.src_ip].flows++;
    }
    return Object.values(m).sort((a,b) => b.bytes - a.bytes).slice(0, 10);
  })();

  // Port distribution
  $: topPorts = (() => {
    const m = {};
    for (const f of flows) {
      const port = f.dst_port;
      if (port) {
        if (!m[port]) m[port] = { port, count: 0, service: f.service_guess || '' };
        m[port].count++;
      }
    }
    return Object.values(m).sort((a,b) => b.count - a.count).slice(0, 15);
  })();

  // Protocol distribution from flows
  $: protoDistrib = (() => {
    const m = {};
    for (const f of flows) {
      const p = f.protocol || 'OTHER';
      m[p] = (m[p] || 0) + 1;
    }
    return Object.entries(m).sort((a,b) => b[1] - a[1]);
  })();

  function fmt(b) {
    if (b >= 1e9) return (b/1e9).toFixed(1)+'G';
    if (b >= 1e6) return (b/1e6).toFixed(1)+'M';
    if (b >= 1e3) return (b/1e3).toFixed(1)+'K';
    return b+'';
  }

  function barWidth(val, max) {
    return max > 0 ? Math.max(2, (val / max) * 100) : 0;
  }
</script>

<div class="stats-module">
  <div class="two-col">
    <!-- Left: Overview + Protocol Hierarchy -->
    <div class="left-col">
      {#if overview}
        <div class="card">
          <h3 class="card-title">Capture Overview</h3>
          <div class="kv-grid">
            <span class="k">Total Packets</span><span class="v">{overview.total_packets?.toLocaleString()}</span>
            <span class="k">Total Bytes</span><span class="v">{fmt(overview.total_bytes || 0)}</span>
            <span class="k">Duration</span><span class="v">{overview.duration_secs?.toFixed(2)}s</span>
            <span class="k">Unique IPs</span><span class="v">{overview.unique_src_ips}</span>
            <span class="k">TCP Flows</span><span class="v">{flows.filter(f=>f.protocol==='TCP').length}</span>
            <span class="k">UDP Flows</span><span class="v">{flows.filter(f=>f.protocol==='UDP').length}</span>
          </div>
        </div>
      {/if}

      <div class="card">
        <h3 class="card-title">Protocol Hierarchy</h3>
        <ProtocolHierarchy nodes={proto} />
      </div>
    </div>

    <!-- Right: Top Talkers + Ports -->
    <div class="right-col">
      <div class="card">
        <h3 class="card-title">Top Talkers (by bytes)</h3>
        {#if topTalkers.length > 0}
          {@const maxBytes = topTalkers[0].bytes}
          <div class="bar-list">
            {#each topTalkers as t}
              <div class="bar-row">
                <span class="bar-label ip">{t.ip}</span>
                <div class="bar-track">
                  <div class="bar-fill" style="width:{barWidth(t.bytes, maxBytes)}%"></div>
                </div>
                <span class="bar-val">{fmt(t.bytes)}</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="empty">No flow data.</div>
        {/if}
      </div>

      <div class="card">
        <h3 class="card-title">Top Destination Ports</h3>
        {#if topPorts.length > 0}
          {@const maxCount = topPorts[0].count}
          <div class="bar-list">
            {#each topPorts as p}
              <div class="bar-row">
                <span class="bar-label port">{p.port}{p.service ? ' ('+p.service+')' : ''}</span>
                <div class="bar-track">
                  <div class="bar-fill port-fill" style="width:{barWidth(p.count, maxCount)}%"></div>
                </div>
                <span class="bar-val">{p.count}</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="empty">No port data.</div>
        {/if}
      </div>

      <div class="card">
        <h3 class="card-title">Protocol Distribution</h3>
        <div class="proto-chips">
          {#each protoDistrib as [proto, count]}
            <div class="proto-chip">
              <span class="pname">{proto}</span>
              <span class="pcount">{count}</span>
            </div>
          {/each}
        </div>
      </div>
    </div>
  </div>
</div>

<style>
  .stats-module { display:flex; flex-direction:column; height:100%; overflow:auto; padding:1rem; }
  .two-col { display:grid; grid-template-columns:1fr 1fr; gap:1rem; align-items:start; }
  @media (max-width:900px) { .two-col { grid-template-columns:1fr; } }
  .left-col, .right-col { display:flex; flex-direction:column; gap:1rem; }
  .card { background:rgba(200,216,240,0.02); border:1px solid rgba(255,255,255,0.05); border-radius:6px; padding:1rem; }
  .card-title { color:#606060; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.06em; margin:0 0 0.75rem; }
  .kv-grid { display:grid; grid-template-columns:auto 1fr; gap:4px 1rem; }
  .k { color:#606060; font-size:0.78rem; }
  .v { color:#f0f0f0; font-size:0.78rem; font-family:monospace; }
  .bar-list { display:flex; flex-direction:column; gap:5px; }
  .bar-row { display:flex; align-items:center; gap:8px; }
  .bar-label { font-family:monospace; font-size:0.72rem; width:160px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; flex-shrink:0; }
  .bar-label.ip { color:#c8d8f0; }
  .bar-label.port { color:#bf5fff; }
  .bar-track { flex:1; height:6px; background:rgba(255,255,255,0.04); border-radius:3px; overflow:hidden; }
  .bar-fill { height:100%; background:rgba(255,255,255,0.2); border-radius:3px; transition:width 0.3s; }
  .bar-fill.port-fill { background:rgba(191,95,255,0.4); }
  .bar-val { color:#787878; font-size:0.7rem; width:42px; text-align:right; flex-shrink:0; }
  .proto-chips { display:flex; flex-wrap:wrap; gap:6px; }
  .proto-chip { display:flex; align-items:center; gap:6px; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.07); border-radius:4px; padding:3px 8px; }
  .pname { color:#888888; font-size:0.75rem; }
  .pcount { color:#c8d8f0; font-size:0.72rem; font-family:monospace; }
  .empty { color:#606060; font-size:0.78rem; }
</style>
