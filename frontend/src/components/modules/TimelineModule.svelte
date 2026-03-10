<script>
  import { investigationFilter, focusOnIp, focusOnAlert, setTimeRange } from '../../stores/investigation.js';
  export let result;

  $: events = result?.timeline_events || [];
  $: filter = $investigationFilter;

  let search = '';
  let sevFilter = 'All';
  let typeFilter = 'All';

  const SEV_ORDER = { critical:0, high:1, medium:2, low:3, info:4 };

  $: filtered = events.filter(e => {
    if (filter.focusIp && e.src_ip !== filter.focusIp && e.dst_ip !== filter.focusIp) return false;
    if (filter.focusTimeRange) {
      const { start, end } = filter.focusTimeRange;
      if (e.timestamp < start || e.timestamp > end) return false;
    }
    if (sevFilter !== 'All' && e.severity !== sevFilter.toLowerCase()) return false;
    if (typeFilter !== 'All' && e.event_type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return e.description.toLowerCase().includes(q)
        || (e.src_ip||'').includes(q)
        || (e.dst_ip||'').includes(q)
        || (e.mitre_technique||'').toLowerCase().includes(q);
    }
    return true;
  }).sort((a,b) => a.timestamp - b.timestamp);

  $: eventTypes = [...new Set(events.map(e => e.event_type))];

  $: sevCounts = events.reduce((acc, e) => {
    acc[e.severity] = (acc[e.severity] || 0) + 1;
    return acc;
  }, {});

  function sevColor(s) {
    return { critical:'#e03e5a', high:'#d4622c', medium:'#c8920a', low:'#4ade80', info:'#c8d8f0' }[s] || '#606060';
  }

  function tsStr(ts) {
    return new Date(ts * 1000).toLocaleTimeString();
  }

  function typeBadgeStyle(type) {
    const colors = { alert:'rgba(255,32,121,0.15)', dns:'rgba(191,95,255,0.15)', http:'rgba(255,255,255,0.07)', tls:'rgba(57,255,20,0.1)' };
    return `background:${colors[type]||'rgba(100,100,100,0.1)'};border:1px solid rgba(255,255,255,0.08);`;
  }
</script>

<div class="timeline-module">
  <div class="stat-bar">
    {#each ['critical','high','medium','low','info'] as sev}
      <div class="stat" style="--c:{sevColor(sev)}">
        <span class="sv" style="color:{sevColor(sev)}">{sevCounts[sev]||0}</span>
        <span class="sl">{sev}</span>
      </div>
    {/each}
  </div>

  <div class="toolbar">
    <div class="sev-tabs">
      {#each ['All','Critical','High','Medium','Low','Info'] as s}
        <button class="st" class:active={sevFilter===s} on:click={() => sevFilter=s}>{s}</button>
      {/each}
    </div>
    <select class="type-sel" bind:value={typeFilter}>
      <option>All</option>
      {#each eventTypes as t}<option>{t}</option>{/each}
    </select>
    <input class="search" type="text" bind:value={search} placeholder="Search…" />
    <span class="count">{filtered.length} events</span>
  </div>

  <div class="timeline-list">
    {#each filtered as ev}
      <div class="ev-row" style="border-left-color:{sevColor(ev.severity)}">
        <div class="ev-time">{tsStr(ev.timestamp)}</div>
        <div class="ev-body">
          <div class="ev-top">
            <span class="ev-type" style={typeBadgeStyle(ev.event_type)}>{ev.event_type}</span>
            {#if ev.mitre_technique}
              <span class="ev-mitre">{ev.mitre_technique}</span>
            {/if}
            <span class="ev-desc">{ev.description}</span>
          </div>
          {#if ev.src_ip || ev.dst_ip}
            <div class="ev-ips">
              {#if ev.src_ip}
                <span class="ev-ip" on:click={() => focusOnIp(ev.src_ip)}>{ev.src_ip}</span>
              {/if}
              {#if ev.src_ip && ev.dst_ip}<span class="arrow">→</span>{/if}
              {#if ev.dst_ip}
                <span class="ev-ip" on:click={() => focusOnIp(ev.dst_ip)}>{ev.dst_ip}</span>
              {/if}
              {#if ev.alert_id}
                <button class="ev-pivot" on:click={() => focusOnAlert(ev.alert_id, ev.mitre_technique)}>
                  Focus Alert
                </button>
              {/if}
            </div>
          {/if}
        </div>
      </div>
    {/each}
    {#if filtered.length === 0}
      <div class="empty">{events.length === 0 ? 'No timeline events.' : 'No events match filter.'}</div>
    {/if}
  </div>
</div>

<style>
  .timeline-module { display:flex; flex-direction:column; height:100%; }
  .stat-bar { display:flex; gap:1rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); }
  .stat { display:flex; flex-direction:column; align-items:center; }
  .sv { font-size:1.1rem; font-weight:700; }
  .sl { font-size:0.65rem; color:#606060; text-transform:uppercase; }
  .toolbar { display:flex; align-items:center; gap:0.5rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); flex-wrap:wrap; }
  .sev-tabs { display:flex; gap:3px; }
  .st { background:none; border:1px solid rgba(255,255,255,0.07); color:#606060; padding:3px 8px; border-radius:4px; font-size:0.73rem; cursor:pointer; }
  .st.active { color:#c8d8f0; border-color:rgba(255,255,255,0.2); }
  .type-sel { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#888888; padding:4px 8px; border-radius:5px; font-size:0.78rem; }
  .search { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#f0f0f0; padding:5px 10px; border-radius:5px; font-size:0.8rem; width:180px; }
  .search:focus { outline:none; border-color:rgba(255,255,255,0.15); }
  .count { margin-left:auto; color:#606060; font-size:0.78rem; }
  .timeline-list { flex:1; overflow-y:auto; }
  .ev-row { display:flex; gap:0.75rem; padding:0.5rem 1rem; border-bottom:1px solid rgba(255,255,255,0.02); border-left:3px solid transparent; }
  .ev-row:hover { background:rgba(200,216,240,0.02); }
  .ev-time { color:#606060; font-size:0.72rem; font-family:monospace; white-space:nowrap; padding-top:2px; width:68px; flex-shrink:0; }
  .ev-body { flex:1; min-width:0; }
  .ev-top { display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:3px; }
  .ev-type { font-size:0.65rem; font-weight:700; padding:1px 6px; border-radius:3px; color:#888888; }
  .ev-mitre { font-size:0.68rem; color:#bf5fff; font-family:monospace; }
  .ev-desc { color:#f0f0f0; font-size:0.8rem; flex:1; }
  .ev-ips { display:flex; align-items:center; gap:6px; font-size:0.75rem; }
  .ev-ip { color:#c8d8f0; font-family:monospace; cursor:pointer; }
  .ev-ip:hover { text-decoration:underline; }
  .arrow { color:#606060; }
  .ev-pivot { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.09); color:#c8d8f0; padding:1px 8px; border-radius:3px; font-size:0.68rem; cursor:pointer; margin-left:auto; }
  .ev-pivot:hover { background:rgba(255,255,255,0.08); }
  .empty { color:#606060; text-align:center; padding:3rem; }
</style>
