<script>
  import { investigationFilter, focusOnIp } from '../../stores/investigation.js';
  export let result;

  $: http = result?.http_log || [];
  $: filter = $investigationFilter;

  let search = '';
  let showSuspiciousOnly = false;
  let typeFilter = 'All';
  let page = 0;
  const PAGE = 100;

  $: filtered = http.filter(e => {
    if (filter.focusIp && e.src_ip !== filter.focusIp && e.dst_ip !== filter.focusIp) return false;
    if (showSuspiciousOnly && !e.suspicious) return false;
    if (typeFilter !== 'All' && e.entry_type !== typeFilter.toLowerCase()) return false;
    if (search) {
      const s = search.toLowerCase();
      return (e.host||'').toLowerCase().includes(s) || (e.path||'').toLowerCase().includes(s)
        || (e.user_agent||'').toLowerCase().includes(s) || e.src_ip.includes(s);
    }
    return true;
  });

  $: paged = filtered.slice(page * PAGE, (page+1)*PAGE);
  $: totalPages = Math.ceil(filtered.length / PAGE);

  $: requests = http.filter(h => h.entry_type === 'request').length;
  $: suspicious = http.filter(h => h.suspicious).length;
  $: suspUa = http.filter(h => h.is_ua_suspicious).length;

  function statusColor(s) {
    if (!s) return '#606060';
    if (s < 300) return '#4ade80';
    if (s < 400) return '#c8920a';
    if (s < 500) return '#d4622c';
    return '#e03e5a';
  }
</script>

<div class="http-module">
  <div class="stat-bar">
    <div class="stat"><span class="sv">{requests}</span><span class="sl">Requests</span></div>
    <div class="stat warn"><span class="sv">{suspicious}</span><span class="sl">Suspicious</span></div>
    <div class="stat danger"><span class="sv">{suspUa}</span><span class="sl">Suspicious UA</span></div>
  </div>

  <div class="toolbar">
    <div class="type-tabs">
      {#each ['All','Request','Response'] as t}
        <button class="tt" class:active={typeFilter===t} on:click={() => { typeFilter=t; page=0; }}>{t}</button>
      {/each}
    </div>
    <input class="search" type="text" bind:value={search} placeholder="Host, path, UA, IP…" on:input={() => page=0} />
    <label class="toggle">
      <input type="checkbox" bind:checked={showSuspiciousOnly} on:change={() => page=0} />
      Suspicious only
    </label>
    <span class="count">{filtered.length} entries</span>
  </div>

  <div class="table-wrap">
    <table class="http-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Src IP</th>
          <th>Method</th>
          <th>Host / Status</th>
          <th>Path</th>
          <th>User-Agent</th>
          <th>UA Type</th>
        </tr>
      </thead>
      <tbody>
        {#each paged as entry}
          <tr class:suspicious={entry.suspicious}>
            <td class="ts">{new Date(entry.timestamp*1000).toLocaleTimeString()}</td>
            <td class="ip" on:click={() => focusOnIp(entry.src_ip)}>{entry.src_ip}</td>
            <td class="method">{entry.method ?? '—'}</td>
            <td class="host">
              {#if entry.entry_type === 'response'}
                <span class="status" style="color:{statusColor(entry.status)}">{entry.status}</span>
              {:else}
                {entry.host ?? '—'}
              {/if}
            </td>
            <td class="path" title={entry.path}>{entry.path?.substring(0,60) ?? '—'}</td>
            <td class="ua" title={entry.user_agent}>{entry.user_agent?.substring(0,40) ?? '—'}</td>
            <td class="ua-cat" class:bad={entry.is_ua_suspicious}>{entry.ua_category ?? '—'}</td>
          </tr>
          {#if entry.suspicious && entry.suspicious_reason}
            <tr class="reason-row">
              <td colspan="7"><span class="reason">⚠ {entry.suspicious_reason}</span></td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
  </div>

  {#if totalPages > 1}
    <div class="pagination">
      <button on:click={() => page--} disabled={page===0}>‹</button>
      <span>Page {page+1}/{totalPages}</span>
      <button on:click={() => page++} disabled={page>=totalPages-1}>›</button>
    </div>
  {/if}
</div>

<style>
  .http-module { display:flex; flex-direction:column; height:100%; }
  .stat-bar { display:flex; gap:1rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); }
  .stat { display:flex; flex-direction:column; align-items:center; }
  .sv { font-size:1.1rem; font-weight:700; color:#f0f0f0; }
  .sl { font-size:0.65rem; color:#606060; text-transform:uppercase; }
  .stat.warn .sv { color:#c8920a; }
  .stat.danger .sv { color:#e03e5a; }
  .toolbar { display:flex; align-items:center; gap:0.5rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); flex-wrap:wrap; }
  .type-tabs { display:flex; gap:3px; }
  .tt { background:none; border:1px solid rgba(255,255,255,0.07); color:#606060; padding:3px 8px; border-radius:4px; font-size:0.73rem; cursor:pointer; }
  .tt.active { color:#c8d8f0; border-color:rgba(255,255,255,0.2); }
  .search { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#f0f0f0; padding:5px 10px; border-radius:5px; font-size:0.8rem; width:220px; }
  .search:focus { outline:none; border-color:rgba(255,255,255,0.15); }
  .toggle { display:flex; align-items:center; gap:6px; font-size:0.78rem; color:#787878; cursor:pointer; }
  .count { margin-left:auto; color:#606060; font-size:0.78rem; }
  .table-wrap { flex:1; overflow:auto; }
  .http-table { width:100%; border-collapse:collapse; font-size:0.78rem; }
  thead th { position:sticky; top:0; background:#0a0a0a; color:#606060; text-align:left; padding:6px 10px; border-bottom:1px solid rgba(255,255,255,0.07); }
  tbody tr { border-bottom:1px solid rgba(255,255,255,0.02); }
  tbody tr.suspicious { background:rgba(255,165,0,0.04); }
  tbody tr:hover { background:rgba(200,216,240,0.02); }
  td { padding:4px 10px; color:#888888; }
  .ts { color:#606060; font-size:0.72rem; white-space:nowrap; }
  .ip { color:#c8d8f0; font-family:monospace; cursor:pointer; }
  .ip:hover { text-decoration:underline; }
  .method { color:#4ade80; font-weight:700; font-size:0.72rem; }
  .host { color:#f0f0f0; max-width:140px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .status { font-weight:700; }
  .path { max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:0.72rem; }
  .ua { max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:0.72rem; color:#787878; }
  .ua-cat { font-size:0.72rem; }
  .ua-cat.bad { color:#d4622c; font-weight:600; }
  .reason-row td { padding:2px 10px 6px 20px; }
  .reason { color:#c8920a; font-size:0.72rem; }
  .pagination { display:flex; align-items:center; gap:0.5rem; justify-content:center; padding:0.5rem; border-top:1px solid rgba(255,255,255,0.05); }
  .pagination button { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#c8d8f0; padding:3px 8px; border-radius:4px; cursor:pointer; }
  .pagination button:disabled { opacity:0.3; cursor:not-allowed; }
  .pagination span { color:#606060; font-size:0.8rem; }
</style>
