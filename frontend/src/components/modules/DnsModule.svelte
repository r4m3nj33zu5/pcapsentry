<script>
  import { investigationFilter, focusOnIp } from '../../stores/investigation.js';
  export let result;

  $: dns = result?.dns_log || [];
  $: filter = $investigationFilter;

  let search = '';
  let showSuspiciousOnly = false;
  let page = 0;
  const PAGE = 100;

  $: filtered = dns.filter(e => {
    if (filter.focusIp && e.src_ip !== filter.focusIp && e.dst_ip !== filter.focusIp) return false;
    if (showSuspiciousOnly && !e.suspicious) return false;
    if (search) {
      const s = search.toLowerCase();
      return e.name.toLowerCase().includes(s) || e.src_ip.includes(s) || e.dst_ip.includes(s);
    }
    return true;
  });

  $: paged = filtered.slice(page * PAGE, (page+1)*PAGE);
  $: totalPages = Math.ceil(filtered.length / PAGE);

  $: stats = (() => {
    const total = dns.length;
    const suspicious = dns.filter(d => d.suspicious).length;
    const nxdomain = dns.filter(d => d.is_nxdomain).length;
    const dga = dns.filter(d => d.is_dga_candidate).length;
    return { total, suspicious, nxdomain, dga };
  })();
</script>

<div class="dns-module">
  <div class="stat-bar">
    <div class="stat"><span class="sv">{stats.total}</span><span class="sl">Total Queries</span></div>
    <div class="stat warn"><span class="sv">{stats.suspicious}</span><span class="sl">Suspicious</span></div>
    <div class="stat danger"><span class="sv">{stats.nxdomain}</span><span class="sl">NXDOMAIN</span></div>
    <div class="stat danger"><span class="sv">{stats.dga}</span><span class="sl">DGA Candidates</span></div>
  </div>

  <div class="toolbar">
    <input class="search" type="text" bind:value={search} placeholder="Search domain, IP…" on:input={() => page=0} />
    <label class="toggle">
      <input type="checkbox" bind:checked={showSuspiciousOnly} on:change={() => page=0} />
      Suspicious only
    </label>
    <span class="count">{filtered.length} entries</span>
  </div>

  <div class="table-wrap">
    <table class="dns-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Src IP</th>
          <th>Domain</th>
          <th>Type</th>
          <th>Response</th>
          <th>Entropy</th>
          <th>Flags</th>
        </tr>
      </thead>
      <tbody>
        {#each paged as entry}
          <tr class:suspicious={entry.suspicious}>
            <td class="ts">{new Date(entry.timestamp*1000).toLocaleTimeString()}</td>
            <td class="ip" on:click={() => focusOnIp(entry.src_ip)}>{entry.src_ip}</td>
            <td class="domain" title={entry.name}>{entry.name}</td>
            <td class="qtype">{entry.query_type}</td>
            <td class="ans">{entry.answers.slice(0,2).join(', ')}{entry.answers.length > 2 ? '…' : ''}</td>
            <td class="entropy" class:high={entry.entropy > 3.5}>{entry.entropy?.toFixed(2) ?? '—'}</td>
            <td class="flags">
              {#if entry.is_nxdomain}<span class="flag nxd">NXDOMAIN</span>{/if}
              {#if entry.is_dga_candidate}<span class="flag dga">DGA</span>{/if}
              {#if entry.suspicious && !entry.is_nxdomain && !entry.is_dga_candidate}<span class="flag susp">⚠</span>{/if}
            </td>
          </tr>
          {#if entry.suspicious && entry.suspicious_reason}
            <tr class="reason-row">
              <td colspan="7"><span class="reason">{entry.suspicious_reason}</span></td>
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
  .dns-module { display:flex; flex-direction:column; height:100%; }
  .stat-bar { display:flex; gap:1rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); }
  .stat { display:flex; flex-direction:column; align-items:center; }
  .sv { font-size:1.1rem; font-weight:700; color:#f0f0f0; }
  .sl { font-size:0.65rem; color:#606060; text-transform:uppercase; }
  .stat.warn .sv { color:#c8920a; }
  .stat.danger .sv { color:#e03e5a; }
  .toolbar { display:flex; align-items:center; gap:0.75rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); }
  .search { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#f0f0f0; padding:5px 10px; border-radius:5px; font-size:0.8rem; width:240px; }
  .search:focus { outline:none; border-color:rgba(255,255,255,0.15); }
  .toggle { display:flex; align-items:center; gap:6px; font-size:0.78rem; color:#787878; cursor:pointer; }
  .count { margin-left:auto; color:#606060; font-size:0.78rem; }
  .table-wrap { flex:1; overflow:auto; }
  .dns-table { width:100%; border-collapse:collapse; font-size:0.78rem; }
  thead th { position:sticky; top:0; background:#0a0a0a; color:#606060; text-align:left; padding:6px 10px; border-bottom:1px solid rgba(255,255,255,0.07); }
  tbody tr { border-bottom:1px solid rgba(255,255,255,0.02); }
  tbody tr.suspicious { background:rgba(255,165,0,0.04); }
  tbody tr:hover { background:rgba(255,255,255,0.02); }
  td { padding:4px 10px; color:#888888; }
  .ts { color:#606060; font-size:0.72rem; white-space:nowrap; }
  .ip { color:#c8d8f0; font-family:monospace; cursor:pointer; }
  .ip:hover { text-decoration:underline; }
  .domain { color:#f0f0f0; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .qtype { color:#bf5fff; font-weight:600; }
  .ans { color:#787878; max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .entropy { font-family:monospace; }
  .entropy.high { color:#c8920a; font-weight:700; }
  .flags { white-space:nowrap; }
  .flag { font-size:0.65rem; padding:1px 5px; border-radius:3px; margin-right:3px; font-weight:700; }
  .nxd { background:rgba(255,32,121,0.15); color:#e03e5a; border:1px solid rgba(255,32,121,0.3); }
  .dga { background:rgba(255,107,53,0.15); color:#d4622c; border:1px solid rgba(255,107,53,0.3); }
  .susp { background:rgba(255,165,0,0.15); color:#c8920a; }
  .reason-row td { padding:2px 10px 6px 20px; }
  .reason { color:#c8920a; font-size:0.72rem; }
  .pagination { display:flex; align-items:center; gap:0.5rem; justify-content:center; padding:0.5rem; border-top:1px solid rgba(255,255,255,0.05); }
  .pagination button { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#c8d8f0; padding:3px 8px; border-radius:4px; cursor:pointer; }
  .pagination button:disabled { opacity:0.3; cursor:not-allowed; }
  .pagination span { color:#606060; font-size:0.8rem; }
</style>
