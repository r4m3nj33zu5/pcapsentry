<script>
  import { focusOnIp } from '../../stores/investigation.js';
  import { activeSessionId } from '../../stores/session.js';
  export let result;

  $: ioc = result?.ioc_bundle;
  $: ips = ioc?.ips || [];
  $: domains = ioc?.domains || [];
  $: urls = ioc?.urls || [];

  let tab = 'ips';
  let search = '';
  let enriching = {};
  let enrichData = {};

  function fmt(b) {
    if (b >= 1e9) return (b/1e9).toFixed(1)+'G';
    if (b >= 1e6) return (b/1e6).toFixed(1)+'M';
    if (b >= 1e3) return (b/1e3).toFixed(1)+'K';
    return b+'';
  }

  $: filteredIps = ips.filter(i => !search || i.ip.includes(search) || (i.country||'').toLowerCase().includes(search.toLowerCase()));
  $: filteredDomains = domains.filter(d => !search || d.domain.toLowerCase().includes(search.toLowerCase()));
  $: filteredUrls = urls.filter(u => !search || u.url.toLowerCase().includes(search.toLowerCase()) || u.host.toLowerCase().includes(search.toLowerCase()));

  async function enrichIp(ip) {
    enriching[ip] = true;
    enriching = enriching;
    try {
      const data = await fetch(`/api/enrich/ip/${ip}`, { method: 'POST' }).then(r => r.json());
      enrichData[ip] = data;
      enrichData = enrichData;
    } catch (e) { enrichData[ip] = { error: e.message }; }
    enriching[ip] = false;
    enriching = enriching;
  }

  async function enrichDomain(domain) {
    enriching[domain] = true;
    enriching = enriching;
    try {
      const data = await fetch(`/api/enrich/domain/${domain}`, { method: 'POST' }).then(r => r.json());
      enrichData[domain] = data;
      enrichData = enrichData;
    } catch (e) { enrichData[domain] = { error: e.message }; }
    enriching[domain] = false;
    enriching = enriching;
  }

  function exportCsv() {
    window.location.href = `/api/results/${$activeSessionId}/export/csv/ioc`;
  }

  function exportJson() {
    const a = document.createElement('a');
    a.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(ioc, null, 2));
    a.download = 'pcapsentry-ioc.json';
    a.click();
  }
</script>

<div class="ioc-module">
  <div class="header">
    <div class="ioc-tabs">
      <button class="ioc-tab" class:active={tab==='ips'} on:click={() => tab='ips'}>
        IPs <span class="cnt">{ips.length}</span>
      </button>
      <button class="ioc-tab" class:active={tab==='domains'} on:click={() => tab='domains'}>
        Domains <span class="cnt">{domains.length}</span>
      </button>
      <button class="ioc-tab" class:active={tab==='urls'} on:click={() => tab='urls'}>
        URLs <span class="cnt">{urls.length}</span>
      </button>
    </div>
    <div class="header-right">
      <input class="search" type="text" bind:value={search} placeholder="Search…" />
      <button class="export-btn" on:click={exportCsv}>↓ CSV</button>
      <button class="export-btn" on:click={exportJson}>↓ JSON</button>
    </div>
  </div>

  <div class="content">
    {#if tab === 'ips'}
      <table class="ioc-table">
        <thead><tr><th>IP</th><th>Country</th><th>ASN</th><th>Packets</th><th>Bytes</th><th>Enrich</th></tr></thead>
        <tbody>
          {#each filteredIps as ip}
            <tr>
              <td class="ip-cell" on:click={() => focusOnIp(ip.ip)}>{ip.ip}</td>
              <td>{ip.country || '—'}</td>
              <td class="asn">{ip.asn_org || '—'}</td>
              <td>{ip.packet_count}</td>
              <td>{fmt(ip.bytes)}</td>
              <td>
                <button class="enrich-btn" on:click={() => enrichIp(ip.ip)} disabled={enriching[ip.ip]}>
                  {enriching[ip.ip] ? '…' : enrichData[ip.ip] ? '✓' : 'VT'}
                </button>
              </td>
            </tr>
            {#if enrichData[ip.ip]}
              <tr class="enrich-row">
                <td colspan="6">
                  {#if enrichData[ip.ip].error}
                    <span class="enrich-err">{enrichData[ip.ip].error}</span>
                  {:else}
                    <span class="enrich-data">{JSON.stringify(enrichData[ip.ip]).substring(0,200)}…</span>
                  {/if}
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    {/if}

    {#if tab === 'domains'}
      <table class="ioc-table">
        <thead><tr><th>Domain</th><th>Queries</th><th>Answers</th><th>Suspicious</th><th>Enrich</th></tr></thead>
        <tbody>
          {#each filteredDomains as d}
            <tr class:susp={d.is_suspicious}>
              <td class="domain-cell">{d.domain}</td>
              <td>{d.query_count}</td>
              <td class="ans-cell">{d.answers.slice(0,2).join(', ')}</td>
              <td>
                {#if d.is_suspicious}<span class="flag warn">{d.suspicious_reason}</span>{/if}
              </td>
              <td>
                <button class="enrich-btn" on:click={() => enrichDomain(d.domain)} disabled={enriching[d.domain]}>
                  {enriching[d.domain] ? '…' : enrichData[d.domain] ? '✓' : 'VT'}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    {#if tab === 'urls'}
      <table class="ioc-table">
        <thead><tr><th>URL</th><th>Method</th><th>Count</th><th>Suspicious</th></tr></thead>
        <tbody>
          {#each filteredUrls as u}
            <tr class:susp={u.is_suspicious}>
              <td class="url-cell" title={u.url}>{u.url.substring(0,80)}</td>
              <td class="method">{u.method || '—'}</td>
              <td>{u.packet_count}</td>
              <td>{u.is_suspicious ? '⚠' : ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    {#if (tab==='ips' && filteredIps.length===0) || (tab==='domains' && filteredDomains.length===0) || (tab==='urls' && filteredUrls.length===0)}
      <div class="empty">No {tab} found.</div>
    {/if}
  </div>
</div>

<style>
  .ioc-module { display:flex; flex-direction:column; height:100%; }
  .header { display:flex; align-items:center; justify-content:space-between; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); flex-wrap:wrap; gap:0.5rem; }
  .ioc-tabs { display:flex; gap:4px; }
  .ioc-tab { background:none; border:1px solid rgba(255,255,255,0.07); color:#606060; padding:5px 12px; border-radius:4px; font-size:0.78rem; cursor:pointer; display:flex; align-items:center; gap:5px; }
  .ioc-tab.active { color:#c8d8f0; border-color:rgba(255,255,255,0.2); }
  .cnt { background:rgba(255,255,255,0.07); padding:0 5px; border-radius:8px; font-size:0.68rem; }
  .header-right { display:flex; align-items:center; gap:0.5rem; }
  .search { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#f0f0f0; padding:5px 10px; border-radius:5px; font-size:0.8rem; width:180px; }
  .search:focus { outline:none; border-color:rgba(255,255,255,0.15); }
  .export-btn { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.09); color:#c8d8f0; padding:4px 10px; border-radius:4px; font-size:0.75rem; cursor:pointer; }
  .export-btn:hover { background:rgba(255,255,255,0.08); }
  .content { flex:1; overflow:auto; }
  .ioc-table { width:100%; border-collapse:collapse; font-size:0.78rem; }
  thead th { position:sticky; top:0; background:#0a0a0a; color:#606060; text-align:left; padding:6px 10px; border-bottom:1px solid rgba(255,255,255,0.07); }
  tbody tr { border-bottom:1px solid rgba(255,255,255,0.02); }
  tbody tr:hover { background:rgba(200,216,240,0.02); }
  tbody tr.susp { background:rgba(255,165,0,0.04); }
  td { padding:5px 10px; color:#888888; }
  .ip-cell, .domain-cell { color:#c8d8f0; font-family:monospace; cursor:pointer; }
  .ip-cell:hover, .domain-cell:hover { text-decoration:underline; }
  .asn { color:#787878; font-size:0.72rem; max-width:120px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .ans-cell { max-width:140px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:0.72rem; }
  .url-cell { max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:0.72rem; }
  .method { color:#4ade80; font-weight:700; font-size:0.72rem; }
  .flag.warn { color:#c8920a; font-size:0.72rem; }
  .enrich-btn { background:rgba(191,95,255,0.1); border:1px solid rgba(191,95,255,0.2); color:#bf5fff; padding:2px 8px; border-radius:4px; font-size:0.72rem; cursor:pointer; }
  .enrich-btn:disabled { opacity:0.5; cursor:not-allowed; }
  .enrich-btn:hover:not(:disabled) { background:rgba(191,95,255,0.2); }
  .enrich-row td { padding:4px 10px; }
  .enrich-data, .enrich-err { font-family:monospace; font-size:0.72rem; color:#787878; }
  .enrich-err { color:#e03e5a; }
  .empty { color:#606060; text-align:center; padding:3rem; }
</style>
