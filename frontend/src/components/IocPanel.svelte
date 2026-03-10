<script>
  export let geoPoints = [];
  export let dnsLog = [];
  export let httpLog = [];
  export let threats = [];

  let activeTab = 'ips';
  let copied = '';

  $: threatIps = new Set(
    threats.flatMap(t => {
      const m = t.description.match(/\d{1,3}(?:\.\d{1,3}){3}/g) || [];
      return m;
    })
  );

  $: iocs = (() => {
    // IPs: from geo points (public IPs)
    const ips = geoPoints.map(p => ({
      value: p.ip,
      meta: [p.city, p.country].filter(Boolean).join(', ') || 'External',
      isThreat: threatIps.has(p.ip),
      packets: p.packet_count,
    })).sort((a, b) => (b.isThreat ? 1 : 0) - (a.isThreat ? 1 : 0) || b.packets - a.packets);

    // Domains: unique names from DNS log
    const domainMap = new Map();
    for (const e of dnsLog) {
      if (!e.name) continue;
      const key = e.name;
      if (!domainMap.has(key)) {
        domainMap.set(key, { value: key, suspicious: e.suspicious, reason: e.suspicious_reason, count: 0 });
      }
      domainMap.get(key).count++;
    }
    const domains = [...domainMap.values()].sort((a, b) => (b.suspicious ? 1 : 0) - (a.suspicious ? 1 : 0) || b.count - a.count);

    // URLs: from HTTP log
    const urlSet = new Map();
    for (const e of httpLog) {
      if (!e.host) continue;
      const url = e.host + (e.path || '');
      if (!urlSet.has(url)) {
        urlSet.set(url, { value: url, suspicious: e.suspicious, reason: e.suspicious_reason, method: e.method, count: 0 });
      }
      urlSet.get(url).count++;
    }
    const urls = [...urlSet.values()].sort((a, b) => (b.suspicious ? 1 : 0) - (a.suspicious ? 1 : 0) || b.count - a.count);

    return { ips, domains, urls };
  })();

  function copyAll() {
    const tab = activeTab;
    let text = '';
    if (tab === 'ips') text = iocs.ips.map(i => i.value).join('\n');
    else if (tab === 'domains') text = iocs.domains.map(d => d.value).join('\n');
    else text = iocs.urls.map(u => u.value).join('\n');
    navigator.clipboard.writeText(text).then(() => {
      copied = tab;
      setTimeout(() => (copied = ''), 2000);
    });
  }

  function copyOne(val) {
    navigator.clipboard.writeText(val).then(() => {
      copied = val;
      setTimeout(() => (copied = ''), 1500);
    });
  }
</script>

<div class="card">
  <div class="card-header">
    <span>Indicators of Compromise</span>
    <div class="header-right">
      <button class="copy-btn" on:click={copyAll}>
        {copied ? '✓ Copied' : 'Copy List'}
      </button>
    </div>
  </div>

  <div class="tabs">
    <button class="tab" class:active={activeTab === 'ips'} on:click={() => activeTab = 'ips'}>
      IPs <span class="badge" class:threat={iocs.ips.some(i => i.isThreat)}>{iocs.ips.length}</span>
    </button>
    <button class="tab" class:active={activeTab === 'domains'} on:click={() => activeTab = 'domains'}>
      Domains <span class="badge" class:threat={iocs.domains.some(d => d.suspicious)}>{iocs.domains.length}</span>
    </button>
    <button class="tab" class:active={activeTab === 'urls'} on:click={() => activeTab = 'urls'}>
      URLs <span class="badge" class:threat={iocs.urls.some(u => u.suspicious)}>{iocs.urls.length}</span>
    </button>
  </div>

  <div class="list-scroll">
    {#if activeTab === 'ips'}
      {#each iocs.ips as item}
        <div class="ioc-row" class:threat={item.isThreat}>
          <div class="ioc-left">
            <span class="ioc-icon">{item.isThreat ? '⚠' : '●'}</span>
            <div class="ioc-vals">
              <span class="ioc-value mono">{item.value}</span>
              <span class="ioc-meta">{item.meta} · {item.packets.toLocaleString()} pkts</span>
            </div>
          </div>
          <button class="row-copy" on:click={() => copyOne(item.value)} title="Copy">
            {copied === item.value ? '✓' : '⎘'}
          </button>
        </div>
      {/each}
      {#if iocs.ips.length === 0}
        <div class="empty">No external IPs (geo DB required)</div>
      {/if}

    {:else if activeTab === 'domains'}
      {#each iocs.domains.slice(0, 200) as item}
        <div class="ioc-row" class:threat={item.suspicious}>
          <div class="ioc-left">
            <span class="ioc-icon">{item.suspicious ? '⚠' : '●'}</span>
            <div class="ioc-vals">
              <span class="ioc-value">{item.value}</span>
              {#if item.reason}<span class="ioc-meta warn">{item.reason}</span>{:else}<span class="ioc-meta">{item.count} queries</span>{/if}
            </div>
          </div>
          <button class="row-copy" on:click={() => copyOne(item.value)} title="Copy">
            {copied === item.value ? '✓' : '⎘'}
          </button>
        </div>
      {/each}
      {#if iocs.domains.length === 0}<div class="empty">No DNS domains captured</div>{/if}

    {:else}
      {#each iocs.urls.slice(0, 200) as item}
        <div class="ioc-row" class:threat={item.suspicious}>
          <div class="ioc-left">
            <span class="ioc-icon">{item.suspicious ? '⚠' : '●'}</span>
            <div class="ioc-vals">
              <span class="ioc-value">{item.value}</span>
              {#if item.reason}<span class="ioc-meta warn">{item.reason}</span>{:else}<span class="ioc-meta">{item.method || ''} · {item.count}×</span>{/if}
            </div>
          </div>
          <button class="row-copy" on:click={() => copyOne(item.value)} title="Copy">
            {copied === item.value ? '✓' : '⎘'}
          </button>
        </div>
      {/each}
      {#if iocs.urls.length === 0}<div class="empty">No HTTP URLs captured</div>{/if}
    {/if}
  </div>
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
    margin-bottom: 0.75rem;
    
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .header-right { display: flex; gap: 0.5rem; }
  .copy-btn {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 2px;
    color: #c8d8f0;
    font-size: 0.68rem;
    padding: 0.2rem 0.6rem;
    cursor: pointer;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 500;
    transition: all 0.15s;
  }
  .copy-btn:hover { background: rgba(255,255,255,0.09); }
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
  }
  .tab {
    padding: 0.35rem 0.75rem;
    background: none;
    border: none;
    color: #606060;
    font-size: 0.8rem;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    display: flex;
    align-items: center;
    gap: 0.35rem;
    transition: color 0.15s;
  }
  .tab.active { color: #c8d8f0; border-bottom-color: #c8d8f0; }
  .badge {
    background: rgba(255,255,255,0.07);
    border-radius: 999px;
    padding: 0.05rem 0.4rem;
    font-size: 0.65rem;
    color: #606060;
  }
  .badge.threat { background: rgba(255,32,121,0.15); color: #e03e5a; }
  .list-scroll { max-height: 280px; overflow-y: auto; }
  .ioc-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.38rem 0.3rem;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    border-radius: 4px;
    transition: background 0.1s;
  }
  .ioc-row:hover { background: rgba(255,255,255,0.03); }
  .ioc-row.threat { background: rgba(255,32,121,0.04); }
  .ioc-row.threat:hover { background: rgba(255,32,121,0.08); }
  .ioc-left { display: flex; align-items: center; gap: 0.5rem; min-width: 0; }
  .ioc-icon {
    font-size: 0.55rem;
    color: #606060;
    flex-shrink: 0;
  }
  .ioc-row.threat .ioc-icon { color: #e03e5a; font-size: 0.75rem; }
  .ioc-vals { display: flex; flex-direction: column; gap: 0.05rem; min-width: 0; }
  .ioc-value {
    font-size: 0.76rem;
    color: #f0f0f0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ioc-value.mono { font-family: monospace; color: #c8d8f0; }
  .ioc-row.threat .ioc-value { color: #ff8080; }
  .ioc-meta { font-size: 0.65rem; color: #606060; }
  .ioc-meta.warn { color: #ffb700; }
  .row-copy {
    background: none;
    border: none;
    color: #606060;
    cursor: pointer;
    padding: 0.2rem 0.4rem;
    font-size: 0.75rem;
    border-radius: 3px;
    transition: all 0.12s;
    flex-shrink: 0;
  }
  .row-copy:hover { color: #c8d8f0; background: rgba(255,255,255,0.05); }
  .empty { color: #606060; font-size: 0.8rem; padding: 1rem 0; text-align: center; }
</style>
