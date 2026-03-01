<script>
  export let dns = [];
  export let http = [];

  let activeTab = 'dns';
  let dnsFilter = '';
  let httpFilter = '';

  $: filteredDns = dns.filter(e =>
    !dnsFilter || e.name.includes(dnsFilter) || e.src_ip.includes(dnsFilter)
  );

  $: filteredHttp = http.filter(e =>
    !httpFilter ||
    (e.host && e.host.includes(httpFilter)) ||
    (e.path && e.path.includes(httpFilter)) ||
    (e.src_ip && e.src_ip.includes(httpFilter))
  );
</script>

<div class="card">
  <div class="card-header">DNS / HTTP Log</div>
  <div class="tabs">
    <button class="tab" class:active={activeTab === 'dns'} on:click={() => activeTab = 'dns'}>
      DNS <span class="count">{dns.length}</span>
    </button>
    <button class="tab" class:active={activeTab === 'http'} on:click={() => activeTab = 'http'}>
      HTTP <span class="count">{http.length}</span>
    </button>
  </div>

  {#if activeTab === 'dns'}
    <div class="filter-row">
      <input
        class="filter-input"
        bind:value={dnsFilter}
        placeholder="Filter by name or IP…"
      />
    </div>
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Src IP</th>
            <th>Type</th>
            <th>Name</th>
            <th>Answers</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each filteredDns.slice(0, 500) as entry}
            <tr class:suspicious={entry.suspicious}>
              <td class="mono">{entry.timestamp_str.split(' ')[1] || ''}</td>
              <td class="mono">{entry.src_ip}</td>
              <td><span class="tag">{entry.query_type}</span></td>
              <td class="name">{entry.name}</td>
              <td class="answers">{entry.answers.join(', ')}</td>
              <td>
                {#if entry.suspicious}
                  <span class="warn-icon" title={entry.suspicious_reason}>⚠</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="filter-row">
      <input
        class="filter-input"
        bind:value={httpFilter}
        placeholder="Filter by host, path, or IP…"
      />
    </div>
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Src IP</th>
            <th>Method</th>
            <th>Host</th>
            <th>Path</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each filteredHttp.slice(0, 500) as entry}
            <tr class:suspicious={entry.suspicious}>
              <td class="mono">{entry.timestamp_str.split(' ')[1] || ''}</td>
              <td class="mono">{entry.src_ip}</td>
              <td>
                {#if entry.method}
                  <span class="tag method-{entry.method.toLowerCase()}">{entry.method}</span>
                {:else}
                  —
                {/if}
              </td>
              <td>{entry.host || '—'}</td>
              <td class="path">{entry.path || '—'}</td>
              <td>
                {#if entry.status}
                  <span class="status" class:ok={entry.status < 400} class:err={entry.status >= 400}>
                    {entry.status}
                  </span>
                {:else}
                  —
                {/if}
              </td>
              <td>
                {#if entry.suspicious}
                  <span class="warn-icon" title={entry.suspicious_reason}>⚠</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .card-header {
    font-size: 0.8rem;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 0.75rem;
  }
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid #21262d;
  }
  .tab {
    padding: 0.4rem 0.9rem;
    background: none;
    border: none;
    color: #8b949e;
    font-size: 0.85rem;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .tab.active {
    color: #e6edf3;
    border-bottom-color: #58a6ff;
  }
  .count {
    background: #21262d;
    border-radius: 999px;
    padding: 0.1rem 0.45rem;
    font-size: 0.7rem;
    color: #8b949e;
  }
  .filter-row {
    margin-bottom: 0.75rem;
  }
  .filter-input {
    width: 100%;
    max-width: 400px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.4rem 0.75rem;
    color: #e6edf3;
    font-size: 0.85rem;
    outline: none;
  }
  .filter-input:focus {
    border-color: #58a6ff;
  }
  .table-scroll {
    overflow-x: auto;
    max-height: 300px;
    overflow-y: auto;
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
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid #21262d;
    position: sticky;
    top: 0;
    background: #161b22;
  }
  td {
    padding: 0.3rem 0.5rem;
    color: #c9d1d9;
    border-bottom: 1px solid #21262d11;
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  tr.suspicious td { background: rgba(248,81,73,0.04); }
  .mono { font-family: monospace; font-size: 0.73rem; color: #58a6ff; }
  .name { color: #e6edf3; }
  .path { color: #8b949e; }
  .answers { color: #8b949e; max-width: 250px; }
  .tag {
    background: #21262d;
    border-radius: 3px;
    padding: 0.1rem 0.35rem;
    font-size: 0.7rem;
    font-weight: 600;
    color: #e6edf3;
  }
  .method-get { color: #3fb950; }
  .method-post { color: #58a6ff; }
  .method-put { color: #e3b341; }
  .method-delete { color: #f85149; }
  .status { font-weight: 600; }
  .status.ok { color: #3fb950; }
  .status.err { color: #f85149; }
  .warn-icon { color: #e3b341; cursor: help; }
</style>
