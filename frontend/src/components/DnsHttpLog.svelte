<script>
  import { openInspector, activeSessionId } from '../stores/session.js';

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

  function viewDnsPacket(entry) {
    openInspector([entry.packet_index], $activeSessionId);
  }

  function viewHttpPacket(entry) {
    openInspector([entry.packet_index], $activeSessionId);
  }
</script>

<div class="card">
  <div class="card-header">DNS / HTTP Log <span class="hint">· click row to inspect packet</span></div>
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
            <tr class:suspicious={entry.suspicious} class="clickable" on:click={() => viewDnsPacket(entry)}>
              <td class="mono">{entry.timestamp_str.split(' ')[1] || ''}</td>
              <td class="mono">{entry.src_ip}</td>
              <td><span class="tag">{entry.query_type}</span></td>
              <td class="name">{entry.name}</td>
              <td class="answers">{entry.answers.join(', ')}</td>
              <td>
                {#if entry.suspicious}
                  <span class="warn-icon" title={entry.suspicious_reason}>⚠</span>
                {:else}
                  <span class="inspect-icon">⬡</span>
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
            <tr class:suspicious={entry.suspicious} class="clickable" on:click={() => viewHttpPacket(entry)}>
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
                {:else}
                  <span class="inspect-icon">⬡</span>
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
    background: #111111;
    border: 1px solid rgba(200, 216, 240, 0.18);
    
    border-radius: 2px;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .card-header {
    font-size: 0.75rem;
    font-weight: 600;
    color: #c8d8f0;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.75rem;
    
  }
  .hint {
    color: #606060;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 400;
    font-size: 0.68rem;
  }
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
  }
  .tab {
    padding: 0.4rem 0.9rem;
    background: none;
    border: none;
    color: #606060;
    font-size: 0.85rem;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    display: flex;
    align-items: center;
    gap: 0.4rem;
    transition: color 0.15s;
  }
  .tab.active {
    color: #c8d8f0;
    border-bottom-color: #c8d8f0;
    
  }
  .count {
    background: rgba(255,255,255,0.07);
    border-radius: 999px;
    padding: 0.1rem 0.45rem;
    font-size: 0.7rem;
    color: #606060;
  }
  .filter-row { margin-bottom: 0.75rem; }
  .filter-input {
    width: 100%;
    max-width: 400px;
    background: rgba(0,0,0,0.4);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 2px;
    padding: 0.4rem 0.75rem;
    color: #f0f0f0;
    font-size: 0.85rem;
    outline: none;
  }
  .filter-input:focus {
    border-color: #c8d8f0;
    
  }
  .table-scroll { overflow-x: auto; max-height: 300px; overflow-y: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.76rem; }
  th {
    color: #606060;
    font-weight: 500;
    text-align: left;
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
    position: sticky;
    top: 0;
    background: #111111;
  }
  td {
    padding: 0.3rem 0.5rem;
    color: #f0f0f0;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  tr.clickable { cursor: pointer; transition: background 0.1s; }
  tr.clickable:hover td { background: rgba(255,255,255,0.04); }
  tr.suspicious td { background: rgba(255,32,121,0.05); }
  tr.suspicious.clickable:hover td { background: rgba(255,32,121,0.1); }
  .mono { font-family: monospace; font-size: 0.71rem; color: #c8d8f0; }
  .name { color: #f0f0f0; }
  .path { color: #606060; }
  .answers { color: #606060; max-width: 250px; }
  .tag {
    background: rgba(255,255,255,0.07);
    border-radius: 3px;
    padding: 0.1rem 0.35rem;
    font-size: 0.68rem;
    font-weight: 600;
    color: #c8d8f0;
  }
  .method-get    { color: #4ade80; }
  .method-post   { color: #c8d8f0; }
  .method-put    { color: #ffb700; }
  .method-delete { color: #e03e5a; }
  .status { font-weight: 600; }
  .status.ok  { color: #4ade80; }
  .status.err { color: #e03e5a; }
  .warn-icon    { color: #ffb700; cursor: help; }
  .inspect-icon { color: #1a3a5c; font-size: 0.7rem; }
  tr.clickable:hover .inspect-icon { color: #606060; }
</style>
