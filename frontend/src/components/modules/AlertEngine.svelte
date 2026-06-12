<script>
  import { focusOnIp, focusOnAlert } from '../../stores/investigation.js';
  import { openInspector } from '../../stores/session.js';
  import { activeSessionId } from '../../stores/session.js';

  export let result;

  $: alerts = result?.alerts || [];

  let filter = 'All';
  let searchTerm = '';
  let selected = null;

  const severities = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info'];

  $: filtered = alerts.filter(a => {
    if (filter !== 'All' && a.severity !== filter) return false;
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      return a.title.toLowerCase().includes(s) || a.description.toLowerCase().includes(s)
        || a.mitre_technique.toLowerCase().includes(s) || a.category.toLowerCase().includes(s);
    }
    return true;
  });

  function sevColor(s) {
    return { Critical:'#e03e5a', High:'#d4622c', Medium:'#c8920a', Low:'#4ade80', Info:'#c8d8f0' }[s] || '#606060';
  }

  function pivotPackets(alert) {
    if ($activeSessionId) openInspector(alert.packet_indices, $activeSessionId);
  }

  function selectAlert(a) {
    selected = selected?.id === a.id ? null : a;
    if (selected) focusOnAlert(a.id, a.mitre_technique);
  }
</script>

<div class="alert-engine">
  <div class="toolbar">
    <div class="filter-tabs">
      {#each severities as sev}
        <button class="sev-tab" class:active={filter === sev}
          on:click={() => filter = sev}
          style={filter === sev ? `border-color:${sevColor(sev)};color:${sevColor(sev)}` : ''}
        >
          {sev}
          {#if sev !== 'All'}
            <span class="sev-count">{alerts.filter(a => a.severity === sev).length}</span>
          {/if}
        </button>
      {/each}
    </div>
    <input class="search" type="text" bind:value={searchTerm} placeholder="Search alerts, MITRE IDs…" />
  </div>

  {#if filtered.length === 0}
    <div class="empty">
      {alerts.length === 0 ? 'No alerts detected in this capture.' : 'No alerts match current filter.'}
    </div>
  {:else}
    <div class="alert-list">
      {#each filtered as alert}
        <div class="alert-row" class:expanded={selected?.id === alert.id}
          on:click={() => selectAlert(alert)}
          style="border-left-color:{sevColor(alert.severity)}"
        >
          <div class="alert-main">
            <div class="alert-header">
              <span class="sev-badge" style="background:{sevColor(alert.severity)}20;color:{sevColor(alert.severity)};border-color:{sevColor(alert.severity)}40">
                {alert.severity}
              </span>
              <span class="alert-title">{alert.title}</span>
              <span class="alert-category">{alert.category}</span>
            </div>
            <div class="alert-meta">
              <span class="mitre-tag">
                <a href={alert.mitre_url} target="_blank" rel="noopener">{alert.mitre_technique}</a>
                · {alert.mitre_technique_name}
              </span>
              <span class="confidence">Conf: {(alert.confidence * 100).toFixed(0)}%</span>
              {#if alert.affected_hosts?.length > 0}
                <span class="hosts">{alert.affected_hosts.join(', ')}</span>
              {/if}
            </div>
          </div>

          {#if selected?.id === alert.id}
            <div class="alert-detail">
              <p class="alert-desc">{alert.description}</p>
              <div class="detail-actions">
                {#if alert.packet_indices?.length > 0}
                  <button class="action-btn" on:click|stopPropagation={() => pivotPackets(alert)}>
                    ⊟ Pivot to Packets ({alert.packet_indices.length})
                  </button>
                {/if}
                {#each (alert.affected_hosts || []) as host}
                  <button class="action-btn host-btn" on:click|stopPropagation={() => focusOnIp(host)}>
                    ◉ Focus on {host}
                  </button>
                {/each}
                <a class="action-btn mitre-link" href={alert.mitre_url} target="_blank" rel="noopener">
                  🔗 MITRE ATT&CK
                </a>
              </div>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .alert-engine { display: flex; flex-direction: column; height: 100%; }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.65rem 1rem;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .filter-tabs { display: flex; gap: 4px; flex-wrap: wrap; }
  .sev-tab {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 3px 10px;
    border-radius: 2px;
    font-size: 0.65rem;
    font-family: var(--font-ui);
    letter-spacing: 0.07em;
    text-transform: uppercase;
    cursor: pointer;
    display: flex; align-items: center; gap: 4px;
    transition: all 0.15s;
  }
  .sev-tab.active { font-weight: 600; }
  .sev-count {
    background: rgba(0,0,0,0.4);
    padding: 0 4px;
    border-radius: 2px;
    font-size: 0.62rem;
    font-family: var(--font-ui);
  }
  .search {
    margin-left: auto;
    background: rgba(10,40,80,0.15);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 5px 10px;
    border-radius: 2px;
    font-size: 0.75rem;
    font-family: var(--font-ui);
    letter-spacing: 0.03em;
    width: 240px;
    transition: border-color 0.15s;
  }
  .search::placeholder { color: var(--text-muted); }
  .search:focus { outline: none; border-color: rgba(200,216,240,0.2); }

  .empty {
    color: var(--text-muted);
    text-align: center;
    padding: 3rem;
    font-family: var(--font-ui);
    letter-spacing: 0.04em;
    font-size: 0.8rem;
  }

  .alert-list { overflow-y: auto; flex: 1; }
  .alert-row {
    border-left: 2px solid #404040;
    padding: 0.6rem 1rem;
    cursor: pointer;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    transition: background 0.12s;
  }
  .alert-row:hover { background: rgba(10,40,80,0.15); }
  .alert-row.expanded { background: rgba(10,40,80,0.2); }

  .alert-header { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .sev-badge {
    padding: 1px 7px; border-radius: 2px; border: 1px solid;
    font-size: 0.6rem; font-weight: 700; flex-shrink: 0;
    text-transform: uppercase; letter-spacing: 0.07em;
    font-family: var(--font-ui);
  }
  .alert-title {
    color: var(--text);
    font-size: 0.82rem;
    font-weight: 500;
    flex: 1;
    font-family: var(--font-body);
  }
  .alert-category {
    color: var(--text-muted);
    font-size: 0.65rem;
    flex-shrink: 0;
    font-family: var(--font-ui);
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  .alert-meta { display: flex; align-items: center; gap: 0.75rem; margin-top: 0.25rem; flex-wrap: wrap; }
  .mitre-tag { color: #bf5fff; font-size: 0.68rem; font-family: var(--font-ui); letter-spacing: 0.03em; }
  .mitre-tag a { color: inherit; text-decoration: none; }
  .mitre-tag a:hover { text-decoration: underline; }
  .confidence { color: var(--text-muted); font-size: 0.65rem; font-family: var(--font-ui); }
  .hosts { color: var(--low); font-size: 0.68rem; font-family: var(--font-ui); letter-spacing: 0.04em; }

  .alert-detail {
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--border);
  }
  .alert-desc {
    color: #808090;
    font-size: 0.78rem;
    line-height: 1.55;
    margin: 0 0 0.75rem;
    font-family: var(--font-body);
  }
  .detail-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }
  .action-btn {
    background: rgba(10,40,80,0.15);
    border: 1px solid rgba(200,216,240,0.12);
    color: var(--accent);
    padding: 4px 12px;
    border-radius: 2px;
    font-size: 0.65rem;
    font-family: var(--font-ui);
    letter-spacing: 0.07em;
    text-transform: uppercase;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: background 0.15s, border-color 0.15s, color 0.15s;
  }
  .action-btn:hover { background: var(--text); color: #000; border-color: var(--text); }
  .host-btn { color: var(--low); border-color: rgba(74,222,128,0.2); background: rgba(74,222,128,0.04); }
  .host-btn:hover { background: var(--low); color: #000; border-color: var(--low); }
  .mitre-link { color: #bf5fff; border-color: rgba(191,95,255,0.2); background: rgba(191,95,255,0.04); }
  .mitre-link:hover { background: #bf5fff; color: #000; border-color: #bf5fff; }
</style>
