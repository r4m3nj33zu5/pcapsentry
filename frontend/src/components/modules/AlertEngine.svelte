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
    padding: 0.75rem 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    flex-wrap: wrap;
  }
  .filter-tabs { display: flex; gap: 4px; flex-wrap: wrap; }
  .sev-tab {
    background: none;
    border: 1px solid rgba(255,255,255,0.07);
    color: #606060;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.75rem;
    cursor: pointer;
    display: flex; align-items: center; gap: 4px;
    transition: all 0.15s;
  }
  .sev-tab.active { font-weight: 600; }
  .sev-count { background: rgba(0,0,0,0.3); padding: 0 4px; border-radius: 2px; font-size: 0.68rem; }
  .search {
    margin-left: auto;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    color: #f0f0f0;
    padding: 5px 10px;
    border-radius: 2px;
    font-size: 0.8rem;
    width: 240px;
  }
  .search:focus { outline: none; border-color: rgba(255,255,255,0.15); }

  .empty { color: #606060; text-align: center; padding: 3rem; }

  .alert-list { overflow-y: auto; flex: 1; }
  .alert-row {
    border-left: 3px solid #606060;
    padding: 0.6rem 1rem;
    cursor: pointer;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    transition: background 0.1s;
  }
  .alert-row:hover { background: rgba(255,255,255,0.02); }
  .alert-row.expanded { background: rgba(255,255,255,0.03); }

  .alert-header { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .sev-badge {
    padding: 1px 7px; border-radius: 4px; border: 1px solid;
    font-size: 0.68rem; font-weight: 700; flex-shrink: 0;
    text-transform: uppercase; letter-spacing: 0.05em;
  }
  .alert-title { color: #f0f0f0; font-size: 0.85rem; font-weight: 500; flex: 1; }
  .alert-category { color: #606060; font-size: 0.72rem; flex-shrink: 0; }

  .alert-meta { display: flex; align-items: center; gap: 0.75rem; margin-top: 0.25rem; flex-wrap: wrap; }
  .mitre-tag { color: #bf5fff; font-size: 0.72rem; }
  .mitre-tag a { color: inherit; text-decoration: none; }
  .mitre-tag a:hover { text-decoration: underline; }
  .confidence { color: #606060; font-size: 0.7rem; }
  .hosts { color: #4ade80; font-size: 0.72rem; font-family: monospace; }

  .alert-detail {
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid rgba(255,255,255,0.04);
  }
  .alert-desc { color: #888888; font-size: 0.8rem; line-height: 1.5; margin: 0 0 0.75rem; }
  .detail-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }
  .action-btn {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.09);
    color: #c8d8f0;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.75rem;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
  }
  .action-btn:hover { background: rgba(255,255,255,0.08); }
  .host-btn { color: #4ade80; border-color: rgba(57,255,20,0.2); background: rgba(57,255,20,0.04); }
  .host-btn:hover { background: rgba(57,255,20,0.08); }
  .mitre-link { color: #bf5fff; border-color: rgba(191,95,255,0.2); background: rgba(191,95,255,0.04); }
</style>
