<script>
  import { openInspector, activeSessionId } from '../stores/session.js';

  export let threats = [];

  const sevColor = {
    Critical: '#f85149',
    High: '#e3b341',
    Medium: '#d29922',
    Info: '#8b949e',
  };

  function viewPackets(threat) {
    openInspector(threat.packet_indices, $activeSessionId);
  }
</script>

<div class="card">
  <div class="card-header">
    Threat Findings
    <span class="count">{threats.length}</span>
  </div>

  {#if threats.length === 0}
    <div class="empty">No threats detected in this capture.</div>
  {:else}
    <div class="findings">
      {#each threats as threat}
        <div
          class="finding"
          style="border-left-color: {sevColor[threat.severity] || '#8b949e'}"
        >
          <div class="finding-top">
            <span class="badge" style="color: {sevColor[threat.severity]}; background: {sevColor[threat.severity]}18; border-color: {sevColor[threat.severity]}33">
              {threat.severity}
            </span>
            <span class="category">{threat.category}</span>
          </div>
          <div class="finding-title">{threat.title}</div>
          <div class="finding-desc">{threat.description}</div>
          <div class="finding-footer">
            <button class="view-btn" on:click={() => viewPackets(threat)}>
              View Packets ({threat.packet_indices.length})
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1.25rem;
    max-height: 420px;
    overflow-y: auto;
  }
  .card-header {
    font-size: 0.8rem;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .count {
    background: #21262d;
    color: #e6edf3;
    border-radius: 999px;
    padding: 0.1rem 0.5rem;
    font-size: 0.75rem;
  }
  .empty {
    color: #8b949e;
    font-size: 0.875rem;
    padding: 1rem 0;
  }
  .findings {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .finding {
    border-left: 3px solid;
    padding: 0.75rem 0.75rem 0.75rem 1rem;
    background: #0d1117;
    border-radius: 0 6px 6px 0;
  }
  .finding-top {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
  }
  .badge {
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    border: 1px solid;
    letter-spacing: 0.05em;
  }
  .category {
    font-size: 0.75rem;
    color: #8b949e;
  }
  .finding-title {
    font-size: 0.875rem;
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 0.35rem;
  }
  .finding-desc {
    font-size: 0.8rem;
    color: #8b949e;
    line-height: 1.5;
    margin-bottom: 0.6rem;
  }
  .view-btn {
    font-size: 0.75rem;
    padding: 0.3rem 0.75rem;
    background: transparent;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #58a6ff;
    cursor: pointer;
    transition: background 0.15s;
  }
  .view-btn:hover {
    background: #21262d;
  }
</style>
