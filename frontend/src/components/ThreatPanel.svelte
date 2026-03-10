<script>
  import { openInspector, activeSessionId } from '../stores/session.js';

  export let threats = [];

  const sevColor = {
    Critical: '#e03e5a',
    High: '#ffb700',
    Medium: '#c8d8f0',
    Info: '#606060',
  };

  let expanded = {};

  function toggle(i) {
    expanded = { ...expanded, [i]: !expanded[i] };
  }

  function viewPackets(threat, e) {
    e.stopPropagation();
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
      {#each threats as threat, i}
        <div
          class="finding"
          style="border-left-color: {sevColor[threat.severity] || '#606060'}"
          on:click={() => toggle(i)}
          role="button"
          tabindex="0"
          on:keydown={e => e.key === 'Enter' && toggle(i)}
        >
          <div class="finding-top">
            <span
              class="badge"
              class:pulse-critical={threat.severity === 'Critical'}
              style="color: {sevColor[threat.severity]}; background: {sevColor[threat.severity]}18; border-color: {sevColor[threat.severity]}44"
            >
              {threat.severity}
            </span>
            <span class="category">{threat.category}</span>
            <span class="expand-icon">{expanded[i] ? '▲' : '▼'}</span>
          </div>
          <div class="finding-title">{threat.title}</div>
          {#if expanded[i]}
            <div class="finding-desc">{threat.description}</div>
            <div class="finding-footer">
              <button class="view-btn" on:click={e => viewPackets(threat, e)}>
                View Packets ({threat.packet_indices.length})
              </button>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .card {
    background: #111111;
    border: 1px solid rgba(200, 216, 240, 0.18);
    
    border-radius: 2px;
    padding: 1.25rem;
    max-height: 460px;
    overflow-y: auto;
  }
  .card-header {
    font-size: 0.75rem;
    font-weight: 600;
    color: #c8d8f0;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    
  }
  .count {
    background: rgba(255,255,255,0.08);
    color: #c8d8f0;
    border-radius: 999px;
    padding: 0.1rem 0.5rem;
    font-size: 0.75rem;
  }
  .empty {
    color: #4ade80;
    font-size: 0.875rem;
    padding: 1rem 0;
    
  }
  .findings {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .finding {
    border-left: 3px solid;
    padding: 0.7rem 0.75rem 0.7rem 1rem;
    background: rgba(0,0,0,0.3);
    border-radius: 0 6px 6px 0;
    cursor: pointer;
    transition: background 0.15s;
  }
  .finding:hover {
    background: rgba(255,255,255,0.03);
  }
  .finding-top {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.35rem;
  }
  .badge {
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    border: 1px solid;
    letter-spacing: 0.05em;
  }
  .pulse-critical {
    animation: pulse-critical 1.5s ease-in-out infinite;
  }
  @keyframes pulse-critical {
    0%, 100% {  }
    50%       {  }
  }
  .category {
    font-size: 0.72rem;
    color: #606060;
    flex: 1;
  }
  .expand-icon {
    font-size: 0.6rem;
    color: #606060;
  }
  .finding-title {
    font-size: 0.84rem;
    font-weight: 600;
    color: #f0f0f0;
  }
  .finding-desc {
    font-size: 0.78rem;
    color: #606060;
    line-height: 1.5;
    margin-top: 0.4rem;
    margin-bottom: 0.5rem;
  }
  .view-btn {
    font-size: 0.72rem;
    padding: 0.28rem 0.75rem;
    background: transparent;
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 4px;
    color: #c8d8f0;
    cursor: pointer;
    transition: background 0.15s, box-shadow 0.15s;
  }
  .view-btn:hover {
    background: rgba(255,255,255,0.05);
    
  }
</style>
