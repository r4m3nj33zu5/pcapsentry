<script>
  import { sessions, loadSession, activeSessionId } from '../stores/session.js';

  let collapsed = false;

  const sevColor = {
    Critical: '#f85149',
    High: '#e3b341',
    Medium: '#d29922',
    Info: '#8b949e',
    None: '#3fb950',
  };
</script>

<aside class="sidebar" class:collapsed>
  <button class="toggle" on:click={() => collapsed = !collapsed} aria-label="Toggle sidebar">
    {collapsed ? '›' : '‹'}
  </button>

  {#if !collapsed}
    <div class="sidebar-header">Sessions</div>
    {#if $sessions.length === 0}
      <div class="empty">No sessions yet</div>
    {:else}
      <div class="session-list">
        {#each $sessions as s}
          <button
            class="session-item"
            class:active={s.session_id === $activeSessionId}
            on:click={() => loadSession(s.session_id)}
          >
            <div class="s-filename">{s.filename}</div>
            <div class="s-meta">
              <span>{(s.total_packets || 0).toLocaleString()} pkts</span>
              {#if s.highest_severity && s.highest_severity !== 'None'}
                <span class="sev-dot" style="color: {sevColor[s.highest_severity]}">●</span>
              {/if}
            </div>
          </button>
        {/each}
      </div>
    {/if}
  {/if}
</aside>

<style>
  .sidebar {
    width: 200px;
    background: #161b22;
    border-right: 1px solid #21262d;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    position: relative;
    transition: width 0.2s;
  }
  .sidebar.collapsed {
    width: 28px;
  }
  .toggle {
    position: absolute;
    top: 12px;
    right: -12px;
    z-index: 10;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: #21262d;
    border: 1px solid #30363d;
    color: #8b949e;
    font-size: 0.85rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0;
  }
  .toggle:hover { color: #e6edf3; }
  .sidebar-header {
    padding: 1rem 0.75rem 0.5rem;
    font-size: 0.7rem;
    font-weight: 700;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    white-space: nowrap;
    overflow: hidden;
  }
  .empty {
    padding: 0.5rem 0.75rem;
    font-size: 0.78rem;
    color: #484f58;
  }
  .session-list {
    overflow-y: auto;
    flex: 1;
  }
  .session-item {
    width: 100%;
    background: none;
    border: none;
    border-bottom: 1px solid #21262d;
    padding: 0.6rem 0.75rem;
    cursor: pointer;
    text-align: left;
  }
  .session-item:hover { background: #21262d; }
  .session-item.active { background: #1f3a5f; }
  .s-filename {
    font-size: 0.78rem;
    color: #e6edf3;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    margin-bottom: 0.2rem;
  }
  .s-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.7rem;
    color: #8b949e;
  }
  .sev-dot { font-size: 0.6rem; }
</style>
