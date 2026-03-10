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
    width: 100%;
    height: 100%;
    background: #000000;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    position: relative;
  }
  .sidebar.collapsed {
    width: 0;
  }
  .toggle { display: none; }
  .sidebar-header {
    padding: 1rem 0.75rem 0.5rem;
    font-size: 0.65rem;
    font-weight: 700;
    font-family: 'Syne', 'Inter', sans-serif;
    color: #383838;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    white-space: nowrap;
    overflow: hidden;
  }
  .empty {
    padding: 0.5rem 0.75rem;
    font-size: 0.75rem;
    color: #303030;
    letter-spacing: 0.02em;
  }
  .session-list {
    overflow-y: auto;
    flex: 1;
  }
  .session-item {
    width: 100%;
    background: none;
    border: none;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    padding: 0.6rem 0.75rem;
    cursor: pointer;
    text-align: left;
    transition: background 0.1s;
  }
  .session-item:hover { background: rgba(255,255,255,0.03); }
  .session-item.active { background: rgba(255,255,255,0.04); border-left: 1px solid #c8d8f0; }
  .s-filename {
    font-size: 0.75rem;
    color: #909090;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    margin-bottom: 0.2rem;
  }
  .session-item.active .s-filename { color: #f0f0f0; }
  .s-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.68rem;
    color: #404040;
  }
  .sev-dot { font-size: 0.55rem; }
</style>
