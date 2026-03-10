<script>
  export let activeTab = 0;
  export let alertCount = 0;
  export let dispatch;

  const tabs = [
    { id: 0, label: 'Triage', icon: '◈' },
    { id: 1, label: 'Alerts', icon: '⚡', badge: true },
    { id: 2, label: 'Flows', icon: '⇌' },
    { id: 3, label: 'DNS', icon: '◎' },
    { id: 4, label: 'HTTP', icon: '⊕' },
    { id: 5, label: 'TLS', icon: '🔒' },
    { id: 6, label: 'IOC', icon: '◉' },
    { id: 7, label: 'Geo', icon: '⊞' },
    { id: 8, label: 'Stats', icon: '≡' },
    { id: 9, label: 'Timeline', icon: '◷' },
    { id: 10, label: 'Packets', icon: '⊟' },
    { id: 11, label: 'Notes', icon: '✎' },
  ];
</script>

<nav class="tab-nav">
  {#each tabs as tab}
    <button
      class="tab-btn"
      class:active={activeTab === tab.id}
      on:click={() => dispatch('tabchange', tab.id)}
    >
      <span class="tab-icon">{tab.icon}</span>
      <span class="tab-label">{tab.label}</span>
      {#if tab.badge && alertCount > 0}
        <span class="badge">{alertCount}</span>
      {/if}
    </button>
  {/each}
</nav>

<style>
  .tab-nav {
    display: flex;
    gap: 0;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    background: #000000;
    overflow-x: auto;
    scrollbar-width: none;
    flex-shrink: 0;
  }
  .tab-nav::-webkit-scrollbar { display: none; }

  .tab-btn {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 9px 14px;
    background: none;
    border: none;
    border-bottom: 1px solid transparent;
    color: #404040;
    font-size: 0.7rem;
    font-family: 'Syne', 'Inter', sans-serif;
    font-weight: 600;
    letter-spacing: 0.09em;
    text-transform: uppercase;
    cursor: pointer;
    white-space: nowrap;
    transition: color 0.15s, border-color 0.15s;
    position: relative;
  }
  .tab-btn:hover { color: #a0a0a0; }
  .tab-btn.active {
    color: #f0f0f0;
    border-bottom-color: rgba(255,255,255,0.7);
  }
  .tab-icon { font-style: normal; opacity: 0.5; font-size: 0.85em; }
  .tab-btn.active .tab-icon { opacity: 0.9; }
  .badge {
    background: #e03e5a;
    color: #fff;
    font-size: 0.6rem;
    font-weight: 700;
    padding: 1px 5px;
    border-radius: 2px;
    min-width: 16px;
    text-align: center;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0;
  }
</style>
