<script>
  export let activeTab = 0;
  export let alertCount = 0;
  export let dispatch;

  const tabs = [
    { id: 0, label: 'Triage', icon: '◈' },
    { id: 1, label: 'Alerts', icon: '⚡', badge: true },
    { id: 2, label: 'Conversations', icon: '⧉' },
    { id: 3, label: 'Flows', icon: '⇌' },
    { id: 4, label: 'DNS', icon: '◎' },
    { id: 5, label: 'HTTP', icon: '⊕' },
    { id: 6, label: 'TLS', icon: '🔒' },
    { id: 7, label: 'IOC', icon: '◉' },
    { id: 8, label: 'Geo', icon: '⊞' },
    { id: 9, label: 'Stats', icon: '≡' },
    { id: 10, label: 'Timeline', icon: '◷' },
    { id: 11, label: 'Packets', icon: '⊟' },
    { id: 12, label: 'Notes', icon: '✎' },
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
    border-bottom: 1px solid var(--border);
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
    padding: 9px 15px;
    background: none;
    border: none;
    border-bottom: 1px solid transparent;
    color: var(--text-dim);
    font-size: 0.66rem;
    font-family: var(--font-ui);
    font-weight: 600;
    letter-spacing: 0.11em;
    text-transform: uppercase;
    cursor: pointer;
    white-space: nowrap;
    transition: color 0.15s, border-color 0.15s, background 0.15s;
    position: relative;
  }
  .tab-btn:hover { color: #808090; background: rgba(255,255,255,0.02); }
  .tab-btn.active {
    color: var(--text);
    border-bottom-color: rgba(200, 216, 240, 0.6);
    background: rgba(10, 40, 80, 0.15);
  }
  .tab-icon { font-style: normal; opacity: 0.4; font-size: 0.85em; }
  .tab-btn.active .tab-icon { opacity: 0.8; }
  .badge {
    background: var(--critical);
    color: #fff;
    font-size: 0.58rem;
    font-weight: 700;
    padding: 1px 5px;
    border-radius: 2px;
    min-width: 16px;
    text-align: center;
    font-family: var(--font-ui);
    letter-spacing: 0.02em;
  }
</style>
