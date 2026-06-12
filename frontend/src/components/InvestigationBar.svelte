<script>
  import { investigationFilter, clearInvestigation, focusOnIp, setTimeRange } from '../stores/investigation.js';

  $: filter = $investigationFilter;
  $: hasFilters = filter.focusIp || filter.focusFlow || filter.focusTimeRange ||
                  filter.focusMitreTechnique || filter.focusAlertId || filter.focusPacketSet;

  function removeIp() { investigationFilter.update(f => ({ ...f, focusIp: null })); }
  function removeFlow() { investigationFilter.update(f => ({ ...f, focusFlow: null })); }
  function removeTime() { investigationFilter.update(f => ({ ...f, focusTimeRange: null })); }
  function removeMitre() { investigationFilter.update(f => ({ ...f, focusMitreTechnique: null })); }
  function removeAlert() { investigationFilter.update(f => ({ ...f, focusAlertId: null })); }
  function removePacketSet() { investigationFilter.update(f => ({ ...f, focusPacketSet: null, focusPacketLabel: null })); }

  function fmtTime(ts) {
    if (!ts) return '';
    return new Date(ts * 1000).toLocaleTimeString();
  }
</script>

{#if hasFilters}
<div class="inv-bar">
  <span class="inv-label">🔍 Focusing:</span>

  {#if filter.focusIp}
    <span class="pill pill-ip">
      IP: {filter.focusIp}
      <button class="pill-x" on:click={removeIp}>×</button>
    </span>
  {/if}

  {#if filter.focusFlow}
    <span class="pill pill-flow">
      Flow: {filter.focusFlow.substring(0, 30)}...
      <button class="pill-x" on:click={removeFlow}>×</button>
    </span>
  {/if}

  {#if filter.focusTimeRange}
    <span class="pill pill-time">
      ⏱ {fmtTime(filter.focusTimeRange.start)} – {fmtTime(filter.focusTimeRange.end)}
      <button class="pill-x" on:click={removeTime}>×</button>
    </span>
  {/if}

  {#if filter.focusMitreTechnique}
    <span class="pill pill-mitre">
      MITRE: {filter.focusMitreTechnique}
      <button class="pill-x" on:click={removeMitre}>×</button>
    </span>
  {/if}

  {#if filter.focusAlertId}
    <span class="pill pill-alert">
      Alert: {filter.focusAlertId.substring(0, 8)}...
      <button class="pill-x" on:click={removeAlert}>×</button>
    </span>
  {/if}

  {#if filter.focusPacketSet}
    <span class="pill pill-flow">
      Conversation: {filter.focusPacketLabel || `${filter.focusPacketSet.size} packets`}
      <button class="pill-x" on:click={removePacketSet}>×</button>
    </span>
  {/if}

  <button class="clear-all" on:click={clearInvestigation}>Clear All</button>
</div>
{/if}

<style>
  .inv-bar {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    padding: 5px 16px;
    background: rgba(10,40,80,0.2);
    border-bottom: 1px solid rgba(200,216,240,0.08);
    font-size: 0.75rem;
  }
  .inv-label {
    color: var(--text-muted);
    font-weight: 600;
    font-family: var(--font-ui);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-size: 0.62rem;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: 2px;
    font-size: 0.68rem;
    font-weight: 500;
    font-family: var(--font-ui);
    letter-spacing: 0.04em;
  }
  .pill-ip { background: rgba(200,216,240,0.07); color: var(--accent); border: 1px solid rgba(200,216,240,0.18); }
  .pill-flow { background: rgba(74,222,128,0.07); color: var(--low); border: 1px solid rgba(74,222,128,0.25); }
  .pill-time { background: rgba(200,146,10,0.07); color: var(--medium); border: 1px solid rgba(200,146,10,0.25); }
  .pill-mitre { background: rgba(191,95,255,0.08); color: #bf5fff; border: 1px solid rgba(191,95,255,0.3); }
  .pill-alert { background: rgba(224,62,90,0.07); color: var(--critical); border: 1px solid rgba(224,62,90,0.25); }
  .pill-x {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    font-size: 1rem;
    line-height: 1;
    padding: 0;
    opacity: 0.6;
  }
  .pill-x:hover { opacity: 1; }
  .clear-all {
    background: none;
    border: 1px solid rgba(224,62,90,0.25);
    color: var(--critical);
    padding: 2px 10px;
    border-radius: 2px;
    font-size: 0.62rem;
    font-family: var(--font-ui);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    cursor: pointer;
    margin-left: auto;
    transition: background 0.15s, color 0.15s;
  }
  .clear-all:hover { background: rgba(224,62,90,0.1); }
</style>
