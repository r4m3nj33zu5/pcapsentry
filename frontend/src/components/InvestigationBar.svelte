<script>
  import { investigationFilter, clearInvestigation, focusOnIp, setTimeRange } from '../stores/investigation.js';

  $: filter = $investigationFilter;
  $: hasFilters = filter.focusIp || filter.focusFlow || filter.focusTimeRange ||
                  filter.focusMitreTechnique || filter.focusAlertId;

  function removeIp() { investigationFilter.update(f => ({ ...f, focusIp: null })); }
  function removeFlow() { investigationFilter.update(f => ({ ...f, focusFlow: null })); }
  function removeTime() { investigationFilter.update(f => ({ ...f, focusTimeRange: null })); }
  function removeMitre() { investigationFilter.update(f => ({ ...f, focusMitreTechnique: null })); }
  function removeAlert() { investigationFilter.update(f => ({ ...f, focusAlertId: null })); }

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

  <button class="clear-all" on:click={clearInvestigation}>Clear All</button>
</div>
{/if}

<style>
  .inv-bar {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    padding: 6px 16px;
    background: rgba(255,255,255,0.03);
    border-bottom: 1px solid rgba(255,255,255,0.07);
    font-size: 0.78rem;
  }
  .inv-label { color: #606060; font-weight: 600; }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 500;
  }
  .pill-ip { background: rgba(255,255,255,0.08); color: #c8d8f0; border: 1px solid rgba(255,255,255,0.15); }
  .pill-flow { background: rgba(57,255,20,0.1); color: #4ade80; border: 1px solid rgba(57,255,20,0.3); }
  .pill-time { background: rgba(255,165,0,0.1); color: #c8920a; border: 1px solid rgba(255,165,0,0.3); }
  .pill-mitre { background: rgba(138,43,226,0.15); color: #bf5fff; border: 1px solid rgba(138,43,226,0.4); }
  .pill-alert { background: rgba(255,32,121,0.1); color: #e03e5a; border: 1px solid rgba(255,32,121,0.3); }
  .pill-x {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    font-size: 1rem;
    line-height: 1;
    padding: 0;
    opacity: 0.7;
  }
  .pill-x:hover { opacity: 1; }
  .clear-all {
    background: none;
    border: 1px solid rgba(255,32,121,0.3);
    color: #e03e5a;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    cursor: pointer;
    margin-left: auto;
  }
  .clear-all:hover { background: rgba(255,32,121,0.1); }
</style>
