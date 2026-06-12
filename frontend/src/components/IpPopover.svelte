<script>
  import { ipPivot, closeIpPivot, focusOnIp } from '../stores/investigation.js';
  import { openInspector, activeSessionId } from '../stores/session.js';

  export let result;

  $: pivot = $ipPivot;
  $: ip = pivot.ip;

  // Compute summary from result data
  $: geo = ip && result?.geo_points?.find(g => g.ip === ip);
  $: alerts = ip ? (result?.alerts || []).filter(a => (a.affected_hosts || []).includes(ip)) : [];
  $: flows = ip ? (result?.flows || []).filter(f => f.src_ip === ip || f.dst_ip === ip) : [];
  $: dnsNames = ip ? (result?.dns_log || [])
    .filter(d => d.client_ip === ip || d.response_ip === ip)
    .map(d => d.query).filter(Boolean).slice(0, 5) : [];
  $: beaconing = ip ? (result?.beaconing || []).filter(b => b.src_ip === ip || b.dst_ip === ip) : [];

  $: highestSev = (() => {
    for (const a of alerts) if (a.severity === 'Critical') return 'Critical';
    for (const a of alerts) if (a.severity === 'High') return 'High';
    for (const a of alerts) if (a.severity === 'Medium') return 'Medium';
    if (alerts.length) return 'Low';
    return null;
  })();

  function sevColor(s) {
    return { Critical:'var(--critical)', High:'var(--high)', Medium:'var(--medium)', Low:'var(--low)' }[s] || '#606070';
  }

  function totalBytes(flows) {
    return flows.reduce((s, f) => s + f.bytes, 0);
  }
  function fmt(b) {
    if (b >= 1e9) return (b/1e9).toFixed(1)+'G';
    if (b >= 1e6) return (b/1e6).toFixed(1)+'M';
    if (b >= 1e3) return (b/1e3).toFixed(1)+'K';
    return b+'';
  }

  function handleFocus() {
    focusOnIp(ip);
    closeIpPivot();
  }

  function handlePackets() {
    const indices = alerts.flatMap(a => a.packet_indices || []).slice(0, 500);
    if (indices.length && $activeSessionId) {
      openInspector(indices, $activeSessionId);
    }
    closeIpPivot();
  }

  // Clamp position to stay within viewport
  let el;
  $: style = ip ? computeStyle(pivot.x, pivot.y) : '';
  function computeStyle(x, y) {
    const w = 300;
    const cx = Math.min(x, window.innerWidth - w - 12);
    return `left:${cx}px;top:${y}px;`;
  }
</script>

{#if ip}
<div class="backdrop" on:click={closeIpPivot}></div>
<div class="popover" {style} bind:this={el}>
  <div class="pop-header">
    <span class="pop-ip">{ip}</span>
    {#if highestSev}
      <span class="sev-dot" style="color:{sevColor(highestSev)};background:{sevColor(highestSev)}18;border:1px solid {sevColor(highestSev)}40">
        {highestSev}
      </span>
    {/if}
    <button class="x-btn" on:click={closeIpPivot}>✕</button>
  </div>

  <div class="pop-body">
    <!-- Geo -->
    {#if geo}
      <div class="pop-row">
        <span class="pop-label">Location</span>
        <span class="pop-value">{[geo.city, geo.country].filter(Boolean).join(', ') || geo.country || '—'}</span>
      </div>
      {#if geo.org}
        <div class="pop-row">
          <span class="pop-label">Org</span>
          <span class="pop-value">{geo.org}</span>
        </div>
      {/if}
    {/if}

    <!-- Flows -->
    <div class="pop-row">
      <span class="pop-label">Flows</span>
      <span class="pop-value">{flows.length} &nbsp;·&nbsp; {fmt(totalBytes(flows))} bytes</span>
    </div>

    <!-- Alerts -->
    <div class="pop-row">
      <span class="pop-label">Alerts</span>
      <span class="pop-value">{alerts.length}</span>
    </div>

    <!-- Beaconing -->
    {#if beaconing.length > 0}
      <div class="pop-row beacon-row">
        <span class="pop-label">Beaconing</span>
        <span class="pop-value beacon-flag">⚡ {beaconing.length} pattern{beaconing.length > 1 ? 's' : ''}</span>
      </div>
    {/if}

    <!-- DNS Names -->
    {#if dnsNames.length > 0}
      <div class="pop-section">
        <span class="pop-label">DNS Names</span>
        <div class="dns-list">
          {#each dnsNames as name}
            <span class="dns-name">{name}</span>
          {/each}
        </div>
      </div>
    {/if}
  </div>

  <div class="pop-actions">
    <button class="action" on:click={handleFocus}>Focus Investigation</button>
    {#if alerts.length > 0}
      <button class="action" on:click={handlePackets}>View Packets</button>
    {/if}
  </div>
</div>
{/if}

<style>
  .backdrop {
    position: fixed; inset: 0;
    z-index: 2000;
  }
  .popover {
    position: fixed;
    width: 300px;
    background: #05050a;
    background-image: linear-gradient(180deg, rgba(10,40,80,0.3) 0%, transparent 50%);
    border: 1px solid rgba(200,216,240,0.15);
    border-radius: 2px;
    z-index: 2001;
    box-shadow: 0 8px 32px rgba(0,0,0,0.6);
    overflow: hidden;
  }
  .pop-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.55rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  .pop-ip {
    font-family: var(--font-ui);
    font-size: 0.8rem;
    font-weight: 700;
    color: var(--text);
    letter-spacing: 0.04em;
    flex: 1;
  }
  .sev-dot {
    font-family: var(--font-ui);
    font-size: 0.58rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    padding: 1px 6px;
    border-radius: 2px;
  }
  .x-btn {
    background: none; border: none;
    color: var(--text-muted); cursor: pointer;
    font-size: 0.85rem; padding: 0 2px;
    transition: color 0.15s;
  }
  .x-btn:hover { color: var(--text); }
  .pop-body { padding: 0.5rem 0.75rem; }
  .pop-row {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    padding: 0.2rem 0;
  }
  .pop-label {
    font-family: var(--font-ui);
    font-size: 0.58rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-muted);
    width: 60px;
    flex-shrink: 0;
  }
  .pop-value {
    font-family: var(--font-ui);
    font-size: 0.75rem;
    color: var(--text);
    letter-spacing: 0.02em;
  }
  .beacon-flag {
    color: var(--high);
    font-weight: 600;
  }
  .pop-section {
    padding: 0.2rem 0;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .dns-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-top: 2px;
  }
  .dns-name {
    font-family: var(--font-ui);
    font-size: 0.7rem;
    color: var(--accent);
    letter-spacing: 0.02em;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .pop-actions {
    display: flex;
    gap: 0.4rem;
    padding: 0.5rem 0.75rem;
    border-top: 1px solid var(--border);
  }
  .action {
    flex: 1;
    background: transparent;
    border: 1px solid rgba(255,255,255,0.12);
    color: #888898;
    padding: 4px 8px;
    border-radius: 2px;
    font-size: 0.62rem;
    font-family: var(--font-ui);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    cursor: pointer;
    transition: background 0.2s, color 0.2s, border-color 0.2s;
  }
  .action:hover { background: var(--text); color: #000; border-color: var(--text); }
</style>
