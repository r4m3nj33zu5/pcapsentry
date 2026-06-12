<script>
  export let candidates = [];

  function fmtInterval(s) {
    if (s >= 3600) return (s / 3600).toFixed(1) + 'h';
    if (s >= 60) return (s / 60).toFixed(1) + 'm';
    return s.toFixed(1) + 's';
  }

  function confColor(c) {
    if (c >= 0.9) return 'var(--critical)';
    if (c >= 0.75) return 'var(--high)';
    if (c >= 0.55) return 'var(--medium)';
    return '#606070';
  }

  function confLabel(c) {
    if (c >= 0.9) return 'Very High';
    if (c >= 0.75) return 'High';
    if (c >= 0.55) return 'Medium';
    return 'Low';
  }
</script>

<div class="beacon-panel">
  <div class="panel-title">Beaconing Candidates</div>
  {#if candidates.length === 0}
    <div class="empty">No beaconing patterns detected.</div>
  {:else}
    <div class="list">
      {#each candidates as c}
        <div class="beacon-row">
          <div class="beacon-header">
            <span class="ip src">{c.src_ip}</span>
            <span class="arrow">→</span>
            <span class="ip dst">{c.dst_ip}:{c.dst_port}</span>
            <span class="proto">{c.protocol}</span>
            <span class="conf-badge" style="color:{confColor(c.confidence)};border-color:{confColor(c.confidence)}40;background:{confColor(c.confidence)}10">
              {confLabel(c.confidence)}
            </span>
          </div>
          <div class="beacon-meta">
            <span class="meta-item"><span class="ml">Interval</span> {fmtInterval(c.mean_interval_secs)}</span>
            <span class="meta-item"><span class="ml">Jitter</span> {c.jitter_pct}%</span>
            <span class="meta-item"><span class="ml">Connections</span> {c.connection_count}</span>
            <span class="meta-item"><span class="ml">Duration</span> {fmtInterval(c.total_duration_secs)}</span>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .beacon-panel {
    background: rgba(10,40,80,0.1);
    border: 1px solid var(--border);
    border-radius: 2px;
  }
  .panel-title {
    font-family: var(--font-ui);
    font-size: 0.62rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 0.6rem 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  .empty {
    color: var(--text-muted);
    font-size: 0.75rem;
    font-family: var(--font-ui);
    padding: 0.75rem 0.85rem;
  }
  .list { display: flex; flex-direction: column; }
  .beacon-row {
    padding: 0.55rem 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  .beacon-row:last-child { border-bottom: none; }
  .beacon-header {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    flex-wrap: wrap;
    margin-bottom: 0.3rem;
  }
  .ip {
    font-family: var(--font-ui);
    font-size: 0.78rem;
    letter-spacing: 0.03em;
  }
  .src { color: var(--accent); }
  .dst { color: var(--text); }
  .arrow { color: var(--text-muted); font-size: 0.7rem; }
  .proto {
    font-family: var(--font-ui);
    font-size: 0.6rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #bf5fff;
    background: rgba(191,95,255,0.08);
    border: 1px solid rgba(191,95,255,0.2);
    border-radius: 2px;
    padding: 1px 5px;
  }
  .conf-badge {
    font-family: var(--font-ui);
    font-size: 0.58rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    border: 1px solid;
    border-radius: 2px;
    padding: 1px 6px;
    margin-left: auto;
  }
  .beacon-meta {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .meta-item {
    display: flex;
    flex-direction: column;
    gap: 1px;
    font-family: var(--font-ui);
    font-size: 0.75rem;
    color: var(--text);
    font-weight: 600;
  }
  .ml {
    font-size: 0.55rem;
    color: var(--text-muted);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-weight: 400;
  }
</style>
