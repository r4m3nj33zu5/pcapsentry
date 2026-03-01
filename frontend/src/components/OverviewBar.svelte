<script>
  export let result;

  $: overview = result?.overview || {};
  $: threats = result?.threats || [];
  $: protocols = result?.protocol_stats || [];

  $: highestSev = (() => {
    for (const t of threats) {
      if (t.severity === 'Critical') return 'Critical';
    }
    for (const t of threats) {
      if (t.severity === 'High') return 'High';
    }
    for (const t of threats) {
      if (t.severity === 'Medium') return 'Medium';
    }
    return threats.length > 0 ? 'Info' : 'None';
  })();

  $: uniqueIps = (() => {
    const ips = new Set();
    (result?.packets || []).forEach(p => {
      if (p.src_ip) ips.add(p.src_ip);
      if (p.dst_ip) ips.add(p.dst_ip);
    });
    return ips.size;
  })();

  $: duration = (() => {
    const d = overview.capture_duration_secs || 0;
    if (d < 60) return `${d.toFixed(2)}s`;
    if (d < 3600) return `${(d / 60).toFixed(1)}m`;
    return `${(d / 3600).toFixed(2)}h`;
  })();

  const sevColor = {
    Critical: '#f85149',
    High: '#e3b341',
    Medium: '#d29922',
    Info: '#8b949e',
    None: '#3fb950',
  };
</script>

<div class="overview-bar">
  <div class="stat-card">
    <div class="label">Total Packets</div>
    <div class="value">{(overview.total_packets || 0).toLocaleString()}</div>
  </div>
  <div class="stat-card">
    <div class="label">Duration</div>
    <div class="value">{duration}</div>
  </div>
  <div class="stat-card">
    <div class="label">Unique IPs</div>
    <div class="value">{uniqueIps.toLocaleString()}</div>
  </div>
  <div class="stat-card">
    <div class="label">Protocols</div>
    <div class="value">{protocols.length}</div>
  </div>
  <div class="stat-card">
    <div class="label">Threats Found</div>
    <div class="value threat-row">
      {threats.length}
      {#if threats.length > 0}
        <span class="sev-badge" style="background: {sevColor[highestSev]}22; color: {sevColor[highestSev]}; border-color: {sevColor[highestSev]}44">
          {highestSev}
        </span>
      {/if}
    </div>
  </div>
</div>

<style>
  .overview-bar {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }
  .stat-card {
    flex: 1;
    min-width: 120px;
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1rem 1.25rem;
  }
  .label {
    font-size: 0.75rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.4rem;
  }
  .value {
    font-size: 1.5rem;
    font-weight: 600;
    color: #e6edf3;
  }
  .threat-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .sev-badge {
    font-size: 0.7rem;
    font-weight: 600;
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
    border: 1px solid;
    letter-spacing: 0.04em;
  }
</style>
