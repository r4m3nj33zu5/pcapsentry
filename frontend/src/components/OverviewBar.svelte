<script>
  import { onMount } from 'svelte';
  export let result;

  $: overview = result?.overview || {};
  $: threats = result?.threats || [];
  $: protocols = result?.protocol_stats || [];
  $: sizeStats = result?.packet_size_stats || {};

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

  function fmtBytes(b) {
    if (!b) return '0 B';
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
    if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  const sevColor = {
    Critical: '#e03e5a',
    High: '#ffb700',
    Medium: '#c8d8f0',
    Info: '#606060',
    None: '#4ade80',
  };

  // Animated count-up
  let displayValues = {};
  let animFrame;

  $: stats = [
    { key: 'packets', label: 'Total Packets', raw: overview.total_packets || 0, fmt: v => Math.round(v).toLocaleString() },
    { key: 'duration', label: 'Duration', raw: null, fmt: () => duration },
    { key: 'ips', label: 'Unique IPs', raw: uniqueIps, fmt: v => Math.round(v).toLocaleString() },
    { key: 'protocols', label: 'Protocols', raw: protocols.length, fmt: v => Math.round(v) },
    { key: 'threats', label: 'Threats Found', raw: threats.length, fmt: v => Math.round(v) },
    { key: 'bytes', label: 'Total Bytes', raw: Number(sizeStats.total_bytes) || 0, fmt: v => fmtBytes(Math.round(v)) },
    { key: 'avgsize', label: 'Avg Packet Size', raw: sizeStats.avg || 0, fmt: v => Math.round(v) + ' B' },
  ];

  function animateTo(targets) {
    if (animFrame) cancelAnimationFrame(animFrame);
    const start = performance.now();
    const duration_ms = 1200;

    const startVals = {};
    for (const s of targets) {
      startVals[s.key] = 0;
    }

    function ease(t) {
      return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
    }

    function step(now) {
      const elapsed = now - start;
      const t = Math.min(elapsed / duration_ms, 1);
      const e = ease(t);
      const next = {};
      for (const s of targets) {
        if (s.raw === null) {
          next[s.key] = s.fmt(0);
        } else {
          next[s.key] = s.fmt(s.raw * e);
        }
      }
      displayValues = next;
      if (t < 1) {
        animFrame = requestAnimationFrame(step);
      }
    }
    animFrame = requestAnimationFrame(step);
  }

  $: if (stats.length) animateTo(stats);
</script>

<div class="overview-bar">
  {#each stats as s}
    <div class="stat-card" class:critical={s.key === 'threats' && highestSev === 'Critical'}>
      <div class="label">{s.label}</div>
      <div class="value">
        {displayValues[s.key] ?? (s.raw === null ? s.fmt(0) : '0')}
        {#if s.key === 'threats' && threats.length > 0}
          <span class="sev-badge" class:pulse-critical={highestSev === 'Critical'}
            style="background: {sevColor[highestSev]}22; color: {sevColor[highestSev]}; border-color: {sevColor[highestSev]}55">
            {highestSev}
          </span>
        {/if}
      </div>
    </div>
  {/each}
</div>

<style>
  .overview-bar {
    display: flex;
    gap: 0.6rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }
  .stat-card {
    flex: 1;
    min-width: 110px;
    background: #111111;
    border: 1px solid rgba(200, 216, 240, 0.18);
    
    border-radius: 2px;
    padding: 0.9rem 1.1rem;
    transition: box-shadow 0.3s;
  }
  .stat-card:hover {
    
  }
  .stat-card.critical {
    border-color: rgba(255,32,121,0.4);
    
  }
  .label {
    font-size: 0.7rem;
    color: #606060;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 0.4rem;
  }
  .value {
    font-size: 1.4rem;
    font-weight: 700;
    color: #4ade80;
    
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .sev-badge {
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
    border: 1px solid;
    letter-spacing: 0.05em;
    text-shadow: none;
  }
  .pulse-critical {
    animation: pulse-critical 1.5s ease-in-out infinite;
  }
  @keyframes pulse-critical {
    0%, 100% {  }
    50%       {  }
  }
</style>
