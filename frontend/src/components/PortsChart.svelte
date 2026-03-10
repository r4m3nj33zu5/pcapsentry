<script>
  import { onMount, onDestroy } from 'svelte';
  import { Chart, registerables } from 'chart.js';
  import { openInspector, activeResult, activeSessionId } from '../stores/session.js';
  Chart.register(...registerables);

  export let topPorts = [];

  let canvas;
  let chart;

  const SAFE_PORTS = new Set([80, 443, 53, 22, 8443]);
  const NOTABLE_PORTS = new Set([8080, 25, 21, 587, 143, 110, 3306, 5432, 3389]);
  const SUSPICIOUS_PORTS = new Set([4444, 31337, 23, 12345, 6666, 6667, 1337]);

  function portColor(port) {
    if (SUSPICIOUS_PORTS.has(port)) return '#e03e5a';
    if (NOTABLE_PORTS.has(port)) return '#ffb700';
    return '#c8d8f0';
  }

  $: chartItems = topPorts.slice(0, 15);

  $: if (chart && chartItems.length) {
    chart.data.labels = chartItems.map(p => `${p.port} ${p.service !== 'Unknown' ? p.service : ''}`);
    chart.data.datasets[0].data = chartItems.map(p => p.packet_count);
    chart.data.datasets[0].backgroundColor = chartItems.map(p => portColor(p.port) + 'cc');
    chart.data.datasets[0].borderColor = chartItems.map(p => portColor(p.port));
    chart.update();
  }

  function viewPort(portIdx) {
    const port = chartItems[portIdx]?.port;
    if (port == null) return;
    const packets = $activeResult?.packets || [];
    const indices = packets
      .filter(p => p.src_port === port || p.dst_port === port)
      .map(p => p.index);
    openInspector(indices, $activeSessionId);
  }

  onMount(() => {
    const ctx = canvas.getContext('2d');
    chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: [],
        datasets: [{
          label: 'Packets',
          data: [],
          backgroundColor: [],
          borderColor: [],
          borderWidth: 1,
          borderRadius: 3,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 900, easing: 'easeInOutQuart' },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#111111',
            borderColor: 'rgba(255,255,255,0.15)',
            borderWidth: 1,
            titleColor: '#f0f0f0',
            bodyColor: '#606060',
            callbacks: {
              afterLabel: () => 'Click to inspect packets',
            },
          },
        },
        onClick: (_, elements) => {
          if (elements.length > 0) viewPort(elements[0].index);
        },
        onHover: (event, elements) => {
          event.native.target.style.cursor = elements.length ? 'pointer' : 'default';
        },
        scales: {
          x: {
            ticks: { color: '#606060', font: { size: 10 } },
            grid: { color: 'rgba(255,255,255,0.04)' },
            beginAtZero: true,
          },
          y: {
            ticks: { color: '#f0f0f0', font: { size: 11 } },
            grid: { color: 'rgba(255,255,255,0.03)' },
          },
        },
      },
    });

    if (chartItems.length) {
      chart.data.labels = chartItems.map(p => `${p.port} ${p.service !== 'Unknown' ? p.service : ''}`);
      chart.data.datasets[0].data = chartItems.map(p => p.packet_count);
      chart.data.datasets[0].backgroundColor = chartItems.map(p => portColor(p.port) + 'cc');
      chart.data.datasets[0].borderColor = chartItems.map(p => portColor(p.port));
      chart.update();
    }
  });

  onDestroy(() => {
    if (chart) chart.destroy();
  });
</script>

<div class="card">
  <div class="card-header">
    Top Destination Ports
    <span class="hint">· click bar to inspect</span>
    <span class="legend">
      <span class="dot cyan"></span>Safe
      <span class="dot amber"></span>Notable
      <span class="dot magenta"></span>Suspicious
    </span>
  </div>
  <div class="chart-wrap">
    {#if topPorts.length === 0}
      <div class="empty">No port data available</div>
    {:else}
      <canvas bind:this={canvas}></canvas>
    {/if}
  </div>
</div>

<style>
  .card {
    background: #111111;
    border: 1px solid rgba(200, 216, 240, 0.18);
    
    border-radius: 2px;
    padding: 1.25rem;
  }
  .card-header {
    font-size: 0.75rem;
    font-weight: 600;
    color: #c8d8f0;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    
    flex-wrap: wrap;
  }
  .hint {
    color: #606060;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 400;
    font-size: 0.68rem;
  }
  .legend {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.68rem;
    color: #606060;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    margin-left: auto;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }
  .dot.cyan    { background: #c8d8f0; }
  .dot.amber   { background: #ffb700; }
  .dot.magenta { background: #e03e5a; }
  .chart-wrap {
    height: 280px;
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .empty {
    color: #606060;
    font-size: 0.875rem;
  }
</style>
