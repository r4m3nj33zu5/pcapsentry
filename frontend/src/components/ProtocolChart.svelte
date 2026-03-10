<script>
  import { onMount, onDestroy } from 'svelte';
  import { Chart, registerables } from 'chart.js';
  import { openInspector, activeResult, activeSessionId } from '../stores/session.js';
  Chart.register(...registerables);

  export let protocols = [];

  let canvas;
  let chart;
  let hoveredLabel = '';
  let hoveredPct = '';

  const COLORS = [
    '#c8d8f0', '#4ade80', '#e03e5a', '#ffb700',
    '#a78bfa', '#f97316', '#06b6d4', '#84cc16',
  ];

  $: chartData = (() => {
    const sorted = [...protocols].sort((a, b) => b.count - a.count);
    const top6 = sorted.slice(0, 6);
    const rest = sorted.slice(6);
    const otherCount = rest.reduce((s, p) => s + p.count, 0);
    const items = otherCount > 0
      ? [...top6, { protocol: 'Other', count: otherCount }]
      : top6;
    const total = items.reduce((s, p) => s + p.count, 0);
    return { items, total };
  })();

  $: if (chart && chartData.items.length) {
    chart.data.labels = chartData.items.map(p => p.protocol);
    chart.data.datasets[0].data = chartData.items.map(p => p.count);
    chart.data.datasets[0].backgroundColor = chartData.items.map((_, i) => COLORS[i % COLORS.length]);
    chart.update();
  }

  function viewProtocol(idx) {
    const label = chart?.data?.labels?.[idx];
    if (!label) return;
    const packets = $activeResult?.packets || [];
    let indices;
    if (label === 'Other') {
      const topProtos = new Set(chartData.items.slice(0, 6).map(p => p.protocol));
      indices = packets.filter(p => !topProtos.has(p.protocol)).map(p => p.index);
    } else {
      indices = packets.filter(p => p.protocol === label).map(p => p.index);
    }
    openInspector(indices, $activeSessionId);
  }

  // Center label plugin
  const centerPlugin = {
    id: 'centerLabel',
    afterDraw(chart) {
      if (!hoveredLabel) return;
      const { ctx, chartArea } = chart;
      const cx = (chartArea.left + chartArea.right) / 2;
      const cy = (chartArea.top + chartArea.bottom) / 2;
      ctx.save();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#f0f0f0';
      ctx.font = 'bold 13px system-ui';
      ctx.fillText(hoveredLabel, cx, cy - 10);
      ctx.fillStyle = '#4ade80';
      ctx.font = 'bold 15px system-ui';
      ctx.fillText(hoveredPct, cx, cy + 10);
      ctx.restore();
    },
  };

  onMount(() => {
    const ctx = canvas.getContext('2d');
    chart = new Chart(ctx, {
      type: 'doughnut',
      plugins: [centerPlugin],
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: [],
          borderColor: '#000000',
          borderWidth: 2,
          hoverBorderWidth: 3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 900, easing: 'easeInOutQuart' },
        cutout: '62%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#606060',
              font: { size: 11 },
              boxWidth: 12,
              padding: 8,
            },
          },
          tooltip: {
            backgroundColor: '#111111',
            borderColor: 'rgba(255,255,255,0.15)',
            borderWidth: 1,
            titleColor: '#f0f0f0',
            bodyColor: '#606060',
            callbacks: {
              label(ctx) {
                const total = ctx.dataset.data.reduce((s, v) => s + v, 0);
                const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : '0';
                return `  ${ctx.parsed.toLocaleString()} pkts (${pct}%)`;
              },
              afterLabel: () => 'Click to inspect',
            },
          },
        },
        onClick: (_, elements) => {
          if (elements.length > 0) viewProtocol(elements[0].index);
        },
        onHover(event, elements) {
          if (event.native?.target) {
            event.native.target.style.cursor = elements.length ? 'pointer' : 'default';
          }
          if (elements.length > 0) {
            const idx = elements[0].index;
            const label = chart.data.labels[idx];
            const val = chart.data.datasets[0].data[idx];
            const total = chart.data.datasets[0].data.reduce((s, v) => s + v, 0);
            hoveredLabel = label;
            hoveredPct = total > 0 ? ((val / total) * 100).toFixed(1) + '%' : '';
          } else {
            hoveredLabel = '';
            hoveredPct = '';
          }
          chart.draw();
        },
      },
    });

    if (chartData.items.length) {
      chart.data.labels = chartData.items.map(p => p.protocol);
      chart.data.datasets[0].data = chartData.items.map(p => p.count);
      chart.data.datasets[0].backgroundColor = chartData.items.map((_, i) => COLORS[i % COLORS.length]);
      chart.update();
    }
  });

  onDestroy(() => {
    if (chart) chart.destroy();
  });
</script>

<div class="card">
  <div class="card-header">Protocol Distribution <span class="hint">· click to inspect</span></div>
  <div class="chart-wrap">
    {#if protocols.length === 0}
      <div class="empty">No protocol data</div>
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
    
  }
  .hint {
    color: #606060;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 400;
    font-size: 0.68rem;
  }
  .chart-wrap {
    height: 220px;
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
