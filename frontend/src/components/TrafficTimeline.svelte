<script>
  import { onMount, onDestroy } from 'svelte';
  import { Chart, registerables } from 'chart.js';
  import { setTimeRange } from '../stores/investigation.js';
  Chart.register(...registerables);

  export let timeline = [];
  export let threats = [];

  let canvas;
  let chart;
  let wrapEl;

  // Drag selection state
  let dragging = false;
  let dragStartX = 0;
  let dragEndX = 0;
  let selectionStyle = '';

  $: if (chart && timeline.length) {
    updateChart();
  }

  function updateChart() {
    const labels = timeline.map(b => {
      const d = new Date(b.timestamp * 1000);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    });
    const packetData = timeline.map(b => b.packet_count);
    const byteData = timeline.map(b => b.byte_count);

    const ctx = canvas.getContext('2d');
    const grad = ctx.createLinearGradient(0, 0, 0, 220);
    grad.addColorStop(0, 'rgba(255,255,255,0.18)');
    grad.addColorStop(1, 'rgba(200,216,240,0.01)');

    chart.data.labels = labels;
    chart.data.datasets[0].data = packetData;
    chart.data.datasets[0].backgroundColor = grad;
    chart.data.datasets[1].data = byteData;
    chart.update();
  }

  function getChartArea() {
    return chart?.chartArea;
  }

  function pixelToTimestamp(px) {
    if (!chart || !timeline.length) return null;
    const area = getChartArea();
    if (!area) return null;
    const ratio = Math.max(0, Math.min(1, (px - area.left) / (area.right - area.left)));
    const idx = Math.round(ratio * (timeline.length - 1));
    const clamped = Math.max(0, Math.min(timeline.length - 1, idx));
    return timeline[clamped]?.timestamp ?? null;
  }

  function onMouseDown(e) {
    if (!chart || !timeline.length) return;
    const rect = wrapEl.getBoundingClientRect();
    const px = e.clientX - rect.left;
    const area = getChartArea();
    if (!area || px < area.left || px > area.right) return;
    dragging = true;
    dragStartX = px;
    dragEndX = px;
    updateSelection();
  }

  function onMouseMove(e) {
    if (!dragging) return;
    const rect = wrapEl.getBoundingClientRect();
    const area = getChartArea();
    dragEndX = Math.max(area?.left ?? 0, Math.min(area?.right ?? 9999, e.clientX - rect.left));
    updateSelection();
  }

  function onMouseUp(e) {
    if (!dragging) return;
    dragging = false;
    selectionStyle = '';
    const ts1 = pixelToTimestamp(Math.min(dragStartX, dragEndX));
    const ts2 = pixelToTimestamp(Math.max(dragStartX, dragEndX));
    if (ts1 !== null && ts2 !== null && Math.abs(dragStartX - dragEndX) > 8) {
      setTimeRange(ts1, ts2);
    }
  }

  function updateSelection() {
    if (!dragging) { selectionStyle = ''; return; }
    const left = Math.min(dragStartX, dragEndX);
    const width = Math.abs(dragEndX - dragStartX);
    selectionStyle = `left:${left}px;width:${width}px;`;
  }

  onMount(() => {
    const ctx = canvas.getContext('2d');
    const grad = ctx.createLinearGradient(0, 0, 0, 220);
    grad.addColorStop(0, 'rgba(255,255,255,0.18)');
    grad.addColorStop(1, 'rgba(200,216,240,0.01)');

    chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Packets/bucket',
            data: [],
            borderColor: '#c8d8f0',
            backgroundColor: grad,
            borderWidth: 2,
            pointRadius: 0,
            fill: true,
            tension: 0.3,
            yAxisID: 'y',
          },
          {
            label: 'Bytes/bucket',
            data: [],
            borderColor: '#e03e5a',
            backgroundColor: 'transparent',
            borderWidth: 1.5,
            borderDash: [4, 3],
            pointRadius: 0,
            fill: false,
            tension: 0.3,
            yAxisID: 'y2',
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 1000, easing: 'easeInOutQuart' },
        plugins: {
          legend: {
            display: true,
            labels: { color: '#606060', font: { size: 11 }, boxWidth: 20 },
          },
          tooltip: {
            backgroundColor: '#111111',
            borderColor: 'rgba(255,255,255,0.15)',
            borderWidth: 1,
            titleColor: '#f0f0f0',
            bodyColor: '#606060',
          },
        },
        scales: {
          x: {
            ticks: { color: '#606060', maxTicksLimit: 8, maxRotation: 0 },
            grid: { color: 'rgba(255,255,255,0.04)' },
          },
          y: {
            ticks: { color: '#606060' },
            grid: { color: 'rgba(255,255,255,0.04)' },
            beginAtZero: true,
          },
          y2: {
            position: 'right',
            ticks: { color: '#e03e5a', font: { size: 10 } },
            grid: { drawOnChartArea: false },
            beginAtZero: true,
          },
        },
      },
    });

    if (timeline.length) updateChart();
  });

  onDestroy(() => {
    if (chart) chart.destroy();
  });
</script>

<div class="card">
  <div class="card-header">
    Traffic Timeline
    <span class="hint">Drag to select time range</span>
  </div>
  <div class="chart-wrap" bind:this={wrapEl}
    on:mousedown={onMouseDown}
    on:mousemove={onMouseMove}
    on:mouseup={onMouseUp}
    on:mouseleave={onMouseUp}
  >
    <canvas bind:this={canvas}></canvas>
    {#if dragging && selectionStyle}
      <div class="drag-selection" style={selectionStyle}></div>
    {/if}
  </div>
</div>

<style>
  .card {
    background: #0a0a0a;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 2px;
    padding: 1.25rem;
  }
  .card-header {
    font-size: 0.68rem;
    font-weight: 700;
    font-family: 'Syne', 'Inter', sans-serif;
    color: #606060;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .hint { color:#2a2a2a; font-size:0.65rem; text-transform:none; letter-spacing:0; font-weight:400; }
  .chart-wrap {
    height: 220px;
    position: relative;
    cursor: crosshair;
    user-select: none;
  }
  .drag-selection {
    position: absolute;
    top: 0;
    height: 100%;
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.15);
    pointer-events: none;
  }
</style>
