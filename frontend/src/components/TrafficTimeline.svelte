<script>
  import { onMount, onDestroy } from 'svelte';
  import { Chart, registerables } from 'chart.js';
  Chart.register(...registerables);

  export let timeline = [];
  export let threats = [];

  let canvas;
  let chart;

  $: if (chart && timeline.length) {
    updateChart();
  }

  function updateChart() {
    const labels = timeline.map(b => {
      const d = new Date(b.timestamp * 1000);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    });
    const data = timeline.map(b => b.packet_count);

    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.update();
  }

  onMount(() => {
    const ctx = canvas.getContext('2d');
    chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: 'Packets/bucket',
          data: [],
          borderColor: '#58a6ff',
          backgroundColor: 'rgba(88,166,255,0.08)',
          borderWidth: 2,
          pointRadius: 0,
          fill: true,
          tension: 0.3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#161b22',
            borderColor: '#30363d',
            borderWidth: 1,
            titleColor: '#e6edf3',
            bodyColor: '#8b949e',
          },
        },
        scales: {
          x: {
            ticks: { color: '#8b949e', maxTicksLimit: 8, maxRotation: 0 },
            grid: { color: '#21262d' },
          },
          y: {
            ticks: { color: '#8b949e' },
            grid: { color: '#21262d' },
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
  <div class="card-header">Traffic Timeline</div>
  <div class="chart-wrap">
    <canvas bind:this={canvas}></canvas>
  </div>
</div>

<style>
  .card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 1.25rem;
  }
  .card-header {
    font-size: 0.8rem;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 1rem;
  }
  .chart-wrap {
    height: 220px;
    position: relative;
  }
</style>
