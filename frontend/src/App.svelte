<script>
  import { activeResult, loading, uploadProgress, inspectorOpen } from './stores/session.js';
  import UploadZone from './components/UploadZone.svelte';
  import OverviewBar from './components/OverviewBar.svelte';
  import TrafficTimeline from './components/TrafficTimeline.svelte';
  import TopTalkers from './components/TopTalkers.svelte';
  import ThreatPanel from './components/ThreatPanel.svelte';
  import GeoMap from './components/GeoMap.svelte';
  import DnsHttpLog from './components/DnsHttpLog.svelte';
  import PacketInspector from './components/PacketInspector.svelte';
  import SessionHistory from './components/SessionHistory.svelte';
</script>

<div class="app-shell">
  <SessionHistory />

  <main class="main-content">
    {#if $loading}
      <div class="loading-screen">
        <div class="loading-inner">
          <div class="logo">PcapSentry</div>
          <div class="progress-bar-wrap">
            <div class="progress-bar-fill" style="width: {$uploadProgress}%"></div>
          </div>
          <div class="progress-label">{$uploadProgress < 100 ? 'Parsing capture…' : 'Building analysis…'}</div>
        </div>
      </div>
    {:else if $activeResult}
      <div class="dashboard">
        <header class="dash-header">
          <span class="logo">PcapSentry</span>
          <span class="filename">{$activeResult.overview?.filename}</span>
        </header>
        <OverviewBar result={$activeResult} />
        <div class="grid-row two-col">
          <TrafficTimeline timeline={$activeResult.timeline} threats={$activeResult.threats} />
          <ThreatPanel threats={$activeResult.threats} />
        </div>
        <div class="grid-row two-col">
          <TopTalkers senders={$activeResult.top_senders} receivers={$activeResult.top_receivers} />
          <GeoMap points={$activeResult.geo_points} threats={$activeResult.threats} />
        </div>
        <DnsHttpLog dns={$activeResult.dns_log} http={$activeResult.http_log} />
      </div>
    {:else}
      <div class="upload-screen">
        <div class="upload-logo">
          <div class="logo-mark">⬡</div>
          <h1>PcapSentry</h1>
          <p>Drop a .pcap or .pcapng file to begin analysis</p>
        </div>
        <UploadZone />
      </div>
    {/if}
  </main>

  {#if $inspectorOpen}
    <PacketInspector />
  {/if}
</div>

<style>
  .app-shell {
    display: flex;
    min-height: 100vh;
    position: relative;
  }
  .main-content {
    flex: 1;
    overflow-y: auto;
    min-width: 0;
  }
  .upload-screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    gap: 2rem;
  }
  .upload-logo {
    text-align: center;
  }
  .logo-mark {
    font-size: 3rem;
    color: #58a6ff;
    margin-bottom: 0.5rem;
  }
  h1 {
    font-size: 2rem;
    font-weight: 700;
    color: #e6edf3;
    letter-spacing: -0.02em;
  }
  .upload-logo p {
    color: #8b949e;
    margin-top: 0.5rem;
  }
  .loading-screen {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .loading-inner {
    text-align: center;
    width: 400px;
  }
  .logo {
    font-size: 1.5rem;
    font-weight: 700;
    color: #58a6ff;
    letter-spacing: -0.02em;
  }
  .progress-bar-wrap {
    margin: 1.5rem 0 0.75rem;
    height: 4px;
    background: #21262d;
    border-radius: 2px;
    overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%;
    background: #58a6ff;
    border-radius: 2px;
    transition: width 0.4s ease;
  }
  .progress-label {
    color: #8b949e;
    font-size: 0.875rem;
  }
  .dashboard {
    padding: 0 1.5rem 2rem;
  }
  .dash-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem 0;
    border-bottom: 1px solid #21262d;
    margin-bottom: 1.25rem;
  }
  .filename {
    color: #8b949e;
    font-size: 0.875rem;
  }
  .grid-row {
    display: grid;
    gap: 1rem;
    margin-bottom: 1rem;
  }
  .two-col {
    grid-template-columns: 1fr 1fr;
  }
  @media (max-width: 900px) {
    .two-col { grid-template-columns: 1fr; }
  }
</style>
