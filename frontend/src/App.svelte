<script>
  import { activeResult, activeSessionId, loading, uploadProgress, uploadError, inspectorOpen } from './stores/session.js';
  import { uploadError as uploadErrorStore } from './stores/session.js';
  import { clearInvestigation } from './stores/investigation.js';

  import UploadZone from './components/UploadZone.svelte';
  import SessionHistory from './components/SessionHistory.svelte';
  import PacketInspector from './components/PacketInspector.svelte';
  import TabNav from './components/TabNav.svelte';
  import InvestigationBar from './components/InvestigationBar.svelte';
  import SettingsPanel from './components/SettingsPanel.svelte';
  import TrafficTimeline from './components/TrafficTimeline.svelte';

  import ExecutiveDashboard from './components/modules/ExecutiveDashboard.svelte';
  import AlertEngine from './components/modules/AlertEngine.svelte';
  import FlowAnalysis from './components/modules/FlowAnalysis.svelte';
  import DnsModule from './components/modules/DnsModule.svelte';
  import HttpModule from './components/modules/HttpModule.svelte';
  import TlsModule from './components/modules/TlsModule.svelte';
  import IocModule from './components/modules/IocModule.svelte';
  import GeoModule from './components/modules/GeoModule.svelte';
  import StatsModule from './components/modules/StatsModule.svelte';
  import TimelineModule from './components/modules/TimelineModule.svelte';
  import PacketModule from './components/modules/PacketModule.svelte';
  import NotesModule from './components/modules/NotesModule.svelte';

  let activeTab = 0;
  let settingsOpen = false;
  let sidebarCollapsed = false;

  $: result = $activeResult;

  $: alertCount = result?.alerts?.filter(a => a.severity === 'critical' || a.severity === 'high').length || 0;

  // TabNav dispatch prop
  function dispatch(event, value) {
    if (event === 'tabchange') activeTab = value;
  }

  // Reset to triage on new result
  let prevResult = null;
  $: if (result && result !== prevResult) {
    prevResult = result;
    activeTab = 0;
  }
</script>

<div class="app-shell">
  <!-- Collapsible sidebar -->
  <div class="sidebar" class:collapsed={sidebarCollapsed}>
    {#if !sidebarCollapsed}
      <SessionHistory />
    {/if}
    <button class="collapse-btn" on:click={() => sidebarCollapsed = !sidebarCollapsed}
      title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
      {sidebarCollapsed ? '›' : '‹'}
    </button>
  </div>

  <main class="main-content">
    {#if $uploadError}
      <div class="loading-screen">
        <div class="loading-inner">
          <div class="logo">PcapSentry</div>
          <div class="error-box">{$uploadError}</div>
          <button class="retry-btn" on:click={() => uploadErrorStore.set(null)}>Try another file</button>
        </div>
      </div>

    {:else if $loading}
      <div class="loading-screen">
        <div class="loading-inner">
          <div class="logo">PcapSentry</div>
          <div class="progress-bar-wrap">
            <div class="progress-bar-fill" style="width:{$uploadProgress}%"></div>
          </div>
          <div class="progress-label">{$uploadProgress < 100 ? 'Parsing capture…' : 'Building analysis…'}</div>
        </div>
      </div>

    {:else if result}
      <!-- Top bar -->
      <div class="topbar">
        <span class="app-logo">PcapSentry</span>
        <span class="filename">{result.overview?.filename || 'unknown'}</span>
        <div class="topbar-right">
          <button class="icon-btn" on:click={() => settingsOpen = true} title="Settings">⚙</button>
          <button class="new-btn" on:click={() => { activeResult.set(null); clearInvestigation(); }}>New Upload</button>
        </div>
      </div>

      <!-- Investigation filter bar (only renders when filters active) -->
      <InvestigationBar />

      <!-- Tab navigation -->
      <TabNav {activeTab} {alertCount} {dispatch} />

      <!-- Tab content -->
      <div class="tab-content">
        {#if activeTab === 0}
          <div class="triage-layout">
            <div class="triage-timeline">
              <TrafficTimeline timeline={result.timeline} threats={result.threats} />
            </div>
            <div class="triage-main">
              <ExecutiveDashboard {result} />
            </div>
          </div>

        {:else if activeTab === 1}
          <AlertEngine {result} />

        {:else if activeTab === 2}
          <FlowAnalysis {result} />

        {:else if activeTab === 3}
          <DnsModule {result} />

        {:else if activeTab === 4}
          <HttpModule {result} />

        {:else if activeTab === 5}
          <TlsModule {result} />

        {:else if activeTab === 6}
          <IocModule {result} />

        {:else if activeTab === 7}
          <GeoModule {result} />

        {:else if activeTab === 8}
          <StatsModule {result} />

        {:else if activeTab === 9}
          <TimelineModule {result} />

        {:else if activeTab === 10}
          <PacketModule {result} />

        {:else if activeTab === 11}
          <NotesModule {result} />
        {/if}
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

  <SettingsPanel open={settingsOpen} onclose={() => settingsOpen = false} />
</div>

<style>
  :global(body) {
    background: #000000;
    color: #f0f0f0;
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    margin: 0;
  }

  /* Syne for all uppercase labels and card headers across modules */
  :global(.card-title), :global(.section-title), :global(.gauge-label),
  :global(.module-title), :global(.panel-title) {
    font-family: 'Syne', 'Inter', sans-serif !important;
  }

  .app-shell {
    display: flex;
    height: 100vh;
    overflow: hidden;
    position: relative;
    background: #000000;
  }

  /* Sidebar */
  .sidebar {
    width: 220px;
    flex-shrink: 0;
    position: relative;
    border-right: 1px solid rgba(255,255,255,0.06);
    transition: width 0.2s ease;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: #000000;
  }
  .sidebar.collapsed { width: 24px; }
  .collapse-btn {
    position: absolute;
    right: -12px;
    top: 50%;
    transform: translateY(-50%);
    width: 24px;
    height: 24px;
    background: #0a0a0a;
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 2px;
    color: #606060;
    cursor: pointer;
    font-size: 0.75rem;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
    transition: color 0.15s, border-color 0.15s;
  }
  .collapse-btn:hover { color: #f0f0f0; border-color: rgba(255,255,255,0.25); }

  /* Main content */
  .main-content {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* Top bar */
  .topbar {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.55rem 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    flex-shrink: 0;
    background: #000000;
  }
  .app-logo {
    font-family: 'Syne', sans-serif;
    font-size: 0.9rem;
    font-weight: 700;
    color: #f0f0f0;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }
  .filename {
    color: #444444;
    font-size: 0.78rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 300px;
    font-weight: 400;
  }
  .topbar-right { margin-left: auto; display: flex; align-items: center; gap: 0.5rem; }
  .icon-btn {
    background: none;
    border: 1px solid rgba(255,255,255,0.08);
    color: #505050;
    width: 28px;
    height: 28px;
    border-radius: 2px;
    cursor: pointer;
    font-size: 0.85rem;
    transition: color 0.15s, border-color 0.15s;
  }
  .icon-btn:hover { color: #f0f0f0; border-color: rgba(255,255,255,0.2); }
  .new-btn {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.12);
    color: #909090;
    padding: 4px 12px;
    border-radius: 2px;
    cursor: pointer;
    font-size: 0.72rem;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    transition: color 0.15s, border-color 0.15s, background 0.15s;
  }
  .new-btn:hover { background: rgba(255,255,255,0.04); color: #f0f0f0; border-color: rgba(255,255,255,0.25); }

  /* Tab content area */
  .tab-content {
    flex: 1;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  /* Triage layout */
  .triage-layout {
    display: flex;
    flex-direction: column;
    height: 100%;
    overflow: auto;
    padding: 1rem;
    gap: 1rem;
  }
  .triage-timeline { flex-shrink: 0; }
  .triage-main { flex: 1; min-height: 0; }

  /* Upload screen */
  .upload-screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 2rem;
    background: #000000;
  }
  .upload-logo { text-align: center; }
  .logo-mark {
    font-family: 'Syne', sans-serif;
    font-size: 1.1rem;
    color: #f0f0f0;
    margin-bottom: 1rem;
    letter-spacing: 0.25em;
    text-transform: uppercase;
    font-weight: 800;
  }
  h1 {
    font-family: 'Syne', sans-serif;
    font-size: 1.6rem;
    font-weight: 700;
    color: #f0f0f0;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .upload-logo p { color: #444444; margin-top: 0.75rem; font-size: 0.8rem; letter-spacing: 0.04em; }

  /* Loading screen */
  .loading-screen {
    display: flex;
    align-items: center;
    justify-content: center;
    flex: 1;
    background: #000000;
  }
  .loading-inner { text-align: center; width: 400px; }
  .logo {
    font-family: 'Syne', sans-serif;
    font-size: 0.9rem;
    font-weight: 700;
    color: #f0f0f0;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
  }
  .progress-bar-wrap {
    margin: 1.5rem 0 0.75rem;
    height: 1px;
    background: rgba(255,255,255,0.08);
    border-radius: 0;
    overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%;
    background: #c8d8f0;
    border-radius: 0;
    transition: width 0.4s ease;
  }
  .error-box {
    margin: 1.5rem 0 1rem;
    padding: 0.75rem 1rem;
    background: rgba(224,62,90,0.06);
    border: 1px solid rgba(224,62,90,0.25);
    border-radius: 2px;
    color: #e03e5a;
    font-size: 0.85rem;
    text-align: left;
    word-break: break-word;
  }
  .retry-btn {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.12);
    color: #909090;
    padding: 0.5rem 1.25rem;
    border-radius: 2px;
    cursor: pointer;
    font-size: 0.75rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    transition: color 0.15s, border-color 0.15s;
  }
  .retry-btn:hover { color: #f0f0f0; border-color: rgba(255,255,255,0.25); }
  .progress-label { color: #444444; font-size: 0.78rem; margin-top: 0.5rem; letter-spacing: 0.04em; }
</style>
