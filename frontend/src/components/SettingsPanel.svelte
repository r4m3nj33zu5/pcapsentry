<script>
  export let open = false;
  export let onclose = () => {};

  let vtKey = '';
  let shodanKey = '';
  let saving = false;
  let saved = false;
  let configStatus = null;

  async function loadConfig() {
    try {
      const cfg = await fetch('/api/config').then(r => r.json());
      configStatus = cfg;
    } catch (e) {}
  }

  async function saveConfig() {
    saving = true;
    saved = false;
    try {
      await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          virustotal_api_key: vtKey || null,
          shodan_api_key: shodanKey || null,
        }),
      });
      saved = true;
      await loadConfig();
      vtKey = '';
      shodanKey = '';
    } catch (e) {}
    saving = false;
  }

  $: if (open) { loadConfig(); }
</script>

{#if open}
<div class="overlay" on:click|self={onclose}></div>
<div class="panel">
  <div class="panel-header">
    <span class="panel-title">⚙ Settings</span>
    <button class="close-btn" on:click={onclose}>✕</button>
  </div>

  <div class="panel-body">
    <section>
      <h3>Enrichment API Keys</h3>
      <p class="hint">Keys are stored locally in <code>~/.config/pcapsentry/config.toml</code> (0600 permissions).</p>

      {#if configStatus}
        <div class="status-row">
          <span>VirusTotal:</span>
          <span class={configStatus.virustotal_configured ? 'configured' : 'not-configured'}>
            {configStatus.virustotal_configured ? '✓ Configured' : '✗ Not set'}
          </span>
        </div>
        <div class="status-row">
          <span>Shodan:</span>
          <span class={configStatus.shodan_configured ? 'configured' : 'not-configured'}>
            {configStatus.shodan_configured ? '✓ Configured' : '✗ Not set'}
          </span>
        </div>
      {/if}

      <div class="field">
        <label>VirusTotal API Key</label>
        <input type="password" bind:value={vtKey} placeholder="Leave blank to keep existing" />
      </div>
      <div class="field">
        <label>Shodan API Key</label>
        <input type="password" bind:value={shodanKey} placeholder="Leave blank to keep existing" />
      </div>

      <button class="save-btn" on:click={saveConfig} disabled={saving}>
        {saving ? 'Saving…' : 'Save Keys'}
      </button>
      {#if saved}<span class="saved-msg">✓ Saved</span>{/if}
    </section>

    <section>
      <h3>About</h3>
      <p class="hint">PcapSentry — Local-first SOC analysis platform.<br>All processing happens on your machine. No data leaves your network.</p>
    </section>
  </div>
</div>
{/if}

<style>
  .overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.5);
    z-index: 999;
  }
  .panel {
    position: fixed; top: 0; right: 0; bottom: 0;
    width: 360px;
    background: #0a0a0a;
    border-left: 1px solid rgba(255,255,255,0.09);
    z-index: 1000;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
  }
  .panel-title {
    color: #c8d8f0;
    font-weight: 700;
    font-size: 0.95rem;
    letter-spacing: 0.05em;
  }
  .close-btn {
    background: none; border: none; color: #606060;
    cursor: pointer; font-size: 1.1rem;
  }
  .close-btn:hover { color: #f0f0f0; }
  .panel-body { padding: 1.25rem; overflow-y: auto; flex: 1; }
  section { margin-bottom: 2rem; }
  h3 { color: #909090; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.1em; margin: 0 0 0.75rem; }
  .hint { color: #606060; font-size: 0.78rem; margin-bottom: 1rem; line-height: 1.5; }
  code { color: #c8d8f0; font-size: 0.75rem; }
  .status-row { display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 0.35rem; color: #787878; }
  .configured { color: #4ade80; }
  .not-configured { color: #e03e5a; }
  .field { margin-bottom: 0.75rem; }
  label { display: block; font-size: 0.75rem; color: #606060; margin-bottom: 4px; }
  input {
    width: 100%; box-sizing: border-box;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.09);
    color: #f0f0f0; padding: 7px 10px;
    border-radius: 2px; font-size: 0.82rem;
    font-family: monospace;
  }
  input:focus { outline: none; border-color: rgba(255,255,255,0.2); }
  .save-btn {
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.15);
    color: #c8d8f0; padding: 7px 16px;
    border-radius: 2px; font-size: 0.82rem;
    cursor: pointer; margin-top: 0.5rem;
  }
  .save-btn:hover:not(:disabled) { background: rgba(255,255,255,0.1); }
  .save-btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .saved-msg { color: #4ade80; font-size: 0.8rem; margin-left: 0.75rem; }
</style>
