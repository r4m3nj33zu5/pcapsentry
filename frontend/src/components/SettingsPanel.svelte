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
    background: rgba(0,0,0,0.6);
    z-index: 999;
  }
  .panel {
    position: fixed; top: 0; right: 0; bottom: 0;
    width: 360px;
    background: #030306;
    background-image: linear-gradient(180deg, rgba(10,40,80,0.25) 0%, transparent 40%);
    border-left: 1px solid var(--border);
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
    border-bottom: 1px solid var(--border);
  }
  .panel-title {
    color: var(--text);
    font-weight: 700;
    font-size: 0.78rem;
    letter-spacing: 0.14em;
    font-family: var(--font-ui);
    text-transform: uppercase;
  }
  .close-btn {
    background: none; border: none; color: var(--text-muted);
    cursor: pointer; font-size: 1rem;
    transition: color 0.15s;
  }
  .close-btn:hover { color: var(--text); }
  .panel-body { padding: 1.25rem; overflow-y: auto; flex: 1; }
  section { margin-bottom: 2rem; }
  h3 {
    color: var(--text-muted);
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    margin: 0 0 0.75rem;
    font-family: var(--font-ui);
  }
  .hint {
    color: var(--text-muted);
    font-size: 0.75rem;
    margin-bottom: 1rem;
    line-height: 1.55;
    font-family: var(--font-body);
  }
  code {
    color: var(--accent);
    font-size: 0.72rem;
    font-family: var(--font-ui);
    letter-spacing: 0.03em;
  }
  .status-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.72rem;
    margin-bottom: 0.35rem;
    color: var(--text-muted);
    font-family: var(--font-ui);
    letter-spacing: 0.04em;
  }
  .configured { color: var(--low); }
  .not-configured { color: var(--critical); }
  .field { margin-bottom: 0.75rem; }
  label {
    display: block;
    font-size: 0.62rem;
    color: var(--text-muted);
    margin-bottom: 4px;
    font-family: var(--font-ui);
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  input {
    width: 100%; box-sizing: border-box;
    background: rgba(10,40,80,0.15);
    border: 1px solid var(--border);
    color: var(--text); padding: 7px 10px;
    border-radius: 2px; font-size: 0.78rem;
    font-family: var(--font-ui);
    letter-spacing: 0.03em;
    transition: border-color 0.15s;
  }
  input::placeholder { color: var(--text-muted); }
  input:focus { outline: none; border-color: rgba(200,216,240,0.2); }
  .save-btn {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.16);
    color: #a0a0b0; padding: 7px 18px;
    border-radius: 2px; font-size: 0.68rem;
    font-family: var(--font-ui);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    cursor: pointer; margin-top: 0.5rem;
    transition: background 0.2s, color 0.2s, border-color 0.2s;
  }
  .save-btn:hover:not(:disabled) { background: var(--text); color: #000; border-color: var(--text); }
  .save-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .saved-msg {
    color: var(--low);
    font-size: 0.68rem;
    margin-left: 0.75rem;
    font-family: var(--font-ui);
    letter-spacing: 0.06em;
  }
</style>
