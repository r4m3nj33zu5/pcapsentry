<script>
  import { activeSessionId } from '../stores/session.js';

  export let flow; // ConnectionFlow object
  export let onclose = () => {};

  let loading = false;
  let error = '';
  let stream = null;
  let view = 'text'; // 'text' | 'hex'
  let side = 'both'; // 'forward' | 'backward' | 'both'

  $: if (flow && $activeSessionId) loadStream();

  async function loadStream() {
    loading = true;
    error = '';
    stream = null;
    try {
      // Find stream by matching src/dst/port against stream list
      const listRes = await fetch(`/api/stream/${$activeSessionId}`);
      if (!listRes.ok) throw new Error('Stream data not available (session may have been restarted)');
      const { streams } = await listRes.json();

      const match = streams.find(s =>
        (s.src_ip === flow.src_ip && s.src_port === flow.src_port && s.dst_ip === flow.dst_ip && s.dst_port === flow.dst_port) ||
        (s.src_ip === flow.dst_ip && s.src_port === flow.dst_port && s.dst_ip === flow.src_ip && s.dst_port === flow.src_port)
      );

      if (!match) {
        error = 'No reassembled stream found for this flow. UDP or short-lived TCP flows may not have stream data.';
        loading = false;
        return;
      }

      const detailRes = await fetch(`/api/stream/${$activeSessionId}/${match.index}`);
      if (!detailRes.ok) throw new Error('Failed to load stream detail');
      stream = await detailRes.json();
    } catch (e) {
      error = e.message;
    }
    loading = false;
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  // Interleave forward/backward lines with direction markers
  function buildConversation(fwd, bwd) {
    // Simple approach: show forward then backward
    const sections = [];
    if (fwd) sections.push({ dir: '→', label: `${stream.src_ip}:${stream.src_port} → ${stream.dst_ip}:${stream.dst_port}`, content: fwd });
    if (bwd) sections.push({ dir: '←', label: `${stream.dst_ip}:${stream.dst_port} → ${stream.src_ip}:${stream.src_port}`, content: bwd });
    return sections;
  }
</script>

<div class="overlay" on:click|self={onclose}></div>
<div class="viewer">
  <div class="viewer-header">
    <div class="viewer-title">
      <span class="title-label">TCP Stream</span>
      {#if stream}
        <span class="title-flow">{stream.src_ip}:{stream.src_port} ↔ {stream.dst_ip}:{stream.dst_port}</span>
      {:else if flow}
        <span class="title-flow">{flow.src_ip}:{flow.src_port ?? '?'} ↔ {flow.dst_ip}:{flow.dst_port ?? '?'}</span>
      {/if}
    </div>
    <div class="header-controls">
      {#if stream}
        <div class="toggle-group">
          <button class:active={view==='text'} on:click={() => view='text'}>Text</button>
          <button class:active={view==='hex'} on:click={() => view='hex'}>Hex</button>
        </div>
        <div class="toggle-group">
          <button class:active={side==='both'} on:click={() => side='both'}>Both</button>
          <button class:active={side==='forward'} on:click={() => side='forward'}>→ Fwd</button>
          <button class:active={side==='backward'} on:click={() => side='backward'}>← Bwd</button>
        </div>
      {/if}
      <button class="close-btn" on:click={onclose}>✕</button>
    </div>
  </div>

  <div class="viewer-body">
    {#if loading}
      <div class="state-msg">Loading stream data…</div>
    {:else if error}
      <div class="state-msg error">{error}</div>
    {:else if stream}
      {#if view === 'hex'}
        <div class="stream-sections">
          {#if side !== 'backward' && stream.forward.bytes > 0}
            <div class="section">
              <div class="section-label fwd">→ {stream.src_ip}:{stream.src_port} → {stream.dst_ip}:{stream.dst_port} &nbsp;·&nbsp; {stream.forward.bytes} bytes</div>
              <pre class="hex-dump">{stream.forward.hex}</pre>
            </div>
          {/if}
          {#if side !== 'forward' && stream.backward.bytes > 0}
            <div class="section">
              <div class="section-label bwd">← {stream.dst_ip}:{stream.dst_port} → {stream.src_ip}:{stream.src_port} &nbsp;·&nbsp; {stream.backward.bytes} bytes</div>
              <pre class="hex-dump">{stream.backward.hex}</pre>
            </div>
          {/if}
        </div>
      {:else}
        <div class="stream-sections">
          {#each buildConversation(
            side !== 'backward' ? stream.forward.text : null,
            side !== 'forward' ? stream.backward.text : null
          ) as section}
            {#if section.content}
              <div class="section">
                <div class="section-label" class:fwd={section.dir==='→'} class:bwd={section.dir==='←'}>
                  {section.dir} {section.label} &nbsp;·&nbsp;
                  {section.dir === '→' ? stream.forward.bytes : stream.backward.bytes} bytes
                </div>
                <pre class="text-content">{section.content}</pre>
              </div>
            {/if}
          {/each}
          {#if stream.forward.bytes === 0 && stream.backward.bytes === 0}
            <div class="state-msg">Stream captured but no payload data.</div>
          {/if}
        </div>
      {/if}
    {/if}
  </div>
</div>

<style>
  .overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.6);
    z-index: 1100;
  }
  .viewer {
    position: fixed;
    top: 5vh; left: 50%;
    transform: translateX(-50%);
    width: min(900px, 92vw);
    height: 88vh;
    background: #050508;
    background-image: linear-gradient(180deg, rgba(10,40,80,0.2) 0%, transparent 30%);
    border: 1px solid var(--border);
    border-radius: 2px;
    z-index: 1101;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .viewer-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .viewer-title {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex: 1;
    min-width: 0;
  }
  .title-label {
    font-family: var(--font-ui);
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text);
    flex-shrink: 0;
  }
  .title-flow {
    font-family: var(--font-ui);
    font-size: 0.72rem;
    color: var(--text-muted);
    letter-spacing: 0.03em;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .header-controls {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-shrink: 0;
  }
  .toggle-group {
    display: flex;
    border: 1px solid var(--border);
    border-radius: 2px;
    overflow: hidden;
  }
  .toggle-group button {
    background: none;
    border: none;
    border-right: 1px solid var(--border);
    color: var(--text-muted);
    padding: 3px 10px;
    font-size: 0.65rem;
    font-family: var(--font-ui);
    letter-spacing: 0.07em;
    text-transform: uppercase;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }
  .toggle-group button:last-child { border-right: none; }
  .toggle-group button.active { background: rgba(200,216,240,0.1); color: var(--text); }
  .toggle-group button:hover:not(.active) { background: rgba(255,255,255,0.04); }
  .close-btn {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 1rem;
    padding: 2px 6px;
    transition: color 0.15s;
  }
  .close-btn:hover { color: var(--text); }
  .viewer-body {
    flex: 1;
    overflow-y: auto;
    padding: 0;
  }
  .state-msg {
    color: var(--text-muted);
    font-family: var(--font-ui);
    font-size: 0.78rem;
    text-align: center;
    padding: 3rem;
    letter-spacing: 0.04em;
  }
  .state-msg.error { color: var(--critical); }
  .stream-sections { display: flex; flex-direction: column; }
  .section { border-bottom: 1px solid var(--border); }
  .section:last-child { border-bottom: none; }
  .section-label {
    font-family: var(--font-ui);
    font-size: 0.62rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 0.4rem 1rem;
    position: sticky;
    top: 0;
    z-index: 1;
  }
  .section-label.fwd {
    color: var(--accent);
    background: rgba(200,216,240,0.05);
    border-bottom: 1px solid rgba(200,216,240,0.1);
  }
  .section-label.bwd {
    color: var(--low);
    background: rgba(74,222,128,0.05);
    border-bottom: 1px solid rgba(74,222,128,0.1);
  }
  .text-content, .hex-dump {
    font-family: 'Courier New', Courier, monospace;
    font-size: 0.75rem;
    line-height: 1.6;
    color: #d0d8e8;
    padding: 0.75rem 1rem;
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
    tab-size: 4;
  }
  .hex-dump {
    color: #a0b8d0;
    white-space: pre;
    word-break: normal;
    font-size: 0.72rem;
  }
</style>
