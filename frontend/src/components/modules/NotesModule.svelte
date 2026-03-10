<script>
  import { marked } from 'marked';
  import { activeSessionId } from '../../stores/session.js';
  export let result;

  $: sessionId = $activeSessionId;

  let notes = result?.notes || '';
  let preview = false;
  let saving = false;
  let saveStatus = '';

  $: rendered = preview ? marked.parse(notes) : '';

  async function save() {
    if (!sessionId) return;
    saving = true;
    saveStatus = '';
    try {
      const r = await fetch(`/api/results/${sessionId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notes })
      });
      if (r.ok) saveStatus = 'saved';
      else saveStatus = 'error';
    } catch (e) {
      saveStatus = 'error';
    }
    saving = false;
    setTimeout(() => saveStatus = '', 2000);
  }

  function exportMd() {
    const a = document.createElement('a');
    a.href = 'data:text/markdown;charset=utf-8,' + encodeURIComponent(notes);
    a.download = 'pcapsentry-notes.md';
    a.click();
  }

  function exportTxt() {
    const a = document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(notes);
    a.download = 'pcapsentry-notes.txt';
    a.click();
  }

  const TEMPLATE = `# Investigation Notes

## Summary


## Suspicious Activity


## IOCs
- **IP:**
- **Domain:**
- **Hash:**

## Timeline


## Recommendations

`;

  function insertTemplate() {
    if (!notes.trim()) notes = TEMPLATE;
  }
</script>

<div class="notes-module">
  <div class="toolbar">
    <div class="view-tabs">
      <button class="vt" class:active={!preview} on:click={() => preview=false}>Edit</button>
      <button class="vt" class:active={preview} on:click={() => preview=true}>Preview</button>
    </div>
    <button class="action-btn" on:click={insertTemplate} disabled={!!notes.trim()}>Template</button>
    <div class="spacer"></div>
    <button class="action-btn" on:click={exportMd}>↓ .md</button>
    <button class="action-btn" on:click={exportTxt}>↓ .txt</button>
    <button class="save-btn" on:click={save} disabled={saving}>
      {saving ? 'Saving…' : 'Save'}
    </button>
    {#if saveStatus}
      <span class="save-status" class:ok={saveStatus==='saved'} class:err={saveStatus==='error'}>
        {saveStatus === 'saved' ? '✓ Saved' : '✗ Error'}
      </span>
    {/if}
  </div>

  <div class="editor-wrap">
    {#if preview}
      <div class="preview">{@html rendered}</div>
    {:else}
      <textarea
        class="editor"
        bind:value={notes}
        placeholder="Start typing your investigation notes here…&#10;&#10;Supports Markdown formatting."
        spellcheck="true"
      ></textarea>
    {/if}
  </div>

  <div class="footer">
    <span class="hint">Markdown supported · Ctrl+S not bound — use Save button</span>
    <span class="char-count">{notes.length} chars</span>
  </div>
</div>

<style>
  .notes-module { display:flex; flex-direction:column; height:100%; }
  .toolbar { display:flex; align-items:center; gap:0.5rem; padding:0.5rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); flex-wrap:wrap; }
  .view-tabs { display:flex; gap:4px; }
  .vt { background:none; border:1px solid rgba(255,255,255,0.07); color:#606060; padding:4px 10px; border-radius:4px; font-size:0.75rem; cursor:pointer; }
  .vt.active { color:#c8d8f0; border-color:rgba(255,255,255,0.2); }
  .action-btn { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#888888; padding:4px 10px; border-radius:4px; font-size:0.75rem; cursor:pointer; }
  .action-btn:hover:not(:disabled) { background:rgba(255,255,255,0.07); }
  .action-btn:disabled { opacity:0.4; cursor:not-allowed; }
  .spacer { flex:1; }
  .save-btn { background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.15); color:#c8d8f0; padding:4px 16px; border-radius:4px; font-size:0.75rem; cursor:pointer; font-weight:600; }
  .save-btn:hover:not(:disabled) { background:rgba(255,255,255,0.1); }
  .save-btn:disabled { opacity:0.5; cursor:not-allowed; }
  .save-status { font-size:0.75rem; }
  .save-status.ok { color:#4ade80; }
  .save-status.err { color:#e03e5a; }
  .editor-wrap { flex:1; display:flex; overflow:hidden; }
  .editor { flex:1; background:rgba(0,0,0,0.2); border:none; resize:none; color:#f0f0f0; font-family:monospace; font-size:0.85rem; line-height:1.6; padding:1.25rem 1.5rem; outline:none; }
  .editor::placeholder { color:#222222; }
  .preview { flex:1; overflow:auto; padding:1.25rem 1.5rem; color:#f0f0f0; line-height:1.7; font-size:0.88rem; }
  /* Markdown preview styles */
  .preview :global(h1) { color:#c8d8f0; font-size:1.3rem; border-bottom:1px solid rgba(255,255,255,0.09); padding-bottom:0.4rem; margin:0 0 1rem; }
  .preview :global(h2) { color:#888888; font-size:1.05rem; margin:1.2rem 0 0.5rem; }
  .preview :global(h3) { color:#787878; font-size:0.95rem; margin:1rem 0 0.4rem; }
  .preview :global(p) { margin:0.5rem 0; }
  .preview :global(code) { background:rgba(200,216,240,0.07); padding:1px 5px; border-radius:3px; font-family:monospace; font-size:0.83rem; color:#4ade80; }
  .preview :global(pre) { background:rgba(0,0,0,0.3); padding:1rem; border-radius:5px; overflow-x:auto; border:1px solid rgba(255,255,255,0.05); }
  .preview :global(ul), .preview :global(ol) { padding-left:1.5rem; margin:0.4rem 0; }
  .preview :global(li) { margin:0.2rem 0; }
  .preview :global(strong) { color:#f0f0f0; font-weight:700; }
  .preview :global(em) { color:#888888; }
  .preview :global(blockquote) { border-left:3px solid rgba(255,255,255,0.15); padding-left:1rem; color:#787878; margin:0.5rem 0; }
  .preview :global(hr) { border:none; border-top:1px solid rgba(255,255,255,0.07); margin:1rem 0; }
  .footer { display:flex; justify-content:space-between; padding:4px 1rem; border-top:1px solid rgba(255,255,255,0.04); }
  .hint { color:#222222; font-size:0.68rem; }
  .char-count { color:#222222; font-size:0.68rem; font-family:monospace; }
</style>
