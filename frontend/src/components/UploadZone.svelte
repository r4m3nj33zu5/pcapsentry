<script>
  import { uploadFile } from '../stores/session.js';

  let dragging = false;
  let error = '';

  function handleDrop(e) {
    e.preventDefault();
    dragging = false;
    const file = e.dataTransfer.files[0];
    processFile(file);
  }

  function handlePick(e) {
    const file = e.target.files[0];
    processFile(file);
  }

  let sizeWarning = '';
  const SIZE_WARN_MB = 500;

  function processFile(file) {
    if (!file) return;
    if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
      error = 'Only .pcap and .pcapng files are supported.';
      return;
    }
    error = '';
    const sizeMB = file.size / 1_048_576;
    if (sizeMB > SIZE_WARN_MB) {
      sizeWarning = `⚠ Large file (${sizeMB.toFixed(0)} MB). Analysis may take several minutes.`;
    } else {
      sizeWarning = '';
    }
    uploadFile(file);
  }
</script>

<div
  class="zone"
  class:dragging
  on:dragover|preventDefault={() => dragging = true}
  on:dragleave={() => dragging = false}
  on:drop={handleDrop}
  role="region"
  aria-label="File upload zone"
>
  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1M16 8l-4-4-4 4M12 4v12" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
  <p class="hint">Drag & drop your .pcap or .pcapng file here</p>
  <span class="or">or</span>
  <label class="btn">
    Browse files
    <input type="file" accept=".pcap,.pcapng" on:change={handlePick} hidden />
  </label>
  {#if sizeWarning}
    <p class="size-warn">{sizeWarning}</p>
  {/if}
  {#if error}
    <p class="error">{error}</p>
  {/if}
</div>

<style>
  .zone {
    width: min(480px, 90vw);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 2px;
    padding: 3.5rem 2.5rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.85rem;
    cursor: pointer;
    transition: border-color 0.25s, background 0.25s;
    color: var(--text-muted);
    background: rgba(10, 40, 80, 0.08);
  }
  .zone.dragging {
    border-color: rgba(200,216,240,0.35);
    background: rgba(10, 40, 80, 0.25);
    color: var(--accent);
  }
  .hint {
    font-size: 0.78rem;
    color: var(--text-muted);
    letter-spacing: 0.04em;
    font-family: var(--font-ui);
  }
  .or {
    font-size: 0.65rem;
    color: var(--text-dim);
    font-family: var(--font-ui);
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }
  .btn {
    padding: 0.55rem 1.75rem;
    background: transparent;
    border: 1px solid rgba(255,255,255,0.16);
    border-radius: 2px;
    color: #a0a0b0;
    font-size: 0.68rem;
    font-family: var(--font-ui);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    cursor: pointer;
    transition: color 0.2s, border-color 0.2s, background 0.2s;
  }
  .btn:hover {
    color: #000000;
    border-color: var(--text);
    background: var(--text);
  }
  .error {
    color: var(--critical);
    font-size: 0.78rem;
    font-family: var(--font-ui);
    letter-spacing: 0.03em;
  }
  .size-warn {
    color: var(--medium);
    font-size: 0.72rem;
    text-align: center;
    font-family: var(--font-ui);
    letter-spacing: 0.03em;
  }
</style>
