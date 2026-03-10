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
    padding: 3rem 2rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
    color: #404040;
    background: #0a0a0a;
  }
  .zone.dragging {
    border-color: rgba(255,255,255,0.2);
    background: rgba(255,255,255,0.02);
    color: #c8d8f0;
  }
  .hint {
    font-size: 0.85rem;
    color: #505050;
    letter-spacing: 0.02em;
  }
  .or {
    font-size: 0.75rem;
    color: #303030;
  }
  .btn {
    padding: 0.5rem 1.5rem;
    background: transparent;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 2px;
    color: #c0c0c0;
    font-size: 0.78rem;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    cursor: pointer;
    transition: color 0.15s, border-color 0.15s, background 0.15s;
  }
  .btn:hover {
    color: #f0f0f0;
    border-color: rgba(255,255,255,0.25);
    background: rgba(255,255,255,0.04);
  }
  .error {
    color: #e03e5a;
    font-size: 0.82rem;
  }
  .size-warn {
    color: #c8920a;
    font-size: 0.78rem;
    text-align: center;
  }
</style>
