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

  function processFile(file) {
    if (!file) return;
    if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
      error = 'Only .pcap and .pcapng files are supported.';
      return;
    }
    error = '';
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
  {#if error}
    <p class="error">{error}</p>
  {/if}
</div>

<style>
  .zone {
    width: min(560px, 90vw);
    border: 2px dashed #30363d;
    border-radius: 12px;
    padding: 3rem 2rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
    color: #8b949e;
  }
  .zone.dragging {
    border-color: #58a6ff;
    background: rgba(88, 166, 255, 0.06);
    color: #58a6ff;
  }
  .hint {
    font-size: 0.95rem;
  }
  .or {
    font-size: 0.8rem;
    color: #484f58;
  }
  .btn {
    padding: 0.5rem 1.25rem;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #e6edf3;
    font-size: 0.875rem;
    cursor: pointer;
    transition: background 0.15s;
  }
  .btn:hover {
    background: #292e36;
  }
  .error {
    color: #f85149;
    font-size: 0.85rem;
  }
</style>
