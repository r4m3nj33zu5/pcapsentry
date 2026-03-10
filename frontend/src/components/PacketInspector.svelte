<script>
  import { inspectorPackets, inspectorOpen, activeSessionId, closeInspector } from '../stores/session.js';
  import { onMount } from 'svelte';

  let packets = [];
  let selectedPacket = null;
  let selectedDetail = null;
  let loading = false;
  let showHex = false;

  $: indices = $inspectorPackets || [];

  onMount(async () => {
    await loadPacketList();
  });

  async function loadPacketList() {
    loading = true;
    packets = [];
    const sid = $activeSessionId;
    const res = await fetch(`/api/results/${sid}`).then(r => r.json());
    const all = res.packets || [];
    packets = indices.length
      ? all.filter(p => indices.includes(p.index))
      : all.slice(0, 200);
    loading = false;
  }

  async function selectPacket(pkt) {
    selectedPacket = pkt;
    selectedDetail = null;
    const sid = $activeSessionId;
    selectedDetail = await fetch(`/api/packet/${sid}/${pkt.index}`).then(r => r.json());
  }

  function protocolColor(proto) {
    const map = {
      TCP: '#58a6ff', UDP: '#3fb950', DNS: '#a371f7',
      HTTP: '#e3b341', ICMP: '#f0883e', ARP: '#d29922',
    };
    return map[proto] || '#8b949e';
  }
</script>

<div class="inspector-backdrop" on:click={closeInspector} role="presentation">
  <div class="inspector-panel" on:click|stopPropagation role="dialog" aria-label="Packet Inspector">
    <div class="inspector-header">
      <span class="inspector-title">Packet Inspector</span>
      <button class="close-btn" on:click={closeInspector}>✕</button>
    </div>

    <div class="inspector-body">
      <!-- Packet list -->
      <div class="pkt-list">
        {#if loading}
          <div class="loading">Loading…</div>
        {:else}
          {#each packets as pkt}
            <button
              class="pkt-row"
              class:selected={selectedPacket?.index === pkt.index}
              on:click={() => selectPacket(pkt)}
            >
              <span class="pkt-idx">#{pkt.index}</span>
              <span class="pkt-proto" style="color: {protocolColor(pkt.protocol)}">{pkt.protocol}</span>
              <span class="pkt-src">{pkt.src_ip || pkt.src_mac || '?'}</span>
              <span class="pkt-arrow">→</span>
              <span class="pkt-dst">{pkt.dst_ip || pkt.dst_mac || '?'}</span>
              <span class="pkt-len">{pkt.length}B</span>
            </button>
          {/each}
        {/if}
      </div>

      <!-- Detail view -->
      <div class="pkt-detail">
        {#if !selectedDetail}
          <div class="detail-empty">Select a packet to inspect</div>
        {:else}
          <div class="detail-scroll">
            <div class="detail-section">
              <div class="detail-label">Summary</div>
              <div class="kv"><span>Index</span><span>#{selectedDetail.index}</span></div>
              <div class="kv"><span>Time</span><span>{selectedDetail.timestamp_str}</span></div>
              <div class="kv"><span>Protocol</span><span style="color:{protocolColor(selectedDetail.protocol)}">{selectedDetail.protocol}</span></div>
              <div class="kv"><span>Length</span><span>{selectedDetail.length} bytes</span></div>
              {#if selectedDetail.info}
                <div class="kv"><span>Info</span><span>{selectedDetail.info}</span></div>
              {/if}
            </div>

            {#if selectedDetail.layers?.ethernet}
              <div class="detail-section">
                <div class="detail-label">Ethernet</div>
                <div class="kv"><span>Src MAC</span><span class="mono">{selectedDetail.layers.ethernet.src_mac}</span></div>
                <div class="kv"><span>Dst MAC</span><span class="mono">{selectedDetail.layers.ethernet.dst_mac}</span></div>
                <div class="kv"><span>Type</span><span>{selectedDetail.layers.ethernet.ether_type}</span></div>
              </div>
            {/if}

            {#if selectedDetail.layers?.arp}
              <div class="detail-section">
                <div class="detail-label">ARP</div>
                <div class="kv"><span>Operation</span><span>{selectedDetail.layers.arp.operation}</span></div>
                <div class="kv"><span>Sender MAC</span><span class="mono">{selectedDetail.layers.arp.sender_mac}</span></div>
                <div class="kv"><span>Sender IP</span><span class="mono">{selectedDetail.layers.arp.sender_ip}</span></div>
                <div class="kv"><span>Target MAC</span><span class="mono">{selectedDetail.layers.arp.target_mac}</span></div>
                <div class="kv"><span>Target IP</span><span class="mono">{selectedDetail.layers.arp.target_ip}</span></div>
              </div>
            {/if}

            {#if selectedDetail.layers?.ip}
              <div class="detail-section">
                <div class="detail-label">IP (v{selectedDetail.layers.ip.version})</div>
                <div class="kv"><span>Src</span><span class="mono">{selectedDetail.layers.ip.src}</span></div>
                <div class="kv"><span>Dst</span><span class="mono">{selectedDetail.layers.ip.dst}</span></div>
                <div class="kv"><span>TTL</span><span>{selectedDetail.layers.ip.ttl}</span></div>
                <div class="kv"><span>Protocol</span><span>{selectedDetail.layers.ip.protocol}</span></div>
                <div class="kv"><span>Length</span><span>{selectedDetail.layers.ip.total_length}</span></div>
                {#if selectedDetail.layers.ip.flags}
                  <div class="kv"><span>Flags</span><span>{selectedDetail.layers.ip.flags}</span></div>
                {/if}
              </div>
            {/if}

            {#if selectedDetail.layers?.transport}
              <div class="detail-section">
                <div class="detail-label">{selectedDetail.layers.transport.protocol}</div>
                <div class="kv"><span>Src Port</span><span>{selectedDetail.layers.transport.src_port}</span></div>
                <div class="kv"><span>Dst Port</span><span>{selectedDetail.layers.transport.dst_port}</span></div>
                {#if selectedDetail.layers.transport.flags}
                  <div class="kv"><span>Flags</span><span class="mono">{selectedDetail.layers.transport.flags}</span></div>
                {/if}
                {#if selectedDetail.layers.transport.seq !== undefined}
                  <div class="kv"><span>Seq</span><span>{selectedDetail.layers.transport.seq}</span></div>
                  <div class="kv"><span>Ack</span><span>{selectedDetail.layers.transport.ack}</span></div>
                  <div class="kv"><span>Window</span><span>{selectedDetail.layers.transport.window}</span></div>
                {/if}
              </div>
            {/if}

            {#if selectedDetail.layers?.application}
              <div class="detail-section">
                <div class="detail-label">{selectedDetail.layers.application.protocol}</div>
                <pre class="app-data">{JSON.stringify(selectedDetail.layers.application.data, null, 2)}</pre>
              </div>
            {/if}

            <div class="detail-section">
              <button class="hex-toggle" on:click={() => showHex = !showHex}>
                {showHex ? '▼' : '▶'} Raw Hex Dump
              </button>
              {#if showHex}
                <pre class="hex-dump">{selectedDetail.raw_hex}</pre>
              {/if}
            </div>
          </div>
        {/if}
      </div>
    </div>
  </div>
</div>

<style>
  .inspector-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.5);
    z-index: 100;
    display: flex;
    justify-content: flex-end;
  }
  .inspector-panel {
    width: min(780px, 92vw);
    height: 100vh;
    background: #161b22;
    border-left: 1px solid #2a2a2a;
    display: flex;
    flex-direction: column;
  }
  .inspector-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid #21262d;
  }
  .inspector-title {
    font-weight: 600;
    font-size: 0.95rem;
    color: #e6edf3;
  }
  .close-btn {
    background: none;
    border: none;
    color: #8b949e;
    font-size: 1rem;
    cursor: pointer;
    padding: 0.25rem;
  }
  .close-btn:hover { color: #e6edf3; }
  .inspector-body {
    display: grid;
    grid-template-columns: 1fr 1fr;
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }
  .pkt-list {
    border-right: 1px solid #21262d;
    overflow-y: auto;
    padding: 0.5rem 0;
  }
  .pkt-row {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    width: 100%;
    padding: 0.4rem 0.75rem;
    background: none;
    border: none;
    cursor: pointer;
    font-size: 0.72rem;
    color: #8b949e;
    text-align: left;
    border-bottom: 1px solid #21262d22;
  }
  .pkt-row:hover { background: #21262d; }
  .pkt-row.selected { background: #1f3a5f; }
  .pkt-idx { color: #484f58; width: 40px; flex-shrink: 0; }
  .pkt-proto { width: 45px; flex-shrink: 0; font-weight: 600; }
  .pkt-src, .pkt-dst { font-family: monospace; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .pkt-arrow { color: #484f58; }
  .pkt-len { color: #484f58; flex-shrink: 0; }
  .pkt-detail {
    overflow-y: auto;
    padding: 0.75rem;
  }
  .detail-empty {
    color: #484f58;
    font-size: 0.85rem;
    text-align: center;
    padding: 2rem;
  }
  .detail-scroll { display: flex; flex-direction: column; gap: 0.75rem; }
  .detail-section {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 2px;
    padding: 0.75rem;
  }
  .detail-label {
    font-size: 0.7rem;
    font-weight: 700;
    color: #58a6ff;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 0.5rem;
  }
  .kv {
    display: flex;
    justify-content: space-between;
    gap: 0.5rem;
    font-size: 0.78rem;
    padding: 0.2rem 0;
    border-bottom: 1px solid #21262d22;
  }
  .kv span:first-child { color: #8b949e; flex-shrink: 0; }
  .kv span:last-child { color: #e6edf3; text-align: right; word-break: break-all; }
  .mono { font-family: monospace; font-size: 0.73rem; }
  .app-data {
    font-family: monospace;
    font-size: 0.72rem;
    color: #c9d1d9;
    white-space: pre-wrap;
    word-break: break-all;
    margin-top: 0.5rem;
  }
  .hex-toggle {
    background: none;
    border: none;
    color: #58a6ff;
    font-size: 0.78rem;
    cursor: pointer;
    padding: 0;
    margin-bottom: 0.5rem;
  }
  .hex-dump {
    font-family: monospace;
    font-size: 0.68rem;
    color: #8b949e;
    white-space: pre;
    overflow-x: auto;
    margin-top: 0.5rem;
  }
  .loading {
    color: #8b949e;
    font-size: 0.85rem;
    padding: 1rem;
    text-align: center;
  }
</style>
