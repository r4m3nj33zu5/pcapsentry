<script>
  import { isolatePackets, openIpPivot } from '../../stores/investigation.js';
  export let result;
  export let gotoPackets = () => {};

  $: convs = result?.suspicious_conversations || [];

  let expanded = null;
  let sevFilter = 'All';

  $: filtered = sevFilter === 'All' ? convs : convs.filter(c => c.severity === sevFilter);
  $: sevCounts = convs.reduce((acc, c) => { acc[c.severity] = (acc[c.severity] || 0) + 1; return acc; }, {});

  function sevColor(s) {
    const map = { Critical: '#e03e5a', High: '#d4622c', Medium: '#c8920a', Low: '#888888' };
    return map[s] || '#888888';
  }

  function fmtBytes(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  function fmtDur(s) {
    if (s >= 3600) return (s / 3600).toFixed(1) + 'h';
    if (s >= 60) return (s / 60).toFixed(1) + 'm';
    return s.toFixed(1) + 's';
  }

  function isolate(c) {
    isolatePackets(c.packet_indices, `${c.initiator_ip} ↔ ${c.responder_ip}:${c.responder_port}`);
    gotoPackets();
  }
</script>

<div class="conv-module">
  <div class="toolbar">
    <span class="module-title">Suspicious Conversations</span>
    <div class="sev-tabs">
      {#each ['All', 'Critical', 'High', 'Medium', 'Low'] as s}
        <button class="st" class:active={sevFilter === s}
          style={s !== 'All' ? `--c:${sevColor(s)}` : ''}
          on:click={() => { sevFilter = s; expanded = null; }}>
          {s}{#if s !== 'All' && sevCounts[s]} ({sevCounts[s]}){/if}
        </button>
      {/each}
    </div>
    <span class="count">{filtered.length} conversation{filtered.length === 1 ? '' : 's'} flagged</span>
  </div>

  {#if convs.length === 0}
    <div class="empty">
      <div class="empty-mark">⊘</div>
      <p>No suspicious conversations detected in this capture.</p>
      <p class="empty-sub">Conversations are flagged when alerts, beaconing patterns, or TLS intel (JA3, certificates) attach to a bidirectional flow.</p>
    </div>
  {:else}
    <div class="conv-list">
      {#each filtered as c, i}
        <div class="conv-card" class:open={expanded === i}>
          <button class="conv-head" on:click={() => expanded = expanded === i ? null : i}>
            <span class="sev-chip" style="--c:{sevColor(c.severity)}">{c.severity}</span>
            <span class="score">{Math.round(c.score)}</span>
            <span class="endpoints">
              <span class="ip">{c.initiator_ip}</span><span class="port">:{c.initiator_port}</span>
              <span class="arrow">→</span>
              <span class="ip">{c.responder_ip}</span><span class="port">:{c.responder_port}</span>
            </span>
            <span class="svc">{c.service_guess !== 'Unknown' ? c.service_guess : c.transport}</span>
            <span class="meta">{c.total_packets.toLocaleString()} pkts · {fmtBytes(c.bytes_out + c.bytes_in)} · {fmtDur(c.duration_secs)}</span>
            <span class="chev">{expanded === i ? '▾' : '▸'}</span>
          </button>

          {#if expanded === i}
            <div class="conv-body">
              <p class="summary">{c.summary}</p>

              <div class="reasons">
                {#each c.reasons as r}
                  <div class="reason">
                    <span class="r-sev" style="--c:{sevColor(r.severity)}">{r.label}</span>
                    <span class="r-detail">{r.detail}</span>
                  </div>
                {/each}
              </div>

              <div class="facts">
                <span>State: <b>{c.state}</b></span>
                <span>Direction: <b>{fmtBytes(c.bytes_out)} out / {fmtBytes(c.bytes_in)} in</b></span>
                <span>Scope: <b>{c.is_external ? 'external' : 'internal'}</b></span>
                {#if c.app_protocols.length}<span>Protocols: <b>{c.app_protocols.join(', ')}</b></span>{/if}
                {#if c.sni}<span>SNI: <b>{c.sni}</b></span>{/if}
                {#if c.ja3_hash}<span>JA3: <b class="mono">{c.ja3_hash}</b></span>{/if}
              </div>

              <div class="actions">
                <button class="act-btn primary" on:click={() => isolate(c)}>
                  ⊟ Isolate {c.packet_indices.length.toLocaleString()} Packets
                </button>
                <button class="act-btn" on:click={(e) => openIpPivot(c.responder_ip, e)}>
                  Pivot on {c.responder_ip}
                </button>
              </div>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .conv-module {
    display: flex;
    flex-direction: column;
    height: 100%;
    overflow: hidden;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .module-title {
    font-family: var(--font-ui);
    font-size: 0.72rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-muted);
    font-weight: 600;
  }
  .sev-tabs { display: flex; gap: 0.25rem; }
  .st {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 3px 10px;
    border-radius: 2px;
    cursor: pointer;
    font-size: 0.68rem;
    font-family: var(--font-ui);
    letter-spacing: 0.04em;
  }
  .st.active { color: var(--c, var(--text)); border-color: var(--c, var(--border-hover)); }
  .count {
    margin-left: auto;
    color: var(--text-muted);
    font-size: 0.7rem;
    font-family: var(--font-ui);
    letter-spacing: 0.04em;
  }

  .empty {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    color: var(--text-muted);
    gap: 0.5rem;
    padding: 2rem;
    text-align: center;
  }
  .empty-mark { font-size: 1.5rem; opacity: 0.4; }
  .empty p { margin: 0; font-size: 0.85rem; }
  .empty-sub { font-size: 0.72rem !important; opacity: 0.6; max-width: 420px; }

  .conv-list {
    flex: 1;
    overflow-y: auto;
    padding: 0.75rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .conv-card {
    border: 1px solid var(--border);
    border-radius: 2px;
    background: rgba(255,255,255,0.015);
  }
  .conv-card.open { border-color: var(--border-hover); }
  .conv-head {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    width: 100%;
    background: none;
    border: none;
    color: var(--text);
    padding: 0.6rem 0.8rem;
    cursor: pointer;
    text-align: left;
    font-size: 0.78rem;
  }
  .sev-chip {
    color: var(--c);
    border: 1px solid var(--c);
    padding: 1px 8px;
    border-radius: 2px;
    font-size: 0.62rem;
    font-family: var(--font-ui);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    flex-shrink: 0;
    width: 52px;
    text-align: center;
  }
  .score {
    font-family: var(--font-ui);
    font-size: 0.8rem;
    font-weight: 700;
    color: var(--text);
    width: 28px;
    text-align: right;
    flex-shrink: 0;
  }
  .endpoints { font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .ip { color: var(--text); }
  .port { color: var(--text-muted); }
  .arrow { color: var(--text-muted); margin: 0 0.35rem; }
  .svc {
    color: #4ade80;
    font-size: 0.68rem;
    font-family: var(--font-ui);
    letter-spacing: 0.05em;
    flex-shrink: 0;
  }
  .meta { margin-left: auto; color: var(--text-muted); font-size: 0.68rem; white-space: nowrap; flex-shrink: 0; }
  .chev { color: var(--text-muted); flex-shrink: 0; }

  .conv-body {
    border-top: 1px solid var(--border);
    padding: 0.75rem 0.9rem;
    display: flex;
    flex-direction: column;
    gap: 0.65rem;
  }
  .summary {
    margin: 0;
    font-size: 0.78rem;
    line-height: 1.5;
    color: var(--text);
  }
  .reasons { display: flex; flex-direction: column; gap: 0.3rem; }
  .reason { display: flex; align-items: baseline; gap: 0.6rem; font-size: 0.74rem; }
  .r-sev {
    color: var(--c);
    border: 1px solid var(--c);
    padding: 0 6px;
    border-radius: 2px;
    font-size: 0.6rem;
    font-family: var(--font-ui);
    letter-spacing: 0.06em;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .r-detail { color: var(--text-muted); line-height: 1.45; }
  .facts {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1.25rem;
    font-size: 0.7rem;
    color: var(--text-muted);
  }
  .facts b { color: var(--text); font-weight: 500; }
  .mono { font-family: monospace; font-size: 0.66rem; }
  .actions { display: flex; gap: 0.5rem; }
  .act-btn {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.14);
    color: #888898;
    padding: 4px 12px;
    border-radius: 2px;
    cursor: pointer;
    font-size: 0.66rem;
    font-family: var(--font-ui);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    transition: color 0.15s, border-color 0.15s, background 0.15s;
  }
  .act-btn:hover { color: var(--text); border-color: var(--border-hover); background: rgba(255,255,255,0.04); }
  .act-btn.primary { color: var(--text); border-color: rgba(255,255,255,0.25); }
  .act-btn.primary:hover { background: var(--text); color: #000; border-color: var(--text); }
</style>
