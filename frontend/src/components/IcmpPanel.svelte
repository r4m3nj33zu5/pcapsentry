<script>
  import { openInspector, activeResult, activeSessionId } from '../stores/session.js';

  export let icmpSummary = {};
  export let deviceMap = {};

  $: summary = icmpSummary || {};
  $: hasActivity = (summary.echo_requests || 0) > 0;
  $: topPairs = summary.top_pairs || [];

  function deviceLabel(ip) {
    const d = deviceMap[ip];
    if (d?.vendor) return d.vendor;
    if (d?.mac) return d.mac.substring(0, 8) + '…';
    return ip;
  }

  function viewPair(pair) {
    const packets = $activeResult?.packets || [];
    const indices = packets
      .filter(p =>
        (p.src_ip === pair.src && p.dst_ip === pair.dst) ||
        (p.src_ip === pair.dst && p.dst_ip === pair.src)
      )
      .map(p => p.index);
    openInspector(indices, $activeSessionId);
  }
</script>

<div class="card">
  <div class="card-header">ICMP / Ping Activity</div>

  <div class="stats-row">
    <div class="mini-stat">
      <div class="mini-label">Echo Requests</div>
      <div class="mini-val cyan">{(summary.echo_requests || 0).toLocaleString()}</div>
    </div>
    <div class="mini-stat">
      <div class="mini-label">Echo Replies</div>
      <div class="mini-val green">{(summary.echo_replies || 0).toLocaleString()}</div>
    </div>
    <div class="mini-stat">
      <div class="mini-label">Unique Sources</div>
      <div class="mini-val cyan">{(summary.unique_sources || 0).toLocaleString()}</div>
    </div>
    <div class="mini-stat">
      <div class="mini-label">Unique Targets</div>
      <div class="mini-val cyan">{(summary.unique_targets || 0).toLocaleString()}</div>
    </div>
  </div>

  {#if !hasActivity}
    <div class="no-activity">No ICMP ping activity detected.</div>
  {:else}
    <div class="table-label">Top Ping Pairs <span class="hint">· click to inspect</span></div>
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th></th>
            <th>Destination</th>
            <th>Count</th>
          </tr>
        </thead>
        <tbody>
          {#each topPairs as pair}
            <tr class:suspicious={pair.count > 50} class="clickable" on:click={() => viewPair(pair)}>
              <td class="dev-cell">
                <span class="dev">{deviceLabel(pair.src)}</span>
                <span class="sub">{pair.src}</span>
              </td>
              <td class="arrow">→</td>
              <td class="dev-cell">
                <span class="dev">{deviceLabel(pair.dst)}</span>
                <span class="sub">{pair.dst}</span>
              </td>
              <td class="count" class:magenta={pair.count > 50}>{pair.count.toLocaleString()}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .card {
    background: #111111;
    border: 1px solid rgba(200, 216, 240, 0.18);
    
    border-radius: 2px;
    padding: 1.25rem;
  }
  .card-header {
    font-size: 0.75rem;
    font-weight: 600;
    color: #c8d8f0;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
    
  }
  .stats-row {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }
  .mini-stat {
    flex: 1;
    min-width: 80px;
    background: rgba(0,0,0,0.3);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 2px;
    padding: 0.6rem 0.75rem;
  }
  .mini-label {
    font-size: 0.65rem;
    color: #606060;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.25rem;
  }
  .mini-val {
    font-size: 1.15rem;
    font-weight: 700;
  }
  .mini-val.cyan {
    color: #c8d8f0;
    
  }
  .mini-val.green {
    color: #4ade80;
    
  }
  .no-activity {
    color: #4ade80;
    font-size: 0.85rem;
    padding: 0.75rem 0;
    
  }
  .table-label {
    font-size: 0.68rem;
    color: #606060;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.4rem;
  }
  .table-scroll {
    max-height: 180px;
    overflow-y: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.76rem;
  }
  th {
    color: #606060;
    font-weight: 500;
    text-align: left;
    padding: 0.25rem 0.4rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
    position: sticky;
    top: 0;
    background: #111111;
  }
  td {
    padding: 0.28rem 0.4rem;
    border-bottom: 1px solid rgba(255,255,255,0.03);
  }
  .dev-cell {
    display: flex;
    flex-direction: column;
    gap: 0.04rem;
  }
  .dev {
    font-size: 0.74rem;
    color: #c8d8f0;
  }
  .sub {
    font-family: monospace;
    font-size: 0.65rem;
    color: #606060;
  }
  .arrow {
    color: #606060;
    padding: 0 0.2rem;
  }
  .count {
    color: #c8d8f0;
    font-weight: 600;
  }
  .count.magenta {
    color: #e03e5a;
    
  }
  tr.suspicious .dev {
    color: #e03e5a;
  }
  .hint {
    color: #606060;
    font-size: 0.65rem;
    font-weight: 400;
    text-transform: none;
    letter-spacing: 0;
  }
  tr.clickable {
    cursor: pointer;
    transition: background 0.1s;
  }
  tr.clickable:hover td {
    background: rgba(255,255,255,0.04);
  }
  tr.clickable.suspicious:hover td {
    background: rgba(255,32,121,0.08);
  }
</style>
