<script>
  import BeaconingPanel from '../BeaconingPanel.svelte';
  import { openIpPivot } from '../../stores/investigation.js';

  export let result;

  $: exec = result?.executive;
  $: alerts = result?.alerts || [];
  $: beaconing = result?.beaconing || [];

  function riskColor(level) {
    return { None:'#606060', Low:'#4ade80', Medium:'#c8920a', High:'#d4622c', Critical:'#e03e5a' }[level] || '#606060';
  }

  function sevColor(s) {
    return { Critical:'#e03e5a', High:'#d4622c', Medium:'#c8920a', Low:'#4ade80', Info:'#c8d8f0' }[s] || '#606060';
  }

  function scoreArc(score) {
    const r = 54;
    const circ = 2 * Math.PI * r;
    const dash = (score / 100) * circ;
    return { circ, dash, gap: circ - dash };
  }

  $: arc = scoreArc(exec?.threat_score || 0);
</script>

<div class="exec-dash">
  {#if !exec}
    <div class="empty">No executive summary available.</div>
  {:else}
    <!-- Threat Score Gauge -->
    <div class="top-row">
      <div class="gauge-card">
        <div class="gauge-label">Threat Score</div>
        <svg class="gauge-svg" viewBox="0 0 120 120" width="140" height="140">
          <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="10"/>
          <circle cx="60" cy="60" r="54" fill="none"
            stroke={riskColor(exec.risk_level)}
            stroke-width="10"
            stroke-dasharray="{arc.dash} {arc.gap}"
            stroke-linecap="round"
            transform="rotate(-90 60 60)"
            style="transition: stroke-dasharray 0.5s ease;"
          />
          <text x="60" y="55" text-anchor="middle" fill={riskColor(exec.risk_level)} font-size="28" font-weight="700">{exec.threat_score}</text>
          <text x="60" y="72" text-anchor="middle" fill="#606060" font-size="11">{exec.risk_level}</text>
        </svg>
      </div>

      <!-- Severity Breakdown -->
      <div class="sev-card">
        <div class="card-title">Alert Severity</div>
        {#each Object.entries(exec.alert_count_by_severity || {}).sort((a,b) => ['Critical','High','Medium','Low','Info'].indexOf(a[0]) - ['Critical','High','Medium','Low','Info'].indexOf(b[0])) as [sev, count]}
          <div class="sev-row">
            <span class="sev-dot" style="background:{sevColor(sev)}"></span>
            <span class="sev-name">{sev}</span>
            <span class="sev-count" style="color:{sevColor(sev)}">{count}</span>
          </div>
        {/each}
        {#if Object.keys(exec.alert_count_by_severity || {}).length === 0}
          <div class="sev-row"><span style="color:#606060">No alerts</span></div>
        {/if}
      </div>

      <!-- Key Findings -->
      <div class="findings-card">
        <div class="card-title">Key Findings</div>
        {#each exec.key_findings as finding}
          <div class="finding">{finding}</div>
        {/each}
      </div>
    </div>

    <!-- Suspicious Hosts -->
    {#if exec.top_suspicious_hosts?.length > 0}
      <div class="section-title">Top Suspicious Hosts</div>
      <div class="hosts-grid">
        {#each exec.top_suspicious_hosts as host}
          <div class="host-card">
            <div class="host-ip" on:click={(e) => openIpPivot(host.ip, e)} style="cursor:pointer">{host.ip}</div>
            <div class="host-meta">
              <span class="host-score" style="color:{riskColor(host.score > 50 ? 'Critical' : host.score > 25 ? 'High' : 'Medium')}">
                Score: {host.score}
              </span>
              {#if host.country}<span class="host-country">🌐 {host.country}</span>{/if}
            </div>
            <div class="host-reasons">
              {#each (host.reasons || []).slice(0, 2) as r}
                <div class="reason-tag">{r}</div>
              {/each}
            </div>
          </div>
        {/each}
      </div>
    {/if}

    <!-- Beaconing -->
    {#if beaconing.length > 0}
      <div style="margin-bottom:1.5rem;">
        <BeaconingPanel candidates={beaconing} />
      </div>
    {/if}

    <!-- C2 + Exfil Candidates -->
    <div class="bottom-row">
      {#if exec.c2_candidates?.length > 0}
        <div class="candidate-card">
          <div class="card-title c2-title">C2 Candidates</div>
          {#each exec.c2_candidates as ip}
            <div class="candidate-ip">{ip}</div>
          {/each}
        </div>
      {/if}
      {#if exec.data_exfil_candidates?.length > 0}
        <div class="candidate-card">
          <div class="card-title exfil-title">Exfiltration Candidates</div>
          {#each exec.data_exfil_candidates as ip}
            <div class="candidate-ip">{ip}</div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .exec-dash { padding: 1rem; }
  .empty { color: #606060; text-align: center; padding: 3rem; }

  .top-row {
    display: grid;
    grid-template-columns: auto 1fr 2fr;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  @media (max-width: 800px) {
    .top-row { grid-template-columns: 1fr; }
  }

  .gauge-card, .sev-card, .findings-card {
    background: rgba(10,40,80,0.12);
    border: 1px solid var(--border);
    border-radius: 2px;
    padding: 1rem;
  }
  .gauge-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
  }
  .gauge-label {
    color: var(--text-muted);
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    font-family: var(--font-ui);
  }
  .gauge-svg { overflow: visible; }

  .card-title {
    color: var(--text-muted);
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 0.75rem;
    font-family: var(--font-ui);
  }

  .sev-row { display: flex; align-items: center; gap: 8px; margin-bottom: 0.4rem; font-size: 0.8rem; }
  .sev-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .sev-name { color: var(--text-muted); flex: 1; font-family: var(--font-ui); font-size: 0.72rem; letter-spacing: 0.05em; }
  .sev-count { font-weight: 700; font-size: 0.9rem; font-family: var(--font-ui); }

  .finding {
    font-size: 0.78rem;
    color: #808090;
    padding: 0.35rem 0;
    border-bottom: 1px solid var(--border);
    line-height: 1.45;
    font-family: var(--font-body);
  }
  .finding:last-child { border-bottom: none; }

  .section-title {
    color: var(--text-muted);
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 0.75rem;
    font-family: var(--font-ui);
  }

  .hosts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  .host-card {
    background: rgba(224,62,90,0.04);
    border: 1px solid rgba(224,62,90,0.14);
    border-radius: 2px;
    padding: 0.75rem;
  }
  .host-ip {
    color: var(--text);
    font-family: var(--font-ui);
    font-size: 0.82rem;
    font-weight: 600;
    margin-bottom: 0.35rem;
    letter-spacing: 0.04em;
  }
  .host-meta { display: flex; gap: 0.75rem; font-size: 0.7rem; margin-bottom: 0.5rem; font-family: var(--font-ui); }
  .host-score { font-weight: 700; }
  .host-country { color: var(--text-muted); }
  .host-reasons { display: flex; flex-wrap: wrap; gap: 4px; }
  .reason-tag {
    background: rgba(212,98,44,0.1);
    border: 1px solid rgba(212,98,44,0.2);
    color: var(--high);
    font-size: 0.6rem;
    padding: 1px 6px;
    border-radius: 2px;
    font-family: var(--font-ui);
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  .bottom-row { display: flex; gap: 1rem; flex-wrap: wrap; }
  .candidate-card {
    flex: 1;
    min-width: 180px;
    background: rgba(10,40,80,0.1);
    border: 1px solid var(--border);
    border-radius: 2px;
    padding: 0.75rem;
  }
  .c2-title { color: var(--critical) !important; }
  .exfil-title { color: var(--high) !important; }
  .candidate-ip {
    font-family: var(--font-ui);
    font-size: 0.78rem;
    color: #808090;
    padding: 2px 0;
    letter-spacing: 0.04em;
  }
</style>
