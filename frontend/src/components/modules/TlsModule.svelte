<script>
  import { focusOnIp } from '../../stores/investigation.js';
  export let result;

  $: sessions = result?.tls_sessions || [];
  let search = '';
  let selected = null;

  $: filtered = sessions.filter(s => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (s.sni||'').toLowerCase().includes(q) || s.src_ip.includes(q) || s.dst_ip.includes(q)
      || s.ja3_hash.includes(q);
  });

  $: badJa3Count = sessions.filter(s => s.known_bad_ja3).length;
  $: expiredCount = sessions.filter(s => s.is_expired).length;
  $: weakCount = sessions.filter(s => s.is_cipher_weak).length;

  function versionName(v) {
    const m = {769:'TLS 1.0',770:'TLS 1.1',771:'TLS 1.2',772:'TLS 1.3',768:'SSL 3.0'};
    return m[v] || `0x${v?.toString(16)?.toUpperCase()}`;
  }
</script>

<div class="tls-module">
  <div class="stat-bar">
    <div class="stat"><span class="sv">{sessions.length}</span><span class="sl">TLS Sessions</span></div>
    <div class="stat danger"><span class="sv">{badJa3Count}</span><span class="sl">Known-Bad JA3</span></div>
    <div class="stat warn"><span class="sv">{expiredCount}</span><span class="sl">Expired Certs</span></div>
    <div class="stat warn"><span class="sv">{weakCount}</span><span class="sl">Weak Ciphers</span></div>
  </div>

  <div class="toolbar">
    <input class="search" type="text" bind:value={search} placeholder="SNI, IP, JA3 hash…" />
    <span class="count">{filtered.length} sessions</span>
  </div>

  <div class="sessions-list">
    {#each filtered as s}
      <div class="session-row"
        class:known-bad={s.known_bad_ja3}
        class:expired={s.is_expired}
        on:click={() => selected = selected?.flow_id === s.flow_id ? null : s}
      >
        <div class="session-main">
          <div class="session-header">
            {#if s.known_bad_ja3}
              <span class="badge bad">☠ {s.known_bad_ja3}</span>
            {/if}
            {#if s.is_expired}
              <span class="badge expired">Expired Cert</span>
            {/if}
            {#if s.is_cipher_weak}
              <span class="badge weak">Weak Cipher</span>
            {/if}
            <span class="sni">{s.sni || '(no SNI)'}</span>
          </div>
          <div class="session-meta">
            <span class="ip-pair" on:click|stopPropagation={() => focusOnIp(s.dst_ip)}>
              {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}
            </span>
            <span class="tls-ver">{versionName(s.tls_version_offered)}</span>
            <span class="ja3-hash" title={s.ja3_hash}>{s.ja3_hash.substring(0,12)}…</span>
          </div>
        </div>

        {#if selected?.flow_id === s.flow_id}
          <div class="session-detail">
            <div class="detail-grid">
              <div><span class="dl">JA3 Hash</span><code class="dv">{s.ja3_hash}</code></div>
              <div><span class="dl">JA3 String</span><code class="dv small">{s.ja3_string}</code></div>
              <div><span class="dl">TLS Version Offered</span><span class="dv">{versionName(s.tls_version_offered)}</span></div>
              <div><span class="dl">SNI</span><span class="dv">{s.sni || '—'}</span></div>
              {#if s.cert_subject}<div><span class="dl">Cert Subject</span><span class="dv">{s.cert_subject}</span></div>{/if}
              {#if s.cert_issuer}<div><span class="dl">Cert Issuer</span><span class="dv">{s.cert_issuer}</span></div>{/if}
              <div><span class="dl">Packets</span><span class="dv">{s.packet_indices?.length || 0}</span></div>
              <div><span class="dl">First Seen</span><span class="dv">{new Date(s.first_seen*1000).toLocaleTimeString()}</span></div>
            </div>
            {#if s.known_bad_ja3}
              <div class="ja3-alert">
                ☠ JA3 fingerprint matched known malware family: <strong>{s.known_bad_ja3}</strong>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/each}

    {#if filtered.length === 0}
      <div class="empty">{sessions.length === 0 ? 'No TLS sessions detected.' : 'No sessions match filter.'}</div>
    {/if}
  </div>
</div>

<style>
  .tls-module { display:flex; flex-direction:column; height:100%; }
  .stat-bar { display:flex; gap:1rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); }
  .stat { display:flex; flex-direction:column; align-items:center; }
  .sv { font-size:1.1rem; font-weight:700; color:#f0f0f0; }
  .sl { font-size:0.65rem; color:#606060; text-transform:uppercase; }
  .stat.warn .sv { color:#c8920a; }
  .stat.danger .sv { color:#e03e5a; }
  .toolbar { display:flex; align-items:center; gap:0.75rem; padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); }
  .search { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:#f0f0f0; padding:5px 10px; border-radius:5px; font-size:0.8rem; width:280px; }
  .search:focus { outline:none; border-color:rgba(255,255,255,0.15); }
  .count { margin-left:auto; color:#606060; font-size:0.78rem; }
  .sessions-list { flex:1; overflow-y:auto; }
  .session-row { padding:0.6rem 1rem; border-bottom:1px solid rgba(255,255,255,0.03); cursor:pointer; border-left:3px solid transparent; }
  .session-row:hover { background:rgba(255,255,255,0.02); }
  .session-row.known-bad { border-left-color:#e03e5a; background:rgba(255,32,121,0.03); }
  .session-row.expired { border-left-color:#c8920a; }
  .session-header { display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:3px; }
  .badge { font-size:0.65rem; font-weight:700; padding:1px 6px; border-radius:3px; }
  .badge.bad { background:rgba(255,32,121,0.2); color:#e03e5a; border:1px solid rgba(255,32,121,0.4); }
  .badge.expired { background:rgba(255,165,0,0.15); color:#c8920a; border:1px solid rgba(255,165,0,0.3); }
  .badge.weak { background:rgba(255,107,53,0.15); color:#d4622c; border:1px solid rgba(255,107,53,0.3); }
  .sni { color:#f0f0f0; font-weight:500; font-size:0.85rem; }
  .session-meta { display:flex; align-items:center; gap:0.75rem; font-size:0.75rem; flex-wrap:wrap; }
  .ip-pair { color:#c8d8f0; font-family:monospace; cursor:pointer; }
  .ip-pair:hover { text-decoration:underline; }
  .tls-ver { color:#bf5fff; }
  .ja3-hash { font-family:monospace; color:#787878; }
  .session-detail { margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid rgba(255,255,255,0.04); }
  .detail-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:0.5rem; margin-bottom:0.75rem; }
  .detail-grid > div { display:flex; flex-direction:column; gap:2px; }
  .dl { color:#606060; font-size:0.68rem; text-transform:uppercase; }
  .dv { color:#f0f0f0; font-size:0.78rem; }
  .dv.small { font-size:0.68rem; word-break:break-all; }
  code.dv { font-family:monospace; color:#4ade80; }
  .ja3-alert { background:rgba(255,32,121,0.1); border:1px solid rgba(255,32,121,0.3); color:#e03e5a; padding:0.5rem 0.75rem; border-radius:5px; font-size:0.8rem; }
  .ja3-alert strong { font-weight:700; }
  .empty { color:#606060; text-align:center; padding:3rem; }
</style>
