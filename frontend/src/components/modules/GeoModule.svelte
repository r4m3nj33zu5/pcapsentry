<script>
  import GeoGlobe from '../GeoGlobe.svelte';
  import GeoMap from '../GeoMap.svelte';
  import { focusOnIp } from '../../stores/investigation.js';
  export let result;

  $: points = result?.geo_points || [];
  $: flows = result?.flows || [];
  $: threats = result?.threats || [];

  let view = 'globe';

  function fmt(b) {
    if (b >= 1e6) return (b/1e6).toFixed(1)+'M';
    if (b >= 1e3) return (b/1e3).toFixed(1)+'K';
    return b+'';
  }
</script>

<div class="geo-module">
  <div class="toolbar">
    <div class="view-tabs">
      <button class="vt" class:active={view==='globe'} on:click={() => view='globe'}>⊞ Globe</button>
      <button class="vt" class:active={view==='map'} on:click={() => view='map'}>⊡ Map</button>
      <button class="vt" class:active={view==='table'} on:click={() => view='table'}>≡ Table</button>
    </div>
    <span class="count">{points.length} unique IPs geolocated</span>
  </div>

  {#if view === 'globe'}
    <div class="globe-wrap">
      <GeoGlobe {points} {threats} {flows} />
    </div>
  {:else if view === 'map'}
    <div class="map-wrap">
      <GeoMap {points} />
    </div>
  {:else}
    <div class="table-wrap">
      <table class="geo-table">
        <thead>
          <tr><th>IP</th><th>Country</th><th>City</th><th>ASN</th><th>Packets</th><th>Bytes</th></tr>
        </thead>
        <tbody>
          {#each points as p}
            <tr>
              <td class="ip" on:click={() => focusOnIp(p.ip)}>{p.ip}</td>
              <td>{p.country}</td>
              <td>{p.city}</td>
              <td class="asn">{p.asn || '—'}</td>
              <td>{p.packet_count}</td>
              <td>{fmt(p.bytes)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .geo-module { display:flex; flex-direction:column; height:100%; }
  .toolbar { display:flex; align-items:center; gap:0.75rem; padding:0.5rem 1rem; border-bottom:1px solid rgba(255,255,255,0.05); }
  .view-tabs { display:flex; gap:4px; }
  .vt { background:none; border:1px solid rgba(255,255,255,0.07); color:#606060; padding:4px 10px; border-radius:4px; font-size:0.75rem; cursor:pointer; }
  .vt.active { color:#c8d8f0; border-color:rgba(255,255,255,0.2); }
  .count { color:#606060; font-size:0.78rem; margin-left:auto; }
  .globe-wrap, .map-wrap { flex:1; min-height:400px; }
  .table-wrap { flex:1; overflow:auto; }
  .geo-table { width:100%; border-collapse:collapse; font-size:0.78rem; }
  thead th { position:sticky; top:0; background:#0a0a0a; color:#606060; text-align:left; padding:6px 10px; border-bottom:1px solid rgba(255,255,255,0.07); }
  tbody tr { border-bottom:1px solid rgba(255,255,255,0.02); }
  tbody tr:hover { background:rgba(200,216,240,0.02); }
  td { padding:5px 10px; color:#888888; }
  .ip { color:#c8d8f0; font-family:monospace; cursor:pointer; }
  .ip:hover { text-decoration:underline; }
  .asn { color:#787878; font-size:0.72rem; }
</style>
