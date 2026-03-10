<script>
  import { onMount, onDestroy } from 'svelte';

  export let points = [];
  export let threats = [];

  let mapEl;
  let map;
  let L;

  $: threatIps = new Set(
    threats.flatMap(t =>
      (t.description.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [])
    )
  );

  $: hasGeo = points && points.length > 0;

  onMount(async () => {
    if (!hasGeo) return;
    L = (await import('leaflet')).default;

    map = L.map(mapEl, { zoomControl: true }).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '© OpenStreetMap © CARTO',
    }).addTo(map);

    addMarkers();
  });

  function addMarkers() {
    if (!map || !L) return;
    const maxBytes = Math.max(...points.map(p => p.bytes), 1);

    for (const pt of points) {
      const isThreat = threatIps.has(pt.ip);
      const color = isThreat ? '#e03e5a' : '#c8d8f0';
      const radius = 4 + Math.sqrt(pt.bytes / maxBytes) * 16;

      const marker = L.circleMarker([pt.lat, pt.lon], {
        radius,
        color,
        fillColor: color,
        fillOpacity: 0.6,
        weight: 1.5,
        opacity: 0.9,
      });

      marker.bindPopup(`
        <div style="font-family:system-ui;font-size:12px;line-height:1.6;background:#111111;color:#f0f0f0;padding:4px">
          <strong style="color:#c8d8f0">${pt.ip}</strong><br/>
          ${pt.city ? pt.city + ', ' : ''}${pt.country}<br/>
          Packets: ${pt.packet_count.toLocaleString()}<br/>
          Bytes: ${fmtBytes(pt.bytes)}
          ${isThreat ? '<br/><span style="color:#e03e5a">⚠ Threat Indicator</span>' : ''}
        </div>
      `);

      marker.addTo(map);
    }
  }

  function fmtBytes(b) {
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  onDestroy(() => {
    if (map) map.remove();
  });
</script>

<div class="card">
  <div class="card-header">Geographic Map</div>
  {#if hasGeo}
    <div bind:this={mapEl} class="map"></div>
  {:else}
    <div class="placeholder">
      <div class="placeholder-icon">🌐</div>
      <div class="placeholder-title">Geo Map Unavailable</div>
      <p class="placeholder-text">
        Place a <code>GeoLite2-City.mmdb</code> file in the <code>assets/</code> directory
        to enable IP geolocation. Available free from <strong>maxmind.com</strong>.
      </p>
    </div>
  {/if}
</div>

<style>
  .card {
    background: #111111;
    border: 1px solid rgba(200, 216, 240, 0.18);
    
    border-radius: 2px;
    padding: 1.25rem;
    overflow: hidden;
  }
  .card-header {
    font-size: 0.75rem;
    font-weight: 600;
    color: #c8d8f0;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
    
  }
  .map {
    height: 260px;
    border-radius: 2px;
    overflow: hidden;
  }
  .placeholder {
    height: 260px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: 0.5rem;
    color: #606060;
    padding: 1rem;
  }
  .placeholder-icon {
    font-size: 2.5rem;
    opacity: 0.3;
  }
  .placeholder-title {
    font-size: 0.95rem;
    font-weight: 600;
    color: #f0f0f0;
  }
  .placeholder-text {
    font-size: 0.8rem;
    line-height: 1.6;
    max-width: 340px;
    color: #606060;
  }
  code {
    background: rgba(255,255,255,0.07);
    color: #c8d8f0;
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
    font-size: 0.8em;
  }
</style>
