<script>
  import { onMount, onDestroy } from 'svelte';
  import { openInspector, activeResult, activeSessionId } from '../stores/session.js';

  export let points = [];
  export let threats = [];
  export let flows = [];

  let el;
  let globe;
  let ro;
  let initError = null;

  $: threatIps = new Set(
    threats.flatMap(t => {
      const m = t.description.match(/\d{1,3}(?:\.\d{1,3}){3}/g) || [];
      return m;
    })
  );

  $: geoMap = new Map(points.map(p => [p.ip, p]));

  $: arcs = (() => {
    const result = [];
    for (const f of flows.slice(0, 80)) {
      const src = geoMap.get(f.src_ip);
      const dst = geoMap.get(f.dst_ip);
      if (src && dst && src !== dst) {
        result.push({
          startLat: src.lat, startLng: src.lon,
          endLat: dst.lat,   endLng: dst.lon,
          isThreat: threatIps.has(f.src_ip) || threatIps.has(f.dst_ip),
          bytes: f.bytes,
          src: f.src_ip, dst: f.dst_ip,
        });
      }
    }
    return result;
  })();

  $: if (globe && points.length) {
    globe
      .pointsData(points)
      .arcsData(arcs);
  }

  function viewHostPackets(ip) {
    const packets = $activeResult?.packets || [];
    const indices = packets
      .filter(p => p.src_ip === ip || p.dst_ip === ip)
      .map(p => p.index);
    openInspector(indices, $activeSessionId);
  }

  onMount(async () => {
    try {
      const [{ default: Globe }, worldData, { feature }] = await Promise.all([
        import('globe.gl'),
        import('world-atlas/countries-110m.json'),
        import('topojson-client'),
      ]);

      const countries = feature(worldData, worldData.objects.countries);

      globe = Globe()(el)
        .backgroundColor('rgba(5,10,15,0)')
        .atmosphereColor('#00b8ff')
        .atmosphereAltitude(0.14)
        .polygonsData(countries.features)
        .polygonCapColor(() => 'rgba(6,18,40,0.95)')
        .polygonSideColor(() => 'rgba(0,180,255,0.04)')
        .polygonStrokeColor(() => 'rgba(255,255,255,0.12)')
        .pointsData(points)
        .pointLat(d => d.lat)
        .pointLng(d => d.lon)
        .pointColor(d => threatIps.has(d.ip) ? '#e03e5a' : '#c8d8f0')
        .pointRadius(d => Math.max(0.18, 0.07 * Math.log(d.packet_count + 2)))
        .pointAltitude(0.01)
        .pointLabel(d => `
          <div style="background:#111111;border:1px solid #c8d8f044;border-radius:6px;padding:6px 10px;font-family:monospace;font-size:12px;color:#f0f0f0;pointer-events:none">
            <div style="color:#c8d8f0;font-weight:bold">${d.ip}</div>
            ${d.city || d.country ? `<div style="color:#606060">${[d.city, d.country].filter(Boolean).join(', ')}</div>` : ''}
            <div>${d.packet_count.toLocaleString()} pkts · ${fmtBytes(d.bytes)}</div>
            ${threatIps.has(d.ip) ? '<div style="color:#e03e5a">⚠ Threat IP</div>' : ''}
          </div>`)
        .onPointClick(d => viewHostPackets(d.ip))
        .arcsData(arcs)
        .arcStartLat(d => d.startLat)
        .arcStartLng(d => d.startLng)
        .arcEndLat(d => d.endLat)
        .arcEndLng(d => d.endLng)
        .arcColor(d => d.isThreat
          ? ['rgba(255,32,121,0.9)', 'rgba(255,32,121,0.1)']
          : ['rgba(200,216,240,0.8)', 'rgba(255,255,255,0.04)'])
        .arcStroke(d => d.isThreat ? 0.6 : 0.3)
        .arcDashLength(0.35)
        .arcDashGap(0.15)
        .arcDashAnimateTime(d => d.isThreat ? 1200 : 2000)
        .arcAltitudeAutoScale(0.3)
        .enablePointerInteraction(true);

      // Slow auto-rotation
      globe.controls().autoRotate = true;
      globe.controls().autoRotateSpeed = 0.4;

      // Responsive resize
      ro = new ResizeObserver(([entry]) => {
        globe.width(entry.contentRect.width).height(entry.contentRect.height);
      });
      ro.observe(el);

    } catch (e) {
      console.error('Globe init failed:', e);
      initError = 'WebGL unavailable';
    }
  });

  onDestroy(() => {
    ro?.disconnect();
    if (globe) {
      globe.controls().dispose?.();
    }
  });

  function fmtBytes(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
    if (b >= 1048576)    return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024)       return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }
</script>

<div class="card">
  <div class="card-header">
    <span>Global Traffic Map</span>
    <span class="legend">
      <span class="dot cyan"></span>IP
      <span class="dot magenta"></span>Threat
      <span class="arc-line cyan-arc"></span>Flow
      <span class="arc-line red-arc"></span>Attack
    </span>
  </div>
  <div class="globe-wrap" bind:this={el}>
    {#if initError}
      <div class="fallback">{initError} — enable WebGL to view 3D map</div>
    {:else if points.length === 0}
      <div class="fallback">No geo data (add GeoLite2-City.mmdb to assets/)</div>
    {/if}
  </div>
</div>

<style>
  .card {
    background: #000000;
    border: 1px solid rgba(255,255,255,0.08);
    
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
    margin-bottom: 0.75rem;
    
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  .legend {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.68rem;
    color: #606060;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 400;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
    
  }
  .dot.cyan    { background: #c8d8f0; color: #c8d8f0; }
  .dot.magenta { background: #e03e5a; color: #e03e5a; }
  .arc-line {
    display: inline-block;
    width: 16px;
    height: 2px;
    border-radius: 1px;
  }
  .arc-line.cyan-arc   { background: linear-gradient(90deg, #c8d8f0, transparent); }
  .arc-line.red-arc    { background: linear-gradient(90deg, #e03e5a, transparent); }
  .globe-wrap {
    height: 420px;
    position: relative;
    background: radial-gradient(ellipse at center, #010a1a 0%, #000000 100%);
    border-radius: 2px;
    overflow: hidden;
  }
  .fallback {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #606060;
    font-size: 0.875rem;
  }
</style>
