<script>
  import { onMount, onDestroy } from 'svelte';
  import { openInspector, activeResult, activeSessionId } from '../stores/session.js';

  export let senders = [];
  export let receivers = [];
  export let flows = [];
  export let threats = [];

  let el;
  let graph;
  let ro;
  let initError = null;

  $: threatIps = new Set(
    threats.flatMap(t => {
      const m = t.description.match(/\d{1,3}(?:\.\d{1,3}){3}/g) || [];
      return m;
    })
  );

  $: graphData = (() => {
    const ipMap = new Map();
    for (const t of [...senders, ...receivers]) {
      if (!ipMap.has(t.ip)) {
        ipMap.set(t.ip, {
          id: t.ip,
          name: t.vendor || t.ip,
          vendor: t.vendor,
          bytes: t.total_bytes || 0,
          isThreat: threatIps.has(t.ip),
        });
      }
    }
    const nodes = Array.from(ipMap.values()).slice(0, 120);
    const nodeIds = new Set(nodes.map(n => n.id));

    const SUSPICIOUS = new Set([4444, 31337, 23, 12345, 6666, 6667, 1337]);
    const links = flows
      .filter(f => nodeIds.has(f.src_ip) && nodeIds.has(f.dst_ip) && f.src_ip !== f.dst_ip)
      .slice(0, 400)
      .map(f => ({
        source: f.src_ip,
        target: f.dst_ip,
        value: f.bytes,
        protocol: f.protocol,
        // Capture at build time — after force-graph processes the link the
        // `target` field is replaced with the node object and dst_port is gone.
        isSuspicious: SUSPICIOUS.has(f.dst_port),
      }));

    return { nodes, links };
  })();

  $: if (graph && graphData.nodes.length) {
    graph.graphData(graphData);
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
      const { default: ForceGraph3D } = await import('3d-force-graph');

      graph = ForceGraph3D({
        antialias: true,
        alpha: true,
      })(el)
        .backgroundColor('rgba(0,0,0,0)')
        .graphData(graphData)
        .nodeId('id')
        // HTML-escape n.id and n.vendor — n.id is an IP from arbitrary pcap
        // data and n.vendor comes from an OUI lookup that could be widened
        // later to less-trusted sources.
        .nodeLabel(n => `
          <div style="background:#111111;border:1px solid #c8d8f044;border-radius:6px;padding:6px 10px;font-family:monospace;font-size:12px;color:#f0f0f0;pointer-events:none">
            <div style="color:${n.isThreat ? '#e03e5a' : '#c8d8f0'};font-weight:bold">${esc(n.id)}</div>
            ${n.vendor ? `<div style="color:#606060">${esc(n.vendor)}</div>` : ''}
            <div>${fmtBytes(n.bytes)}</div>
          </div>`)
        .nodeColor(n => n.isThreat ? '#e03e5a' : '#c8d8f0')
        .nodeVal(n => Math.max(1, Math.log2(n.bytes / 1024 + 2)))
        .nodeOpacity(0.9)
        .nodeThreeObjectExtend(true)
        .linkColor(() => 'rgba(255,255,255,0.08)')
        .linkWidth(l => Math.max(0.2, Math.log10(l.value + 1) * 0.2))
        .linkOpacity(0.4)
        .linkDirectionalParticles(2)
        .linkDirectionalParticleSpeed(0.004)
        .linkDirectionalParticleColor(l => l.isSuspicious ? '#e03e5a' : '#c8d8f0')
        .onNodeClick(n => viewHostPackets(n.id))
        .onNodeHover(n => {
          if (el) el.style.cursor = n ? 'pointer' : 'default';
        });

      // Gentle auto-rotate
      let angle = 0;
      const rotateTimer = setInterval(() => {
        if (graph && graph.cameraPosition) {
          const dist = 400;
          graph.cameraPosition({
            x: dist * Math.sin(angle),
            z: dist * Math.cos(angle),
          });
          angle += 0.003;
        }
      }, 30);

      // Store cleanup
      el._rotateTimer = rotateTimer;

      // On user interaction, stop auto-rotate
      el.addEventListener('mousedown', () => {
        clearInterval(el._rotateTimer);
      }, { once: true });

      // Responsive
      ro = new ResizeObserver(([entry]) => {
        graph.width(entry.contentRect.width).height(entry.contentRect.height);
      });
      ro.observe(el);

    } catch (e) {
      console.error('NetworkGraph init failed:', e);
      initError = 'WebGL unavailable';
    }
  });

  onDestroy(() => {
    ro?.disconnect();
    if (el?._rotateTimer) clearInterval(el._rotateTimer);
  });

  function fmtBytes(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
    if (b >= 1048576)    return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024)       return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
</script>

<div class="card">
  <div class="card-header">
    <span>Network Topology</span>
    <span class="hint">Click a node to inspect its traffic</span>
  </div>
  <div class="graph-wrap" bind:this={el}>
    {#if initError}
      <div class="fallback">{initError} — enable WebGL to view 3D graph</div>
    {:else if graphData.nodes.length === 0}
      <div class="fallback">No connection data</div>
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
  .hint {
    font-size: 0.68rem;
    color: #606060;
    text-transform: none;
    letter-spacing: 0;
    text-shadow: none;
    font-weight: 400;
  }
  .graph-wrap {
    height: 420px;
    position: relative;
    background: radial-gradient(ellipse at 50% 50%, #020810 0%, #000000 100%);
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
