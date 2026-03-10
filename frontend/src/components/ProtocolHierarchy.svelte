<script>
  export let nodes = [];

  let expanded = new Set(['Ethernet', 'IPv4', 'IPv6']);

  function toggle(name) {
    if (expanded.has(name)) expanded.delete(name);
    else expanded.add(name);
    expanded = new Set(expanded);
  }

  function fmt(b) {
    if (b >= 1e6) return (b/1e6).toFixed(1)+'M';
    if (b >= 1e3) return (b/1e3).toFixed(1)+'K';
    return b+'';
  }
</script>

<div class="proto-hierarchy">
  {#if nodes.length === 0}
    <div class="empty">No protocol data.</div>
  {:else}
    <div class="header-row">
      <span class="h-name">Protocol</span>
      <span class="h-num">Packets</span>
      <span class="h-pct">%</span>
      <span class="h-num">Bytes</span>
      <span class="h-pct">%</span>
    </div>
    {#each nodes as node}
      <div class="node-row" on:click={() => node.children?.length && toggle(node.name)}>
        <span class="name" class:has-children={node.children?.length > 0}>
          {#if node.children?.length > 0}
            <span class="arrow">{expanded.has(node.name) ? '▾' : '▸'}</span>
          {:else}
            <span class="indent"></span>
          {/if}
          {node.name}
        </span>
        <span class="num">{node.packet_count?.toLocaleString()}</span>
        <span class="pct">{node.percent_packets?.toFixed(1)}%</span>
        <span class="num">{fmt(node.byte_count || 0)}</span>
        <span class="pct">{node.percent_bytes?.toFixed(1)}%</span>
      </div>
      {#if expanded.has(node.name) && node.children?.length > 0}
        {#each node.children as child}
          <div class="node-row child-row" on:click={() => child.children?.length && toggle(child.name)}>
            <span class="name" class:has-children={child.children?.length > 0}>
              <span class="child-indent"></span>
              {#if child.children?.length > 0}
                <span class="arrow">{expanded.has(child.name) ? '▾' : '▸'}</span>
              {:else}
                <span class="indent"></span>
              {/if}
              {child.name}
            </span>
            <span class="num">{child.packet_count?.toLocaleString()}</span>
            <span class="pct">{child.percent_packets?.toFixed(1)}%</span>
            <span class="num">{fmt(child.byte_count || 0)}</span>
            <span class="pct">{child.percent_bytes?.toFixed(1)}%</span>
          </div>
          {#if expanded.has(child.name) && child.children?.length > 0}
            {#each child.children as leaf}
              <div class="node-row leaf-row">
                <span class="name">
                  <span class="leaf-indent"></span>
                  {leaf.name}
                </span>
                <span class="num">{leaf.packet_count?.toLocaleString()}</span>
                <span class="pct">{leaf.percent_packets?.toFixed(1)}%</span>
                <span class="num">{fmt(leaf.byte_count || 0)}</span>
                <span class="pct">{leaf.percent_bytes?.toFixed(1)}%</span>
              </div>
            {/each}
          {/if}
        {/each}
      {/if}
    {/each}
  {/if}
</div>

<style>
  .proto-hierarchy { font-size:0.78rem; }
  .header-row, .node-row { display:grid; grid-template-columns:1fr 70px 46px 70px 46px; gap:4px; padding:4px 0; align-items:center; }
  .header-row { border-bottom:1px solid rgba(255,255,255,0.07); margin-bottom:4px; }
  .h-name, .h-num, .h-pct { color:#606060; font-size:0.68rem; text-transform:uppercase; }
  .h-num, .h-pct, .num, .pct { text-align:right; }
  .node-row { border-bottom:1px solid rgba(255,255,255,0.02); }
  .node-row:hover { background:rgba(200,216,240,0.02); }
  .node-row.child-row { background:rgba(0,0,0,0.1); }
  .node-row.leaf-row { background:rgba(0,0,0,0.15); }
  .has-children { cursor:pointer; }
  .name { display:flex; align-items:center; color:#f0f0f0; gap:2px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .arrow { color:#606060; font-size:0.65rem; width:12px; flex-shrink:0; }
  .indent { width:12px; flex-shrink:0; display:inline-block; }
  .child-indent { width:12px; flex-shrink:0; display:inline-block; }
  .leaf-indent { width:24px; flex-shrink:0; display:inline-block; }
  .num { color:#888888; font-family:monospace; }
  .pct { color:#606060; font-family:monospace; }
  .empty { color:#606060; font-size:0.78rem; }
</style>
