import { writable } from 'svelte/store';

// IP Pivot Popover state
export const ipPivot = writable({ ip: null, x: 0, y: 0 });

export function openIpPivot(ip, event) {
  event.stopPropagation();
  const rect = event.target.getBoundingClientRect();
  ipPivot.set({ ip, x: rect.left, y: rect.bottom + 6 });
}

export function closeIpPivot() {
  ipPivot.set({ ip: null, x: 0, y: 0 });
}

export const investigationFilter = writable({
  focusIp: null,
  focusFlow: null,
  focusTimeRange: null,
  focusMitreTechnique: null,
  focusAlertId: null,
  markedPackets: new Set(),
  // Conversation isolation: restrict the packet view to this set of indices.
  focusPacketSet: null,
  focusPacketLabel: null,
});

export function isolatePackets(indices, label) {
  investigationFilter.update(f => ({
    ...f,
    focusPacketSet: new Set(indices),
    focusPacketLabel: label || null,
  }));
}

export function focusOnIp(ip) {
  investigationFilter.update(f => ({ ...f, focusIp: ip }));
}

export function focusOnFlow(id) {
  investigationFilter.update(f => ({ ...f, focusFlow: id }));
}

export function setTimeRange(start, end) {
  investigationFilter.update(f => ({ ...f, focusTimeRange: { start, end } }));
}

export function focusOnAlert(alertId, mitreTechnique) {
  investigationFilter.update(f => ({
    ...f,
    focusAlertId: alertId,
    focusMitreTechnique: mitreTechnique || null,
  }));
}

export function clearInvestigation() {
  investigationFilter.set({
    focusIp: null,
    focusFlow: null,
    focusTimeRange: null,
    focusMitreTechnique: null,
    focusAlertId: null,
    markedPackets: new Set(),
    focusPacketSet: null,
    focusPacketLabel: null,
  });
}

export function markPacket(idx) {
  investigationFilter.update(f => {
    const s = new Set(f.markedPackets);
    s.has(idx) ? s.delete(idx) : s.add(idx);
    return { ...f, markedPackets: s };
  });
}
