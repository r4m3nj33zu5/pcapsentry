import { writable } from 'svelte/store';

export const investigationFilter = writable({
  focusIp: null,
  focusFlow: null,
  focusTimeRange: null,
  focusMitreTechnique: null,
  focusAlertId: null,
  markedPackets: new Set(),
});

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
  });
}

export function markPacket(idx) {
  investigationFilter.update(f => {
    const s = new Set(f.markedPackets);
    s.has(idx) ? s.delete(idx) : s.add(idx);
    return { ...f, markedPackets: s };
  });
}
