import { writable, derived } from 'svelte/store';

export const sessions = writable([]);
export const activeSessionId = writable(null);
export const activeResult = writable(null);
export const loading = writable(false);
export const uploadProgress = writable(0);
export const inspectorPackets = writable(null);
export const inspectorOpen = writable(false);

export async function uploadFile(file) {
  loading.set(true);
  uploadProgress.set(0);

  const form = new FormData();
  form.append('file', file);

  const res = await fetch('/api/upload', { method: 'POST', body: form });
  const { session_id } = await res.json();

  activeSessionId.set(session_id);

  // Poll progress
  await new Promise((resolve) => {
    const interval = setInterval(async () => {
      const prog = await fetch(`/api/progress/${session_id}`).then(r => r.json());
      if (prog.status === 'complete') {
        uploadProgress.set(100);
        clearInterval(interval);
        resolve();
      } else if (prog.status === 'error') {
        clearInterval(interval);
        resolve();
      } else {
        uploadProgress.set(prog.progress || 50);
      }
    }, 500);
  });

  const result = await fetch(`/api/results/${session_id}`).then(r => r.json());
  activeResult.set(result);
  loading.set(false);

  // Add to session list
  sessions.update(list => [{
    session_id,
    filename: result.overview?.filename || file.name,
    total_packets: result.overview?.total_packets,
    highest_severity: result.highest_severity || 'None',
    analyzed_at: result.overview?.analyzed_at,
  }, ...list]);

  return result;
}

export async function loadSession(session_id) {
  loading.set(true);
  activeSessionId.set(session_id);
  const result = await fetch(`/api/results/${session_id}`).then(r => r.json());
  activeResult.set(result);
  loading.set(false);
  return result;
}

export async function openInspector(packetIndices, sessionId) {
  inspectorPackets.set(packetIndices);
  inspectorOpen.set(true);
}

export function closeInspector() {
  inspectorOpen.set(false);
  inspectorPackets.set(null);
}
