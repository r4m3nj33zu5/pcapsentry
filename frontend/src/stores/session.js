import { writable, derived } from 'svelte/store';

export const sessions = writable([]);
export const activeSessionId = writable(null);
export const activeResult = writable(null);
export const loading = writable(false);
export const uploadProgress = writable(0);
export const uploadError = writable(null);
export const inspectorPackets = writable(null);
export const inspectorOpen = writable(false);
export const moduleData = writable({});

export async function loadModuleData(sessionId, module) {
  if (!sessionId) return null;
  try {
    const data = await fetch(`/api/results/${sessionId}/${module}`).then(r => r.json());
    moduleData.update(m => ({ ...m, [module]: data }));
    return data;
  } catch (e) {
    console.error(`Failed to load module ${module}:`, e);
    return null;
  }
}

export async function uploadFile(file) {
  loading.set(true);
  uploadProgress.set(0);
  uploadError.set(null);

  let session_id;
  try {
    const res = await fetch('/api/upload', { method: 'POST', body: (() => { const f = new FormData(); f.append('file', file); return f; })() });
    const json = await res.json();
    if (json.error) throw new Error(json.error);
    session_id = json.session_id;
  } catch (e) {
    uploadError.set(e.message || 'Upload failed');
    loading.set(false);
    return;
  }

  activeSessionId.set(session_id);

  // Poll progress with 5-minute timeout
  let parseError = null;
  const TIMEOUT_MS = 5 * 60 * 1000;
  const started = Date.now();
  await new Promise((resolve) => {
    const interval = setInterval(async () => {
      if (Date.now() - started > TIMEOUT_MS) {
        clearInterval(interval);
        parseError = 'Analysis timed out after 5 minutes.';
        resolve();
        return;
      }
      try {
        const prog = await fetch(`/api/progress/${session_id}`).then(r => r.json());
        if (prog.status === 'complete') {
          uploadProgress.set(100);
          clearInterval(interval);
          resolve();
        } else if (prog.status === 'error') {
          parseError = prog.error || 'Parsing failed.';
          clearInterval(interval);
          resolve();
        } else {
          uploadProgress.set(prog.progress || 50);
        }
      } catch (_) {
        // network blip, keep polling
      }
    }, 500);
  });

  if (parseError) {
    uploadError.set(parseError);
    loading.set(false);
    return;
  }

  let result;
  try {
    result = await fetch(`/api/results/${session_id}`).then(r => r.json());
    if (result.error) throw new Error(result.error);
  } catch (e) {
    uploadError.set(e.message || 'Failed to load results.');
    loading.set(false);
    return;
  }

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
  uploadError.set(null);
  activeSessionId.set(session_id);
  // Reset transient UI state from any previous session so old inspector
  // contents / filters do not leak across.
  closeInspector();
  try {
    const res = await fetch(`/api/results/${session_id}`);
    if (!res.ok) throw new Error(`Failed to load session (${res.status})`);
    const result = await res.json();
    if (result.error) throw new Error(result.error);
    activeResult.set(result);
    return result;
  } catch (e) {
    uploadError.set(e.message || 'Failed to load session.');
    return null;
  } finally {
    loading.set(false);
  }
}

export function openInspector(packetIndices) {
  inspectorPackets.set(packetIndices);
  inspectorOpen.set(true);
}

export function closeInspector() {
  inspectorOpen.set(false);
  inspectorPackets.set(null);
}
