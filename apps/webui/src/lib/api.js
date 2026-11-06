let base = '';
let token = '';
let bootError = '';

export function configure(url, tok) {
  base = url.replace(/\/$/, '');
  token = tok;
}

export function configured() {
  return base !== '' && token !== '';
}

export function isMobile() {
  return (
    typeof window !== 'undefined' &&
    (window.__GLYX__?.mobile === true || window.__GLYX_MOBILE__ === true)
  );
}

export function mobileDataDir() {
  return typeof window !== 'undefined' ? window.__GLYX__?.dataDir || '' : '';
}

export function bootstrapDesktop() {
  if (typeof window !== 'undefined' && window.__GLYX__) {
    configure(window.__GLYX__.url, window.__GLYX__.token);
    bootError = '';
    return true;
  }
  if (typeof window !== 'undefined' && window.__GLYX_BOOT__?.error) {
    bootError = window.__GLYX_BOOT__.error;
  }
  return false;
}

export function bootstrapError() {
  return bootError;
}

export async function retryDesktopBootstrap() {
  if (isMobile()) return configured();
  if (typeof window === 'undefined' || !window.__TAURI__?.core?.invoke) {
    return configured();
  }
  try {
    const info = await window.__TAURI__.core.invoke('desktop_bootstrap');
    if (info.url && info.token) {
      configure(info.url, info.token);
      bootError = '';
      return true;
    }
    bootError = info.error || 'daemon did not start';
  } catch (e) {
    bootError = e.message || String(e);
  }
  return false;
}

export async function pickFolder(title = 'Choose folder') {
  if (isMobile()) return prompt(title) || '';
  if (typeof window !== 'undefined' && window.__TAURI__?.core?.invoke) {
    return (await window.__TAURI__.core.invoke('desktop_pick_folder', { title })) || '';
  }
  return prompt(title) || '';
}

export async function pickFile(title = 'Choose file') {
  if (isMobile()) return prompt(title) || '';
  if (typeof window !== 'undefined' && window.__TAURI__?.core?.invoke) {
    return (await window.__TAURI__.core.invoke('desktop_pick_file', { title })) || '';
  }
  return prompt(title) || '';
}

export async function pickSave(title = 'Choose file', fileName = '') {
  if (isMobile()) return prompt(title) || '';
  if (typeof window !== 'undefined' && window.__TAURI__?.core?.invoke) {
    return (
      (await window.__TAURI__.core.invoke('desktop_pick_save', {
        title,
        fileName: fileName || undefined
      })) || ''
    );
  }
  return prompt(title) || '';
}

async function reqPage(method, path) {
  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
  });
  const data = await res.json().catch(() => []);
  if (!res.ok) throw new Error(data.error || `request failed: ${res.status}`);
  return { data, total: Number(res.headers.get('x-total-count') || data.length || 0) };
}

async function req(method, path, body) {
  const res = await fetch(base + path, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed: ${res.status}`);
  return data;
}

export const api = {
  status: () => req('GET', '/v1/status'),
  templates: () => req('GET', '/v1/templates'),
  unlock: (password, keyfile, newPin, options = {}) =>
    req('POST', '/v1/unlock', { password, keyfile, new_pin: newPin, ...options }),
  unlockPin: (pin, options = {}) => req('POST', '/v1/unlock', { pin, ...options }),
  lock: () => req('POST', '/v1/lock'),
  items: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req('GET', '/v1/items' + (q ? `?${q}` : ''));
  },
  passkeys: () => req('GET', '/v1/passkeys'),
  itemsPage: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return reqPage('GET', '/v1/items' + (q ? `?${q}` : ''));
  },
  bulk: (body) => req('POST', '/v1/items/bulk', body),
  devices: () => req('GET', '/v1/devices'),
  labelDevice: (id, label) => req('POST', '/v1/devices/label', { id, label }),
  health: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req('GET', '/v1/health/report' + (q ? `?${q}` : ''));
  },
  audit: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return reqPage('GET', '/v1/audit' + (q ? `?${q}` : ''));
  },
  generate: (options) => req('POST', '/v1/generate', options),
  library: () => req('GET', '/v1/library'),
  renameTag: (from, to) => req('POST', '/v1/library/tags/rename', { from, to }),
  deleteTag: (name) => req('POST', '/v1/library/tags/delete', { name }),
  renameFolder: (from, to) => req('POST', '/v1/library/folders/rename', { from, to }),
  deleteFolder: (folder) => req('POST', '/v1/library/folders/delete', { folder }),
  duplicates: () => req('GET', '/v1/items/duplicates'),
  recents: () => req('GET', '/v1/recents'),
  show: (id, reveal = false) => req('GET', `/v1/items/${id}?reveal=${reveal}`),
  rendered: (id, reveal = false) => req('GET', `/v1/items/${id}/rendered?reveal=${reveal}`),
  create: (body) => req('POST', '/v1/items', body),
  edit: (id, body) => req('PATCH', `/v1/items/${id}`, body),
  remove: (id) => req('DELETE', `/v1/items/${id}`),
  totp: (id) => req('GET', `/v1/items/${id}/totp`),
  related: (id) => req('GET', `/v1/items/${id}/related`),
  link: (id, child) => req('POST', `/v1/items/${id}/link`, { child }),
  unlink: (id, child) => req('POST', `/v1/items/${id}/unlink`, { child }),
  fill: (id, field, timeout = 15) => req('POST', `/v1/items/${id}/fill`, { field, timeout }),
  history: (id) => req('GET', `/v1/items/${id}/history`),
  historyItem: (id, file, reveal = false) =>
    req('GET', `/v1/items/${id}/history/${encodeURIComponent(file)}?reveal=${reveal}`),
  historyCompare: (id, file) =>
    req('GET', `/v1/items/${id}/history/${encodeURIComponent(file)}/compare`),
  restoreHistory: (id, file) =>
    req('POST', `/v1/items/${id}/history/${encodeURIComponent(file)}`),
  rekey: (body) => req('POST', '/v1/vaults/rekey', body),
  addExport: (body) => req('POST', '/v1/exports', body),
  sshGen: (body) => req('POST', '/v1/ssh-gen', body),
  sshExport: (body) => req('POST', '/v1/ssh/export', body),
  sync: (body = {}) => req('POST', '/v1/sync', body),
  conflicts: () => req('GET', '/v1/conflicts'),
  conflict: (id, reveal = false) => req('GET', `/v1/conflicts/${id}?reveal=${reveal}`),
  resolve: (id, body) => req('POST', `/v1/conflicts/${id}/resolve`, body),
  gc: (body) => req('POST', '/v1/gc', body),
  doctor: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req('GET', '/v1/doctor' + (q ? `?${q}` : ''));
  },
  exports: () => req('GET', '/v1/exports'),
  recall: (target) => req('DELETE', `/v1/exports?target=${encodeURIComponent(target)}`),
  updateExport: (target, body) => req('PATCH', '/v1/exports', { target, ...body }),
  enforce: (force) => req('POST', '/v1/exports/enforce', { force }),
  trackInject: (target, form, glob) => req('POST', '/v1/injects', { target, form, glob }),
  injectContent: (target, reveal = false) =>
    req(
      'GET',
      `/v1/injects/content?target=${encodeURIComponent(target)}&reveal=${reveal}`
    ),
  injectPreview: (target, reveal = false) =>
    req(
      'GET',
      `/v1/injects/preview?target=${encodeURIComponent(target)}&reveal=${reveal}`
    ),
  saveInject: (body) => req('PUT', '/v1/injects/content', body),
  scanInjects: () => req('POST', '/v1/injects/scan'),
  targetUnlock: (target, force = false) => req('POST', '/v1/agent/unlock', { target, force }),
  targetLock: (target) => req('POST', '/v1/agent/lock', { target }),
  targetMove: (old, nu) => req('POST', '/v1/agent/relocate', { old, new: nu }),
  tamper: () => req('GET', '/v1/agent/tamper'),
  resolveTamper: (target, action) => req('POST', '/v1/agent/resolve', { target, action }),
  mergePreview: (target) => req('GET', `/v1/agent/merge?target=${encodeURIComponent(target)}`),
  mergeApply: (target, picks) => req('POST', '/v1/agent/merge', { target, picks }),
  sshEnv: () => req('GET', '/v1/ssh/env'),
  vaults: () => req('GET', '/v1/vaults'),
  addVault: (body) => req('POST', '/v1/vaults', body),
  forgetVault: (path) => req('DELETE', `/v1/vaults?path=${encodeURIComponent(path)}`),
  createVault: (body) => req('POST', '/v1/vaults/create', body),
  selectVault: (path) => req('POST', '/v1/vaults/select', { path }),
  addBiometricSlot: (keyfile) => req('POST', '/v1/vaults/slots', { keyfile }),
  retireBiometricSlot: (id) => req('DELETE', `/v1/vaults/slots/${encodeURIComponent(id)}`),
  settings: () => req('GET', '/v1/settings'),
  saveSettings: (body) => req('POST', '/v1/settings', body),
  uploadBlob: async (file) => {
    const res = await fetch(`${base}/v1/blobs`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: file
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `upload failed: ${res.status}`);
    return data;
  },
  gcBlobs: (dryRun = true) => req('POST', '/v1/blobs/gc', { dry_run: dryRun }),
  backup: () => download('/v1/vaults/backup'),
  restore: async (file, dest) => {
    const res = await fetch(`${base}/v1/vaults/restore?dest=${encodeURIComponent(dest)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: file
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `restore failed: ${res.status}`);
    return data;
  }
};

export async function download(path, filename) {
  const res = await fetch(base + path, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `download failed: ${res.status}`);
  }
  const disposition = res.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="([^"]+)"/);
  const name = filename || (match ? match[1] : 'download.bin');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export async function downloadBlob(addr) {
  return download(`/v1/blobs/${encodeURIComponent(addr)}`, `${addr}.bin`);
}
