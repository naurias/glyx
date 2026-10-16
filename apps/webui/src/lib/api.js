let base = '';
let token = '';

export function configure(url, tok) {
  base = url.replace(/\/$/, '');
  token = tok;
}

export function configured() {
  return base !== '' && token !== '';
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
  unlock: (password, keyfile) => req('POST', '/v1/unlock', { password, keyfile }),
  unlockPin: (pin) => req('POST', '/v1/unlock', { pin }),
  lock: () => req('POST', '/v1/lock'),
  items: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req('GET', '/v1/items' + (q ? `?${q}` : ''));
  },
  show: (id, reveal = false) => req('GET', `/v1/items/${id}?reveal=${reveal}`),
  create: (body) => req('POST', '/v1/items', body),
  edit: (id, body) => req('PATCH', `/v1/items/${id}`, body),
  remove: (id) => req('DELETE', `/v1/items/${id}`),
  totp: (id) => req('GET', `/v1/items/${id}/totp`),
  sshGen: (body) => req('POST', '/v1/ssh-gen', body),
  sync: (body = {}) => req('POST', '/v1/sync', body),
  conflicts: () => req('GET', '/v1/conflicts'),
  conflict: (id, reveal = false) => req('GET', `/v1/conflicts/${id}?reveal=${reveal}`),
  resolve: (id, body) => req('POST', `/v1/conflicts/${id}/resolve`, body),
  gc: (body) => req('POST', '/v1/gc', body),
  doctor: () => req('GET', '/v1/doctor'),
  exports: () => req('GET', '/v1/exports'),
  recall: (target) => req('DELETE', `/v1/exports?target=${encodeURIComponent(target)}`),
  enforce: (force) => req('POST', '/v1/exports/enforce', { force }),
  trackInject: (target, form) => req('POST', '/v1/injects', { target, form }),
  tamper: () => req('GET', '/v1/agent/tamper'),
  resolveTamper: (target, action) => req('POST', '/v1/agent/resolve', { target, action }),
  sshEnv: () => req('GET', '/v1/ssh/env')
};
