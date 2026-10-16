const HOST = 'dev.glyx.bridge';
let seq = 0;
const pending = new Map();

function send(op, args = {}) {
  return new Promise((resolve, reject) => {
    const request_id = ++seq;
    pending.set(request_id, { resolve, reject });
    chrome.runtime.sendNativeMessage(HOST, { op, request_id, args }, (res) => {
      pending.delete(request_id);
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!res || !res.ok) {
        reject(new Error((res && res.error) || 'bridge failed'));
        return;
      }
      resolve(res.data);
    });
  });
}

function registrable(host) {
  const parts = host.split('.').filter(Boolean);
  if (parts.length < 2) return host;
  return parts.slice(-2).join('.');
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg.kind === 'search') {
      const items = await send('search', { query: msg.query || '' });
      const domain = registrable(new URL(sender.url).hostname);
      const scored = (Array.isArray(items) ? items : [])
        .map((item) => ({ item, hit: domain && JSON.stringify(item).includes(domain) }))
        .sort((a, b) => Number(b.hit) - Number(a.hit))
        .map(({ item }) => item);
      reply({ ok: true, items: scored });
    } else if (msg.kind === 'fill') {
      const data = await send('fill', { id: msg.id });
      reply({ ok: true, item: data });
    } else if (msg.kind === 'totp') {
      const data = await send('totp', { id: msg.id });
      reply({ ok: true, item: data });
    } else if (msg.kind === 'status') {
      reply(await send('status'));
    } else if (msg.kind === 'lock') {
      reply(await send('lock'));
    } else {
      reply({ ok: false, error: 'unknown message' });
    }
  })().catch((e) => reply({ ok: false, error: String((e && e.message) || e) }));
  return true;
});
