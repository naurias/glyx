const HOST = 'dev.glyx.bridge';
let seq = 0;
const pending = new Map();
const passkeyRequests = new Map();
let passkeyAttached = false;
let passkeyError = '';

chrome.storage.local.get('passkeyError').then((stored) => {
  if (stored.passkeyError) passkeyError = stored.passkeyError;
});

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

function proxyAvailable() {
  return (
    typeof chrome !== 'undefined' &&
    chrome.webAuthenticationProxy &&
    typeof chrome.webAuthenticationProxy.attach === 'function'
  );
}

async function passkeysEnabled() {
  const stored = await chrome.storage.local.get('passkeysEnabled');
  return stored.passkeysEnabled === true;
}

async function setPasskeyError(message) {
  passkeyError = message || '';
  await chrome.storage.local.set({ passkeyError });
}

async function attachPasskeys() {
  if (!proxyAvailable() || passkeyAttached) return;
  try {
    const error = await chrome.webAuthenticationProxy.attach();
    if (error) {
      await setPasskeyError(error);
      return;
    }
    passkeyAttached = true;
    await setPasskeyError('');
  } catch (e) {
    await setPasskeyError(String((e && e.message) || e));
  }
}

async function detachPasskeys() {
  if (!proxyAvailable() || !passkeyAttached) return;
  try {
    await chrome.webAuthenticationProxy.detach();
  } catch {
    /* already detached */
  }
  passkeyAttached = false;
}

async function reconcilePasskeys() {
  if (!proxyAvailable()) return;
  if (await passkeysEnabled()) {
    await attachPasskeys();
  } else {
    await detachPasskeys();
  }
}

function parseNativeError(e) {
  const text = String((e && e.message) || e);
  const start = text.indexOf('{');
  if (start >= 0) {
    try {
      const body = JSON.parse(text.slice(start));
      return {
        name: body.name || 'NotAllowedError',
        message: body.error || text
      };
    } catch {
      /* fall through */
    }
  }
  return { name: 'NotAllowedError', message: text };
}

async function activeOrigin() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return null;
  let parsed;
  try {
    parsed = new URL(tab.url);
  } catch {
    return null;
  }
  const local = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) return null;
  return { origin: parsed.origin, host: parsed.hostname.toLowerCase() };
}

function rpAllowed(host, rpId) {
  if (!rpId) return false;
  const rp = rpId.toLowerCase();
  return host === rp || host.endsWith(`.${rp}`);
}

function completePasskey(kind, requestId, responseJson) {
  if (kind === 'create') {
    return chrome.webAuthenticationProxy.completeCreateRequest({ requestId, responseJson });
  }
  return chrome.webAuthenticationProxy.completeGetRequest({ requestId, responseJson });
}

function completePasskeyError(kind, requestId, error) {
  if (kind === 'create') {
    return chrome.webAuthenticationProxy.completeCreateRequest({ requestId, error });
  }
  return chrome.webAuthenticationProxy.completeGetRequest({ requestId, error });
}

async function safeCompletePasskeyError(kind, requestId, error) {
  try {
    await completePasskeyError(kind, requestId, error);
  } catch {
    /* request already completed or canceled */
  }
}

function sendToPasskeyWindow(rid, message) {
  chrome.runtime.sendMessage({ ...message, rid }).catch(() => {});
}

async function openPasskeyWindow(state) {
  const url = chrome.runtime.getURL(`passkey.html?rid=${state.requestId}`);
  const win = await chrome.windows.create({
    url,
    type: 'popup',
    width: 430,
    height: 560,
    focused: true
  });
  state.windowId = win.id;
}

async function handlePasskeyRequest(kind, info) {
  const requestId = info.requestId;
  try {
    if (!(await passkeysEnabled())) {
      throw { name: 'NotAllowedError', message: 'glyx passkeys are disabled' };
    }
    const tab = await activeOrigin();
    if (!tab) {
      throw { name: 'NotAllowedError', message: 'no active https tab for this passkey request' };
    }
    let request;
    try {
      request = JSON.parse(info.requestDetailsJson);
    } catch {
      throw { name: 'TypeError', message: 'invalid WebAuthn request' };
    }
    const rpId =
      kind === 'create'
        ? request?.rp?.id || tab.host
        : request?.rpId || tab.host;
    if (!rpAllowed(tab.host, rpId)) {
      throw {
        name: 'NotAllowedError',
        message: 'the request relying party does not match the active tab'
      };
    }
    let items = [];
    if (kind === 'get') {
      const allow = (request.allowCredentials || [])
        .map((credential) => credential.id)
        .filter(Boolean);
      items = await send('passkey_lookup', {
        origin: tab.origin,
        rp_id: rpId,
        allow_credentials: allow
      });
      if (!Array.isArray(items) || items.length === 0) {
        throw { name: 'NotAllowedError', message: 'no glyx passkey matches this request' };
      }
    }
    const state = {
      kind,
      requestId,
      origin: tab.origin,
      rpId,
      request,
      items,
      windowId: null,
      done: false
    };
    const decision = new Promise((resolve) => {
      state.resolve = resolve;
    });
    passkeyRequests.set(requestId, state);
    await openPasskeyWindow(state);
    const choice = await decision;
    if (choice.action !== 'confirm') {
      throw { name: 'NotAllowedError', message: 'passkey request canceled' };
    }
    if (kind === 'create') {
      const data = await send('passkey_create', {
        origin: tab.origin,
        request,
        user_verified: true
      });
      await completePasskey(kind, requestId, JSON.stringify(data.response));
      state.done = true;
      sendToPasskeyWindow(requestId, {
        kind: 'passkey-result',
        ok: true,
        mode: 'create',
        itemId: data.item_id,
        name: data.name
      });
      setTimeout(() => passkeyRequests.delete(requestId), 10000);
    } else {
      const data = await send('passkey_get', {
        origin: tab.origin,
        request,
        item_id: choice.itemId,
        user_verified: true
      });
      await completePasskey(kind, requestId, JSON.stringify(data.response));
      state.done = true;
      sendToPasskeyWindow(requestId, {
        kind: 'passkey-result',
        ok: true,
        mode: 'get',
        itemId: data.item_id,
        name: data.name
      });
      setTimeout(() => passkeyRequests.delete(requestId), 10000);
    }
  } catch (e) {
    const error =
      e && e.name && e.message
        ? { name: e.name, message: e.message }
        : parseNativeError(e);
    await safeCompletePasskeyError(kind, requestId, error);
    sendToPasskeyWindow(requestId, {
      kind: 'passkey-result',
      ok: false,
      error
    });
    const state = passkeyRequests.get(requestId);
    if (state && state.windowId != null) {
      setTimeout(() => chrome.windows.remove(state.windowId).catch(() => {}), 2500);
    }
    setTimeout(() => passkeyRequests.delete(requestId), 10000);
  } finally {
    const state = passkeyRequests.get(requestId);
    if (state) state.done = true;
  }
}

if (proxyAvailable()) {
  chrome.webAuthenticationProxy.onCreateRequest.addListener((info) => {
    void handlePasskeyRequest('create', info);
  });
  chrome.webAuthenticationProxy.onGetRequest.addListener((info) => {
    void handlePasskeyRequest('get', info);
  });
  chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((info) => {
    chrome.webAuthenticationProxy
      .completeIsUvpaaRequest({
        requestId: info.requestId,
        isUvpaa: true
      })
      .catch(() => {});
  });
  chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
    const state = passkeyRequests.get(requestId);
    if (!state) return;
    state.resolve({ action: 'cancel' });
    if (state.windowId != null) {
      chrome.windows.remove(state.windowId).catch(() => {});
    }
    passkeyRequests.delete(requestId);
  });
  void reconcilePasskeys();
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.passkeysEnabled) {
    void reconcilePasskeys();
  }
});

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [rid, state] of passkeyRequests) {
    if (state.windowId === windowId) {
      if (!state.done) state.resolve({ action: 'cancel' });
      passkeyRequests.delete(rid);
    }
  }
});

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
    } else if (msg.kind === 'passkey-settings') {
      reply({
        ok: true,
        available: proxyAvailable(),
        enabled: await passkeysEnabled(),
        attached: passkeyAttached,
        error: passkeyError
      });
    } else if (msg.kind === 'set-passkeys-enabled') {
      await chrome.storage.local.set({ passkeysEnabled: msg.enabled === true });
      await reconcilePasskeys();
      reply({
        ok: true,
        available: proxyAvailable(),
        enabled: await passkeysEnabled(),
        attached: passkeyAttached,
        error: passkeyError
      });
    } else if (msg.kind === 'passkey-state') {
      const state = passkeyRequests.get(Number(msg.rid));
      if (!state) {
        reply({ ok: false, error: 'this passkey request is no longer active' });
        return;
      }
      reply({
        ok: true,
        kind: state.kind,
        origin: state.origin,
        rpId: state.rpId,
        request: state.request,
        items: state.items
      });
    } else if (msg.kind === 'passkey-submit') {
      const state = passkeyRequests.get(Number(msg.rid));
      if (!state) {
        reply({ ok: false, error: 'this passkey request is no longer active' });
        return;
      }
      state.resolve({ action: 'confirm', itemId: msg.itemId || null });
      reply({ ok: true });
    } else if (msg.kind === 'passkey-cancel') {
      const state = passkeyRequests.get(Number(msg.rid));
      if (state) state.resolve({ action: 'cancel' });
      reply({ ok: true });
    } else if (msg.kind === 'passkey-open-glyx') {
      await chrome.tabs.create({ url: msg.url || 'glyx://quick' });
      reply({ ok: true });
    } else if (msg.kind === 'passkey-manage') {
      await chrome.tabs.create({ url: `glyx://items/${msg.itemId}` });
      reply({ ok: true });
    } else if (msg.kind === 'passkey-result') {
      reply({ ok: true });
    } else {
      reply({ ok: false, error: 'unknown message' });
    }
  })().catch((e) => reply({ ok: false, error: String((e && e.message) || e) }));
  return true;
});
