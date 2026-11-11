if (typeof importScripts === 'function' && !globalThis.glyxCompat) {
  importScripts('compat.js', 'lib.js');
}

const HOST = 'dev.glyx.bridge';
const compat = globalThis.glyxCompat;
const native = compat.native;
const proxy = compat.proxy;
let seq = 0;
const pending = new Map();
const passkeyRequests = new Map();
let passkeyAttached = false;
let passkeyError = '';
let lastSite = null;

compat.storageGet('passkeyError').then((stored) => {
  if (stored && stored.passkeyError) passkeyError = stored.passkeyError;
});

function rememberTab(tab) {
  const site = glyxLib.hostFromUrl(tab && tab.url);
  if (site) lastSite = site;
}

compat
  .tabsQuery({ active: true, currentWindow: true })
  .then((tabs) => rememberTab(tabs && tabs[0]))
  .catch(() => {});

if (native.tabs && native.tabs.onActivated) {
  native.tabs.onActivated.addListener(async ({ tabId }) => {
    try {
      rememberTab(await compat.tabsGet(tabId));
    } catch {
      /* tab closed */
    }
  });
}
if (native.tabs && native.tabs.onUpdated) {
  native.tabs.onUpdated.addListener((_tabId, info, tab) => {
    if (info && (info.url || info.status === 'complete')) rememberTab(tab);
  });
}

function send(op, args = {}) {
  return new Promise((resolve, reject) => {
    const request_id = ++seq;
    pending.set(request_id, { resolve, reject });
    compat
      .sendNative(HOST, { op, request_id, args })
      .then((res) => {
        pending.delete(request_id);
        if (!res || !res.ok) {
          reject(new Error((res && res.error) || 'bridge failed'));
          return;
        }
        resolve(res.data);
      })
      .catch((error) => {
        pending.delete(request_id);
        reject(error);
      });
  });
}

function proxyAvailable() {
  return !!proxy && typeof proxy.attach === 'function';
}

async function passkeysEnabled() {
  const stored = await compat.storageGet('passkeysEnabled');
  return !!stored && stored.passkeysEnabled === true;
}

async function captureSettings() {
  const stored = await compat.storageGet(['captureLogins', 'captureTotp']);
  return {
    captureLogins: !stored || stored.captureLogins !== false,
    captureTotp: !stored || stored.captureTotp !== false
  };
}

async function setPasskeyError(message) {
  passkeyError = message || '';
  await compat.storageSet({ passkeyError });
}

async function attachPasskeys() {
  if (!proxyAvailable() || passkeyAttached) return;
  try {
    const error = await proxy.attach();
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
  if (!proxyAvailable()) return;
  try {
    await proxy.detach();
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
  try {
    const tabs = await compat.tabsQuery({ active: true, currentWindow: true });
    const site = glyxLib.hostFromUrl(tabs && tabs[0] && tabs[0].url);
    if (site) {
      lastSite = site;
      return site;
    }
  } catch {
    /* fall through to the last site tab */
  }
  return lastSite;
}

function rpAllowed(host, rpId) {
  if (!rpId) return false;
  const rp = rpId.toLowerCase();
  return host === rp || host.endsWith(`.${rp}`);
}

async function completePasskey(kind, requestId, responseJson) {
  try {
    const result =
      kind === 'create'
        ? await proxy.completeCreateRequest({ requestId, responseJson })
        : await proxy.completeGetRequest({ requestId, responseJson });
    await setPasskeyError('');
    return result;
  } catch (e) {
    await setPasskeyError(String((e && e.message) || e));
    throw e;
  }
}

function completePasskeyError(kind, requestId, error) {
  if (kind === 'create') {
    return proxy.completeCreateRequest({ requestId, error });
  }
  return proxy.completeGetRequest({ requestId, error });
}

async function safeCompletePasskeyError(kind, requestId, error) {
  try {
    await completePasskeyError(kind, requestId, error);
  } catch {
    /* request already completed or canceled */
  }
}

function sendToPasskeyWindow(rid, message) {
  compat.sendMessage({ ...message, rid }).catch(() => {});
}

async function openPasskeyWindow(state) {
  const url = compat.getURL(`passkey.html?rid=${state.requestId}`);
  if (compat.isFirefox) {
    const tab = await compat.tabsCreate({ url });
    state.tabId = tab.id;
    return;
  }
  const win = await compat.windowsCreate({
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
    if (!proxyAvailable()) {
      throw { name: 'NotAllowedError', message: 'passkeys need a Chromium browser' };
    }
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
      kind === 'create' ? request?.rp?.id || tab.host : request?.rpId || tab.host;
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
      tabId: null,
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
      setTimeout(() => compat.windowsRemove(state.windowId).catch(() => {}), 2500);
    }
    setTimeout(() => passkeyRequests.delete(requestId), 10000);
  } finally {
    const state = passkeyRequests.get(requestId);
    if (state) state.done = true;
  }
}

if (proxyAvailable()) {
  proxy.onCreateRequest.addListener((info) => {
    void handlePasskeyRequest('create', info);
  });
  proxy.onGetRequest.addListener((info) => {
    void handlePasskeyRequest('get', info);
  });
  proxy.onIsUvpaaRequest.addListener((info) => {
    passkeysEnabled()
      .catch(() => false)
      .then((enabled) =>
        proxy.completeIsUvpaaRequest({
          requestId: info.requestId,
          isUvpaa: enabled
        })
      )
      .catch(() => {});
  });
  proxy.onRequestCanceled.addListener((requestId) => {
    const state = passkeyRequests.get(requestId);
    if (!state) return;
    state.resolve({ action: 'cancel' });
    if (state.windowId != null) {
      compat.windowsRemove(state.windowId).catch(() => {});
    }
    passkeyRequests.delete(requestId);
  });
  void reconcilePasskeys();
}

native.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.passkeysEnabled) {
    void reconcilePasskeys();
  }
});

native.windows.onRemoved.addListener((windowId) => {
  for (const [rid, state] of passkeyRequests) {
    if (state.windowId === windowId) {
      if (!state.done) state.resolve({ action: 'cancel' });
      passkeyRequests.delete(rid);
    }
  }
});

native.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg.kind === 'search') {
      const items = await send('search', { query: msg.query || '' });
      const senderUrl =
        sender.url || (sender.tab && sender.tab.url) || 'https://localhost/';
      const domain = glyxLib.registrable(new URL(senderUrl).hostname);
      const scored = (Array.isArray(items) ? items : [])
        .map((item) => ({
          item,
          hit: domain && JSON.stringify(item).includes(domain)
        }))
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
    } else if (msg.kind === 'capture-settings') {
      reply({ ok: true, settings: await captureSettings() });
    } else if (msg.kind === 'set-capture-settings') {
      const settings = {
        captureLogins: msg.settings?.captureLogins !== false,
        captureTotp: msg.settings?.captureTotp !== false
      };
      await compat.storageSet(settings);
      reply({ ok: true, settings });
    } else if (msg.kind === 'capture-login') {
      const settings = await captureSettings();
      if (!settings.captureLogins) {
        reply({ ok: true, action: 'none' });
        return;
      }
      const result = await send('login_match', {
        origin: msg.origin,
        username: msg.username
      });
      const match = result && result.match;
      if (match && match.password === msg.password) {
        reply({ ok: true, action: 'none' });
        return;
      }
      reply({ ok: true, action: match ? 'update' : 'create', match: match || null });
    } else if (msg.kind === 'capture-save-login') {
      const site =
        glyxLib.hostFromUrl(msg.url) || glyxLib.hostFromUrl(msg.origin);
      const fields = {
        username: msg.username || '',
        password: msg.password || '',
        url: msg.url || msg.origin || ''
      };
      if (msg.action === 'update' && msg.itemId) {
        await send('login_update', {
          id: msg.itemId,
          fields: {
            username: fields.username,
            password: fields.password,
            url: fields.url
          }
        });
        reply({ ok: true, id: msg.itemId });
      } else {
        const saved = await send('login_save', {
          type: 'login',
          name: site ? site.host : msg.origin || 'login',
          fields
        });
        reply({ ok: true, id: saved && saved.id });
      }
    } else if (msg.kind === 'capture-save-totp') {
      const site =
        glyxLib.hostFromUrl(msg.url) || glyxLib.hostFromUrl(msg.origin);
      const candidate = msg.candidate || {};
      const fields = { seed: candidate.uri || candidate.secret || '' };
      if (!fields.seed) {
        reply({ ok: false, error: 'no TOTP secret found' });
        return;
      }
      if (candidate.digits) fields.digits = String(candidate.digits);
      if (candidate.period) fields.period = String(candidate.period);
      if (msg.loginId) fields.login_id = msg.loginId;
      const saved = await send('totp_save', {
        type: 'totp',
        name: candidate.issuer || candidate.account || (site ? site.host : 'totp'),
        fields
      });
      reply({ ok: true, id: saved && saved.id });
    } else if (msg.kind === 'passkey-settings') {
      reply({
        ok: true,
        available: proxyAvailable(),
        firefox: compat.isFirefox,
        browser: compat.isFirefox ? 'firefox' : 'chromium',
        enabled: await passkeysEnabled(),
        attached: passkeyAttached,
        error: passkeyError
      });
    } else if (msg.kind === 'set-passkeys-enabled') {
      await compat.storageSet({ passkeysEnabled: msg.enabled === true });
      await reconcilePasskeys();
      reply({
        ok: true,
        available: proxyAvailable(),
        firefox: compat.isFirefox,
        browser: compat.isFirefox ? 'firefox' : 'chromium',
        enabled: await passkeysEnabled(),
        attached: passkeyAttached,
        error: passkeyError
      });
    } else if (msg.kind === 'passkey-spike') {
      const site = await activeOrigin();
      const query = site
        ? `?origin=${encodeURIComponent(site.origin)}&host=${encodeURIComponent(site.host)}`
        : '';
      await compat.tabsCreate({ url: compat.getURL(`firefox-passkey.html${query}`) });
      reply({ ok: true });
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
      await compat.tabsCreate({ url: msg.url || 'glyx://quick' });
      reply({ ok: true });
    } else if (msg.kind === 'passkey-manage') {
      await compat.tabsCreate({ url: `glyx://items/${msg.itemId}` });
      reply({ ok: true });
    } else if (msg.kind === 'passkey-result') {
      reply({ ok: true });
    } else {
      reply({ ok: false, error: 'unknown message' });
    }
  })().catch((e) => reply({ ok: false, error: String((e && e.message) || e) }));
  return true;
});
