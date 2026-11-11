const compat = globalThis.glyxCompat;
const q = document.getElementById('q');
const list = document.getElementById('list');
const err = document.getElementById('err');
const passkeys = document.getElementById('passkeys');
const passkeyStatus = document.getElementById('passkey-status');
const spike = document.getElementById('spike');
const captureLogins = document.getElementById('capture-logins');
const captureTotp = document.getElementById('capture-totp');
const scanTotp = document.getElementById('scan-totp');
const diag = document.getElementById('diag');

function fail(e) {
  err.textContent = String((e && e.message) || e);
}

async function bg(msg) {
  return compat.sendMessage(msg);
}

async function activeTab() {
  const tabs = await compat.tabsQuery({ active: true, currentWindow: true });
  return tabs && tabs[0];
}

async function refresh() {
  err.textContent = '';
  try {
    const tab = await activeTab();
    const host = tab && tab.url ? new URL(tab.url).hostname : '';
    const res = await bg({ kind: 'search', query: q.value || host });
    render(res.items || [], tab);
  } catch (e) {
    fail(e);
  }
}

function render(items, tab) {
  list.innerHTML = '';
  for (const item of items.slice(0, 20)) {
    const div = document.createElement('div');
    div.className = 'item';
    const title = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = item.name || item.id;
    const type = document.createElement('span');
    type.className = 'dim';
    type.textContent = ` ${item.type || ''}`;
    title.append(name, type);
    const row = document.createElement('div');
    row.className = 'row';
    const fill = document.createElement('button');
    fill.textContent = 'Fill';
    fill.onclick = async () => {
      try {
        const res = await bg({ kind: 'fill', id: item.id });
        const fields = (res.item && res.item.fields) || {};
        await compat.tabsSendMessage(tab.id, {
          kind: 'do-fill',
          username: fields.username || fields.email || '',
          password: fields.password || ''
        });
        window.close();
      } catch (e) {
        fail(e);
      }
    };
    const code = document.createElement('button');
    code.textContent = 'TOTP';
    code.onclick = async () => {
      try {
        const res = await bg({ kind: 'totp', id: item.id });
        const val =
          (res.item && (res.item.code || (res.item.fields && res.item.fields.code))) || '';
        await compat.tabsSendMessage(tab.id, { kind: 'do-fill', totp: val });
        window.close();
      } catch (e) {
        fail(e);
      }
    };
    row.append(fill, code);
    div.append(title, row);
    list.append(div);
  }
  if (!items.length) list.innerHTML = '<div class="item dim">No matches.</div>';
}

function renderTotp(candidates, tab) {
  list.innerHTML = '';
  if (!candidates.length) {
    list.innerHTML = '<div class="item dim">No TOTP found on this page.</div>';
    return;
  }
  for (const candidate of candidates) {
    const div = document.createElement('div');
    div.className = 'item';
    const name = document.createElement('div');
    name.textContent = candidate.issuer || candidate.account || 'TOTP';
    const detail = document.createElement('div');
    detail.className = 'dim';
    detail.textContent = [candidate.source || 'page', candidate.account]
      .filter(Boolean)
      .join(' · ');
    const row = document.createElement('div');
    row.className = 'row';
    const save = document.createElement('button');
    save.textContent = 'Save TOTP';
    save.onclick = async () => {
      save.disabled = true;
      try {
        const origin = tab && tab.url ? new URL(tab.url).origin : '';
        const res = await bg({
          kind: 'capture-save-totp',
          candidate,
          origin,
          url: tab && tab.url,
          loginId: null
        });
        if (!res || !res.ok) throw new Error((res && res.error) || 'save failed');
        list.innerHTML = '<div class="item dim">Authenticator saved.</div>';
        setTimeout(() => window.close(), 800);
      } catch (e) {
        fail(e);
        save.disabled = false;
      }
    };
    row.append(save);
    div.append(name, detail, row);
    list.append(div);
  }
}

document.getElementById('lock').onclick = async () => {
  try {
    await bg({ kind: 'lock' });
    list.innerHTML = '<div class="item dim">Locked.</div>';
  } catch (e) {
    fail(e);
  }
};

async function loadCapture() {
  try {
    const res = await bg({ kind: 'capture-settings' });
    if (res && res.settings) {
      captureLogins.checked = res.settings.captureLogins;
      captureTotp.checked = res.settings.captureTotp;
    }
  } catch {
    /* leave the defaults checked */
  }
}

async function saveCapture() {
  const settings = {
    captureLogins: captureLogins.checked,
    captureTotp: captureTotp.checked
  };
  const res = await bg({ kind: 'set-capture-settings', settings });
  const tab = await activeTab();
  if (tab) {
    compat
      .tabsSendMessage(tab.id, {
        kind: 'set-capture-settings',
        settings: res.settings
      })
      .catch(() => {});
  }
}

captureLogins.onchange = () => saveCapture().catch(fail);
captureTotp.onchange = () => saveCapture().catch(fail);

scanTotp.onclick = async () => {
  err.textContent = '';
  try {
    const tab = await activeTab();
    if (!tab || !/^https?:/.test(tab.url || '')) {
      throw new Error('open an http(s) page first');
    }
    const res = await compat.tabsSendMessage(tab.id, { kind: 'scan-totp' });
    renderTotp((res && res.candidates) || [], tab);
  } catch (e) {
    fail(e);
  }
};

function passkeyState(res) {
  passkeys.checked = !!res.enabled;
  passkeys.disabled = !res.available;
  if (spike) spike.hidden = !res.firefox;
  if (!res.available) {
    passkeyStatus.textContent = res.firefox
      ? 'Chromium only; use the spike to test Firefox'
      : 'Chromium only';
  } else if (res.error) {
    passkeyStatus.textContent = res.error;
  } else if (res.enabled) {
    passkeyStatus.textContent = res.attached ? 'active' : 'not attached';
  } else {
    passkeyStatus.textContent = 'off';
  }
}

async function loadPasskeys() {
  try {
    passkeyState(await bg({ kind: 'passkey-settings' }));
  } catch (e) {
    passkeyStatus.textContent = String((e && e.message) || e);
  }
}

passkeys.onchange = async () => {
  passkeyStatus.textContent = '…';
  try {
    passkeyState(await bg({ kind: 'set-passkeys-enabled', enabled: passkeys.checked }));
  } catch (e) {
    passkeyStatus.textContent = String((e && e.message) || e);
  }
  void loadDiagnostics();
};

if (spike) {
  spike.onclick = async () => {
    try {
      await bg({ kind: 'passkey-spike' });
      window.close();
    } catch (e) {
      fail(e);
    }
  };
}

async function loadDiagnostics() {
  diag.textContent = '';
  const line = (text) => {
    const div = document.createElement('div');
    div.textContent = text;
    diag.append(div);
  };
  try {
    const status = await bg({ kind: 'status' });
    line(`daemon: ${status.locked ? 'locked' : 'unlocked'}`);
    if (status.vault && status.vault.path) line(`vault: ${status.vault.path}`);
  } catch (e) {
    line(`daemon: ${String((e && e.message) || e)}`);
  }
  try {
    const pk = await bg({ kind: 'passkey-settings' });
    line(`browser: ${pk.browser || 'unknown'}`);
    const state = !pk.available
      ? 'unavailable'
      : pk.enabled
        ? pk.attached
          ? 'active'
          : 'not attached'
        : 'off';
    line(`passkeys: ${state}`);
    if (pk.error) line(`passkey error: ${pk.error}`);
  } catch (e) {
    line(`passkeys: ${String((e && e.message) || e)}`);
  }
}

q.oninput = () => refresh();
loadCapture();
loadPasskeys();
loadDiagnostics();
refresh();
