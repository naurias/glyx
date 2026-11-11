const compat = globalThis.glyxCompat;
const q = document.getElementById('q');
const list = document.getElementById('list');
const err = document.getElementById('err');
const passkeys = document.getElementById('passkeys');
const passkeyStatus = document.getElementById('passkey-status');
const spike = document.getElementById('spike');

function fail(e) {
  err.innerHTML = `<div class="err">${String((e && e.message) || e)}</div>`;
}

async function bg(msg) {
  return compat.sendMessage(msg);
}

async function refresh() {
  err.innerHTML = '';
  try {
    const tabs = await compat.tabsQuery({ active: true, currentWindow: true });
    const tab = tabs && tabs[0];
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
    div.innerHTML = `<div><strong></strong> <span class="dim"></span></div><div class="row"></div>`;
    div.querySelector('strong').textContent = item.name || item.id;
    div.querySelector('.dim').textContent = item.type || '';
    const row = div.querySelector('.row');
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
        const val = (res.item && (res.item.code || (res.item.fields && res.item.fields.code))) || '';
        await compat.tabsSendMessage(tab.id, { kind: 'do-fill', totp: val });
        window.close();
      } catch (e) {
        fail(e);
      }
    };
    row.append(fill, code);
    list.append(div);
  }
  if (!items.length) list.innerHTML = '<div class="item dim">No matches.</div>';
}

document.getElementById('lock').onclick = async () => {
  try {
    await bg({ kind: 'lock' });
    list.innerHTML = '<div class="item dim">Locked.</div>';
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

q.oninput = () => refresh();
loadPasskeys();
refresh();
