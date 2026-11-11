const compat = globalThis.glyxCompat;
const rid = new URLSearchParams(location.search).get('rid');
const main = document.getElementById('main');
const origin = document.getElementById('origin');

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function button(label, primary, onClick) {
  const node = el('button', primary ? 'primary' : '', label);
  node.onclick = onClick;
  return node;
}

function showError(message) {
  main.innerHTML = '';
  main.append(el('h2', 'error', 'Passkey request failed'));
  main.append(el('p', 'error', message || 'Unknown error'));
  const row = el('div', 'row');
  row.append(button('Close', false, () => window.close()));
  if (/lock/i.test(message || '')) {
    row.append(
      button('Open glyx', true, async () => {
        await compat.sendMessage({ kind: 'passkey-open-glyx', url: 'glyx://quick' });
        window.close();
      })
    );
  }
  main.append(row);
}

function showSuccess(result) {
  main.innerHTML = '';
  main.append(el('h2', 'success', result.mode === 'create' ? 'Passkey saved' : 'Passkey used'));
  main.append(el('p', '', result.name || 'glyx'));
  main.append(el('p', 'dim', 'The website can continue now.'));
  const row = el('div', 'row');
  if (result.mode === 'create' && result.itemId) {
    row.append(
      button('Manage in glyx', true, async () => {
        await compat.sendMessage({ kind: 'passkey-manage', itemId: result.itemId });
        window.close();
      })
    );
  }
  row.append(button('Close', false, () => window.close()));
  main.append(row);
  if (result.mode === 'get') {
    setTimeout(() => window.close(), 800);
  }
}

async function submit(itemId) {
  main.querySelectorAll('button').forEach((node) => {
    node.disabled = true;
  });
  const notice = el('p', 'dim', 'Waiting for glyx…');
  main.append(notice);
  const res = await compat.sendMessage({
    kind: 'passkey-submit',
    rid,
    itemId: itemId || null
  });
  if (!res || !res.ok) showError((res && res.error) || 'could not submit');
}

function render(state) {
  origin.textContent = state.origin || '';
  main.innerHTML = '';
  if (state.kind === 'create') {
    const rpName = state.request?.rp?.name || state.rpId || 'this site';
    const userName = state.request?.user?.name || '';
    const displayName = state.request?.user?.displayName || '';
    main.append(el('h2', '', `Create a passkey for ${rpName}?`));
    if (userName) main.append(el('p', '', `Account: ${userName}`));
    if (displayName && displayName !== userName) main.append(el('p', 'dim', displayName));
    main.append(
      el(
        'p',
        'dim',
        'The passkey is stored in your synced glyx vault. The website receives only the public key and attestation.'
      )
    );
    const row = el('div', 'row');
    row.append(button('Create passkey', true, () => submit(null)));
    row.append(button('Cancel', false, cancel));
    main.append(row);
    return;
  }
  const rpName = state.items?.[0]?.rp_name || state.rpId || 'this site';
  main.append(el('h2', '', `Use a glyx passkey for ${rpName}?`));
  main.append(el('p', 'dim', 'Select the account to sign in with.'));
  for (const item of state.items || []) {
    const card = el('div', 'item');
    card.append(el('div', 'name', item.user_name || item.display_name || item.name || 'passkey'));
    const details = [];
    if (item.display_name && item.display_name !== item.user_name) details.push(item.display_name);
    if (item.last_used_ms) details.push(`last used ${new Date(item.last_used_ms).toLocaleDateString()}`);
    if (!item.usable) details.push('private key missing');
    if (details.length) card.append(el('div', 'dim', details.join(' · ')));
    const row = el('div', 'row');
    const use = button('Use passkey', true, () => submit(item.item_id));
    use.disabled = !item.usable;
    row.append(use);
    card.append(row);
    main.append(card);
  }
  const row = el('div', 'row');
  row.append(el('span', 'spacer'));
  row.append(button('Cancel', false, cancel));
  main.append(row);
}

async function cancel() {
  await compat.sendMessage({ kind: 'passkey-cancel', rid });
  window.close();
}

compat.native.runtime.onMessage.addListener((msg) => {
  if (msg.kind !== 'passkey-result' || String(msg.rid) !== String(rid)) return false;
  if (msg.ok) showSuccess(msg);
  else showError(msg.error?.message || 'passkey request failed');
  return false;
});

(async () => {
  try {
    const state = await compat.sendMessage({ kind: 'passkey-state', rid });
    if (!state || !state.ok) {
      showError((state && state.error) || 'this passkey request is no longer active');
      return;
    }
    render(state);
  } catch (e) {
    showError(String((e && e.message) || e));
  }
})();
