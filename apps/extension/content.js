const lib = globalThis.glyxLib;
const compat = globalThis.glyxCompat;

let settings = { captureLogins: true, captureTotp: true };
let lastCaptureKey = '';
let promptHost = null;

function visibleInputs() {
  return [...document.querySelectorAll('input')].filter((el) => {
    if (el.disabled || el.type === 'hidden' || el.type === 'submit') return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  });
}

function inputLabel(el) {
  return [el.name, el.id, el.autocomplete, el.placeholder, el.getAttribute('aria-label')]
    .filter(Boolean)
    .join(' ');
}

function classify(inputs) {
  const user = inputs.find(
    (el) =>
      /user|email|login|account/i.test(inputLabel(el)) && el.type !== 'password'
  );
  const pass = inputs.find((el) => el.type === 'password');
  const totp = inputs.find(
    (el) =>
      /totp|2fa|otp|authenticator|verification.?code/i.test(inputLabel(el)) &&
      el !== pass
  );
  return { user, pass, totp };
}

function setValue(el, value) {
  el.focus();
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

function siteInfo() {
  return lib.hostFromUrl(location.href);
}

function sessionKey(name) {
  return `glyx:${name}:${location.origin}`;
}

function readSession(name) {
  try {
    return sessionStorage.getItem(sessionKey(name)) || '';
  } catch {
    return '';
  }
}

function writeSession(name, value) {
  try {
    if (value) sessionStorage.setItem(sessionKey(name), value);
  } catch {
    /* storage disabled */
  }
}

function rememberUsername() {
  const inputs = visibleInputs();
  const user = inputs.find(
    (el) => el.type !== 'password' && /user|email|login|account/i.test(inputLabel(el))
  );
  if (user && user.value) writeSession('username', user.value);
}

function currentLogin() {
  const inputs = visibleInputs();
  const pass = inputs.find((el) => el.type === 'password' && el.value);
  if (!pass) return null;
  const autocomplete = String(pass.autocomplete || '').toLowerCase();
  if (autocomplete === 'new-password') {
    const current = document.querySelector('input[autocomplete="current-password"]');
    if (!current) return null;
  }
  const scope = pass.form ? [...pass.form.querySelectorAll('input')] : inputs;
  const user =
    scope.find(
      (el) => el.type !== 'password' && /user|email|login|account/i.test(inputLabel(el))
    ) || classify(inputs).user;
  const username = (user && user.value) || readSession('username');
  if (!username) return null;
  return { username, password: pass.value };
}

function parseOtpauth(uri) {
  if (!uri || !/^otpauth:\/\/totp\//i.test(uri)) return null;
  try {
    const parsed = new URL(uri);
    const secret = parsed.searchParams.get('secret');
    if (!secret) return null;
    const account = decodeURIComponent(parsed.pathname.replace(/^\/totp\//i, ''));
    return {
      uri,
      secret,
      issuer: parsed.searchParams.get('issuer') || '',
      account,
      digits: Number(parsed.searchParams.get('digits')) || 6,
      period: Number(parsed.searchParams.get('period')) || 30,
      source: 'otpauth'
    };
  } catch {
    return null;
  }
}

function scanTotp() {
  const found = [];
  const seen = new Set();
  const add = (candidate) => {
    if (!candidate) return;
    const key = candidate.uri || candidate.secret;
    if (!key || seen.has(key)) return;
    seen.add(key);
    found.push(candidate);
  };
  for (const link of document.querySelectorAll('a[href^="otpauth://"]')) {
    add(parseOtpauth(link.href));
  }
  const text = (document.body ? document.body.innerText : '').slice(0, 200_000);
  for (const match of text.matchAll(/otpauth:\/\/totp\/[^\s"'<>]+/gi)) {
    add(parseOtpauth(match[0]));
  }
  for (const element of document.querySelectorAll('[data-otpauth], [data-secret], [data-totp]')) {
    const uri =
      element.getAttribute('data-otpauth') ||
      element.getAttribute('data-totp') ||
      '';
    const secret = element.getAttribute('data-secret') || '';
    add(parseOtpauth(uri) || (secret ? { secret, source: 'attribute' } : null));
  }
  for (const input of document.querySelectorAll('input')) {
    const value = String(input.value || '').trim();
    if (!value) continue;
    if (!/secret|setup|manual|authenticator|2fa|otp|totp/i.test(inputLabel(input))) {
      continue;
    }
    if (!/^[A-Z2-7\s-]{16,}$/i.test(value)) continue;
    add({
      secret: value.replace(/[\s-]/g, '').toUpperCase(),
      issuer: document.title,
      source: 'setup-key'
    });
  }
  return found;
}

async function scanQr() {
  if (typeof BarcodeDetector !== 'function') return [];
  const detector = new BarcodeDetector({ formats: ['qr_code'] });
  const found = [];
  for (const element of document.querySelectorAll('img, canvas')) {
    const rect = element.getBoundingClientRect();
    if (rect.width < 80 || rect.height < 80) continue;
    try {
      const bitmap =
        element instanceof HTMLCanvasElement ? element : await createImageBitmap(element);
      const codes = await detector.detect(bitmap);
      for (const code of codes) {
        const candidate = parseOtpauth(code.rawValue);
        if (candidate) found.push(candidate);
      }
    } catch {
      /* not a decodable image */
    }
  }
  return found;
}

async function collectTotp(includeQr) {
  const found = scanTotp();
  if (includeQr) {
    for (const candidate of await scanQr()) {
      if (!found.some((item) => item.secret === candidate.secret)) found.push(candidate);
    }
  }
  return found;
}

function dismissPrompt() {
  if (promptHost) {
    promptHost.remove();
    promptHost = null;
  }
}

function promptCard(title, detail) {
  dismissPrompt();
  const host = document.createElement('div');
  host.style.cssText =
    'all: initial; position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;';
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = `
    .card { width: 300px; background: #14161a; color: #e8eaf0; border: 1px solid #2c313a;
      border-radius: 10px; padding: 14px; font: 13px/1.45 system-ui, sans-serif;
      box-shadow: 0 8px 28px rgba(0,0,0,.45); }
    .title { font-weight: 600; margin-bottom: 4px; }
    .detail { color: #9aa1b2; font-size: 12px; margin-bottom: 10px; word-break: break-word; }
    .row { display: flex; gap: 8px; justify-content: flex-end; align-items: center; }
    button { font: inherit; border-radius: 6px; padding: 7px 10px; cursor: pointer;
      background: #1c1f25; color: inherit; border: 1px solid #2c313a; }
    button.primary { background: #2b5cff; border-color: #2b5cff; }
    label { display: flex; gap: 6px; align-items: center; color: #9aa1b2;
      font-size: 12px; margin: 0 0 10px; }
    .status { color: #9aa1b2; font-size: 12px; margin-top: 8px; }
    .error { color: #ff7a7a; }
  `;
  const card = document.createElement('div');
  card.className = 'card';
  const heading = document.createElement('div');
  heading.className = 'title';
  heading.textContent = title;
  const detailNode = document.createElement('div');
  detailNode.className = 'detail';
  detailNode.textContent = detail;
  card.append(heading, detailNode);
  root.append(style, card);
  document.documentElement.append(host);
  promptHost = host;
  return card;
}

function showLoginPrompt(action, match, login, totp) {
  const site = siteInfo();
  if (!site) return;
  const card = promptCard(
    action === 'update' ? 'Update password in glyx?' : 'Save login to glyx?',
    `${site.host} · ${login.username}`
  );
  let saveTotp = null;
  if (totp.length > 0) {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = true;
    const text = document.createElement('span');
    text.textContent = `Also save authenticator${totp[0].issuer ? ` (${totp[0].issuer})` : ''}`;
    label.append(checkbox, text);
    card.append(label);
    saveTotp = { checkbox, candidate: totp[0] };
  }
  const status = document.createElement('div');
  status.className = 'status';
  const row = document.createElement('div');
  row.className = 'row';
  const later = document.createElement('button');
  later.textContent = 'Not now';
  later.onclick = dismissPrompt;
  const save = document.createElement('button');
  save.className = 'primary';
  save.textContent = action === 'update' ? 'Update' : 'Save';
  save.onclick = async () => {
    save.disabled = true;
    later.disabled = true;
    status.className = 'status';
    status.textContent = 'Saving…';
    try {
      const result = await compat.sendMessage({
        kind: 'capture-save-login',
        action,
        itemId: match ? match.id : null,
        origin: location.origin,
        url: location.href,
        username: login.username,
        password: login.password
      });
      if (!result || !result.ok) throw new Error((result && result.error) || 'save failed');
      if (saveTotp && saveTotp.checkbox.checked) {
        const totpResult = await compat.sendMessage({
          kind: 'capture-save-totp',
          candidate: saveTotp.candidate,
          origin: location.origin,
          url: location.href,
          loginId: result.id || null
        });
        if (!totpResult || !totpResult.ok) {
          throw new Error((totpResult && totpResult.error) || 'authenticator save failed');
        }
      }
      status.textContent = 'Saved to glyx.';
      setTimeout(dismissPrompt, 1400);
    } catch (error) {
      status.className = 'status error';
      status.textContent = String((error && error.message) || error);
      save.disabled = false;
      later.disabled = false;
    }
  };
  row.append(later, save);
  card.append(row, status);
}

function showTotpPrompt(candidate) {
  const site = siteInfo();
  if (!site) return;
  const card = promptCard(
    'Save authenticator to glyx?',
    `${candidate.issuer || site.host}${candidate.account ? ` · ${candidate.account}` : ''}`
  );
  const status = document.createElement('div');
  status.className = 'status';
  const row = document.createElement('div');
  row.className = 'row';
  const later = document.createElement('button');
  later.textContent = 'Not now';
  later.onclick = dismissPrompt;
  const save = document.createElement('button');
  save.className = 'primary';
  save.textContent = 'Save';
  save.onclick = async () => {
    save.disabled = true;
    later.disabled = true;
    status.textContent = 'Saving…';
    try {
      const result = await compat.sendMessage({
        kind: 'capture-save-totp',
        candidate,
        origin: location.origin,
        url: location.href,
        loginId: null
      });
      if (!result || !result.ok) throw new Error((result && result.error) || 'save failed');
      status.textContent = 'Saved to glyx.';
      setTimeout(dismissPrompt, 1400);
    } catch (error) {
      status.className = 'status error';
      status.textContent = String((error && error.message) || error);
      save.disabled = false;
      later.disabled = false;
    }
  };
  row.append(later, save);
  card.append(row, status);
}

function captureLogin() {
  if (!settings.captureLogins) return;
  const site = siteInfo();
  if (!site) return;
  const login = currentLogin();
  if (!login) return;
  const key = `${site.origin}|${login.username}|${login.password}`;
  if (key === lastCaptureKey) return;
  lastCaptureKey = key;
  compat
    .sendMessage({
      kind: 'capture-login',
      origin: site.origin,
      url: location.href,
      username: login.username,
      password: login.password
    })
    .then(async (result) => {
      if (!result || !result.ok || result.action === 'none') return;
      const totp = settings.captureTotp ? await collectTotp(false) : [];
      showLoginPrompt(result.action, result.match, login, totp);
    })
    .catch(() => {});
}

document.addEventListener(
  'submit',
  () => {
    rememberUsername();
    setTimeout(captureLogin, 0);
  },
  true
);

document.addEventListener(
  'click',
  (event) => {
    if (!(event.target instanceof Element)) return;
    const button = event.target.closest('button, input[type="submit"], a[role="button"]');
    if (!button) return;
    const label = String(button.innerText || button.value || '').toLowerCase();
    if (button.type !== 'submit' && !/log ?in|sign ?in|continue|next|submit|save/.test(label)) {
      return;
    }
    rememberUsername();
    setTimeout(captureLogin, 0);
  },
  true
);

document.addEventListener(
  'keydown',
  (event) => {
    if (event.key !== 'Enter') return;
    if (event.target && event.target.type === 'password') {
      rememberUsername();
      setTimeout(captureLogin, 0);
    }
  },
  true
);

compat.native.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    if (msg.kind === 'probe') {
      const found = classify(visibleInputs());
      reply({
        ok: true,
        hasUser: !!found.user,
        hasPass: !!found.pass,
        hasTotp: !!found.totp
      });
    } else if (msg.kind === 'do-fill') {
      const found = classify(visibleInputs());
      if (msg.username && found.user) setValue(found.user, msg.username);
      if (msg.password && found.pass) setValue(found.pass, msg.password);
      if (msg.totp && found.totp) setValue(found.totp, msg.totp);
      reply({
        ok: true,
        filled: { user: !!found.user, pass: !!found.pass, totp: !!found.totp }
      });
    } else if (msg.kind === 'scan-totp') {
      const candidates = await collectTotp(true);
      if (candidates.length === 1 && msg.autoSave) {
        showTotpPrompt(candidates[0]);
      }
      reply({ ok: true, candidates });
    } else if (msg.kind === 'set-capture-settings') {
      settings = {
        captureLogins: msg.settings?.captureLogins !== false,
        captureTotp: msg.settings?.captureTotp !== false
      };
      reply({ ok: true });
    } else {
      reply({ ok: false, error: 'unknown message' });
    }
  })().catch((error) => reply({ ok: false, error: String((error && error.message) || error) }));
  return true;
});

compat.native.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.captureLogins) {
    settings.captureLogins = changes.captureLogins.newValue !== false;
  }
  if (changes.captureTotp) {
    settings.captureTotp = changes.captureTotp.newValue !== false;
  }
});

compat
  .sendMessage({ kind: 'capture-settings' })
  .then((result) => {
    if (result && result.ok && result.settings) settings = result.settings;
  })
  .catch(() => {});
