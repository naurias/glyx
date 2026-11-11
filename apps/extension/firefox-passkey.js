const compat = globalThis.glyxCompat;
const params = new URLSearchParams(location.search);
const hostInput = document.getElementById('host');
const optionsInput = document.getElementById('options');
const output = document.getElementById('output');
const originLabel = document.getElementById('origin');

const siteOrigin = params.get('origin') || '';
const siteHost = params.get('host') || '';
hostInput.value = siteHost;
originLabel.textContent = siteOrigin || 'no active site tab';

function toBytes(value) {
  return glyxLib.decodeBase64Url(value);
}

function toBase64Url(buffer) {
  if (!buffer) return '';
  return glyxLib.encodeBase64Url(new Uint8Array(buffer));
}

function sample() {
  const host = hostInput.value || siteHost || 'example.com';
  return {
    rp: { id: host, name: host },
    user: {
      id: 'dXNlcjEyMw',
      name: `user@${host}`,
      displayName: 'Example User'
    },
    challenge: 'cmFuZG9tQ2hhbGxlbmdl',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' }
  };
}

function loadSample() {
  optionsInput.value = JSON.stringify(sample(), null, 2);
}

function serialize(credential) {
  const response = credential.response || {};
  const out = {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults:
      typeof credential.getClientExtensionResults === 'function'
        ? credential.getClientExtensionResults()
        : {},
    response: {}
  };
  for (const key of [
    'clientDataJSON',
    'attestationObject',
    'authenticatorData',
    'signature',
    'userHandle'
  ]) {
    if (response[key]) out.response[key] = toBase64Url(response[key]);
  }
  return out;
}

function describe(credential, json) {
  let origin = '';
  try {
    const data = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
    origin = data.origin || '';
  } catch {
    /* ignore */
  }
  const lines = [
    `clientDataJSON.origin: ${origin || '(unknown)'}`,
    '',
    JSON.stringify(json, null, 2)
  ];
  output.className = 'ok';
  output.textContent = lines.join('\n');
}

async function run(kind) {
  output.className = 'dim';
  output.textContent = 'Waiting for the browser…';
  try {
    const options = JSON.parse(optionsInput.value);
    const host = hostInput.value || siteHost;
    if (!host) throw new Error('set the RP host first');
    if (kind === 'create') {
      options.challenge = toBytes(options.challenge);
      if (options.user && options.user.id) options.user.id = toBytes(options.user.id);
      options.rp = { ...(options.rp || {}), id: options.rp?.id || host };
      for (const credential of options.excludeCredentials || []) {
        credential.id = toBytes(credential.id);
      }
      const created = await navigator.credentials.create({ publicKey: options });
      describe(created, serialize(created));
    } else {
      options.challenge = toBytes(options.challenge);
      options.rpId = options.rpId || host;
      for (const credential of options.allowCredentials || []) {
        credential.id = toBytes(credential.id);
      }
      const assertion = await navigator.credentials.get({ publicKey: options });
      describe(assertion, serialize(assertion));
    }
  } catch (error) {
    output.className = 'error';
    output.textContent = String((error && error.message) || error);
  }
}

document.getElementById('sample').onclick = loadSample;
document.getElementById('create').onclick = () => run('create');
document.getElementById('get').onclick = () => run('get');

if (!optionsInput.value) loadSample();
