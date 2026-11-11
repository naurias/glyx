(() => {
  const MULTI_PART_SUFFIXES = new Set([
    'co.uk',
    'org.uk',
    'ac.uk',
    'gov.uk',
    'com.au',
    'net.au',
    'org.au',
    'co.nz',
    'co.jp',
    'co.kr',
    'co.in',
    'com.br',
    'com.mx',
    'com.ar',
    'com.tr',
    'com.cn',
    'com.sg',
    'com.hk',
    'co.za',
    'co.il'
  ]);

  function registrable(host) {
    const parts = String(host || '')
      .toLowerCase()
      .split('.')
      .filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return lastTwo;
  }

  function decodeBase64Url(value) {
    const text = String(value || '')
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    const padded = text + '='.repeat((4 - (text.length % 4)) % 4);
    if (typeof atob === 'function') {
      const binary = atob(padded);
      return Uint8Array.from(binary, (char) => char.charCodeAt(0));
    }
    return Uint8Array.from(Buffer.from(padded, 'base64'));
  }

  function encodeBase64Url(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    if (typeof btoa === 'function') {
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    return Buffer.from(bytes).toString('base64url');
  }

  function credentialIdEqual(left, right) {
    try {
      const a = decodeBase64Url(left);
      const b = decodeBase64Url(right);
      if (a.length !== b.length) return false;
      return a.every((byte, index) => byte === b[index]);
    } catch {
      return left === right;
    }
  }

  function hostFromUrl(url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
      return {
        origin: parsed.origin,
        host: parsed.hostname.toLowerCase()
      };
    } catch {
      return null;
    }
  }

  globalThis.glyxLib = {
    registrable,
    decodeBase64Url,
    encodeBase64Url,
    credentialIdEqual,
    hostFromUrl
  };
})();
