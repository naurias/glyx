export function parseOtpauth(value) {
  const text = String(value || '').trim();
  if (!text.toLowerCase().startsWith('otpauth://')) return null;
  try {
    const url = new URL(text);
    if (url.hostname.toLowerCase() !== 'totp') return null;
    const secret = url.searchParams.get('secret');
    if (!secret) return null;
    const label = decodeURIComponent(url.pathname.replace(/^\/totp\//i, ''));
    const separator = label.indexOf(':');
    const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : '';
    const labelAccount = (separator >= 0 ? label.slice(separator + 1) : label).trim();
    const issuer = (url.searchParams.get('issuer') || labelIssuer).trim();
    const digits = Number(url.searchParams.get('digits')) || 6;
    const period = Number(url.searchParams.get('period')) || 30;
    return { issuer, account: labelAccount || label, digits, period, secret };
  } catch {
    return null;
  }
}
