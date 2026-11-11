import { writable } from 'svelte/store';
import { isMobile } from './api.js';

export const totpCapture = writable('');

export function canScanQr() {
  return (
    isMobile() &&
    typeof window !== 'undefined' &&
    !!window.__TAURI__?.core?.invoke
  );
}

export async function scanTotp() {
  if (!canScanQr()) throw new Error('QR scanning is only available in the Android app.');
  let result;
  try {
    await window.__TAURI__.core
      .invoke('plugin:barcode-scanner|request_permissions')
      .catch(() => {});
    result = await window.__TAURI__.core.invoke('plugin:barcode-scanner|scan', {
      windowed: true,
      formats: ['QR_CODE']
    });
  } catch (e) {
    const message = String(e?.message || e);
    if (/permission|camera/i.test(message)) {
      throw new Error('Allow camera access for glyx, then scan the QR code again.');
    }
    throw new Error(message || 'QR scan cancelled.');
  }
  const content = String(result?.content || '').trim();
  if (!content.toLowerCase().startsWith('otpauth://')) {
    throw new Error('That QR code is not a TOTP setup code.');
  }
  return content;
}

export async function pasteTotp() {
  if (typeof navigator === 'undefined' || !navigator.clipboard?.readText) {
    throw new Error('Clipboard access is not available; paste into the field instead.');
  }
  const text = String(await navigator.clipboard.readText()).trim();
  if (!text) throw new Error('The clipboard is empty.');
  return text;
}

export function watchOtpauthLinks(handler) {
  if (typeof window === 'undefined') return () => {};
  const listener = (event) => {
    const uri = event?.detail;
    if (typeof uri === 'string' && uri.toLowerCase().startsWith('otpauth://')) {
      handler(uri);
    }
  };
  window.addEventListener('glyx-otpauth', listener);
  const initial = window.__GLYX_OTPAUTH__;
  if (typeof initial === 'string' && initial.toLowerCase().startsWith('otpauth://')) {
    window.__GLYX_OTPAUTH__ = '';
    handler(initial);
  }
  return () => window.removeEventListener('glyx-otpauth', listener);
}
