const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';

export function generatePassword(length = 24) {
  const out = new Uint32Array(length);
  crypto.getRandomValues(out);
  let result = '';
  for (let i = 0; i < length; i += 1) {
    result += ALPHABET[out[i] % ALPHABET.length];
  }
  return result;
}
