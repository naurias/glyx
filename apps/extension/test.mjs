import test from 'node:test';
import assert from 'node:assert/strict';
import './lib.js';

const { registrable, credentialIdEqual, hostFromUrl } = globalThis.glyxLib;

test('registrable keeps simple domains', () => {
  assert.equal(registrable('example.com'), 'example.com');
  assert.equal(registrable('login.example.com'), 'example.com');
  assert.equal(registrable('localhost'), 'localhost');
});

test('registrable handles multi-part suffixes', () => {
  assert.equal(registrable('login.example.co.uk'), 'example.co.uk');
  assert.equal(registrable('example.com.au'), 'example.com.au');
});

test('credential ids compare by decoded bytes', () => {
  assert.equal(credentialIdEqual('AQI', 'AQI='), true);
  assert.equal(credentialIdEqual('AQI', 'AQM'), false);
  assert.equal(credentialIdEqual('not base64!', 'not base64!'), true);
});

test('hostFromUrl only accepts http and https', () => {
  assert.deepEqual(hostFromUrl('https://example.com/login'), {
    origin: 'https://example.com',
    host: 'example.com'
  });
  assert.equal(hostFromUrl('chrome-extension://abc/popup.html'), null);
  assert.equal(hostFromUrl('not a url'), null);
});
