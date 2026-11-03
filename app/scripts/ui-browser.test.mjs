import { strict as assert } from 'node:assert';
import test from 'node:test';
import { parseDevToolsEndpoint } from './ui-browser.mjs';

test('reads the standard Chrome active-port file', () => {
  assert.equal(parseDevToolsEndpoint('9222\n/devtools/browser/abc-123\n'), 'ws://127.0.0.1:9222/devtools/browser/abc-123');
});

test('reads the startup endpoint even if the profile file is delayed', () => {
  assert.equal(parseDevToolsEndpoint('DevTools listening on ws://127.0.0.1:9322/devtools/browser/abc-123\n'), 'ws://127.0.0.1:9322/devtools/browser/abc-123');
});

test('does not accept remote or malformed debugging addresses', () => {
  for (const input of ['DevTools listening on ws://remote.example:9222/devtools/browser/abc', '65536\n/devtools/browser/abc', '9222\n/other', '9222\n']) {
    assert.equal(parseDevToolsEndpoint(input), null);
  }
});
