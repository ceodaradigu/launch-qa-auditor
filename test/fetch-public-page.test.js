import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPinnedLookup,
  fetchPublicPage,
  isBlockedAddress,
  MAX_BODY_BYTES,
  validatePublicUrl,
} from '../src/fetch-public-page.js';

const publicLookup = async () => [{ address: '93.184.216.34', family: 4 }];
const noTimeoutSignal = () => undefined;

test('blocks private, reserved, mapped, and special-use addresses', () => {
  for (const address of [
    '0.0.0.1', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.1.1',
    '172.16.0.1', '192.168.1.1', '192.0.2.1', '198.18.0.1', '198.51.100.1',
    '203.0.113.1', '224.0.0.1', '255.255.255.255', '::', '::1', 'fc00::1',
    'fe80::1', 'fec0::1', 'ff02::1', '2001:db8::1', '::ffff:127.0.0.1', '::ffff:7f00:1',
    '::ffff:0:127.0.0.1',
    '2002:7f00:1::', '64:ff9b::7f00:1', '64:ff9b:1::1',
    '3ffe::1', '3fff::1', '100::1', '2001:2::1', '2001:10::1', '2001:20::1',
  ]) assert.equal(isBlockedAddress(address), true, `expected ${address} to be blocked`);
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
    assert.equal(isBlockedAddress(address), false, `expected ${address} to be public`);
  }
});

test('validates protocols, credentials, local names, and every DNS answer', async () => {
  await assert.rejects(validatePublicUrl('file:///etc/passwd'), /Only HTTP/);
  await assert.rejects(validatePublicUrl('https://user:pass@example.com'), /credentials/);
  await assert.rejects(validatePublicUrl('http://service.internal'), /Local and private/);
  await assert.rejects(validatePublicUrl('http://127.0.0.1'), /Private or reserved/);
  await assert.rejects(validatePublicUrl('https://example.com:444'), /standard public web ports/);
  await assert.rejects(validatePublicUrl('https://example.com', {
    lookup: async () => [{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.1', family: 4 }],
  }), /Private, reserved, or unresolved/);
  assert.equal((await validatePublicUrl('https://example.com/path', { lookup: publicLookup })).href, 'https://example.com/path');
});

test('pins the validated addresses instead of resolving again at connection time', async () => {
  const addresses = [
    { address: '93.184.216.34', family: 4 },
    { address: '2606:4700:4700::1111', family: 6 },
  ];
  const pinnedLookup = createPinnedLookup(addresses);
  const all = await new Promise((resolve, reject) => pinnedLookup('attacker-controlled.example', { all: true }, (error, records) => error ? reject(error) : resolve(records)));
  const one = await new Promise((resolve, reject) => pinnedLookup('attacker-controlled.example', {}, (error, address, family) => error ? reject(error) : resolve({ address, family })));
  assert.deepEqual(all, addresses);
  assert.deepEqual(one, addresses[0]);
  assert.throws(() => createPinnedLookup([{ address: '127.0.0.1', family: 4 }]), /validated public address/);
});

test('fetches one bounded public HTML page without network access', async () => {
  let calls = 0;
  const times = [1000, 1000, 1000, 1025];
  const page = await fetchPublicPage('https://example.com', {
    lookup: publicLookup,
    fetchImpl: async (url, options) => {
      calls += 1;
      assert.equal(url.href, 'https://example.com/');
      assert.deepEqual(options.addresses, [{ address: '93.184.216.34', family: 4 }]);
      return new Response('<html><title>Fixture</title></html>', { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
    },
    now: () => times.shift(),
    timeoutSignal: noTimeoutSignal,
  });
  assert.equal(calls, 1);
  assert.equal(page.httpStatus, 200);
  assert.equal(page.responseTimeMs, 25);
  assert.equal(page.redirects.length, 0);
  assert.equal(page.contentBytes, 35);
  assert.match(page.contentSha256, /^[a-f0-9]{64}$/);
});

test('revalidates redirects and stops before a private destination', async () => {
  let calls = 0;
  await assert.rejects(fetchPublicPage('https://example.com', {
    lookup: publicLookup,
    fetchImpl: async () => {
      calls += 1;
      return new Response(null, { status: 302, headers: { location: 'https://127.0.0.1/admin' } });
    },
    timeoutSignal: noTimeoutSignal,
  }), /Private or reserved/);
  assert.equal(calls, 1);
});

test('records a validated public redirect chain', async () => {
  const page = await fetchPublicPage('https://example.com/start', {
    lookup: publicLookup,
    fetchImpl: async (url) => url.pathname === '/start'
      ? new Response(null, { status: 301, headers: { location: '/final' } })
      : new Response('<html>Done</html>', { status: 200, headers: { 'content-type': 'text/html' } }),
    now: (() => { const values = [10, 10, 10, 15, 15, 20]; return () => values.shift(); })(),
    timeoutSignal: noTimeoutSignal,
  });
  assert.deepEqual(page.redirects, [{ from: 'https://example.com/start', to: 'https://example.com/final', status: 301 }]);
  assert.equal(page.finalUrl, 'https://example.com/final');
});

test('uses one page deadline across redirects', async () => {
  const timeoutCalls = [];
  const page = await fetchPublicPage('https://example.com/start', {
    timeoutSeconds: 1,
    lookup: publicLookup,
    fetchImpl: async (url) => url.pathname === '/start'
      ? new Response(null, { status: 302, headers: { location: '/final' } })
      : new Response('<html>Done</html>', { status: 200, headers: { 'content-type': 'text/html' } }),
    now: (() => { const values = [0, 0, 0, 400, 400, 450]; return () => values.shift(); })(),
    timeoutSignal: (milliseconds) => { timeoutCalls.push(milliseconds); return undefined; },
  });
  assert.deepEqual(timeoutCalls, [1000, 600]);
  assert.equal(page.responseTimeMs, 450);
});

test('includes DNS resolution in the page deadline', async () => {
  const lookup = () => new Promise(() => {});
  await assert.rejects(fetchPublicPage('https://example.com', {
    timeoutSeconds: 0.005,
    lookup,
  }), /timed out/);
});

test('blocks HTTPS downgrade redirects before the second request', async () => {
  let calls = 0;
  await assert.rejects(fetchPublicPage('https://example.com', {
    lookup: publicLookup,
    fetchImpl: async () => {
      calls += 1;
      return new Response(null, { status: 302, headers: { location: 'http://example.com/final' } });
    },
    timeoutSignal: noTimeoutSignal,
  }), /HTTPS to HTTP/);
  assert.equal(calls, 1);
});

test('rejects non-HTML, oversized, and timed-out responses', async () => {
  await assert.rejects(fetchPublicPage('https://example.com', {
    lookup: publicLookup,
    fetchImpl: async () => new Response('{}', { headers: { 'content-type': 'application/json' } }),
    timeoutSignal: noTimeoutSignal,
  }), /Expected an HTML page/);
  await assert.rejects(fetchPublicPage('https://example.com', {
    lookup: publicLookup,
    fetchImpl: async () => new Response('{}', { headers: { 'content-type': 'application/json; profile=text/html' } }),
    timeoutSignal: noTimeoutSignal,
  }), /Expected an HTML page/);
  await assert.rejects(fetchPublicPage('https://example.com', {
    lookup: publicLookup,
    fetchImpl: async () => new Response('', { headers: { 'content-type': 'text/html', 'content-length': String(MAX_BODY_BYTES + 1) } }),
    timeoutSignal: noTimeoutSignal,
  }), /exceeds the 2 MB/);
  await assert.rejects(fetchPublicPage('https://example.com', {
    lookup: publicLookup,
    fetchImpl: async () => { throw new Error('synthetic timeout'); },
    timeoutSignal: noTimeoutSignal,
  }), /synthetic timeout/);
  await assert.rejects(fetchPublicPage('https://example.com', {
    lookup: publicLookup,
    fetchImpl: async () => new Response('compressed bytes', { headers: { 'content-type': 'text/html', 'content-encoding': 'gzip' } }),
    timeoutSignal: noTimeoutSignal,
  }), /Compressed responses are not supported/);
});
