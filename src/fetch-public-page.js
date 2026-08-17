import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { Readable } from 'node:stream';

export const MAX_BODY_BYTES = 2 * 1024 * 1024;
export const MAX_REDIRECTS = 5;

const SAFE_WEB_PORTS = new Set(['', '80', '443', '8080', '8443']);

const BLOCKED_IPV4_RANGES = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

function ipv4ToInteger(address) {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return null;
  }
  return ((((octets[0] * 256) + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
}

function isInIpv4Cidr(address, network, prefixLength) {
  const value = ipv4ToInteger(address);
  const base = ipv4ToInteger(network);
  if (value === null || base === null) return false;
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
  return (value & mask) === (base & mask);
}

function expandIpv6(rawAddress) {
  let address = String(rawAddress).toLowerCase().split('%')[0];
  const dottedTail = address.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (dottedTail) {
    const ipv4 = ipv4ToInteger(dottedTail);
    if (ipv4 === null) return null;
    const high = ((ipv4 >>> 16) & 0xffff).toString(16);
    const low = (ipv4 & 0xffff).toString(16);
    address = `${address.slice(0, -dottedTail.length)}${high}:${low}`;
  }

  const halves = address.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (missing < 0 || (halves.length === 1 && left.length !== 8)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.map((group) => Number.parseInt(group, 16));
}

function mappedIpv4(groups) {
  if (!groups || !groups.slice(0, 5).every((group) => group === 0) || groups[5] !== 0xffff) return null;
  return [groups[6] >>> 8, groups[6] & 0xff, groups[7] >>> 8, groups[7] & 0xff].join('.');
}

export function isBlockedAddress(rawAddress) {
  const address = String(rawAddress).replace(/^\[|\]$/g, '').split('%')[0];
  if (net.isIPv4(address)) {
    return BLOCKED_IPV4_RANGES.some(([network, prefix]) => isInIpv4Cidr(address, network, prefix));
  }
  if (!net.isIPv6(address)) return true;

  const groups = expandIpv6(address);
  if (!groups) return true;
  const mapped = mappedIpv4(groups);
  if (mapped) return isBlockedAddress(mapped);

  const allZero = groups.every((group) => group === 0);
  const loopback = groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1;
  const ipv4Compatible = groups.slice(0, 6).every((group) => group === 0);
  const uniqueLocal = (groups[0] & 0xfe00) === 0xfc00;
  const linkLocal = (groups[0] & 0xffc0) === 0xfe80;
  const siteLocal = (groups[0] & 0xffc0) === 0xfec0;
  const multicast = (groups[0] & 0xff00) === 0xff00;
  const documentation = groups[0] === 0x2001 && groups[1] === 0x0db8;
  const teredo = groups[0] === 0x2001 && groups[1] === 0;
  const sixToFour = groups[0] === 0x2002;
  const nat64 = groups[0] === 0x0064 && groups[1] === 0xff9b;
  const ipv4Translated = groups.slice(0, 4).every((group) => group === 0)
    && groups[4] === 0xffff && groups[5] === 0;
  const nonGlobalLegacy = groups[0] === 0x3ffe || groups[0] === 0x3fff;
  const discardOnly = groups[0] === 0x0100 && groups.slice(1, 7).every((group) => group === 0);
  const benchmarking = groups[0] === 0x2001 && groups[1] === 0x0002;
  const orchid = groups[0] === 0x2001 && (groups[1] === 0x0010 || groups[1] === 0x0020);
  const localNat64 = groups[0] === 0x0064 && groups[1] === 0xff9b && groups[2] === 1;
  const globalUnicast = (groups[0] & 0xe000) === 0x2000;
  const ietfSpecial = groups[0] === 0x2001 && groups[1] <= 0x01ff;
  return allZero || loopback || ipv4Compatible || uniqueLocal || linkLocal || siteLocal || multicast
    || ipv4Translated
    || documentation || teredo || sixToFour || nat64 || localNat64
    || nonGlobalLegacy || discardOnly || benchmarking || orchid || !globalUnicast || ietfSpecial;
}

function remainingMilliseconds(deadline, now) {
  const remaining = deadline - now();
  if (remaining <= 0) throw new Error('Page request timed out.');
  return remaining;
}

async function withinDeadline(promise, deadline, now) {
  if (!Number.isFinite(deadline)) return promise;
  const remaining = remainingMilliseconds(deadline, now);
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('Page request timed out.')), remaining);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function resolvePublicUrl(rawUrl, { lookup = dns.lookup, deadline = Number.POSITIVE_INFINITY, now = Date.now } = {}) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('Provide a valid absolute URL.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP(S) URLs are allowed.');
  if (url.username || url.password) throw new Error('URLs containing credentials are not allowed.');
  if (!SAFE_WEB_PORTS.has(url.port)) throw new Error('Only standard public web ports are allowed.');

  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!hostname || hostname === 'localhost' || ['.localhost', '.local', '.internal', '.lan', '.home.arpa'].some((suffix) => hostname.endsWith(suffix))) {
    throw new Error('Local and private hosts are not allowed.');
  }

  if (net.isIP(hostname)) {
    if (isBlockedAddress(hostname)) throw new Error('Private or reserved hosts are not allowed.');
    return { url, addresses: [{ address: hostname, family: net.isIP(hostname) }] };
  }

  let addresses;
  try {
    addresses = await withinDeadline(Promise.resolve(lookup(hostname, { all: true, verbatim: true })), deadline, now);
  } catch (error) {
    if (error.message === 'Page request timed out.') throw error;
    throw new Error('The hostname could not be resolved.');
  }
  if (!Array.isArray(addresses) || !addresses.length) {
    throw new Error('Private, reserved, or unresolved hosts are not allowed.');
  }
  const normalizedAddresses = addresses.map((record) => {
    const address = String(record?.address || '').replace(/^\[|\]$/g, '').split('%')[0];
    const family = Number(record?.family) || net.isIP(address);
    if (![4, 6].includes(family) || net.isIP(address) !== family || isBlockedAddress(address)) {
      throw new Error('Private, reserved, or unresolved hosts are not allowed.');
    }
    return { address, family };
  });
  const deduplicated = [...new Map(normalizedAddresses.map((record) => [`${record.family}:${record.address}`, record])).values()];
  return { url, addresses: deduplicated };
}

export async function validatePublicUrl(rawUrl, options = {}) {
  return (await resolvePublicUrl(rawUrl, options)).url;
}

export function createPinnedLookup(addresses) {
  const pinned = addresses.map(({ address, family }) => ({ address, family }));
  if (!pinned.length || pinned.some(({ address, family }) => net.isIP(address) !== family || isBlockedAddress(address))) {
    throw new Error('A validated public address is required.');
  }
  return (_hostname, options, callback) => {
    if (options && typeof options === 'object' && options.all) {
      callback(null, pinned.map((record) => ({ ...record })));
      return;
    }
    callback(null, pinned[0].address, pinned[0].family);
  };
}

export async function requestPinnedUrl(url, { addresses, headers, signal } = {}) {
  const lookup = createPinnedLookup(addresses || []);
  const transport = url.protocol === 'https:' ? https : http;
  const families = new Set(addresses.map(({ family }) => family));
  const requestOptions = {
    method: 'GET',
    headers,
    signal,
    lookup,
    autoSelectFamily: families.size > 1,
    autoSelectFamilyAttemptTimeout: 250,
  };
  if (url.protocol === 'https:' && !net.isIP(url.hostname.replace(/^\[|\]$/g, ''))) {
    requestOptions.servername = url.hostname;
  }

  return new Promise((resolve, reject) => {
    const request = transport.request(url, requestOptions, (response) => {
      resolve({
        status: response.statusCode || 0,
        headers: {
          get(name) {
            const value = response.headers[String(name).toLowerCase()];
            if (value === undefined) return null;
            return Array.isArray(value) ? value.join(', ') : String(value);
          },
        },
        body: Readable.toWeb(response),
      });
    });
    request.once('error', reject);
    request.end();
  });
}

export async function readBoundedBody(response, { maxBytes = MAX_BODY_BYTES } = {}) {
  const contentEncoding = String(response.headers.get('content-encoding') || '').trim().toLowerCase();
  if (contentEncoding && contentEncoding !== 'identity') {
    await response.body?.cancel?.();
    throw new Error(`Compressed responses are not supported (${contentEncoding}).`);
  }
  const declaredLength = Number(response.headers.get('content-length') || 0);
  if (declaredLength > maxBytes) {
    await response.body?.cancel?.();
    throw new Error('Page exceeds the 2 MB audit limit.');
  }
  if (!response.body) {
    return { html: '', contentBytes: 0, contentSha256: crypto.createHash('sha256').digest('hex') };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error('Page exceeds the 2 MB audit limit.');
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return {
    html: new TextDecoder().decode(bytes),
    contentBytes: total,
    contentSha256: crypto.createHash('sha256').update(bytes).digest('hex'),
  };
}

export async function fetchPublicPage(rawUrl, {
  timeoutSeconds = 15,
  fetchImpl = requestPinnedUrl,
  lookup = dns.lookup,
  now = Date.now,
  timeoutSignal = (milliseconds) => AbortSignal.timeout(milliseconds),
} = {}) {
  const startedAt = now();
  const timeoutMilliseconds = timeoutSeconds * 1000;
  const deadline = startedAt + timeoutMilliseconds;
  let target = await resolvePublicUrl(rawUrl, { lookup, deadline, now });
  const redirects = [];

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    const remaining = remainingMilliseconds(deadline, now);
    const response = await fetchImpl(target.url, {
      addresses: target.addresses,
      redirect: 'manual',
      signal: timeoutSignal(remaining),
      headers: {
        accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
        'accept-encoding': 'identity',
        'user-agent': 'RELAUNCH-DEPT-Launch-QA-Auditor/1.0 (+https://apify.com/relaunch_dept)',
      },
    });

    const location = response.headers.get('location');
    if (response.status >= 300 && response.status < 400 && location) {
      if (redirectCount === MAX_REDIRECTS) {
        await response.body?.cancel?.();
        throw new Error('Too many redirects.');
      }
      await response.body?.cancel?.();
      const nextUrl = new URL(location, target.url);
      if (target.url.protocol === 'https:' && nextUrl.protocol === 'http:') {
        throw new Error('HTTPS to HTTP redirects are not allowed.');
      }
      const nextTarget = await resolvePublicUrl(nextUrl.href, { lookup, deadline, now });
      redirects.push({ from: target.url.href, to: nextTarget.url.href, status: response.status });
      target = nextTarget;
      continue;
    }

    const contentType = (response.headers.get('content-type') || '').toLowerCase();
    const mimeType = contentType.split(';', 1)[0].trim();
    if (!['text/html', 'application/xhtml+xml'].includes(mimeType)) {
      await response.body?.cancel?.();
      throw new Error(`Expected an HTML page but received ${contentType || 'an unknown content type'}.`);
    }
    const body = await readBoundedBody(response);
    return {
      ...body,
      finalUrl: target.url.href,
      httpStatus: response.status,
      responseTimeMs: Math.max(0, now() - startedAt),
      redirects,
    };
  }
  throw new Error('Redirect limit reached.');
}
