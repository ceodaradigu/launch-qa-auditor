import dns from 'node:dns/promises';
import net from 'node:net';
import { Actor, log } from 'apify';
import { analyzeHtml } from './analyze.js';

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECTS = 5;

function isBlockedAddress(address) {
  if (net.isIPv4(address)) {
    const octets = address.split('.').map(Number);
    return octets[0] === 0
      || octets[0] === 10
      || octets[0] === 127
      || (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127)
      || (octets[0] === 169 && octets[1] === 254)
      || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
      || (octets[0] === 192 && octets[1] === 168)
      || (octets[0] === 198 && (octets[1] === 18 || octets[1] === 19))
      || octets[0] >= 224;
  }
  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase();
    return normalized === '::' || normalized === '::1'
      || normalized.startsWith('fc') || normalized.startsWith('fd')
      || /^fe[89ab]/.test(normalized)
      || normalized.startsWith('2001:db8:');
  }
  return true;
}

async function validatePublicUrl(rawUrl) {
  const url = new URL(rawUrl);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP(S) URLs are allowed.');
  if (url.username || url.password) throw new Error('URLs containing credentials are not allowed.');
  const hostname = url.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    throw new Error('Local and private hosts are not allowed.');
  }
  const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => isBlockedAddress(address))) {
    throw new Error('Private, reserved, or unresolved hosts are not allowed.');
  }
  return url;
}

async function readBoundedBody(response) {
  const declaredLength = Number(response.headers.get('content-length') || 0);
  if (declaredLength > MAX_BODY_BYTES) throw new Error('Page exceeds the 2 MB audit limit.');
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error('Page exceeds the 2 MB audit limit.');
    }
    chunks.push(value);
  }
  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(buffer);
}

async function fetchPublicPage(rawUrl, timeoutSeconds) {
  let url = await validatePublicUrl(rawUrl);
  const startedAt = Date.now();
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    const response = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutSeconds * 1000),
      headers: {
        accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
        'user-agent': 'RELAUNCH-DEPT-Launch-QA-Auditor/1.0 (+https://apify.com/relaunch_dept)',
      },
    });
    if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
      if (redirects === MAX_REDIRECTS) throw new Error('Too many redirects.');
      url = await validatePublicUrl(new URL(response.headers.get('location'), url).href);
      continue;
    }
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml+xml')) {
      throw new Error(`Expected an HTML page but received ${contentType || 'an unknown content type'}.`);
    }
    return {
      html: await readBoundedBody(response),
      finalUrl: url.href,
      httpStatus: response.status,
      responseTimeMs: Date.now() - startedAt,
    };
  }
  throw new Error('Redirect limit reached.');
}

await Actor.init();

try {
  const input = await Actor.getInput() || {};
  const urls = [...new Set((input.urls || []).map((value) => String(value).trim()).filter(Boolean))].slice(0, 10);
  const timeoutSeconds = Math.min(30, Math.max(5, Number(input.timeoutSeconds) || 15));
  if (!urls.length) throw new Error('Provide at least one public HTTP(S) URL.');

  for (const requestedUrl of urls) {
    try {
      const page = await fetchPublicPage(requestedUrl, timeoutSeconds);
      const result = analyzeHtml(page.html, { requestedUrl, ...page });
      const charge = await Actor.pushData(result, 'page-audited');
      log.info(`Audited ${requestedUrl}: ${result.grade} (${result.score}/100)`);
      if (charge?.eventChargeLimitReached) {
        log.info('Run spending limit reached; stopping cleanly.');
        break;
      }
    } catch (error) {
      const result = {
        requestedUrl,
        finalUrl: requestedUrl,
        auditedAt: new Date().toISOString(),
        httpStatus: 0,
        responseTimeMs: 0,
        score: 0,
        grade: 'F',
        summary: { high: 1, medium: 0, low: 0, total: 1 },
        metadata: {},
        findings: [{ severity: 'high', code: 'audit-failed', message: error.message }],
      };
      const charge = await Actor.pushData(result, 'page-audited');
      log.warning(`Could not audit ${requestedUrl}: ${error.message}`);
      if (charge?.eventChargeLimitReached) break;
    }
  }
} finally {
  await Actor.exit();
}
