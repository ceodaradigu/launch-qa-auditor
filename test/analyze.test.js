import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyzeHtml, CHECK_IDS } from '../src/analyze.js';

const completePage = readFileSync(new URL('./fixtures/pass.html', import.meta.url), 'utf8');
const incompletePage = readFileSync(new URL('./fixtures/fail.html', import.meta.url), 'utf8');
const fixedTime = '2026-08-13T20:00:00.000Z';

test('scores a complete page as grade A', () => {
  const result = analyzeHtml(completePage, { requestedUrl: 'https://site.test', httpStatus: 200, auditedAt: fixedTime });
  assert.equal(result.grade, 'A');
  assert.equal(result.score, 100);
  assert.equal(result.findings.length, 0);
  assert.equal(result.auditedAt, fixedTime);
  assert.deepEqual(result.checks.map(({ id }) => id), CHECK_IDS);
  assert.ok(result.checks.every(({ passed }) => passed));
});

test('detects high-impact launch mistakes', () => {
  const result = analyzeHtml(incompletePage, {
    requestedUrl: 'https://site.test',
    httpStatus: 500,
    auditedAt: fixedTime,
  });
  const codes = new Set(result.findings.map((finding) => finding.code));
  for (const expected of ['http-status', 'missing-title', 'missing-description', 'missing-viewport', 'missing-h1', 'missing-image-alt', 'placeholder-copy']) {
    assert.ok(codes.has(expected), `expected ${expected}`);
  }
  assert.equal(result.grade, 'F');
});

test('parses metadata regardless of attribute order', () => {
  const page = completePage.replace('property="og:title" content="Launch readiness audit"', 'content="Launch readiness audit" property="og:title"');
  const result = analyzeHtml(page, { requestedUrl: 'https://site.test', httpStatus: 200, auditedAt: fixedTime });
  assert.equal(result.metadata.openGraphTitle, 'Launch readiness audit');
});

test('does not confuse visible URLs or JSON-LD context with mixed content', () => {
  const html = `<html lang="en"><head><script type="application/ld+json">{"@context":"http://schema.org"}</script></head><body><p>Documentation: http://example.test</p></body></html>`;
  const result = analyzeHtml(html, { requestedUrl: 'https://fixture.example', finalUrl: 'https://fixture.example/', httpStatus: 200 });
  assert.equal(result.checks.find((item) => item.id === 'no-mixed-content').passed, true);
  assert.equal(result.findings.some((item) => item.code === 'mixed-content-risk'), false);
});

test('treats an unresolved redirect as an HTTP failure', () => {
  const result = analyzeHtml(completePage, { requestedUrl: 'https://fixture.example', httpStatus: 302 });
  assert.equal(result.checks.find((item) => item.id === 'http-success').passed, false);
  assert.equal(result.findings.some((item) => item.code === 'http-status'), true);
  assert.ok(result.score < 100);
});

test('ignores launch metadata hidden inside HTML comments', () => {
  const hidden = `<!-- ${completePage} -->`;
  const result = analyzeHtml(hidden, { requestedUrl: 'https://fixture.example', httpStatus: 200 });
  assert.equal(result.checks.find((item) => item.id === 'title').passed, false);
  assert.equal(result.checks.find((item) => item.id === 'single-h1').passed, false);
  assert.ok(result.score < 80);
});

test('ignores inert and non-head markup that resembles launch metadata', () => {
  const hidden = `<html><head></head><body>
    <svg><title>A long SVG title that is not the document title</title></svg>
    <script type="text/plain"><title>Fake but sufficiently long script title</title><h1>Fake script H1</h1></script>
    <template><title>Fake but sufficiently long template title</title><h1>Fake template H1</h1></template>
  </body></html>`;
  const result = analyzeHtml(hidden, { requestedUrl: 'https://fixture.example', httpStatus: 200 });
  assert.equal(result.metadata.title, '');
  assert.equal(result.checks.find((item) => item.id === 'title').passed, false);
  assert.equal(result.checks.find((item) => item.id === 'single-h1').passed, false);
  assert.ok(result.score < 80);
});

test('does not call ordinary HTTP links mixed subresources', () => {
  const html = completePage.replace('</body>', '<a href="http://external.example">External documentation</a></body>');
  const result = analyzeHtml(html, { requestedUrl: 'https://fixture.example', finalUrl: 'https://fixture.example/', httpStatus: 200 });
  assert.equal(result.checks.find((item) => item.id === 'no-mixed-content').passed, true);
});

test('detects actual insecure subresources', () => {
  const html = completePage.replace('src="hero.png"', 'src="http://fixture.example/hero.png"');
  const result = analyzeHtml(html, { requestedUrl: 'https://fixture.example', finalUrl: 'https://fixture.example/', httpStatus: 200 });
  assert.equal(result.checks.find((item) => item.id === 'no-mixed-content').passed, false);
});

test('does not treat an HTTP canonical link as a fetched subresource', () => {
  const html = completePage.replace('https://fixture.example/launch', 'http://fixture.example/launch');
  const result = analyzeHtml(html, { requestedUrl: 'https://fixture.example', finalUrl: 'https://fixture.example/', httpStatus: 200 });
  assert.equal(result.checks.find((item) => item.id === 'no-mixed-content').passed, true);
});

test('detects CSS imports and relative resources under an insecure base URL', () => {
  const imported = completePage.replace('</head>', '<style>@import "http://fixture.example/theme.css";</style></head>');
  const underBase = completePage.replace('</head>', '<base href="http://fixture.example/assets/"></head>');
  for (const html of [imported, underBase]) {
    const result = analyzeHtml(html, { requestedUrl: 'https://fixture.example', finalUrl: 'https://fixture.example/', httpStatus: 200 });
    assert.equal(result.checks.find((item) => item.id === 'no-mixed-content').passed, false);
  }
});

test('finds placeholder copy after 200,000 visible characters', () => {
  const html = completePage.replace('</body>', `<p>${'safe words '.repeat(22000)} coming soon</p></body>`);
  const result = analyzeHtml(html, { requestedUrl: 'https://fixture.example', finalUrl: 'https://fixture.example/', httpStatus: 200 });
  assert.equal(result.checks.find((item) => item.id === 'no-placeholder-copy').passed, false);
});
