import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHtml } from '../src/analyze.js';

const completePage = `<!doctype html>
<html lang="en"><head>
<title>Launch readiness audit for modern product teams</title>
<meta name="description" content="A practical launch readiness audit that catches public page mistakes before customers, investors, and search engines see them during a product launch.">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta property="og:title" content="Launch readiness audit">
<meta property="og:description" content="Catch launch page mistakes before customers do.">
<meta property="og:image" content="https://site.test/preview.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="canonical" href="https://site.test/launch">
<link rel="icon" href="/favicon.ico">
<script type="application/ld+json">{"@type":"WebSite"}</script>
</head><body><h1>Ship a launch page that is ready</h1><img src="hero.png" alt="Launch dashboard"></body></html>`;

test('scores a complete page as grade A', () => {
  const result = analyzeHtml(completePage, { requestedUrl: 'https://site.test', httpStatus: 200 });
  assert.equal(result.grade, 'A');
  assert.equal(result.score, 100);
  assert.equal(result.findings.length, 0);
});

test('detects high-impact launch mistakes', () => {
  const result = analyzeHtml('<html><head></head><body><img src="hero.jpg"><p>Lorem ipsum</p></body></html>', {
    requestedUrl: 'https://site.test',
    httpStatus: 500,
  });
  const codes = new Set(result.findings.map((finding) => finding.code));
  for (const expected of ['http-status', 'missing-title', 'missing-description', 'missing-viewport', 'missing-h1', 'missing-image-alt', 'placeholder-copy']) {
    assert.ok(codes.has(expected), `expected ${expected}`);
  }
  assert.equal(result.grade, 'F');
});

test('parses metadata regardless of attribute order', () => {
  const page = completePage.replace('property="og:title" content="Launch readiness audit"', 'content="Launch readiness audit" property="og:title"');
  const result = analyzeHtml(page, { requestedUrl: 'https://site.test', httpStatus: 200 });
  assert.equal(result.metadata.openGraphTitle, 'Launch readiness audit');
});
