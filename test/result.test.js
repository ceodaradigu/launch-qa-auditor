import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAcceptance } from '../src/oracle.js';
import { ANALYZER_VERSION, CONTRACT_VERSION, resultForAudit, resultForError, safeErrorMessage, sanitizeUrlForOutput } from '../src/result.js';

const audit = {
  requestedUrl: 'https://fixture.example',
  finalUrl: 'https://fixture.example/',
  auditedAt: '2026-08-13T20:00:00.000Z',
  httpStatus: 200,
  responseTimeMs: 25,
  score: 100,
  grade: 'A',
  summary: { high: 0, medium: 0, low: 0, total: 0 },
  metadata: {},
  findings: [],
  checks: [],
};

const page = {
  contentBytes: 35,
  contentSha256: 'a'.repeat(64),
  redirects: [],
};

test('keeps legacy audit data while adding a non-evaluated envelope', () => {
  const result = resultForAudit(audit, page, null);
  assert.equal(result.mode, 'audit');
  assert.equal(result.verdict, 'not-evaluated');
  assert.equal(result.accepted, undefined);
  assert.equal(result.score, 100);
  assert.equal(result.evidence.contractVersion, CONTRACT_VERSION);
  assert.equal(result.evidence.analyzerVersion, ANALYZER_VERSION);
  assert.equal(result.evidence.contentSha256, 'a'.repeat(64));
});

test('adds a machine-readable decision only when acceptance is requested', () => {
  const result = resultForAudit(audit, page, normalizeAcceptance({}));
  assert.equal(result.mode, 'acceptance');
  assert.equal(result.verdict, 'pass');
  assert.equal(result.accepted, true);
});

test('turns a fetch failure into a deterministic error result', () => {
  const result = resultForError(
    'https://fixture.example',
    new Error('synthetic fetch failure'),
    normalizeAcceptance({}),
    '2026-08-13T20:00:00.000Z',
  );
  assert.equal(result.verdict, 'error');
  assert.equal(result.accepted, false);
  assert.deepEqual(result.failedCriteria, ['audit-succeeded']);
  assert.equal(result.evidence.evaluatedAt, '2026-08-13T20:00:00.000Z');
});

test('redacts credentials, query parameters, and fragments from every output URL', () => {
  assert.equal(sanitizeUrlForOutput('https://user:pass@example.com/path?token=secret#access_token=secret'), 'https://example.com/path');
  const result = resultForError(
    'https://user:pass@example.com/path?token=secret#access_token=secret',
    new Error('blocked'),
    null,
    '2026-08-13T20:00:00.000Z',
  );
  assert.equal(result.requestedUrl, 'https://example.com/path');
  assert.equal(result.evidence.requestedUrl, 'https://example.com/path');
  assert.equal(safeErrorMessage('failed at https://user:pass@example.com/path?token=secret#value\nnext'), 'failed at https://example.com/path next');
  assert.equal(sanitizeUrlForOutput('data:text/plain,TOPSECRET'), '[redacted URL]');
});

test('redacts URL parameters from metadata and canonical check evidence', () => {
  const sensitiveAudit = {
    ...audit,
    metadata: {
      canonical: 'https://fixture.example/launch?token=SECRET#private',
      openGraphImage: '/image.png?signature=SECRET',
    },
    checks: [{
      id: 'canonical',
      passed: true,
      actual: 'https://fixture.example/launch?token=SECRET#private',
      evidence: 'https://fixture.example/launch?token=SECRET#private',
    }],
  };
  const result = resultForAudit(sensitiveAudit, page, normalizeAcceptance({ requiredChecks: ['canonical'] }));
  assert.equal(result.metadata.canonical, 'https://fixture.example/launch');
  assert.equal(result.metadata.openGraphImage, 'https://fixture.example/image.png');
  assert.equal(result.checks[0].actual, 'https://fixture.example/launch');
  assert.doesNotMatch(JSON.stringify(result), /SECRET/);
});
