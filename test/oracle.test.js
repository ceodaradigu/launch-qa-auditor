import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyzeHtml, CHECK_IDS } from '../src/analyze.js';
import { evaluateAcceptance, normalizeAcceptance } from '../src/oracle.js';

const completePage = readFileSync(new URL('./fixtures/pass.html', import.meta.url), 'utf8');
const incompletePage = readFileSync(new URL('./fixtures/fail.html', import.meta.url), 'utf8');
const context = { requestedUrl: 'https://fixture.example', httpStatus: 200, auditedAt: '2026-08-13T20:00:00.000Z' };

test('accepts a complete page under the default policy', () => {
  const audit = analyzeHtml(completePage, context);
  const result = evaluateAcceptance(audit, normalizeAcceptance({}));
  assert.equal(result.verdict, 'pass');
  assert.equal(result.accepted, true);
  assert.deepEqual(result.failedCriteria, []);
});

test('rejects a page with failed score, grade, severity, and required checks', () => {
  const audit = analyzeHtml(incompletePage, context);
  const policy = normalizeAcceptance({
    minimumScore: 90,
    allowedGrades: ['A'],
    maximumFindings: { high: 0, total: 0 },
    requiredChecks: ['title', 'description', 'viewport', 'single-h1', 'no-placeholder-copy'],
  });
  const result = evaluateAcceptance(audit, policy);
  assert.equal(result.verdict, 'fail');
  assert.equal(result.accepted, false);
  for (const id of ['minimum-score', 'allowed-grades', 'maximum-findings-high', 'maximum-findings-total', 'required-check-title', 'required-check-no-placeholder-copy']) {
    assert.ok(result.failedCriteria.includes(id), `expected ${id}`);
  }
});

test('normalizes required checks into stable contract order', () => {
  const policy = normalizeAcceptance({ requiredChecks: ['no-mixed-content', 'title', 'http-success', 'title'] });
  assert.deepEqual(policy.requiredChecks, ['http-success', 'title', 'no-mixed-content']);
});

test('never accepts an HTTP page even when every page check passes', () => {
  const audit = analyzeHtml(completePage, { ...context, finalUrl: 'http://fixture.example/' });
  const result = evaluateAcceptance(audit, normalizeAcceptance({}));
  assert.equal(result.accepted, false);
  assert.ok(result.failedCriteria.includes('secure-transport'));
});

test('rejects unknown checks and malformed grade lists', () => {
  assert.throws(() => normalizeAcceptance({ requiredChecks: 'title' }), /requiredChecks must be an array/);
  assert.throws(() => normalizeAcceptance({ requiredChecks: ['made-up-check'] }), /Unknown requiredChecks/);
  assert.throws(() => normalizeAcceptance({ allowedGrades: 'A' }), /allowedGrades must be an array/);
  assert.throws(() => normalizeAcceptance({ allowedGrades: ['Z'] }), /allowedGrades/);
});

test('keeps the public input schema check IDs synchronized with the analyzer', () => {
  const schema = JSON.parse(readFileSync(new URL('../.actor/input_schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(schema.properties.acceptance.properties.requiredChecks.items.enum, CHECK_IDS);
});
