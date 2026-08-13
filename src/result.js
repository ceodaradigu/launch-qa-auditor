import { evaluateAcceptance } from './oracle.js';

export const CONTRACT_VERSION = '1.0.0';
export const ANALYZER_VERSION = '0.2.0';

export function sanitizeUrlForOutput(rawUrl, baseUrl) {
  try {
    const url = baseUrl ? new URL(String(rawUrl), baseUrl) : new URL(String(rawUrl));
    if (!['http:', 'https:'].includes(url.protocol)) return '[redacted URL]';
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.href.slice(0, 1000);
  } catch {
    return '[invalid URL]';
  }
}

function sanitizedRedirects(redirects = []) {
  return redirects.map((redirect) => ({
    from: sanitizeUrlForOutput(redirect.from),
    to: sanitizeUrlForOutput(redirect.to),
    status: redirect.status,
  }));
}

export function safeErrorMessage(error) {
  const raw = error instanceof Error ? error.message : String(error ?? 'Unknown audit error');
  return raw
    .replace(/https?:\/\/[^\s"'<>]+/gi, (url) => sanitizeUrlForOutput(url))
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .trim()
    .slice(0, 500) || 'Unknown audit error';
}

export function evidenceFor(audit, page = {}) {
  return {
    contractVersion: CONTRACT_VERSION,
    analyzerVersion: ANALYZER_VERSION,
    requestedUrl: sanitizeUrlForOutput(audit.requestedUrl),
    finalUrl: sanitizeUrlForOutput(audit.finalUrl),
    httpStatus: audit.httpStatus,
    responseTimeMs: audit.responseTimeMs,
    contentBytes: page.contentBytes ?? 0,
    contentSha256: page.contentSha256 ?? '',
    redirects: sanitizedRedirects(page.redirects),
    evaluatedAt: audit.auditedAt,
  };
}

export function resultForAudit(audit, page, acceptance) {
  const safeFinalUrl = sanitizeUrlForOutput(audit.finalUrl);
  const safeMetadata = {
    ...audit.metadata,
    canonical: audit.metadata?.canonical ? sanitizeUrlForOutput(audit.metadata.canonical, safeFinalUrl) : '',
    openGraphImage: audit.metadata?.openGraphImage ? sanitizeUrlForOutput(audit.metadata.openGraphImage, safeFinalUrl) : '',
  };
  const safeChecks = (audit.checks || []).map((item) => item.id === 'canonical'
    ? {
      ...item,
      actual: item.actual === 'missing' ? item.actual : sanitizeUrlForOutput(item.actual, safeFinalUrl),
      evidence: item.evidence === 'missing' ? item.evidence : sanitizeUrlForOutput(item.evidence, safeFinalUrl),
    }
    : item);
  const safeAudit = {
    ...audit,
    requestedUrl: sanitizeUrlForOutput(audit.requestedUrl),
    finalUrl: safeFinalUrl,
    metadata: safeMetadata,
    checks: safeChecks,
  };
  if (!acceptance) {
    return {
      ...safeAudit,
      mode: 'audit',
      verdict: 'not-evaluated',
      criteria: [],
      failedCriteria: [],
      evidence: evidenceFor(safeAudit, page),
    };
  }

  return {
    ...safeAudit,
    mode: 'acceptance',
    ...evaluateAcceptance(safeAudit, acceptance),
    evidence: evidenceFor(safeAudit, page),
  };
}

export function resultForError(requestedUrl, error, acceptance, evaluatedAt = new Date().toISOString()) {
  const safeRequestedUrl = sanitizeUrlForOutput(requestedUrl);
  const message = safeErrorMessage(error);
  const audit = {
    requestedUrl: safeRequestedUrl,
    finalUrl: safeRequestedUrl,
    auditedAt: evaluatedAt,
    httpStatus: 0,
    responseTimeMs: 0,
    score: 0,
    grade: 'F',
    summary: { high: 1, medium: 0, low: 0, total: 1 },
    metadata: {},
    findings: [{ severity: 'high', code: 'audit-failed', message }],
    checks: [],
  };
  const result = {
    ...audit,
    mode: acceptance ? 'acceptance' : 'audit',
    verdict: 'error',
    criteria: acceptance ? [{
      id: 'audit-succeeded',
      operator: 'equals',
      expected: 'true',
      actual: 'false',
      passed: false,
      evidence: message,
    }] : [],
    failedCriteria: acceptance ? ['audit-succeeded'] : [],
    evidence: evidenceFor(audit),
  };
  if (acceptance) result.accepted = false;
  return result;
}
