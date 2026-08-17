import { CHECK_IDS } from './analyze.js';

const GRADES = Object.freeze(['A', 'B', 'C', 'D', 'F']);
const FINDING_LEVELS = Object.freeze(['high', 'medium', 'low', 'total']);

function integerInRange(value, label, minimum, maximum) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < minimum || number > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} to ${maximum}.`);
  }
  return number;
}

function optionalLimit(value, label) {
  if (value === undefined || value === null) return null;
  return integerInRange(value, label, 0, 1000);
}

export function normalizeAcceptance(rawAcceptance) {
  if (rawAcceptance === undefined || rawAcceptance === null) return null;
  if (typeof rawAcceptance !== 'object' || Array.isArray(rawAcceptance)) {
    throw new Error('acceptance must be an object.');
  }

  if (rawAcceptance.allowedGrades !== undefined && !Array.isArray(rawAcceptance.allowedGrades)) {
    throw new Error('allowedGrades must be an array.');
  }

  if (rawAcceptance.requiredChecks !== undefined && !Array.isArray(rawAcceptance.requiredChecks)) {
    throw new Error('requiredChecks must be an array.');
  }

  const allowedGrades = rawAcceptance.allowedGrades === undefined
    ? ['A', 'B']
    : [...new Set(rawAcceptance.allowedGrades.map((grade) => String(grade).toUpperCase()))];
  if (!allowedGrades.length || allowedGrades.some((grade) => !GRADES.includes(grade))) {
    throw new Error('allowedGrades must contain one or more of A, B, C, D, or F.');
  }

  const requiredChecks = rawAcceptance.requiredChecks === undefined
    ? []
    : [...new Set(rawAcceptance.requiredChecks.map(String))];
  const unknownChecks = requiredChecks.filter((id) => !CHECK_IDS.includes(id));
  if (unknownChecks.length) throw new Error(`Unknown requiredChecks: ${unknownChecks.join(', ')}.`);

  const rawMaximums = rawAcceptance.maximumFindings ?? {};
  if (typeof rawMaximums !== 'object' || Array.isArray(rawMaximums)) {
    throw new Error('maximumFindings must be an object.');
  }

  return {
    minimumScore: integerInRange(rawAcceptance.minimumScore ?? 80, 'minimumScore', 0, 100),
    allowedGrades,
    maximumFindings: {
      high: optionalLimit(rawMaximums.high ?? 0, 'maximumFindings.high'),
      medium: optionalLimit(rawMaximums.medium, 'maximumFindings.medium'),
      low: optionalLimit(rawMaximums.low, 'maximumFindings.low'),
      total: optionalLimit(rawMaximums.total, 'maximumFindings.total'),
    },
    requiredChecks: CHECK_IDS.filter((id) => requiredChecks.includes(id)),
  };
}

function printable(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function criterion(id, operator, expected, actual, passed, evidence = '') {
  return {
    id,
    operator,
    expected: printable(expected),
    actual: printable(actual),
    passed,
    evidence: String(evidence),
  };
}

export function evaluateAcceptance(audit, acceptance) {
  if (!acceptance) throw new Error('An acceptance policy is required for evaluation.');
  const criteria = [
    criterion('secure-transport', 'equals', 'https', String(audit.finalUrl || '').toLowerCase().startsWith('https://') ? 'https' : 'not-https', String(audit.finalUrl || '').toLowerCase().startsWith('https://'), 'Acceptance decisions require a final HTTPS URL.'),
    criterion('minimum-score', 'greater-than-or-equal', acceptance.minimumScore, audit.score, audit.score >= acceptance.minimumScore, `${audit.score}/100`),
    criterion('allowed-grades', 'one-of', acceptance.allowedGrades, audit.grade, acceptance.allowedGrades.includes(audit.grade), `grade ${audit.grade}`),
  ];

  for (const level of FINDING_LEVELS) {
    const maximum = acceptance.maximumFindings[level];
    if (maximum === null) continue;
    const actual = audit.summary[level];
    criteria.push(criterion(`maximum-findings-${level}`, 'less-than-or-equal', maximum, actual, actual <= maximum, `${actual} ${level} findings`));
  }

  const checkMap = new Map((audit.checks || []).map((item) => [item.id, item]));
  for (const id of acceptance.requiredChecks) {
    const item = checkMap.get(id);
    criteria.push(criterion(
      `required-check-${id}`,
      'equals',
      true,
      item?.passed ?? false,
      item?.passed === true,
      item?.evidence || 'check result missing',
    ));
  }

  const failedCriteria = criteria.filter((item) => !item.passed).map((item) => item.id);
  return {
    verdict: failedCriteria.length ? 'fail' : 'pass',
    accepted: failedCriteria.length === 0,
    criteria,
    failedCriteria,
  };
}
