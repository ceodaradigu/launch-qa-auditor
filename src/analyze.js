import { load } from 'cheerio';

const PLACEHOLDER_PATTERNS = [
  /lorem ipsum/i,
  /\bcoming soon\b/i,
  /\byour company\b/i,
  /\bexample\.com\b/i,
  /\[(?:insert|your|company|name|email)[^\]]*\]/i,
];

export const CHECK_IDS = Object.freeze([
  'http-success',
  'title',
  'description',
  'viewport',
  'language',
  'single-h1',
  'canonical',
  'open-graph',
  'image-alt',
  'no-placeholder-copy',
  'no-mixed-content',
]);

function clean(value = '', maximum = 400) {
  return String(value).replace(/\s+/g, ' ').trim().slice(0, maximum);
}

function addFinding(findings, severity, code, message, evidence) {
  const finding = { severity, code, message };
  if (evidence) finding.evidence = clean(evidence, 500);
  findings.push(finding);
}

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function check(id, passed, actual, evidence = '') {
  return { id, passed, actual: clean(actual, 500), evidence: clean(evidence || actual, 500) };
}

function firstMeta($, key) {
  let value = '';
  $('head meta').each((_index, element) => {
    if (value) return;
    const candidate = clean($(element).attr('property') || $(element).attr('name')).toLowerCase();
    if (candidate === key) value = clean($(element).attr('content'));
  });
  return value;
}

function firstHeadLink($, relation) {
  let value = '';
  $('head link').each((_index, element) => {
    if (value) return;
    const relations = clean($(element).attr('rel')).toLowerCase().split(/\s+/);
    if (relations.includes(relation)) value = clean($(element).attr('href'));
  });
  return value;
}

function insecureSubresource($, finalUrl) {
  let baseUrl = finalUrl;
  const declaredBase = clean($('head base[href]').first().attr('href'));
  try {
    if (declaredBase) baseUrl = new URL(declaredBase, finalUrl).href;
  } catch {
    baseUrl = finalUrl;
  }
  const isHttp = (raw) => {
    try {
      return new URL(clean(raw), baseUrl).protocol === 'http:';
    } catch {
      return false;
    }
  };
  const selectors = [
    ['script[src],img[src],iframe[src],audio[src],video[src],source[src],track[src],input[src],embed[src]', 'src'],
    ['object[data]', 'data'],
    ['video[poster]', 'poster'],
  ];
  for (const [selector, attribute] of selectors) {
    let found = false;
    $(selector).each((_index, element) => {
      if (isHttp($(element).attr(attribute))) found = true;
    });
    if (found) return true;
  }
  const fetchingLinkRelations = new Set(['stylesheet', 'icon', 'preload', 'modulepreload', 'prefetch', 'manifest']);
  let found = false;
  $('link[href]').each((_index, element) => {
    const relations = clean($(element).attr('rel')).toLowerCase().split(/\s+/);
    if (relations.some((relation) => fetchingLinkRelations.has(relation)) && isHttp($(element).attr('href'))) found = true;
  });
  if (found) return true;
  $('[srcset]').each((_index, element) => {
    if (String($(element).attr('srcset') || '').split(',').some((candidate) => isHttp(candidate.trim().split(/\s+/)[0]))) found = true;
  });
  if (found) return true;
  $('[style]').add('style').each((_index, element) => {
    const css = element.tagName === 'style' ? $(element).text() : $(element).attr('style');
    if (/\burl\(\s*['"]?http:\/\//i.test(String(css || ''))
      || /@import\s+(?:url\(\s*)?['"]?http:\/\//i.test(String(css || ''))) found = true;
  });
  return found;
}

export function analyzeHtml(html, {
  requestedUrl,
  finalUrl = requestedUrl,
  httpStatus = 200,
  responseTimeMs = 0,
  auditedAt = new Date().toISOString(),
} = {}) {
  const $ = load(String(html));
  $('template,noscript').remove();
  const findings = [];
  const title = clean($('head > title').first().text(), 200);
  const description = firstMeta($, 'description');
  const viewport = firstMeta($, 'viewport');
  const openGraphTitle = firstMeta($, 'og:title');
  const openGraphDescription = firstMeta($, 'og:description');
  const openGraphImage = firstMeta($, 'og:image');
  const twitterCard = firstMeta($, 'twitter:card');
  const language = clean($('html').first().attr('lang'), 50);
  const canonical = firstHeadLink($, 'canonical');
  const favicon = firstHeadLink($, 'icon');
  const h1Count = $('body h1').length;
  const images = $('body img').toArray();
  const missingAlt = images.filter((element) => $(element).attr('alt') === undefined).length;

  if (httpStatus < 200 || httpStatus >= 300) addFinding(findings, 'high', 'http-status', `Page returned HTTP ${httpStatus}.`);
  if (!title) addFinding(findings, 'high', 'missing-title', 'Add a unique HTML title.');
  else if (title.length < 20 || title.length > 65) addFinding(findings, 'medium', 'title-length', 'Keep the title between 20 and 65 characters.', `${title.length} characters`);

  if (!description) addFinding(findings, 'high', 'missing-description', 'Add a concise meta description.');
  else if (description.length < 70 || description.length > 170) addFinding(findings, 'medium', 'description-length', 'Keep the meta description between 70 and 170 characters.', `${description.length} characters`);

  if (!viewport) addFinding(findings, 'high', 'missing-viewport', 'Add a mobile viewport meta tag.');
  if (!language) addFinding(findings, 'medium', 'missing-language', 'Declare the page language on the html element.');
  if (h1Count === 0) addFinding(findings, 'high', 'missing-h1', 'Add one clear H1 heading.');
  else if (h1Count > 1) addFinding(findings, 'medium', 'multiple-h1', 'Use one primary H1 heading.', `${h1Count} H1 elements`);

  for (const [key, value] of [['og:title', openGraphTitle], ['og:description', openGraphDescription], ['og:image', openGraphImage]]) {
    if (!value) addFinding(findings, 'medium', `missing-${key.replace(':', '-')}`, `Add ${key} for reliable social previews.`);
  }
  if (!twitterCard) addFinding(findings, 'low', 'missing-twitter-card', 'Add a Twitter/X card meta tag.');
  if (!canonical) addFinding(findings, 'medium', 'missing-canonical', 'Add a canonical URL.');
  if (!favicon) addFinding(findings, 'low', 'missing-favicon', 'Add an explicit favicon link.');
  if (missingAlt) addFinding(findings, missingAlt > 2 ? 'high' : 'medium', 'missing-image-alt', 'Add alt attributes to meaningful images and empty alt text to decorative images.', `${missingAlt} of ${images.length} images`);

  const visibleDocument = $.root().clone();
  visibleDocument.find('script,style,template,noscript,textarea').remove();
  const visibleText = visibleDocument.find('body').text().replace(/\s+/g, ' ').trim();
  const placeholder = PLACEHOLDER_PATTERNS.find((pattern) => pattern.test(visibleText));
  if (placeholder) addFinding(findings, 'high', 'placeholder-copy', 'Replace placeholder or unfinished copy before launch.', placeholder.source);
  const hasMixedContentRisk = Boolean(finalUrl?.startsWith('https://')) && insecureSubresource($, finalUrl);
  if (hasMixedContentRisk) addFinding(findings, 'medium', 'mixed-content-risk', 'Review HTTP subresource references on this HTTPS page.');
  if (!$('head script[type="application/ld+json"]').length) addFinding(findings, 'low', 'missing-structured-data', 'Consider adding relevant JSON-LD structured data.');

  const weights = { high: 15, medium: 8, low: 3 };
  const score = Math.max(0, 100 - findings.reduce((sum, finding) => sum + weights[finding.severity], 0));
  const summary = {
    high: findings.filter((finding) => finding.severity === 'high').length,
    medium: findings.filter((finding) => finding.severity === 'medium').length,
    low: findings.filter((finding) => finding.severity === 'low').length,
    total: findings.length,
  };
  const missingOpenGraph = [['og:title', openGraphTitle], ['og:description', openGraphDescription], ['og:image', openGraphImage]]
    .filter(([, value]) => !value).map(([key]) => key);
  const checks = [
    check('http-success', httpStatus >= 200 && httpStatus < 300, `HTTP ${httpStatus}`),
    check('title', Boolean(title) && title.length >= 20 && title.length <= 65, title ? `${title.length} characters` : 'missing'),
    check('description', Boolean(description) && description.length >= 70 && description.length <= 170, description ? `${description.length} characters` : 'missing'),
    check('viewport', Boolean(viewport), viewport || 'missing'),
    check('language', Boolean(language), language || 'missing'),
    check('single-h1', h1Count === 1, `${h1Count} H1 elements`),
    check('canonical', Boolean(canonical), canonical || 'missing'),
    check('open-graph', missingOpenGraph.length === 0, missingOpenGraph.length ? `missing ${missingOpenGraph.join(', ')}` : 'complete'),
    check('image-alt', missingAlt === 0, `${missingAlt} of ${images.length} images missing alt`),
    check('no-placeholder-copy', !placeholder, placeholder ? `matched ${placeholder.source}` : 'no placeholder pattern matched'),
    check('no-mixed-content', !hasMixedContentRisk, hasMixedContentRisk ? 'HTTP subresource found on HTTPS page' : 'no HTTP subresource found on HTTPS page'),
  ];

  return {
    requestedUrl,
    finalUrl,
    auditedAt,
    httpStatus,
    responseTimeMs,
    score,
    grade: gradeFor(score),
    summary,
    metadata: {
      title,
      description,
      canonical,
      openGraphTitle,
      openGraphDescription,
      openGraphImage,
      viewport,
      language,
      h1Count,
      imageCount: images.length,
    },
    findings,
    checks,
  };
}
