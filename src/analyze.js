const PLACEHOLDER_PATTERNS = [
  /lorem ipsum/i,
  /\bcoming soon\b/i,
  /\byour company\b/i,
  /\bexample\.com\b/i,
  /\[(?:insert|your|company|name|email)[^\]]*\]/i,
];

function decodeEntities(value = '') {
  return value
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

function stripTags(value = '') {
  return decodeEntities(value.replace(/<[^>]*>/g, ' '));
}

function attributes(tag) {
  const result = {};
  const body = tag.replace(/^<\/?[^\s>]+/i, '').replace(/\/?\s*>$/, '');
  const pattern = /([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const match of body.matchAll(pattern)) {
    result[match[1].toLowerCase()] = decodeEntities(match[2] ?? match[3] ?? match[4] ?? '');
  }
  return result;
}

function firstContent(html, tagName) {
  const match = html.match(new RegExp(`<${tagName}\\b[^>]*>([\\s\\S]*?)<\\/${tagName}>`, 'i'));
  return match ? stripTags(match[1]) : '';
}

function collectTags(html, tagName) {
  return [...html.matchAll(new RegExp(`<${tagName}\\b[^>]*>`, 'gi'))].map((match) => attributes(match[0]));
}

function addFinding(findings, severity, code, message, evidence) {
  const finding = { severity, code, message };
  if (evidence) finding.evidence = evidence;
  findings.push(finding);
}

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export function analyzeHtml(html, { requestedUrl, finalUrl = requestedUrl, httpStatus = 200, responseTimeMs = 0 } = {}) {
  const findings = [];
  const title = firstContent(html, 'title');
  const htmlTag = html.match(/<html\b[^>]*>/i);
  const htmlAttrs = htmlTag ? attributes(htmlTag[0]) : {};
  const metas = collectTags(html, 'meta');
  const links = collectTags(html, 'link');
  const images = collectTags(html, 'img');
  const h1Count = (html.match(/<h1\b/gi) || []).length;
  const metadata = {};

  for (const meta of metas) {
    const key = (meta.property || meta.name || '').toLowerCase();
    if (key && meta.content && metadata[key] === undefined) metadata[key] = meta.content;
  }

  if (httpStatus < 200 || httpStatus >= 400) {
    addFinding(findings, 'high', 'http-status', `Page returned HTTP ${httpStatus}.`);
  }
  if (!title) addFinding(findings, 'high', 'missing-title', 'Add a unique HTML title.');
  else if (title.length < 20 || title.length > 65) addFinding(findings, 'medium', 'title-length', 'Keep the title between 20 and 65 characters.', `${title.length} characters`);

  const description = metadata.description || '';
  if (!description) addFinding(findings, 'high', 'missing-description', 'Add a concise meta description.');
  else if (description.length < 70 || description.length > 170) addFinding(findings, 'medium', 'description-length', 'Keep the meta description between 70 and 170 characters.', `${description.length} characters`);

  if (!metadata.viewport) addFinding(findings, 'high', 'missing-viewport', 'Add a mobile viewport meta tag.');
  if (!htmlAttrs.lang) addFinding(findings, 'medium', 'missing-language', 'Declare the page language on the html element.');
  if (h1Count === 0) addFinding(findings, 'high', 'missing-h1', 'Add one clear H1 heading.');
  else if (h1Count > 1) addFinding(findings, 'medium', 'multiple-h1', 'Use one primary H1 heading.', `${h1Count} H1 elements`);

  for (const key of ['og:title', 'og:description', 'og:image']) {
    if (!metadata[key]) addFinding(findings, 'medium', `missing-${key.replace(':', '-')}`, `Add ${key} for reliable social previews.`);
  }
  if (!metadata['twitter:card']) addFinding(findings, 'low', 'missing-twitter-card', 'Add a Twitter/X card meta tag.');

  const canonical = links.find((link) => (link.rel || '').toLowerCase().split(/\s+/).includes('canonical'))?.href;
  if (!canonical) addFinding(findings, 'medium', 'missing-canonical', 'Add a canonical URL.');
  const favicon = links.find((link) => /(?:^|\s)(?:shortcut\s+)?icon(?:\s|$)/i.test(link.rel || ''))?.href;
  if (!favicon) addFinding(findings, 'low', 'missing-favicon', 'Add an explicit favicon link.');

  const missingAlt = images.filter((image) => image.alt === undefined).length;
  if (missingAlt) addFinding(findings, missingAlt > 2 ? 'high' : 'medium', 'missing-image-alt', 'Add alt attributes to meaningful images and empty alt text to decorative images.', `${missingAlt} of ${images.length} images`);

  const visibleText = stripTags(html.replace(/<script\b[\s\S]*?<\/script>/gi, ' ').replace(/<style\b[\s\S]*?<\/style>/gi, ' '));
  const placeholder = PLACEHOLDER_PATTERNS.find((pattern) => pattern.test(visibleText));
  if (placeholder) addFinding(findings, 'high', 'placeholder-copy', 'Replace placeholder or unfinished copy before launch.', placeholder.source);
  if (/\bhttp:\/\//i.test(html) && finalUrl?.startsWith('https://')) addFinding(findings, 'medium', 'mixed-content-risk', 'Review HTTP resource references on this HTTPS page.');
  if (!/<script\b[^>]*type=["']application\/ld\+json["']/i.test(html)) addFinding(findings, 'low', 'missing-structured-data', 'Consider adding relevant JSON-LD structured data.');

  const weights = { high: 15, medium: 8, low: 3 };
  const score = Math.max(0, 100 - findings.reduce((sum, finding) => sum + weights[finding.severity], 0));
  const summary = {
    high: findings.filter((finding) => finding.severity === 'high').length,
    medium: findings.filter((finding) => finding.severity === 'medium').length,
    low: findings.filter((finding) => finding.severity === 'low').length,
    total: findings.length,
  };

  return {
    requestedUrl,
    finalUrl,
    auditedAt: new Date().toISOString(),
    httpStatus,
    responseTimeMs,
    score,
    grade: gradeFor(score),
    summary,
    metadata: {
      title,
      description,
      canonical: canonical || '',
      openGraphTitle: metadata['og:title'] || '',
      openGraphDescription: metadata['og:description'] || '',
      openGraphImage: metadata['og:image'] || '',
      language: htmlAttrs.lang || '',
      h1Count,
      imageCount: images.length,
    },
    findings,
  };
}
