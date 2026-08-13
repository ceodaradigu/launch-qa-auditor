import { Actor, log } from 'apify';
import { analyzeHtml } from './analyze.js';
import { fetchPublicPage } from './fetch-public-page.js';
import { normalizeAcceptance } from './oracle.js';
import { resultForAudit, resultForError, safeErrorMessage, sanitizeUrlForOutput } from './result.js';

await Actor.main(async () => {
  const input = await Actor.getInput() || {};
  if (!Array.isArray(input.urls)) throw new Error('urls must be an array.');
  const urls = [...new Set(input.urls.map((value) => String(value).trim()).filter(Boolean))].slice(0, 10);
  const timeoutSeconds = Math.min(30, Math.max(5, Number(input.timeoutSeconds) || 15));
  const acceptance = normalizeAcceptance(input.acceptance);
  if (!urls.length) throw new Error('Provide at least one public HTTP(S) URL.');

  for (const requestedUrl of urls) {
    try {
      const page = await fetchPublicPage(requestedUrl, { timeoutSeconds });
      const audit = analyzeHtml(page.html, {
        requestedUrl,
        ...page,
        auditedAt: new Date().toISOString(),
      });
      const result = resultForAudit(audit, page, acceptance);
      const charge = await Actor.pushData(result, 'page-audited');
      const acceptanceNote = acceptance ? `; acceptance ${result.verdict.toUpperCase()}` : '';
      log.info(`Audited ${sanitizeUrlForOutput(requestedUrl)}: ${result.grade} (${result.score}/100)${acceptanceNote}`);
      if (charge?.eventChargeLimitReached) {
        log.info('Run spending limit reached; stopping cleanly.');
        break;
      }
    } catch (error) {
      const result = resultForError(requestedUrl, error, acceptance);
      await Actor.pushData(result);
      log.warning(`Could not audit ${sanitizeUrlForOutput(requestedUrl)}: ${safeErrorMessage(error)}`);
    }
  }
});
