# Launch QA Auditor

Catch expensive public-page mistakes before a launch goes live. This Apify Actor audits up to ten public HTTP(S) pages and returns a prioritized, exportable report covering:

- HTTP delivery and redirect outcome
- title, meta description, canonical URL, mobile viewport, and language
- Open Graph and Twitter/X preview metadata
- H1 structure, image alt text, favicon, and basic structured data
- unfinished placeholder copy and mixed-content risk

Each result includes a 0–100 launch score, grade, severity summary, metadata snapshot, and actionable findings.

## Input

```json
{
  "urls": ["https://example.com"],
  "timeoutSeconds": 15
}
```

## Output

One dataset item is produced per requested page. The paid version uses the `page-audited` pay-per-event event so users can set a maximum run cost and pay only for pages that produce a result.

## Want a human repair plan?

The report tells you what is leaking. RELAUNCH DEPT. can turn the findings into concrete launch copy and page decisions:

- **$59 / 24-hour Landing Page Teardown:** rewritten hero, three stronger calls to action, and annotated screenshots delivered by email.
- **$249 / 48-hour Launch Rescue:** positioning, a production-ready hero, launch visuals, reusable copy, and distribution support.

[See the exact scope and one-time pricing](https://www.daradigu.com/?utm_source=apify&utm_medium=marketplace&utm_campaign=launch_qa_auditor#offers). No subscription or discovery call is required.

## Safety and limits

Use this Actor only on public pages you own or are authorized to inspect. It performs one bounded HTML request per URL, follows at most five validated redirects, blocks private/reserved network addresses and URLs containing credentials, accepts no more than 2 MB per page, and never logs in or bypasses access controls.

## AI disclosure

This Actor was developed with AI assistance. Its output is deterministic rules-based analysis, not legal, security, accessibility-certification, or search-ranking advice. Review findings before acting on them.
