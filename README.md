# Launch QA Acceptance Oracle

Give an AI agent an independent, deterministic answer to a simple question: **is this public launch page ready under the policy I supplied?**

The Actor makes one bounded HTML request per URL, runs fixed QA checks, and returns both the original scored audit and an optional acceptance verdict. It is designed to work as a narrowly scoped tool through the Apify MCP server.

## What it checks

- HTTP delivery and redirect outcome
- title, meta description, canonical URL, mobile viewport, and language
- Open Graph and Twitter/X preview metadata
- H1 structure, image alt text, favicon, and basic structured data
- unfinished placeholder copy and mixed-content risk

Each result keeps the legacy 0–100 score, grade, severity summary, metadata, and findings. It also exposes stable check IDs and content evidence.

## Audit-only input

Omit `acceptance` to preserve the original audit workflow:

```json
{
  "urls": ["https://example.com"],
  "timeoutSeconds": 15
}
```

The result uses `mode: "audit"` and `verdict: "not-evaluated"`. No pass/fail decision is implied.

## Acceptance input for AI agents

Supply `acceptance` when an agent needs a machine-readable gate:

```json
{
  "urls": ["https://example.com"],
  "timeoutSeconds": 15,
  "acceptance": {
    "minimumScore": 80,
    "allowedGrades": ["A", "B"],
    "maximumFindings": {
      "high": 0,
      "total": 5
    },
    "requiredChecks": [
      "http-success",
      "title",
      "description",
      "viewport",
      "single-h1",
      "no-placeholder-copy"
    ]
  }
}
```

The result includes:

- `accepted`: one boolean for agent branching
- `verdict`: `pass`, `fail`, or `error`
- `criteria`: every evaluated rule with expected, actual, and evidence
- `failedCriteria`: stable IDs for the rules that failed
- `checks`: the fixed page checks and their observations
- `evidence`: contract/analyzer versions, final URL, status, content size and SHA-256, redirects, and evaluation time

Fetch or safety failures return `verdict: "error"`, never an ordinary failing grade disguised as a completed audit.
Acceptance mode also requires the final page URL to use HTTPS; HTTP remains available for audit-only diagnostics.

## Closed-loop agent workflow

1. A coding agent changes a page it is authorized to edit.
2. The agent calls `relaunch_dept/launch-qa-auditor` through the Apify MCP server with an explicit acceptance policy.
3. The Actor independently fetches the public page and returns `accepted` plus observable evidence.
4. If the verdict is `fail`, the agent uses `failedCriteria` and findings to make a targeted correction.
5. The agent calls the Actor once more only when a retry is authorized.

This separation prevents the same agent that wrote the page from declaring success without an external check.

## Stable check IDs

`http-success`, `title`, `description`, `viewport`, `language`, `single-h1`, `canonical`, `open-graph`, `image-alt`, `no-placeholder-copy`, and `no-mixed-content`.

## Local verification

```powershell
npm.cmd test
node --check src\analyze.js
node --check src\fetch-public-page.js
node --check src\oracle.js
node --check src\main.js
```

The fetch tests inject DNS and HTTP responses. They make zero network requests and cover private/reserved addresses, IPv4-mapped IPv6, mixed DNS answers, redirect revalidation, response limits, content type, and timeout errors.

## Safety and limits

Use this Actor only on public pages you own or are authorized to inspect. It:

- accepts at most ten HTTP(S) URLs and never accepts URL credentials;
- resolves and rejects private, reserved, local, documentation, multicast, mapped, and transition addresses;
- revalidates every redirect and follows at most five;
- reads at most 2 MB of HTML per page with a 5–30 second timeout;
- never logs in, submits forms, bypasses access controls, or crawls a site.

Each connection is pinned to the public DNS answers validated immediately before the request, and redirects are resolved and pinned again. This is still a bounded public-page utility rather than a complete network-isolation boundary; run it without access to sensitive internal networks.

## What it does not prove

The Actor inspects one server-returned HTML response. It does not render JavaScript, test interactions or visual layout, take screenshots, certify accessibility, perform a security audit, provide legal advice, or guarantee search rankings. Response time is evidence only and is not an acceptance criterion.

## AI disclosure

This Actor was developed with AI assistance. Its verdict is produced by transparent, deterministic rules. Review findings before acting on them.
