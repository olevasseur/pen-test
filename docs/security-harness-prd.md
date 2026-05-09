# PRD: Minimal Reusable Security Harness With Cheddar Adapter

## Goal

Build a small but solid security testing harness that we can use immediately for the Cheddar staging review, while keeping the architecture modular enough to reuse and extend later.

This should take about 1 day to get useful, not 1 week.

## Core Principles

- Useful immediately
- Safe by default
- Staging-only unless explicitly overridden
- No secrets in logs, ledgers, committed files, or artifacts
- Every test writes to a ledger
- Modules are easy to add
- Project-specific behavior lives in adapters/profiles
- Cheddar-specific behavior lives only in the Cheddar adapter/profile
- Avoid overbuilding orchestration, UI, or generic scanner features

## Repository And Runtime Locations

The harness source code should live in the dedicated `pen-test` repository:

```text
/Users/olivier-ludex/repos/pen-test
```

Runtime data should not be committed. Generated ledgers, artifacts, and findings should live outside git by default:

```text
/tmp/security-harness/runs/<project>
```

Cheddar-specific runtime data/artifacts should live under:

```text
/tmp/security-harness/runs/cheddar
```

The repository should include a `.gitignore` that excludes at least:

```text
node_modules/
dist/
runs/
*.log
.env
.env.*
```

Do not commit copied staging artifacts from `/tmp`, real ledgers, generated findings with sensitive evidence, credentials, cookies, request headers, private keys, API keys, database URLs, or environment files.

## Architecture

```text
/Users/olivier-ludex/repos/pen-test
  package.json
  README.md
  docs/
    security-harness-prd.md
  src/
    cli/
    core/
      artifactStore.ts
      config.ts
      ledger.ts
      redaction.ts
      targetGuard.ts
      moduleRunner.ts
      types.ts
    modules/
      staticRouteInventory.ts
      httpNegativeAuth.ts
    adapters/
      cheddar/
        profile.ts
        seedHistory.ts
        modules/
          cheddarWebhookNegative.ts
          cheddarPublicCheckoutExposure.ts

/tmp/security-harness
  runs/
    cheddar/
      ledger.jsonl
      artifacts/
      findings/
```

Use TypeScript or modern Node.js.

SQLite is nice, but JSONL is fine for the first version.

## CLI

Implement:

```bash
sec-harness init --project cheddar
sec-harness list --project cheddar
sec-harness run --project cheddar --module route-inventory
sec-harness run --project cheddar --module webhook-negative
sec-harness run --project cheddar --module checkout-exposure-summary
sec-harness status --project cheddar
sec-harness report --project cheddar
```

Optional if quick:

```bash
sec-harness run --project cheddar --suite baseline
```

## Core Features

### Ledger

Append-only JSONL is acceptable.

Each entry should include:

- id
- project
- module
- title
- hypothesis
- status: `passed | finding | blocked | error | skipped`
- severityGuess: `critical | high | medium | low | info | none`
- confidence: `confirmed | likely | candidate | unknown`
- startedAt
- finishedAt
- target
- sanitizedSummary
- artifactPaths
- nextSteps

### Artifacts

Write sanitized artifacts outside git under:

```text
/tmp/security-harness/runs/<project>/artifacts/<date>/<module>/<run-id>/
```

For Cheddar:

```text
/tmp/security-harness/runs/cheddar/artifacts/<date>/<module>/<run-id>/
```

### Redaction

Shared redaction utility.

Redact common sensitive keys/values:

- authorization
- cookie
- apiKey
- token
- secret
- signature
- mnemonic
- privateKey
- password
- databaseUrl
- DATABASE_URL
- PEPPER
- AWS credentials
- sessionKey
- validation key

Hash UUIDs and long hex strings in summaries where practical.

Do not hash ledger IDs or artifact paths unless there is a specific reason; those are needed for traceability.

### Target Guard

All HTTP modules must call the target guard.

For Cheddar:

Allowed:

- `https://staging-api-aws.cheddar.biz`
- `https://staging.cheddar.biz`
- `https://staging-admin.cheddar.biz`
- `https://staging-checkout.cheddar.biz`

Forbidden:

- production-looking hosts
- `https://staging-api.cheddar.biz`

If a module tries the old staging API host, fail with a clear message that it is the legacy/wrong Heroku endpoint.

## Initial Cheddar Adapter

### Profile

Cheddar profile should define:

- repo path: `/Users/olivier-ludex/repos/cheddar`
- current staging API: `https://staging-api-aws.cheddar.biz`
- forbidden legacy staging API: `https://staging-api.cheddar.biz`
- runtime artifact path: `/tmp/security-harness/runs/cheddar/artifacts`
- runtime finding path: `/tmp/security-harness/runs/cheddar/findings`
- finding template path: `.security/findings/TEMPLATE.md`
- relevant security docs path: `.security`

### Seed History

Seed the ledger with existing known work:

1. Batch 1 API-key org scoping:
   - status: passed
   - no issue found in tested matrix
   - artifact reference: `/tmp/cheddar-security-batch1-api-key-org-scope-aws-20260508T234100Z.json`
2. Batch 2 public checkout session exposure:
   - status: finding
   - severity guess: medium
   - summary: public session read endpoints expose raw internal session fields including derivation-path and risk data
   - artifact reference: `/tmp/cheddar-security-public-checkout-exposure-aws-20260509T003537Z.json`
   - finding draft reference: `/tmp/cheddar-finding-public-checkout-session-exposes-internal-fields.md`
3. Batch 3 webhook negative auth:
   - status: passed
   - all simple bad/missing auth probes returned 401
   - artifact reference: `/tmp/cheddar-webhook-auth-negative-20260509T015924Z.txt`
   - blocked next step: signed stale/replay checks need AWS auth or provider test signing material

The seed entries may reference existing `/tmp` artifacts by path, but must not copy their raw contents into the repository.

## Module 1: Static Route Inventory

Scan Cheddar repo:

- `api/src/index.ts`
- `api/src/rest/**`
- `api/src/graphql/**`

Output route inventory with:

- method/path when available
- file
- rough surface: `public | admin | api-key | provider-webhook | unknown`
- auth middleware hints if obvious

Write artifact and ledger entry.

## Module 2: Cheddar Webhook Negative Auth

Run safe staging probes:

- `POST /coinflow` missing Authorization
- `POST /coinflow` wrong Authorization
- `POST /crypto-data` missing signature
- `POST /crypto-data` wrong signature
- `POST /quicknode/sol/streams` wrong signature
- `POST /quicknode/btc/streams` wrong signature

Expected: all 401.

Store only:

- label
- method
- path
- status
- expected status
- pass/fail

Do not store full request bodies, request headers, response bodies, cookies, or secrets.

## Module 3: Public Checkout Exposure Summary

For now, do not recreate DB fixtures.

Read the existing Batch 2 artifact from `/tmp` if present and produce a normalized finding summary in the new ledger/report format.

Later this module can become a dynamic re-test.

## Reporting

`sec-harness report --project cheddar` should show:

- confirmed findings
- passed checks
- blocked checks
- recommended next checks

It should clearly say:

- no High confirmed yet
- one Medium candidate/confirmed finding: public checkout session raw field exposure
- webhook replay/freshness still pending

## Acceptance Criteria

- Tool source lives in `/Users/olivier-ludex/repos/pen-test`
- Runtime data lives under `/tmp/security-harness/runs/<project>`
- Tool initializes cleanly
- Ledger is seeded
- Route inventory module runs
- Webhook negative module runs against AWS staging only
- Report shows current state accurately
- No secrets are printed, stored in repo, or stored in artifacts
- Forbidden host guard is covered by a simple test or demo command
- Code is organized so adding modules later does not require rewriting the core
- `.gitignore` prevents committing generated ledgers, artifacts, builds, dependencies, logs, and env files
