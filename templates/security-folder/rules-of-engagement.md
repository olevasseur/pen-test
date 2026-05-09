# Rules Of Engagement

This document defines authorized testing scope, target restrictions, evidence handling, and escalation requirements for this project.

## Authorization

- Authorized owner:
- Authorization source or ticket:
- Effective date:
- Expiration or review date:
- Scope summary:

## Authorized Environments

| Environment | Purpose | Authorized? | Notes |
|---|---|---|---|
| Development | Local or isolated testing | TBD | |
| Staging | Pre-production testing | TBD | |
| Production | Live environment | TBD | Requires explicit production gates. |

## Allowed Targets

| Environment | URL or Host | Purpose | Notes |
|---|---|---|---|
| staging | `https://replace-with-staging-host.example` | Application/API | Placeholder only. |
| production | `https://replace-with-production-host.example` | Application/API | Placeholder only; requires explicit approval. |

## Forbidden Targets

| URL or Host | Reason |
|---|---|
| `https://replace-with-forbidden-host.example` | Placeholder. |

## Allowed Testing

- Static code review.
- Passive route and configuration inventory.
- Non-mutating authentication and authorization checks against authorized non-production targets.
- Input validation checks that do not create lasting state.
- Replay/idempotency review using controlled non-sensitive fixtures.

## Mini-Plan Required Before Testing

- Any production test.
- Any test that may change persistent state.
- Any test involving money, credits, inventory, entitlements, or irreversible side effects.
- Any test expected to trigger alerts, fraud/risk review, rate limits, or provider callbacks.
- Any test using third-party provider APIs.

## Disallowed Testing

- Volumetric denial-of-service, brute force, credential stuffing, or load testing.
- Testing against real customer accounts without explicit written approval.
- Exfiltrating secrets, customer data, full database dumps, or private keys.
- Irreversible state changes outside approved test resources.
- Storing raw sensitive evidence in git.

## Evidence Handling

- Store private runtime evidence outside git, for example `/tmp/security-harness/runs/<project>`.
- Commit only sanitized summaries, drift notes, code references, and regression test names.
- Redact tokens, cookies, auth headers, API keys, signing material, private keys, seed phrases, PII, and provider credentials.
- Use private tracker IDs or runtime run IDs instead of embedding raw evidence.

## Production Testing Requirements

Production testing requires all of the following:

- Written authorization or ticket:
- Explicit production flag in tooling:
- Explicit evidence level:
- Approved target:
- Scope and stop conditions:
- Impact cap if money, credits, inventory, or customer-visible state may be affected:
- Named rollback or recovery owner:

No raw production evidence may be written to `.security/`.
