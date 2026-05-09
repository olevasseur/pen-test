# `.security/AGENTS.md` - Agent Guide

Audience: AI agents and reviewers doing security-sensitive work in this repository.

## Read Order

1. Repository root agent or contributor instructions.
2. `.security/rules-of-engagement.md`.
3. `.security/attack-surface.md`.
4. `.security/trust-boundaries.md`.
5. `.security/methodology.md`.
6. Relevant files under `flows/`, `invariants/`, `webhooks/`, or `jobs/`.

## Working Rules

- Prefer facts from code over assumptions.
- Use `path/to/file.ext:LINE` for code references when available.
- Mark unknowns as audit questions.
- Keep this folder sanitized and commit-safe.
- Put raw evidence, sensitive payloads, screenshots, and exploit details in the approved private evidence location.

## Common Tasks

### Audit An Authenticated Surface

1. Locate the entry point in `attack-surface.md`.
2. Identify the principal: user, admin, API key, service account, provider, queue, or public caller.
3. Verify authentication is separate from authorization.
4. Check object ownership and permission boundaries for every caller-supplied ID.
5. Add or update regression tests for unauthorized, wrong-owner, expired, malformed, and privilege-boundary cases.

### Audit A Webhook

1. Read `methodology.md#webhook-authenticity-and-replay`.
2. Open the relevant page under `webhooks/`.
3. Confirm verification occurs before side effects.
4. Confirm duplicate and replayed events are harmless or rejected.
5. Confirm logs and artifacts do not contain secrets or sensitive payloads.

### Audit A Background Job

1. Read `jobs/README.md`.
2. Identify the queue, scheduler, cursor, lock, and retry model.
3. Confirm duplicate execution and partial failure are safe.
4. Update `attack-surface.md` when jobs or workers change.

## Findings

Use `findings/TEMPLATE.md` for sanitized drafts only. Do not commit real exploit details, credentials, raw payloads, production IDs, customer data, or replayable PoCs.
