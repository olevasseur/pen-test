# Audit Methodology

Use this file as a checklist library for security reviews. Add project-specific prompts as the system evolves.

## Authorization And Object Ownership

- Authentication identifies a caller; it does not authorize arbitrary object IDs.
- Every caller-supplied ID must be scoped to the authenticated principal, organization, tenant, account, or approved capability.
- Admin-only operations must prove admin semantics and required privileges.
- Public routes must expose only data needed for the public workflow.

Review prompts:

```text
findUnique
findFirst
id:
tenantId
organizationId
accountId
userId
adminId
```

## API Keys, JWTs, And Session Boundaries

- API keys should be scoped to exactly one tenant/account and stored hashed where practical.
- New plaintext API keys should only be returned at creation or rotation time.
- JWT/session verification must enforce expiration, issuer/audience where relevant, and allowed algorithms.
- Refresh tokens must not be accepted as access tokens unless explicitly designed.
- Sensitive comparisons should use timing-safe logic where practical.

## Webhook Authenticity And Replay

- Verify signatures, validation tokens, or mTLS before parsing into side effects.
- Prefer raw-body verification or document canonicalization.
- Compare signatures safely.
- Enforce timestamp, nonce, event ID, transaction ID, or durable idempotency controls where available.
- Duplicate valid events must be harmless under retries and concurrency.

## Money Movement And State Transitions

- Transactional rows or durable events should be the source of truth for balances, credits, inventory, or settlement.
- Final states must not be overwritten by stale provider events or retried workers.
- Ambiguous external transfer results should remain pending/manual-review until reconciled.
- Rollbacks must be complete or move to durable recoverable state.

## Amount Precision And Bounds

- Validate amounts server-side at entry or service boundaries.
- Reject negative values, invalid zero values, unsafe integers, `NaN`, `Infinity`, scientific notation surprises, and impossible decimal precision.
- Avoid floating point for money, credits, token amounts, thresholds, or fees.
- Snapshot prices, fees, thresholds, and accepted payment rules where in-flight operations depend on them.

## Provider Request Safety

- Do not log raw provider request configs, auth headers, tokens, secrets, customer documents, or full sensitive payloads.
- Sanitize provider errors before returning them to callers or writing artifacts.
- Verify retry semantics cannot duplicate money movement or persistent side effects.
- Preserve ambiguous provider states for manual recovery.

## Background Job Safety

- Jobs should be safe under duplicate execution unless infrastructure proves mutual exclusion.
- Queue delivery should be treated as at-least-once.
- Cursors and "last processed" markers must advance atomically with completed work.
- Missing cursors should fail closed or do bounded reconciliation.
- Jobs that enqueue work need idempotency per source row/event.

## Environment Gates

- Debug features, test bypasses, admin consoles, and provider sandboxes must be impossible to enable accidentally in production.
- Environment variables and deployment settings should be reviewed together.
- Any `test`, `dev`, or `local` bypass needs an explicit production-safety check.
