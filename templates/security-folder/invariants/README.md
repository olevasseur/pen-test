# Security Invariants

Use this directory for stable rules that reviewers and findings can cite.

Suggested format:

```text
# <Invariant Group>

Use these IDs when touching <scope>.

## AUTH-1: Authentication Is Not Authorization

Short rule and rationale.
```

Suggested invariant groups:

- `AUTH-*`: authentication, authorization, sessions, API keys, permissions
- `DATA-*`: tenant isolation, PII handling, data minimization
- `STATE-*`: state transitions, idempotency, retries
- `MONEY-*`: amounts, credits, payments, balances, settlement
- `WEBHOOK-*`: signature verification, replay, duplicate delivery
- `OPS-*`: environment gates, secrets, deployment safety

Invariants should be concise, testable, and reusable across reviews.
