# Webhook Replay and Freshness Coverage Design

## Purpose

Design a future reusable harness module that covers the security-review invariant:

> Webhook receivers must reject stale, replayed, or otherwise expired signed events.

This document is intentionally design-only. It does not add live probes, production testing, provider-specific payloads, secrets, replayable proofs of concept, or target-private evidence. Cheddar may use this module through an adapter later, but the design is generic for any target repo with a sanitized `.security/` map.

## Invariant Scope

The future module should evaluate whether webhook receivers reject events that should no longer be trusted. Coverage should be reported per webhook surface where the target adapter or `.security/` docs identify a safe test route.

The intended checks are:

- **Replayed event rejected:** the same signed event or delivery identifier cannot be accepted more than once, when the provider contract includes a replay identifier.
- **Stale timestamp rejected:** an otherwise well-formed signed event with a timestamp older than the allowed tolerance is rejected.
- **Missing timestamp rejected:** a signed-event envelope with no timestamp is rejected.
- **Malformed timestamp rejected:** unparsable, non-integer, negative, or out-of-range timestamp values are rejected.
- **Timestamp outside tolerance rejected:** future-skewed or past-skewed timestamps outside the documented tolerance are rejected.
- **Duplicated delivery ID rejected, if applicable:** duplicate provider delivery IDs are rejected or idempotently ignored according to the documented provider contract.

The module should distinguish "not tested", "not applicable", "blocked", and "finding candidate". Lack of evidence must never be reported as secure behavior.

## Evidence Level and Safety Classification

Recommended initial metadata for a future module:

```text
id: webhook-replay-freshness
title: Webhook Replay and Freshness Coverage
safety_level: http_safe
evidence_levels_supported:
  - observe_only
  - non_mutating_probe
requires_credentials: false by default
production_allowed: false
destructive: false
money_impact_possible: true unless the adapter proves the configured fixture cannot trigger state changes
requires_authorization_ticket: true for any production use
```

The first implementation should support `observe_only` only. It can inspect `.security/` docs, module configuration, synthetic local fixtures, and adapter metadata without network access.

A later staging implementation may support `non_mutating_probe` only when all of these are true:

- the target is staging or another rules-of-engagement approved non-production environment;
- the adapter identifies explicit safe webhook test routes or fixtures;
- the request body is synthetic and non-replayable against real providers;
- the module stores only sanitized summaries in the ledger;
- raw request and response material, if ever needed, stays under `/tmp/security-harness/runs/<project>` with redaction metadata.

Do not add production support until there is a separate design and implementation review. Production would require `production_allowed=true`, explicit CLI production flags, a written authorization ticket, an evidence level, impact caps when money movement is possible, and rules-of-engagement approval.

## Safe Staging Test Categories

### Pure Local Fixture Validation

Safe for the first implementation slice.

The module can use synthetic provider-agnostic fixtures to validate local timestamp parsing and decision logic. These fixtures must not include real signatures, provider secrets, customer identifiers, production object IDs, captured request bodies, or replayable payloads.

Examples of safe local cases:

- current timestamp within tolerance;
- timestamp older than tolerance;
- timestamp too far in the future;
- missing timestamp field;
- malformed timestamp values;
- duplicate synthetic delivery ID in an in-memory test fixture.

### Non-Mutating HTTP Negative Tests

Potentially safe in staging later, but not in the first slice.

These tests would send synthetic invalid or expired signed-event envelopes to adapter-approved staging webhook routes. The expected outcome is rejection before provider-specific processing or state mutation. The adapter must prove the route and fixture are safe enough for `non_mutating_probe`.

The module should store only:

- label;
- method;
- sanitized path or route key;
- status;
- expected status;
- pass/fail;
- sanitized rejection summary if safe.

It must not store full request bodies, full response bodies, auth headers, cookies, webhook signatures, provider secrets, or replayable payloads.

### Mutation-Adjacent Webhook Delivery Attempts

Not part of the first implementation.

Webhook receivers often sit near state changes, money movement, account changes, provider synchronization, or background jobs. Even negative tests can be mutation-adjacent if a malformed request reaches application logic. These checks require a stricter adapter safety proof and may need isolated test accounts, idempotency controls, and impact caps.

### Tests Requiring Real Provider Secrets or Real Payloads

Out of scope until separately approved.

Real provider secrets, captured provider payloads, real delivery IDs, production object IDs, and real signatures must not be committed to this repo or written into `.security/`. If a future authorized test needs private evidence, it belongs only in the runtime evidence store under `/tmp/security-harness/runs/<project>`.

## Behavior Not To Implement Yet

Do not implement any of the following in the next slice:

- replaying real production webhook payloads;
- storing provider secrets in the repo, `.security/`, ledger summaries, reports, or exports;
- committing captured webhook bodies;
- committing auth headers, cookies, signatures, screenshots, customer data, production IDs, or replayable proofs of concept;
- enabling production testing;
- setting `production_allowed=true`;
- sending money-impacting checkout, payment, refund, settlement, account-credit, account-debit, or provider-sync events;
- bypassing adapter target guards or rules-of-engagement parsing;
- writing generated findings to target `.security/` from this module;
- treating "not yet observed" as "secure".

## Sanitized `.security/` Documentation

Target repos should maintain sanitized webhook trust docs before live testing. The harness may read these docs, but should not require target-private details in the reusable repo.

Recommended target-repo files and section outlines:

### `.security/invariants/webhook-trust.md`

- Invariant summary
- Trusted webhook providers, using generic or approved sanitized names
- Signature verification requirements
- Timestamp freshness tolerance
- Replay and duplicate-delivery expectations
- Idempotency behavior
- State-change and money-impact notes
- Known safe test constraints
- Runtime evidence handling rules

### `.security/flows/webhooks.md`

- Webhook receive flow
- Verification order
- Rejection behavior before state mutation
- Queue/job handoff behavior
- Retry behavior
- Idempotency and duplicate handling
- Safe staging test accounts or fixture notes, if sanitized

### `.security/methodology/webhook-negative-testing.md`

- Allowed negative test classes
- Mini-plan-required test classes
- Disallowed test classes
- Approved environments
- Evidence handling rules
- Required authorization for mutation-adjacent or production checks
- Sanitized reporting expectations

If a target repo uses a different `.security/` layout, the adapter should map its docs into generic categories without copying private content into this repo.

## Future Module API

Proposed module id:

```text
webhook-replay-freshness
```

Proposed configuration inputs:

- target environment, resolved through the existing target guard;
- target repo path, for `.security/` docs;
- evidence level;
- route keys or webhook surface IDs from adapter metadata;
- provider-agnostic timestamp tolerance, preferably derived from `.security/` or adapter config;
- optional safe fixture names, not raw payloads;
- optional runtime-only credential reference for a later approved staging probe, never a secret value.

Proposed output:

- one ledger entry per module run;
- sanitized artifact containing only case labels, route keys, outcomes, expected rejection class, and artifact references;
- linked `.security` docs;
- blocked status when safe fixtures, safe routes, or authorization are missing;
- finding candidate only when an approved safe test reaches a clear unexpected accept path.

## Synthetic Fixtures

Fixtures must be synthetic, generic, and non-replayable. They should use placeholder values such as:

```json
{
  "event_type": "example.webhook.test",
  "delivery_id": "synthetic-delivery-001",
  "created_at": "2000-01-01T00:00:00Z",
  "data": {
    "object_id": "synthetic-object-001"
  }
}
```

Fixture rules:

- no real provider names unless they are public generic examples;
- no real signatures;
- no real signing secrets;
- no real request or response bodies;
- no production IDs;
- no customer or account data;
- no payloads that could trigger real money movement or account state changes;
- no provider-specific replayable proof of concept.

Local helper tests can generate timestamps relative to a fixed test clock so results are deterministic.

## First Implementation Slice

The smallest safe next slice should be:

1. Add module skeleton and metadata for `webhook-replay-freshness`.
2. Mark it `production_allowed=false`.
3. Support `observe_only` only.
4. Add synthetic local timestamp parsing and tolerance helper tests.
5. Add read-only suggestion/listing integration so the existing suggestion no longer says the module is missing once the skeleton exists.
6. Return `blocked` or `skipped` for live target probing with a clear message that HTTP replay/freshness probes are not implemented yet.

Do not send HTTP requests in the first slice.

## Review Checklist Before Live Probing

Before any `non_mutating_probe` implementation, require:

- adapter-approved staging route keys;
- rules-of-engagement coverage for the target environment;
- documented freshness tolerance;
- proof that synthetic invalid events reject before state mutation;
- redaction tests for all stored summaries and artifacts;
- no raw payload storage in `.security/`, reports, exports, or ledger summaries;
- tests proving production gates cannot be bypassed;
- tests proving mutation-adjacent cases are blocked without explicit approval.
