# Finding Template

This template is for sanitized finding stubs only.

Do not include raw payloads, auth headers, cookies, request bodies, response bodies, webhook signatures, screenshots with sensitive data, customer PII, secrets, production object IDs, private keys, seed phrases, database dumps, or replayable PoCs.

Store private evidence outside git, for example under `/tmp/security-harness/runs/<project>`, and reference only the private run ID or tracker ID here.

## Title

Short vulnerable behavior summary.

## Severity

Critical / High / Medium / Low / Informational.

## Status

Candidate / Likely / Confirmed / Fixed / Won't Fix / Duplicate.

## Affected Surface

- Entry point:
- Code references:
- Related `.security` docs:

## Linked Invariant

- Invariant ID or checklist section:

## Impact

What an attacker or unauthorized caller can do, described without replayable exploit details.

## Preconditions

Required auth level, object state, timing condition, provider event, feature flag, or environment.

## High-Level Reproduction

Use a non-replayable summary. Put exact payloads, credentials, production IDs, screenshots, and request/response bodies in the approved private tracker or runtime evidence store.

## Root Cause

Why the code allowed the behavior.

## Suggested Fix

Concrete mitigation and any migration or rollout considerations.

## Regression Test

- Existing test:
- Proposed test:

## Private Evidence Reference

- Runtime run ID:
- Private tracker ID:
