# Trust Boundaries

This page documents what the system trusts and where that trust enters the code.

## Users And Sessions

- Entry points:
- Token/session storage:
- Verification code:
- Expiration and rotation:

Audit questions:

- Are sessions scoped to the correct tenant/account/user?
- Are expired, malformed, or revoked sessions rejected?
- Can session data be confused with admin or service credentials?

## Admin Users

- Admin entry points:
- Role/permission checks:
- Privileged state changes:

Audit questions:

- Does admin auth prove admin identity, not just a valid user token?
- Are roles or permissions enforced at the operation level?
- Are admin actions audited without logging sensitive material?

## API Keys

- Creation/rotation:
- Storage:
- Lookup:
- Scope:

Audit questions:

- Are API keys hashed or otherwise protected at rest?
- Is every API-key request scoped to the resolved owner?
- Are old keys revoked during rotation as intended?

## Provider Webhooks

- Inbound providers:
- Signature or token verification:
- Replay controls:
- Idempotency keys:

Audit questions:

- Is verification before side effects?
- Does the signature cover the intended payload?
- Are duplicate and replayed events harmless or rejected?

## Public Capability IDs

- Public capability surfaces:
- Capability format:
- Expiration:
- Revocation:

Audit questions:

- Can a capability reveal internal state beyond the public workflow?
- Is guessing/enumeration mitigated?
- Are capabilities invalidated when state changes?

## Queues

- Queue system:
- Producers:
- Consumers:
- Payload validation:

Audit questions:

- Can unauthorized producers enqueue work?
- Are payloads validated before use?
- Are retries and concurrent delivery safe?

## Databases And Caches

- Primary database:
- Cache/session stores:
- Replicas/search indexes:

Audit questions:

- Does missing cache state fail safely for sensitive paths?
- Are durable records the source of truth for money/state?
- Are cache keys scoped to tenant/account/user?

## Secrets And Signing Keys

- Secret sources:
- Rotation owner:
- Signing/verification paths:
- Deployment references:

Audit questions:

- Are secrets kept out of logs, artifacts, and `.security/`?
- Are keys rotated safely with overlap where required?
- Are old keys retired intentionally?
