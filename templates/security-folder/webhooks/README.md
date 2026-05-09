# Webhook Maps

Create one sanitized page per inbound or outbound webhook integration.

Suggested sections:

```text
# <Webhook Name>

## Entry Points

## Verification

## Payload Trust Boundary

## Side Effects

## Replay And Idempotency

## Logging And Evidence Rules

## Related Tests
```

Checklist:

- Verify before side effects.
- Compare secrets/signatures safely.
- Bind signatures to the intended payload.
- Reject or safely ignore replays.
- Make duplicate delivery harmless.
- Log minimal sanitized metadata only.
- Keep provider secrets and raw payloads out of git.
