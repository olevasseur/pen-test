# Flow Guides

Create one sanitized markdown file per sensitive business or technical flow.

Suggested sections:

```text
# <Flow Name>

## Entry Points

## Trust Boundary

## Sensitive State

## Invariants

## Things To Verify

## Tests To Run Or Add

## Open Audit Questions
```

Good candidates:

- account creation and login
- admin actions
- payment or credit flows
- entitlement changes
- file upload/download
- provider integration flows
- public capability flows

Keep flow docs practical: entry points, trust boundary, side effects, invariants, and tests. Do not include raw evidence or replayable exploit details.
