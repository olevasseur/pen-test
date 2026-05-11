# Reachability Snapshot

Campaign:
Target:
Environment:
Snapshot time:

## Scope

- Money-moving path:
- Relevant queues:
- Relevant side-effect worker:
- Expected attacker-controlled trigger:
- Safety stance:

## Deployment Topology

- worker/task count:
- consumer count per relevant queue:
- prefetch/concurrency settings:
- queue retry/redelivery behavior:
- duplicate messages can exist: yes/no/inconclusive
- current topology serializes the race: yes/no/inconclusive
- topology change that would make the race reachable:

## External Trigger Reachability

- attacker can externally produce duplicate events: yes/no/inconclusive
- attacker capability required:
- exact external trigger:
- buyer/merchant/provider/internal actor:
- duplicate event evidence available:
- local harness realism:

## Side-Effect Safety

- side-effect worker state: active/paused/dry-run/testnet/provider-bound/inconclusive
- staging can safely observe without money-moving side effects: yes/no/inconclusive
- safety controls found:
- safety controls missing:
- explicit approval required: yes/no

## Evidence Rules

Allowed:
- aggregate queue counts
- worker/task counts
- consumer and prefetch settings
- sanitized status classes
- local source references

Do not store:
- secrets
- auth headers
- cookies
- provider signatures
- raw provider payloads
- customer data
- wallet/deposit addresses
- transaction hashes
- production IDs
- replayable proof material

## Snapshot Decision

Choose one in `decision-gate.md`:
- Continue deep exploit proof
- Stop and write latent finding
- Do staging-readiness first
- Needs explicit approval
