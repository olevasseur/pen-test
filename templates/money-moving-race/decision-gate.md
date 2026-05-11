# Reachability Before Depth Decision Gate

Campaign:
Snapshot file:
Decision:

## Decision Options

### 1. Continue deep exploit proof

Use when:
- topology supports concurrency or reachability is plausible enough;
- duplicate messages can exist or attacker-controlled duplicate events are realistic;
- staging safety controls are sufficient for planned observation, or local-only depth is clearly justified.

Required note:
- Explain why more local exploit depth is worth the time before staging reachability is proven.

### 2. Stop and write latent finding

Use when:
- code is race-prone;
- current deployed topology serializes the race;
- external trigger is unavailable or implausible under current deployment;
- impact would become high/critical if worker count, consumer count, prefetch, retry, or provider delivery behavior changes.

Required note:
- Record "high impact if topology changes/scales" and move on.

### 3. Do staging-readiness first

Use when:
- local proof exists;
- staging safety controls are unknown;
- side-effect worker may be active, provider-bound, mainnet-mode, or otherwise unsafe;
- more local downstream proof will not answer external reachability.

Required note:
- List missing safety controls and topology facts before any live staging trigger.

### 4. Needs explicit approval

Use when:
- only provider-bound validation, real-funds behavior, or mutation-adjacent replay would answer the question;
- safe dry-run/testnet/paused-worker controls are unavailable;
- authorization scope must be clarified.

Required note:
- State the exact approval and safety controls required.

## Required Classification Fields

- local proof: confirmed/not-confirmed/inconclusive
- external reachability: yes/no/inconclusive
- deployed topology: supports-race/serializes-race/inconclusive
- staging allowed but gated: yes/no
- application fix attempted: must be no unless explicitly requested
- next action:

## Sanitized Example

Local duplicate-settlement exploit chain confirmed. Current staging worker topology has one worker and prefetch(1), which likely serializes the split-deposit trigger. Classify as high local proof-of-risk with external reachability inconclusive/lower under current topology. Do not spend more time deepening downstream impact until topology or staging controls make reachability testable.
