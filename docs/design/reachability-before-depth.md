# Reachability Before Depth

## Purpose

Money-moving queue and worker race campaigns must take a deployment reachability snapshot before investing deeply in downstream local exploit chains.

Local exploit depth is useful only after the campaign can explain how the deployed system could exercise the race class. A race-prone code path may be high impact, but if the current worker topology serializes the relevant messages, the campaign should record a latent finding and move to the next highest-value question.

This methodology is for exploit research and pen-test evidence. It is not an application remediation guide, and agents must not default to implementing application fixes in the target repository.

## Required Early Snapshot

Before deep local exploit chaining, capture a sanitized deployment reachability snapshot for each relevant queue and side-effect worker:

- worker/task count
- consumer count per relevant queue
- prefetch/concurrency settings
- queue retry/redelivery behavior
- whether duplicate messages can exist
- whether the attacker can externally produce duplicate events
- whether the side-effect worker is active, paused, dry-run, testnet, or provider-bound
- whether staging can safely observe the condition without executing money-moving side effects
- whether current topology serializes the race
- what topology change would make the race reachable

Do not store secrets, raw provider payloads, signatures, auth headers, cookies, wallet addresses, transaction hashes, production IDs, or customer data in this snapshot.

## Decision Gate

Every money-moving queue/worker race campaign should choose exactly one early decision:

1. **Continue deep exploit proof**

   Topology supports concurrency or external reachability is plausible enough. Local exploit depth is justified.

2. **Stop and write latent finding**

   Code is race-prone, but current deployed topology serializes the race. Record "high impact if topology changes/scales" and move on.

3. **Do staging-readiness first**

   Local proof exists but staging safety controls are unknown. Inspect worker topology and money-moving safety controls before more local depth.

4. **Needs explicit approval**

   Only provider-bound or real-funds validation would answer the question. Stop until approval and safety controls are explicit.

## Staging Stance

Staging is allowed, but gated. It is not forbidden by default.

For money-moving races, staging probes require explicit evidence that the test is bounded and cannot execute unsafe provider-bound side effects. Acceptable controls include a paused side-effect worker, isolated queues, dry-run mode, testnet-only behavior, harmless wallets/providers, or explicit approval for the exact validation path.

## Evidence Interpretation

Reports must distinguish:

- **Local proof:** exploit behavior reproduced in local code/tests or stubs.
- **External reachability:** an attacker-controlled or naturally external trigger can create the needed duplicate event/message.
- **Deployed topology:** the currently deployed worker, queue, retry, and side-effect configuration can actually exercise or serialize the race.

Do not upgrade a local proof to externally reachable severity until the campaign has deployment evidence or a safe staging validation.

## Sanitized Example

Classification example:

> Local duplicate-settlement exploit chain confirmed. Current staging worker topology has one worker and prefetch(1), which likely serializes the split-deposit trigger. Classify as high local proof-of-risk with external reachability inconclusive/lower under current topology. Do not spend more time deepening downstream impact until topology or staging controls make reachability testable.

This example is intentionally sanitized. It contains no endpoints, secrets, object IDs, addresses, transaction hashes, provider payloads, or raw logs.
