# Product Scope: Security Review and Exploit-Proof Harness

## Product Statement

`pen-test` is a safety-first security review and exploit-proof harness for authorized owned systems.

The harness must help teams move from review findings to controlled proof. Static review, inventory, suggestions, and review plans are useful inputs, but they are not enough on their own. The product must support authorized real exploit attempts against owned applications when scope, authorization, impact caps, evidence handling, and target guards are explicit.

## Core Requirement

The harness must support real exploit/proof-of-exploit modules, not just passive scanning.

Exploit-proof modules should be deterministic, bounded, auditable, and reusable. They should attempt to prove exploitability where possible while keeping the safety model enforceable:

- default to staging or another explicitly allowed non-production environment;
- require target guards and rules-of-engagement checks;
- record structured proof evidence;
- keep sensitive runtime evidence outside git;
- support production only through explicit authorization gates and module metadata.

## Non-Goal

The tool must not become an uncontrolled autonomous hacking bot against arbitrary third-party systems.

It is for authorized owned systems, approved environments, scoped test accounts, controlled fixtures, and documented proof strategies. It should not perform broad internet scanning, opportunistic exploitation, stealth behavior, credential attacks against third parties, volumetric denial-of-service, or unsupervised production attacks.

## Operating Modes

### `review`

Inspect code, known surfaces, `.security` docs, previous evidence, ledgers, scan state, and artifacts. Generate suggestions, drift summaries, and review plans. This mode should not send HTTP requests or mutate target state.

Examples:

- `pentest suggest <project> --target-repo <path>`
- `pentest review-plan <project> --target-repo <path>`
- static inventory and `.security` drift checks

### `safe_proof`

Run bounded low-impact probes to prove specific issues where possible. Use staging, test accounts, synthetic fixtures, non-mutating requests, low-risk mutation checks, and explicit caps. Evidence may prove an issue, but the module must avoid uncontrolled side effects.

Examples:

- negative-auth checks against staging;
- stale/invalid webhook checks against approved staging fixtures;
- object-ownership probes using test-owned records;
- bounded state-transition checks that can be safely reset.

### `real_attack_proof`

Run realistic exploit attempts against authorized owned targets to prove exploitability. This mode can exercise real application behavior and may collect proof-of-exploit evidence. It must be gated, scoped, logged, and reversible where applicable.

Production use is never accidental. It requires explicit CLI flags, a written authorization ticket, module metadata support, rules-of-engagement approval, impact caps when relevant, and private runtime evidence handling.

## Proposed CLI Shape

Existing and planned command families:

```bash
pentest scan <project> <plan> --target staging --target-repo <path>
pentest suggest <project> --target-repo <path>
pentest review-plan <project> --target-repo <path>
pentest exploit <project> <module-id> --target staging --target-repo <path>
```

Future alias, if useful:

```bash
pentest attack <project> <module-id> ...
```

`exploit` should not mean "unsafe". It should mean "this module is intentionally trying to prove exploitability within approved scope." The command should make proof intent explicit and should apply stricter gates than ordinary scan/review commands.

## Module Categories

- `inventory`: find or summarize surfaces, routes, jobs, flows, or trust boundaries.
- `passive_review`: inspect code, docs, ledgers, and artifacts without live target interaction.
- `negative_auth_probe`: send bounded invalid/missing auth checks and expect rejection.
- `exploit_probe`: attempt to prove a vulnerability with controlled exploit behavior.
- `impact_probe`: verify impact-sensitive behavior such as money movement, account state, notifications, external providers, or availability under explicit caps.

## Evidence Levels

- `observe_only`: static or passive review only; no HTTP requests.
- `non_mutating_probe`: live checks expected not to mutate target state.
- `mutating_low_impact`: controlled mutation against staging or approved test resources with cleanup/reversibility notes.
- `exploit_proof_staging`: realistic exploit proof against staging or another approved non-production environment.
- `exploit_proof_production_capped`: realistic proof against production with explicit authorization, production-capable metadata, and impact caps.
- `real_attack_authorized`: highest-friction authorized attack simulation mode for owned systems only, with scope, stop conditions, private evidence handling, and human approval.

The existing implementation may not support every level yet. The architecture should make these levels explicit so future modules do not blur review, safe proof, and real exploit proof.

## Exploit Module Metadata Requirements

Every real exploit/proof module must declare:

- module id;
- category;
- target environments allowed;
- `production_allowed` true/false;
- required authorization ticket;
- required accounts, fixtures, credentials, or runtime-only credential references;
- expected impact;
- max impact cap when applicable;
- reversibility and cleanup notes;
- evidence redaction requirements;
- runtime artifact destination;
- stop conditions;
- whether it can affect money, customer data, account state, notifications, external providers, or availability.

Defaults should remain conservative:

- `production_allowed=false`;
- no production execution without explicit CLI flags;
- no credential use unless declared;
- no mutation unless declared;
- no money impact without a cap and written authorization;
- no sensitive evidence in git.

## Execution Model

Real attack/proof modules may execute realistic exploit attempts against authorized owned environments. They must:

- resolve the target through adapter profile and rules of engagement;
- validate module metadata before execution;
- fail closed on unknown or forbidden targets;
- default to staging;
- require explicit production flags and production-capable module metadata for production;
- produce structured proof evidence;
- record ledger entries that identify module id, target environment, evidence level, authorization ticket when applicable, timestamp, outcome, artifact references, and stop/cleanup notes;
- store sensitive runtime evidence only under `/tmp/security-harness/runs/<project>`;
- write only sanitized summaries to reports, exports, and `.security`;
- redact request bodies, response bodies, auth headers, cookies, signatures, provider secrets, customer data, production object IDs, and replayable proof material by default.

The harness should support stopping conditions such as:

- target guard ambiguity;
- missing authorization;
- unexpected production target;
- missing impact cap;
- unexpected state mutation;
- non-test customer or account exposure;
- provider or money movement outside approved scope;
- evidence redaction failure.

## Agent Workflow

Separate agents can help when their roles are explicit and gated:

- **Reconnaissance agent:** reads code, `.security`, ledgers, and artifacts to find possible weaknesses.
- **Hypothesis agent:** turns review findings into exploit hypotheses with expected outcomes and affected invariants.
- **Exploit designer:** proposes proof strategies, fixture requirements, target scope, evidence needs, and stop conditions.
- **Safety reviewer:** checks authorization, rules of engagement, impact, production gates, evidence handling, and rollback/cleanup.
- **Implementer:** builds deterministic modules with metadata, target guards, redaction, and tests.
- **Execution agent:** runs only approved modules with explicit CLI flags and records evidence according to the module contract.

No agent should independently escalate from review to real attack/proof mode without the required module metadata and authorization gates.

## First Real Exploit-Proof Candidate

The first real exploit-proof candidate is webhook replay/freshness against Cheddar staging, using real staging behavior once scope and fixtures are confirmed.

The current safe path is:

1. Keep `webhook-replay-freshness` local-only until staging fixture scope is approved.
2. Confirm the `.security` webhook trust invariant, route scope, timestamp/freshness source, tolerance, and duplicate-delivery semantics.
3. Define a staging-only fixture contract that avoids production payloads, customer data, real provider secrets in git, and uncontrolled money-impacting events.
4. Add module metadata for the first live staging proof attempt.
5. Implement a deterministic staging proof module with `production_allowed=false`.
6. Store proof evidence only under `/tmp/security-harness/runs/cheddar`.

Synthetic fixtures remain useful for developing parser and decision logic, but they are not a substitute for proving the target application's real behavior under authorized conditions.
