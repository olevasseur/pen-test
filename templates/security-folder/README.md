# `.security/` Security Map

This folder is a sanitized security knowledge base for this project. It helps reviewers and security tools understand externally reachable surfaces, trust boundaries, invariants, testing scope, and safe finding formats.

It is safe to commit only sanitized operational security context. Private runtime evidence belongs outside git, for example:

```text
/tmp/security-harness/runs/<project>
```

## Contents

| Path | Purpose |
|---|---|
| `AGENTS.md` | Read-first guide for agents and reviewers. |
| `rules-of-engagement.md` | Authorized environments, allowed targets, forbidden targets, and evidence handling rules. |
| `attack-surface.md` | Human-maintained inventory of routes, operations, jobs, queues, webhooks, and admin/public surfaces. |
| `methodology.md` | Review prompts and checklists by bug class. |
| `trust-boundaries.md` | What the system trusts and where that trust enters. |
| `findings/TEMPLATE.md` | Sanitized finding template. Do not commit raw evidence. |
| `flows/` | Flow-specific guides. |
| `invariants/` | Stable security rules to cite in reviews and findings. |
| `webhooks/` | Inbound and outbound webhook maps. |
| `jobs/` | Background and scheduled job audit map. |

## Allowed To Commit

- Sanitized route and operation inventories.
- High-level security assumptions and trust boundaries.
- Rules of engagement and authorized testing scope.
- Checklists, TODOs, and audit questions.
- Sanitized finding stubs without replayable details.
- Links to private runtime run IDs or private tracker IDs.
- Regression test names and safe code references.

## Never Commit

- Secrets, API keys, private keys, seed phrases, signing keys, or database URLs.
- Raw request bodies, response bodies, auth headers, cookies, or webhook signatures.
- Replayable exploit payloads or exact proof-of-concept steps.
- Production object IDs, customer data, PII, documents, or full screenshots containing sensitive data.
- Database dumps, provider credentials, or logs containing credentials.
- Raw runtime artifacts from `/tmp/security-harness/runs/<project>`.

## Update Guidance

Update this folder when the project adds or changes externally reachable routes, privileged operations, webhooks, background jobs, queues, trust boundaries, secrets, environment gates, or money/state-changing flows.

When in doubt, add a sanitized audit question rather than unverified claims.
