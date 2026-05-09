# Pen-Test Harness

Safety-first security evidence harness for repeatable project audits.

The immediate adapter is Cheddar, but the core is reusable. Project-specific target rules, security-map paths, and live probes belong in adapters.

## Storage Model

The harness has three storage domains:

1. This `pen-test` repo: reusable source code, adapters, generic modules, and tests. No runtime evidence.
2. Target repo `.security/`: sanitized security map, rules of engagement, attack-surface docs, flow docs, invariant docs, and safe stubs/summaries. No raw exploit evidence or secrets.
3. `/tmp/security-harness/runs/<project>`: private runtime ledger, artifacts, generated reports, and sensitive evidence when explicitly needed. Never commit this.

## Evidence Levels

- `observe_only`: static or passive review only. No HTTP requests.
- `non_mutating_probe`: safe HTTP checks that should not change application state.
- `safe_mutation`: controlled changes against staging or approved test resources.
- `controlled_exploit`: real vulnerability proof with explicit authorization, scope, impact cap when relevant, and private runtime evidence.

## Production Authorization Model

Production is supported but never accidental. A production run requires:

- `--allow-production`
- `--authorization-ticket <ticket>`
- module metadata `production_allowed=true`
- target allowed by adapter profile or `.security/rules-of-engagement.md`
- explicit `--evidence-level`
- `--max-impact-cad` when money impact is possible

No production raw evidence may be written to `.security/`.

Example shape only, using fake values:

```bash
pentest run cheddar some-production-safe-module \
  --target production \
  --allow-production \
  --authorization-ticket TICKET-1234 \
  --evidence-level non_mutating_probe \
  --target-repo /Users/olivier-ludex/repos/cheddar
```

## `.security` Folder Template

This repo includes a generic reusable template at `templates/security-folder/`.

Real project `.security/` folders should be initialized from this template and then maintained in the target repo as sanitized project-local security maps. The template includes placeholders for rules of engagement, attack-surface inventory, trust boundaries, methodology, findings, flows, invariants, webhooks, and jobs.

Do not copy a real project's `.security/` folder back into this reusable harness. Cheddar's `.security/` folder is internal project context and should stay in the Cheddar repo.

## Cheddar Staging Examples

```bash
pentest init cheddar --target-repo /Users/olivier-ludex/repos/cheddar
pentest run cheddar route-inventory --target staging --evidence-level observe_only --target-repo /Users/olivier-ludex/repos/cheddar
pentest run cheddar webhook-negative --target staging --evidence-level non_mutating_probe --target-repo /Users/olivier-ludex/repos/cheddar
pentest security-map diff cheddar --target-repo /Users/olivier-ludex/repos/cheddar
pentest report cheddar --latest
pentest export cheddar --latest --output /tmp/security-harness/export-cheddar
```

`.security` updates are read-only by default. Actual writes require:

```bash
pentest security-map update cheddar --target-repo /Users/olivier-ludex/repos/cheddar --write
```

## Safety Notes

- The Cheddar adapter allows `https://staging-api-aws.cheddar.biz`.
- The Cheddar adapter forbids `https://staging-api.cheddar.biz` by default because it is the legacy/wrong Heroku staging endpoint.
- Runtime output belongs under `/tmp/security-harness/runs/<project>`.
- `.security/` is sanitized project-local documentation, not a place for request bodies, response bodies, auth headers, cookies, webhook signatures, private keys, mnemonics, customer PII, screenshots with sensitive data, or replayable payloads.

## Current Limitations

- Custom/non-staging target override is not implemented yet. Unknown or non-staging hosts fail closed unless they are explicit production targets with all production gates satisfied.
- Route drift is approximate. The current scanner finds local route declarations but does not fully reconstruct Express mount prefixes or all GraphQL/job/worker surfaces.
- No production-capable modules exist yet. Production support is a guarded framework path, not an enabled test capability.
- `.security` parsing is markdown-convention based. It reads the current Cheddar tables and sections, but it is not a complete Markdown or application-framework parser.
