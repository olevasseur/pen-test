# Jobs, Queues, And Workers

Use this folder to document scheduled jobs, background workers, queues, and retry behavior.

## Inventory Template

| Job/Worker | File | Trigger | State Impact | Idempotency | Monitoring | Notes |
|---|---|---|---|---|---|---|
| `replaceJob` | `path/to/file.ext:LINE` | scheduler/queue/manual | Read-only/Updates state | durable key/TBD | alert/log/TBD | Placeholder row. |

## Review Checklist

- Is the job safe if two copies run at once?
- Are queue messages treated as at-least-once delivery?
- Are payloads validated before use?
- Are cursors, locks, and retry markers durable?
- Can missing cache/cursor state cause unbounded replay?
- Are partial failures recoverable?
- Are external calls retried safely?
- Are logs and artifacts sanitized?

## Evidence Handling

Commit only sanitized job behavior, code references, TODOs, and test names. Keep raw logs, provider payloads, customer data, credentials, and screenshots in the approved private evidence store.
