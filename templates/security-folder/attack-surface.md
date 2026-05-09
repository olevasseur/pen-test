# Attack Surface

This is a sanitized, human-maintained inventory of externally reachable surfaces and sensitive internal execution paths. It is not an exploit catalog.

## Legend

| Column | Meaning |
|---|---|
| Auth | `Public`, `Session`, `JWT`, `API key`, `Admin`, `Provider signature`, `Service`, `Queue`, or `Unknown`. |
| State | `Read-only`, `Creates state`, `Updates state`, `Deletes state`, `Money/credit impact`, or `Unknown`. |
| Bounds | Primary validation or authorization boundary. Use `?` when unknown. |

## REST Routes

| Method | Path | File | Handler | Auth | State | Bounds | Notes |
|---|---|---|---|---|---|---|---|
| `GET` | `/replace/example` | `path/to/file.ext:LINE` | `handlerName` | Public | Read-only | schema/query validation | Placeholder row. |
| `POST` | `/replace/example` | `path/to/file.ext:LINE` | `handlerName` | Session | Creates state | ownership check | Placeholder row. |

## GraphQL Operations

| Operation Type | Operation | File | Auth | State | Bounds | Notes |
|---|---|---|---|---|---|---|
| query | `replaceQuery` | `path/to/file.ext:LINE` | Session | Read-only | owner scope | Placeholder row. |
| mutation | `replaceMutation` | `path/to/file.ext:LINE` | Admin | Updates state | role check | Placeholder row. |

## Webhooks

| Provider/System | Direction | Path or Topic | File | Auth | State | Replay/Idempotency | Notes |
|---|---|---|---|---|---|---|---|
| Replace provider | inbound | `/replace/webhook` | `path/to/file.ext:LINE` | Provider signature | Updates state | event ID uniqueness | Placeholder row. |
| Replace callback | outbound | `event.name` | `path/to/file.ext:LINE` | Signed outbound | Read-only external side effect | stable event ID | Placeholder row. |

## Background Jobs

| Job | File | Trigger | State | Idempotency | Monitoring | Notes |
|---|---|---|---|---|---|---|
| `replaceJob` | `path/to/file.ext:LINE` | queue/scheduler/manual | Updates state | durable cursor | alert/run log | Placeholder row. |

## Scheduled Jobs

| Schedule | Job | File | State | Concurrency Guard | Notes |
|---|---|---|---|---|---|
| `replace schedule` | `replaceScheduledJob` | `path/to/file.ext:LINE` | Read-only | lock/cursor/TBD | Placeholder row. |

## Queues And Workers

| Queue/Topic | Producer | Consumer | Payload Trust | State | Retry Safety | Notes |
|---|---|---|---|---|---|---|
| `replace.queue` | `path/to/producer.ext:LINE` | `path/to/consumer.ext:LINE` | internal service | Updates state | idempotent key/TBD | Placeholder row. |

## Admin Surfaces

| Surface | File | Auth | Privilege Boundary | State | Notes |
|---|---|---|---|---|---|
| Replace admin action | `path/to/file.ext:LINE` | Admin | role/permission/TBD | Updates state | Placeholder row. |

## Public Surfaces

| Surface | File | Auth | Capability Boundary | State | Notes |
|---|---|---|---|---|---|
| Replace public page/API | `path/to/file.ext:LINE` | Public | opaque ID/rate limit/TBD | Read-only | Placeholder row. |

## Audit Questions

- Which rows have `Unknown` auth, state, or bounds?
- Which public surfaces rely on capability IDs?
- Which state-changing operations lack idempotency notes?
- Which provider or queue surfaces lack replay/duplicate-delivery notes?
