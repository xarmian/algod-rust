# Network rate limiting — enforcement audit

**Status:** audit complete · **As of:** 2026-04-23 · **Owner:** algo-network

This note maps every incoming-connection / rate-limit knob to its
enforcement site in `crates/node/algo-network/`, so future readers do not
have to re-run the audit when triaging DoS-shaped concerns.

It is the written-up deliverable for `TASK-72` under
[PLAN-33 · P2P & Gossip Completion] and closes out gap **G4** in
[DOC-23 · Gap — Networking & Sync].

## 1. Knobs

| Config field | Default | Go source | Purpose |
|---|---|---|---|
| `incoming_connections_limit` | 2400 | `config/local_defaults.go` | Total number of concurrent incoming connections the relay will hold open |
| `connections_rate_limiting_count` | 60 | `config/local_defaults.go` | Per-source-IP connection attempts allowed within the rate window |
| `connections_rate_limiting_window` (Rust: fixed at 1 s) | 1 s | `network/requestTracker.go` | Rolling window for the rate-limit counter |
| `max_connections_per_ip` | (see `WebsocketNetworkConfig`) | `config/local_defaults.go` | Cap on concurrent connections from a single IP |
| `reserved_health_service_connections` | 10 | `network/wsNetwork.go` | Extra TCP slots over the limit, reserved for the `/health` endpoint |

## 2. Enforcement chain

Incoming TCP → WebSocket upgrade passes through **two independent gates**:

```
client TCP dial
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ Gate 1 — RejectingLimitListener (TCP level)                 │
│   file: crates/node/algo-network/src/listener.rs            │
│   guards: incoming_connections_limit + reserved_health      │
│   mechanism: tokio::sync::Semaphore; exhausted permits      │
│              → accept() drops the socket immediately        │
│   Mirrors: go-algorand/network/limitlistener/               │
│            rejectingLimitListener.go                        │
└─────────────────────────────────────────────────────────────┘
      │ permit acquired
      ▼
axum HTTP / WS upgrade handler
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ Gate 2 — validate_incoming_connection (app level)           │
│   file: crates/node/algo-network/src/ws_network.rs          │
│   checks (in order):                                        │
│     1. genesis ID matches                 → 412             │
│     2. protocol version matches           → 412             │
│     3. track_connection(remote_ip)        (bookkeeping)     │
│     4. max_connections_per_ip             → 403             │
│     5. connections_rate_limiting_count    → 429             │
│     6. NodeRandom present, not self-loop  → 412 / 508       │
│   mechanism: ConnectionTracker (request_tracker.rs)         │
│     active map: HashMap<IpAddr, u32>                        │
│     rate map:   HashMap<IpAddr, Vec<Instant>>               │
│   Mirrors: go-algorand/network/requestTracker.go            │
└─────────────────────────────────────────────────────────────┘
      │ all checks pass
      ▼
WebSocket established; peer added to mesh
```

## 3. Verification — tests that back each knob

**Gate 1 (`RejectingLimitListener`, `incoming_connections_limit`)**
- Unit: `listener.rs::tests::accept_within_limit` — permits decrement/release correctly.
- Unit: `listener.rs::tests::reject_over_limit` — full-capacity listener rejects + resumes after a slot is freed.
- Unit: `listener.rs::tests::guard_drop_releases_slot` — RAII guard releases the semaphore permit.

**Gate 2 — per-IP connection cap (`max_connections_per_ip`)**
- Unit: `ws_network.rs::tests::validate_incoming_per_ip_connection_limit` — tracking + rejection + release.
- Integration: `tests/relay_integration.rs::connection_limit_enforcement` — real relay, flood from a single IP via WS, assert rejection status.

**Gate 2 — per-IP rate limit (`connections_rate_limiting_count`)**
- Unit: `ws_network.rs::tests::validate_incoming_rate_limit` — pre-populated timestamps, assertion on rejection path.
- Unit: `request_tracker.rs::tests::rate_limit_window_prunes_stale_attempts` et al. — sliding-window pruning semantics.
- **Integration:** `tests/rate_limit_flood.rs::per_ip_rate_limit_rejects_rapid_redial` — end-to-end rapid re-dial from single IP, assert non-101 response on over-limit dial. *(added by TASK-72)*

**Gate 2 — `ConnectionTracker` internals**
- `request_tracker.rs::tests` — 7 unit tests covering track/release, counts, rate windows, pruning.

## 4. Reserved health slots

`RejectingLimitListener::new(tcp, incoming_connections_limit)` allocates
`incoming_connections_limit + RESERVED_HEALTH_SERVICE_CONNECTIONS` (= 10)
permits. The reserved slots are not policy-gated — they exist to keep
`/health` reachable from load-balancer probes even when the relay is at
application-level capacity. This matches Go's
`ReservedHealthServiceConnections = 10` in `network/wsNetwork.go`.

## 5. Findings — is G4 still open?

**No.** Every knob listed in G4 is enforced and tested:

- `incoming_connections_limit` → `RejectingLimitListener` (Gate 1)
- `connections_rate_limiting_count` → `ConnectionTracker::check_rate_limit` (Gate 2, step 5)
- `max_connections_per_ip` → `ConnectionTracker::check_connection_limit` (Gate 2, step 4)

Enforcement paths are invoked from `start_relay_server` (Gate 1 wrap) and
from `validate_incoming_connection` (Gate 2 on every upgrade). Both have
unit + integration coverage after TASK-72.

The remaining DoS surface area is peer reputation / ban list
(DOC-23 **G6**), which is deliberately deferred and not in PLAN-33's
scope.

## 6. Follow-ups considered, not shipped

- **Per-source rate-limit window as a config knob.** Currently fixed at
  1 s inside `WebsocketNetwork::new` — matches Go's default but does not
  expose the underlying `ConnectionsRateLimitingWindowSeconds` Go config
  field. Not worth wiring until ops needs to tune it.
- **Metrics counters for rejections.** Deferred to PLAN-44 (observability).
- **Connection-attempt throttling at the TCP accept layer.** Would
  reduce the TCP backlog churn but breaks Go's "always accept then
  close" pattern; not planned.

[PLAN-33 · P2P & Gossip Completion]: ../docs/PHASE6_PROPOSAL.md
[DOC-23 · Gap — Networking & Sync]: ../docs/PHASE6_PROPOSAL.md
