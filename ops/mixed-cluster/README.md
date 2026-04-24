# Mixed-Cluster Consensus Harness (TASK-86)

A 4-node docker-compose harness that runs 3 go-algorand v4.5.1-stable
nodes + 1 algod-rust node on a private network. Foundation for:

- TASK-87 — 200-round soak test (needs this harness + a metrics collector)
- TASK-88 — fork detector / cert cross-verify (needs the same harness)

## Topology

```
┌────────────┐   gossip   ┌────────────┐
│ go-node-1  │◀──────────▶│ go-node-2  │
│ relay+prop │            │ relay+prop │
└─────┬──────┘            └──────┬─────┘
      │                          │
      │                          │
      │         ┌────────────┐   │
      └────────▶│ go-node-3  │◀──┘
                │ relay+prop │
                └──────┬─────┘
                       │
                       ▼
                ┌─────────────┐
                │ rust-node-4 │
                │ relay only  │
                └─────────────┘
```

- **go-node-1/2/3**: algorand/algod:4.5.1-stable images with 33% stake
  each, all online, all proposing. These form the consensus quorum.
- **rust-node-4**: a built-from-source algod-rust running as a relay
  peer pointed at the 3 Go nodes. Holds a tiny (1 unit) stake that is
  marked offline, so it does not participate in consensus. Its job in
  this iteration is to prove the Rust node can join a live private
  network, sync blocks via gossip, and remain stable.

Full Rust consensus participation (the Rust node actually proposing
blocks) requires participation-key format interop with Go's netgoal
output — tracked as a follow-up (see `docs/MIXED_CLUSTER_HARNESS.md`
§Open questions).

## Prerequisites

- Docker + Docker Compose v2.
- Python 3 (used by `status.sh`).
- The repo root as the build context — the Rust node uses
  `docker/Dockerfile` from the repo root to compile `algod-rust` from
  source. First start takes several minutes; subsequent starts reuse
  the cached image.

## Usage

```bash
# bring up the cluster (generates netroot/ on first run)
ops/mixed-cluster/scripts/start.sh

# peek at each node's round
ops/mixed-cluster/scripts/status.sh

# tear down (keeps netroot/ so restarts reuse keys + genesis)
ops/mixed-cluster/scripts/stop.sh

# tear down and wipe keys (fresh network next start)
ops/mixed-cluster/scripts/stop.sh --purge
```

After ~30s the 3 Go nodes should be at round ≥ 3. After 2 minutes
all 3 should be at round ≥ 10 (assuming the default 4.5s block time
under the `future` consensus protocol baked into the template).

## Host ports

| Service       | Host port | Container port | Purpose                |
|---------------|-----------|----------------|------------------------|
| go-node-1     | `4001`    | `8080`         | REST API (token auth)  |
| go-node-2     | `4002`    | `8080`         | REST API               |
| go-node-3     | `4003`    | `8080`         | REST API               |
| rust-node-4   | `4160`    | `4160`         | Gossip (no REST today) |

Hit the Go nodes with:

```
curl -sf -H "X-Algo-API-Token: $(cat netroot/Node1/algod.token)" \
    http://localhost:4001/v2/status | jq .
```

The Rust node's `relay` subcommand does not yet expose REST — see the
design doc for the follow-up. `status.sh` reports `n/a` for it.

## What's in `netroot/`

`scripts/start.sh` runs `goal network create` on first invocation,
producing:

```
netroot/
├── network.json
├── genesis.json
├── Node1/
│   ├── config.json           (rewritten by start.sh — see below)
│   ├── genesis.json
│   ├── algod.token
│   └── <wallet>.partkey
├── Node2/
├── Node3/
└── Node4Rust/
```

`start.sh` then calls `algocfg` inside the Go image to overlay each
node's `config.json` with:

- `NetAddress = 0.0.0.0:4161`
- `EndpointAddress = 0.0.0.0:8080`
- `DNSBootstrapID = ""` (so private-net nodes don't reach public DNS)

The `netroot/` tree is `.gitignore`d — it contains private participation
keys and should never be committed.

## Platform notes

Validated on Linux with native Docker. macOS and Windows should work in
principle but some gotchas you may hit:

- **macOS (Docker Desktop, VirtioFS / gRPC-FUSE):** bind mounts like
  `./netroot/Node1:/algod/data` go through a filesystem shim. The
  uid-1001 ownership that `goal network create` writes survives the
  round trip, so `stop.sh --purge`'s in-container `rm` is still the
  correct path. The host-side fallback in `stop.sh` silently handles
  the less-common case where `rm -rf` from the host user succeeds.
- **Windows / WSL2:** native Linux rules apply inside the WSL2 distro.
  Running `scripts/start.sh` from a PowerShell shell through a Docker
  Desktop backed by WSL2 should work the same as Linux; scripts assume
  POSIX tools (`bash`, `python3`, `curl`, `mktemp`).
- **Colima / non-Docker-Desktop:** untested but should work as long as
  the runtime supports `docker compose` and bind mounts. Report back if
  you hit issues.

If you're on a platform where the in-container cleanup path can't reach
the algorand/algod image (offline, rate-limited, etc.), `stop.sh
--purge` falls back to a host-side `rm -rf` best-effort — you may see
a "root-owned files still present" warning and need to `sudo rm -rf
netroot/` manually.

## Troubleshooting

- **`docker compose up` fails with "missing netroot/Node1"**: run
  `scripts/start.sh` (not `docker compose up` directly) — it bootstraps
  the tree before invoking compose.
- **Nodes never advance past round 0**: verify each Node's `config.json`
  has `NetAddress = 0.0.0.0:4161` (not `127.0.0.1:<port>` from the
  goal-generated default). `start.sh` does this rewrite; if you poked
  at netroot/ manually, re-run `stop.sh --purge && start.sh`.
- **Rust node doesn't connect to Go nodes**: check the Rust container's
  logs with `docker logs phase6-rust-node-4`. Common cause: the
  `--genesis-id` passed in the compose file doesn't match what
  `goal network create` actually produced. `start.sh` captures the ID
  in `netroot/.phase6-genesis-id`; the Rust peer's `--genesis-id` in
  `docker-compose.yml` is hard-coded to `phase6net-v1` which matches
  the default produced by the template's `NetworkName: phase6net`.
- **"address already in use" on host port**: another service is bound
  to 4001/4002/4003/4160. Edit the compose file's `ports:` section to
  remap.

## Scope (TASK-86)

This PR delivers the harness plus local-run scripts. It explicitly does
NOT:

- Run a long soak — TASK-87 builds on this with a metrics collector.
- Detect forks or cross-verify certificates — TASK-88.
- Exercise Rust consensus participation — gated on participation-key
  interop with Go's netgoal output (see the follow-up in the design
  doc).
- Integrate into CI — left as a follow-up so CI doesn't take a
  container-build hit on every PR.

## Design doc

See `docs/MIXED_CLUSTER_HARNESS.md` for the rationale behind the
topology choices, the open questions on Rust-side participation, and the
relationship to the existing `docker/docker-compose.mixed-cluster.yml`
harness (which serves a different purpose — gossip / catchup interop
testing, not consensus agreement).
