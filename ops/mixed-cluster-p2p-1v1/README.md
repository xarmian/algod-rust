# mixed-cluster-p2p-1v1

Minimal 1 go-algorand + 1 algod-rust P2P (`P2pOnly`) cluster with a 50/50
online-stake split, built for issue #1580's fourth investigation round.

## Why 1-1 / 50-50

`ops/mixed-cluster-p2p/` (3 go-algorand nodes @ 30% stake each + 1 Rust
node @ 10%) can absorb Rust's votes never being accepted and still close
quorum most rounds, since the 3 Go nodes alone hold 90% of stake — well
above go-algorand's `CertCommitteeThreshold`/`CertCommitteeSize` of
720/1000 (72%, see `../../go-algorand/config/consensus.go`). That makes
"Rust votes sometimes/rarely get accepted" a fundamentally ambiguous
signal to interpret: is it flakiness, or is it broken and just getting
lucky within a sampled window?

At 50/50 stake with only one Go node, the Go node's own stake (50%)
cannot reach the 72% cert threshold by itself. If the round nonetheless
closes and a go-side log shows `VoteAccepted` with the Rust account as
sender, that is unambiguous proof the P2P vote path works. If the round
never closes, that is equally unambiguous proof it does not — no
"occasionally missed a check" ambiguity remains.

It also halves the number of containers contending for host/CI-runner
CPU (2 vs. 4), which doubles as a natural experiment on the
external-CPU-contention hypothesis from PR #1583's investigation: if the
problem disappears with 2 containers, that supports the contention
theory; if it persists identically, that points at a real code-level bug.

## Usage

```bash
ops/mixed-cluster-p2p-1v1/scripts/start.sh    # generate netroot + start both nodes
ops/mixed-cluster-p2p-1v1/scripts/status.sh   # per-node round snapshot
ops/mixed-cluster-p2p-1v1/scripts/stop.sh     # tear down (add --purge to wipe netroot/)

# One-shot up -> soak -> vote-acceptance check -> down:
ROUNDS=100 bash ops/mixed-cluster-p2p-1v1/scripts/consensus-soak.sh
```

Host ports: go-node-1 REST `5101` (P2P `5261`), rust-node-2 REST `5102`.
(Chosen disjoint from `ops/mixed-cluster-p2p/`'s 5001-5004/5161-5163 so
both harnesses can run concurrently if ever needed.)

See `../mixed-cluster-p2p/docker-compose.yml` for the fuller commentary
on flags/addressing quirks shared with this harness (static
non-unspecified `NetAddress`, the `/ip4/` vs `/dns4/` bootstrap-multiaddr
distinction, etc.) — this harness intentionally does not re-explain them.
