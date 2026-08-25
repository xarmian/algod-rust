# P2P interop harness (issue #543)

A single real go-algorand v4.7.0-stable node, started in plain P2P mode
(`EnableP2P: true`, no WS-gossip listener — `config/localTemplate.go`'s
`IsP2PListenServer`), for algod-rust's `algo-p2p` libp2p transport to dial
directly. Proves real cross-implementation libp2p interop: a
Noise-authenticated TCP connection between rust-libp2p (`algo-p2p`) and
go-libp2p (go-algorand's `network/p2p/`).

This is a narrower sibling of `ops/mixed-cluster/` (3 Go + 1 Rust,
WS-gossip, full consensus round-trip). See
`docs/MIXED_CLUSTER_HARNESS.md`'s "P2P interop harness" section for what
this harness currently proves and what's tracked as follow-up (multi-node
P2P mesh, bidirectional gossipsub round-trip, cross-implementation
capability-advertisement lookup, a soak variant).

## Usage

```bash
make p2p-interop-test    # up + run the live interop test + down
```

or manually:

```bash
ops/mixed-cluster-p2p/scripts/start.sh
# prints and writes the go node's dialable multiaddr, e.g.
#   /ip4/127.0.0.1/tcp/5161/p2p/12D3KooW...
ALGOD_RUST_P2P_GO_MULTIADDR="$(cat ops/mixed-cluster-p2p/netroot/.p2p-multiaddr)" \
  cargo test --package algod-rust --test p2p_go_algorand_interop -- --ignored --nocapture
ops/mixed-cluster-p2p/scripts/stop.sh
```

`start.sh` bootstraps a 1-node private network via `goal network create`
(`template.json`), patches `config.json` with `EnableP2P=true`,
`NetAddress=0.0.0.0:4161`, and a non-zero `IncomingConnectionsLimit`
(go-algorand's `p2p.go` forces the listener off when this is 0), starts
the container, and scrapes the "P2P host created: peer ID %s addrs %s"
log line go-algorand emits unconditionally at P2P host creation
(`network/p2pNetwork.go`) to recover its PeerID.
