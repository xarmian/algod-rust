# P2P interop harness (issues #543, #560, #564)

Three real go-algorand v4.7.0-stable nodes, each started in plain P2P
mode (`EnableP2P: true`, no WS-gossip listener — `config/localTemplate.go`'s
`IsP2PListenServer`), chain-bootstrapped to each other (1 <- 2 <- 3 —
go-node-2 is only ever told go-node-1's multiaddr; go-node-3 is only ever
told go-node-2's), for algod-rust's `algo-p2p` libp2p transport to dial.

Proves real cross-implementation transport interop: a Noise-authenticated
TCP connection between rust-libp2p (`algo-p2p`) and go-libp2p
(go-algorand's `network/p2p/`) — see
`bin/algod-rust/tests/p2p_go_algorand_interop.rs`.

This is a narrower sibling of `ops/mixed-cluster/` (3 Go + 1 Rust,
WS-gossip, full consensus round-trip). See
`docs/MIXED_CLUSTER_HARNESS.md`'s "P2P interop harness" section for what
this harness currently proves and what's tracked as follow-up.

## Issue #560 status

Building this harness's 3-node chain (up from #543's single node) to
test cross-implementation DHT peer discovery found and fixed one real
bug: `algo_p2p::dht::dht_protocol_name` (`crates/node/algo-p2p/src/dht.rs`)
was missing the `/kad/1.0.0` suffix `go-libp2p-kad-dht`'s `makeDHT`
always appends to whatever `ProtocolPrefix` go-algorand configures —
without it, a rust host's DHT queries against a real go-algorand peer
negotiated no shared protocol at all. Fixed and regression-tested.

After that fix, a rust host's DHT query against a live go-node DOES
reach go's DHT handler (a real round trip happens), but `get_closest_peers`
does not return other peers that node is directly connected to.
Issue #564 root-caused this: go's `handleFindPeer` only returns
`CloserPeers` entries its **peerstore** already has an address for, and
that peerstore is populated exclusively via DHT **provider records**
(the "gossip"/"archival" capability-namespace mechanism), never by
`FIND_NODE` responses or vanilla libp2p Identify (go passes
`libp2p.NoListenAddrs`) — so `get_closest_peers` cannot surface a peer's
address against a real go-algorand node *by design*, not as a remaining
wire bug. #564 also found and fixed a second, distinct bug in the
correct mechanism: `algo_p2p::capabilities::Capability::record_key` used
the wrong DHT key (raw namespace bytes instead of go's
`nsToCid(ns).Hash()` SHA-256-multihash derivation) — fixed, and verified
live that `find_peers_for_capability` now genuinely round-trips against
a real go-algorand node. Multi-hop provider-record propagation across
more than one node is tracked as its own follow-up issue.

## Usage

```bash
make p2p-interop-test    # up + run the live interop test + down
```

or manually:

```bash
ops/mixed-cluster-p2p/scripts/start.sh
# prints and writes each node's dialable multiaddr, e.g.
#   /ip4/127.0.0.1/tcp/5161/p2p/12D3KooW...   (netroot/.p2p-multiaddr-1)
#   /ip4/127.0.0.1/tcp/5162/p2p/12D3KooW...   (netroot/.p2p-multiaddr-2)
#   /ip4/127.0.0.1/tcp/5163/p2p/12D3KooW...   (netroot/.p2p-multiaddr-3)
ALGOD_RUST_P2P_GO_MULTIADDR="$(cat ops/mixed-cluster-p2p/netroot/.p2p-multiaddr-1)" \
  cargo test --package algod-rust --test p2p_go_algorand_interop -- --ignored --nocapture
ops/mixed-cluster-p2p/scripts/stop.sh
```

`start.sh` bootstraps a 3-relay-node private network via `goal network
create` (`template.json`), patches each node's `config.json` with
`EnableP2P=true`, `NetAddress=0.0.0.0:<port>`, a non-zero
`IncomingConnectionsLimit` (go-algorand's `p2p.go` forces the listener
off when this is 0), and **`EnableDHTProviders=true`** — this last one is
easy to miss: it defaults to `false`
(`config/localTemplate.go`/`local_defaults.go`), and without it
`network/p2pNetwork.go` never attaches a kad DHT node to the libp2p host
at all, so any DHT query against the node comes back empty instantly
rather than reaching out over the network. This was issue #560's first
real finding while building this harness.

Each node is started with `docker compose up -d <service>` in sequence
(not all at once), because each one after the first needs the previous
node's real `PeerId` (scraped from the "P2P host created: peer ID %s
addrs %s" log line go-algorand emits unconditionally at P2P host
creation, `network/p2pNetwork.go`) to set its `PEER_ADDRESS` environment
variable — the `-p`/`PEER_ADDRESS` phonebook override
(`cmd/algod/main.go`, `run.sh`'s `start_public_network`) accepts a
semicolon-separated list of full multiaddrs (including a trailing
`/p2p/<peer-id>` component,
`network/p2p/peerstore.PeerInfoFromAddr`/`AddrInfoFromP2pAddr`), which
seeds that node's DHT routing table and phonebook with exactly one
directly-known peer.
