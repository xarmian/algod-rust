# P2P interop harness (issues #543, #560, #564, #566)

Three real go-algorand v5.0.0-stable nodes, each started in plain P2P
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
more than one node did not initially work in this harness — root-caused
and fixed by issue #566, see below.

## Issue #566 status

With #563/#565's fixes applied, single-hop provider-record advertisement
worked (a node reports *itself* as a "gossip" provider), but a provider
record advertised by one go-algorand node never propagated to its
neighbors' local provider stores — querying any node only ever returned
that node itself, never its DHT neighbors, no matter how long the test
waited. Root-caused live (with `BaseLoggerDebugLevel` raised to `5` to
observe go's own DHT debug logs) to a **harness configuration** issue,
not a wire-protocol or algod-rust bug: this harness originally bound each
node's `NetAddress` to the *unspecified* address (`0.0.0.0:<port>`).
go-algorand's own `network/p2p.addressFilter` (`network/p2p/p2p.go`)
strips every candidate advertised address whenever `NetAddress` is
unspecified (`manet.IsIPUnspecified`) — a real-deployment safeguard
against advertising unroutable private addresses to a public DHT — which
in this all-private-IP Docker network left **every** node with zero
addresses to announce. `go-libp2p-kad-dht@v0.38.0`'s
`ProtocolMessenger.PutProviderAddrs` correctly detects this and silently
skips sending the `ADD_PROVIDER` RPC at all (`"no known addresses for
self, cannot put provider"`, confirmed present in all three nodes' debug
logs, once per every single `Provide` attempt) — so the record never left
the advertising node's own local provider store, permanently, regardless
of how long a test waited.

Fixed entirely within this harness (no algod-rust production code
change): `docker-compose.yml` pins each node to a **static**, non-zero
docker-bridge IP (`networks.p2pinterop.ipam` + each service's
`ipv4_address`), and `start.sh` binds `NetAddress` to that specific IP
instead of `0.0.0.0`. A specific `NetAddress` keeps `needAddressFilter`
false, so go-algorand never installs the stripping `addrFactory`, and
each node's real (Docker-bridge-routable) address is advertised
correctly — verified live: `bin/algod-rust/tests/p2p_go_algorand_interop.rs`'s
`provider_record_advertised_by_neighbor_propagates_to_queried_node`
queries **only** go-node-1 and correctly discovers go-node-2 as a
"gossip" provider, proving genuine multi-hop DHT provider-record
propagation between real go-algorand nodes.

## Issue #560 status: `/algorand-ws/2.2.0` agreement-traffic stream (PR #590)

With #563/#565/#566's fixes applied, DHT discovery and capability
advertisement both round-trip cleanly against real go-algorand nodes — but
a full consensus round-trip still needed one more piece: go-algorand
v5.0.0-stable's own `gossipSubTags` map (`network/p2pNetwork.go`) wires
gossipsub up for the `TX` tag **only**. A real go-algorand P2P node never
subscribes to or publishes on a gossipsub topic for proposals, votes, or
vote bundles — that traffic travels over a separate raw bidirectional
libp2p stream per connected peer, on the `/algorand-ws/2.2.0` protocol
(`wsStreamHandlerV22`), tunneling the same tag-prefixed message framing
the WS-gossip transport uses (a length-prefixed frame instead of relying
on WebSocket message boundaries, and a msgpack-encoded handshake instead
of an HTTP upgrade).

`crates/node/algo-p2p/src/wsproto.rs` now implements this protocol, and
`bin/algod-rust/src/commands/p2p_transport.rs`'s `P2pTransport` opens/
accepts one such stream per peer, fanning AV/PP/VB traffic out over it in
addition to gossipsub. Live-verified against this harness:
`bin/algod-rust/tests/p2p_go_algorand_interop.rs`'s
`algorand_ws_stream_handshake_round_trips_with_real_go_algorand_node`
dials go-node-1, opens a `/algorand-ws/2.2.0` stream, and completes go's
actual msgpack `peerMetaHeaders` handshake end-to-end.

This harness still has **no stake-provisioned rust node** (all 100% stake
sits on go-node-1, per `template.json`, and there is no `P2pOnly`
`algod-rust participate` service here) — building that out to prove a
full multi-round consensus round-trip is tracked as issue #589.

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
