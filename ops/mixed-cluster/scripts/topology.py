#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Peer graphs of the mixed-cluster harness (issue #2280).

`default` is the historical topology: the three Go relays peer with each other
and the Rust participation node dials all three. Nothing changes for it.

The two opt-in topologies isolate one Go PARTICIPATION node (go-node-3, 30 % of
the stake) so that its only link to the rest of the cluster is one relay:

  rust-relay   go-node-3 dials only rust-node-4's WS-gossip listener (:4162),
               which relays between it and go-node-1/go-node-2. The transactions,
               votes and proposals go-node-3 sends and receives all cross the
               Rust relay: go-node-1 and go-node-2 do not list go-node-3 and
               rust-node-4 does not dial it.
  go-relay     the control: the same graph with go-node-1 (a Go relay) where
               rust-node-4 was, so any difference is the relay implementation.

`start.sh` turns a plan into the PHASE6_*_PEERS / PHASE6_GO3_NET_ADDRESS /
PHASE6_RUST_FORCE_RELAY variables docker-compose.yml interpolates; the
`sources` the transaction-gossip check submits to come from the same plan.

Usage:
  topology.py env <topology>       KEY=VALUE lines for start.sh
  topology.py sources <topology>   comma-separated tx_gossip.py sources
"""
import sys
from collections import namedtuple

TOPOLOGIES = ("default", "rust-relay", "go-relay")

Plan = namedtuple("Plan", "name peers go3_net_address rust_force_relay sources")

GO_PORT = "4161"        # the Go relays' NetAddress
RUST_PORT = "4162"      # rust-node-4's --listen-address (WS gossip)


def plan(name):
    """The peer lists of every node for `name`; ValueError for an unknown one."""
    if name == "default":
        return Plan(
            name,
            {"go-node-1": ["go-node-2:4161", "go-node-3:4161"],
             "go-node-2": ["go-node-1:4161", "go-node-3:4161"],
             "go-node-3": ["go-node-1:4161", "go-node-2:4161"],
             "rust-node-4": ["go-node-1:4161", "go-node-2:4161", "go-node-3:4161"]},
            "0.0.0.0:4161", False, ("go-node-1", "rust-node-4"))
    if name == "rust-relay":
        return Plan(
            name,
            {"go-node-1": ["go-node-2:4161"],
             "go-node-2": ["go-node-1:4161"],
             "go-node-3": ["rust-node-4:" + RUST_PORT],
             "rust-node-4": ["go-node-1:4161", "go-node-2:4161"]},
            "", True, ("go-node-3", "go-node-1", "rust-node-4"))
    if name == "go-relay":
        return Plan(
            name,
            {"go-node-1": ["go-node-2:4161"],
             "go-node-2": ["go-node-1:4161"],
             "go-node-3": ["go-node-1:4161"],
             "rust-node-4": ["go-node-1:4161", "go-node-2:4161"]},
            "", False, ("go-node-3", "go-node-1", "rust-node-4"))
    raise ValueError("unknown topology {!r}: want {}".format(name, ", ".join(TOPOLOGIES)))


def env_lines(p):
    """The variables docker-compose.yml and start.sh read, as KEY=VALUE lines
    (no whitespace or quotes: the values are used unquoted in a shell)."""
    return [
        "PHASE6_TOPOLOGY=" + p.name,
        "PHASE6_GO1_PEERS=" + ";".join(p.peers["go-node-1"]),
        "PHASE6_GO2_PEERS=" + ";".join(p.peers["go-node-2"]),
        "PHASE6_GO3_PEERS=" + ";".join(p.peers["go-node-3"]),
        "PHASE6_RUST_PEERS=" + ",".join(p.peers["rust-node-4"]),
        "PHASE6_GO3_NET_ADDRESS=" + p.go3_net_address,
        "PHASE6_RUST_FORCE_RELAY=" + ("1" if p.rust_force_relay else "0"),
    ]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] not in ("env", "sources"):
        print(__doc__.split("Usage:")[1].strip(), file=sys.stderr)
        return 2
    try:
        p = plan(argv[1])
    except ValueError as e:
        print("error: {}".format(e), file=sys.stderr)
        return 2
    if argv[0] == "env":
        print("\n".join(env_lines(p)))
    else:
        print(",".join(p.sources))
    return 0


if __name__ == "__main__":
    sys.exit(main())
