// Per-message routing across the cluster.
//
// Mirrors the `messageRouting` portion of go-algorand's
// `agreement/fuzzer/fuzzer_test.go` — given an outgoing message from
// node S, expand it into the set of (target, message) pairs that the
// scheduler should hand to each node's incoming filter chain.
//
// The router is intentionally a pure function over `AlgoMessage`
// (no state). The cluster size is the only configuration it carries.
// Topology constraints (e.g. circular / partitioned) belong to a
// future TopologyFilter, not here, mirroring Go's split.

use super::AlgoMessage;

/// A trivial topology / dispatch helper. The cluster has `node_count`
/// nodes indexed `0..node_count`; broadcasts (`target_node = None`)
/// fan out to every peer except the sender.
#[derive(Clone, Debug)]
pub struct Router {
    node_count: usize,
}

impl Router {
    /// Construct a router for an N-node cluster. Panics if `node_count`
    /// is zero — a zero-node fuzzer is meaningless and indicates a
    /// harness setup bug.
    pub fn new(node_count: usize) -> Self {
        assert!(node_count > 0, "Router requires at least one node");
        Self { node_count }
    }

    /// Number of nodes in the cluster.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Expand `msg` into the per-target deliveries the scheduler should
    /// route. Always allocates a fresh `Vec` — clusters are small in
    /// fuzz tests (≤ tens of nodes) so this is cheap relative to the
    /// SHA-tag work the production network does on the same path.
    ///
    /// * Unicast (`target_node = Some(t)`) → one delivery to `t`.
    ///   If `t` equals the source it is dropped (loopback isn't
    ///   meaningful for the agreement network — Go's facade discards
    ///   the same).
    /// * Broadcast (`target_node = None`) → one delivery per peer
    ///   (every node except the source), in ascending node-ID order
    ///   so the per-tick sequence is deterministic.
    pub fn route(&self, msg: &AlgoMessage) -> Vec<AlgoMessage> {
        match msg.target_node {
            Some(t) => {
                if t == msg.source_node || t >= self.node_count {
                    Vec::new()
                } else {
                    vec![AlgoMessage {
                        source_node: msg.source_node,
                        target_node: Some(t),
                        tag: msg.tag.clone(),
                        data: msg.data.clone(),
                    }]
                }
            }
            None => (0..self.node_count)
                .filter(|&t| t != msg.source_node)
                .map(|t| AlgoMessage {
                    source_node: msg.source_node,
                    target_node: Some(t),
                    tag: msg.tag.clone(),
                    data: msg.data.clone(),
                })
                .collect(),
        }
    }
}
