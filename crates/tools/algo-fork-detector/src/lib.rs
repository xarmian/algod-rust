//! Fork detection across a mixed-cluster (PLAN-32 / TASK-88).
//!
//! The library exposes the pieces the binary uses so unit tests can exercise
//! the comparison logic without going through the REST client:
//!
//! - [`NodeEndpoint`] — a `(name, base_url, token)` triple for a node.
//! - [`DigestByNode`] — the per-round observation shape `{ node -> digest }`.
//! - [`compare_round`] — given a per-round map, returns the unique digests.
//! - [`FindingKind`] / [`Finding`] — what the detector emits.
//! - [`aggregate_findings`] — turn per-round comparisons into findings.
//!
//! The binary ([`main.rs`]) ties these to [`algo_rest_client::AlgodClient`]
//! and an argparsed CLI.

use std::collections::{BTreeMap, HashMap};

use algo_types::Digest;

/// A single node we'll poll.
#[derive(Debug, Clone)]
pub struct NodeEndpoint {
    /// Friendly name used in output (e.g. "go-node-1").
    pub name: String,
    /// Base URL for the node's REST API (e.g. "http://127.0.0.1:4001").
    pub base_url: String,
    /// API token (matching the cluster; for the TASK-86 harness this is 64×'a').
    pub token: String,
}

/// Map of node name → block digest observed at a round.
pub type DigestByNode = BTreeMap<String, Digest>;

/// Result of comparing all nodes' digests at a single round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundVerdict {
    /// Every node reported the same digest — no fork.
    Agreed { digest: Digest, nodes: Vec<String> },
    /// Nodes disagreed — clusters of {digest → nodes reporting it}.
    Forked {
        clusters: Vec<(Digest, Vec<String>)>,
    },
    /// Fewer than two nodes reported a digest — inconclusive.
    Insufficient { reporting: Vec<String> },
}

/// Compare per-node digests for a single round.
///
/// Returns one of:
/// - `Agreed` if all reporting nodes have the same digest
/// - `Forked` if 2+ distinct digests are reported (the detector's firing case)
/// - `Insufficient` if 0 or 1 nodes reported — the caller decides how strict to be
pub fn compare_round(by_node: &DigestByNode) -> RoundVerdict {
    if by_node.len() < 2 {
        return RoundVerdict::Insufficient {
            reporting: by_node.keys().cloned().collect(),
        };
    }

    // Group nodes by the digest they reported. `Digest` implements `Hash`
    // + `Eq` but not `Ord`, so use a HashMap here and sort the emitted
    // clusters deterministically by hex-encoded bytes on the way out.
    let mut groups: HashMap<Digest, Vec<String>> = HashMap::new();
    for (node, digest) in by_node {
        groups.entry(*digest).or_default().push(node.clone());
    }

    if groups.len() == 1 {
        let (digest, nodes) = groups.into_iter().next().unwrap();
        RoundVerdict::Agreed { digest, nodes }
    } else {
        let mut clusters: Vec<(Digest, Vec<String>)> = groups.into_iter().collect();
        // Stable ordering for deterministic output.
        clusters.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        for (_, nodes) in clusters.iter_mut() {
            nodes.sort();
        }
        RoundVerdict::Forked { clusters }
    }
}

/// Severity classification for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// A real fork — nodes reported different digests.
    Fork,
    /// Fewer than two nodes reported a digest for this round.
    InsufficientCoverage,
    /// A single node failed to return the block; comparison proceeds with the
    /// remaining nodes but we still surface the failure.
    FetchError,
}

/// An issue the detector observed.
#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: FindingKind,
    pub round: u64,
    pub detail: String,
}

/// Given a stream of per-round verdicts, materialize findings.
pub fn aggregate_findings<I>(per_round: I) -> Vec<Finding>
where
    I: IntoIterator<Item = (u64, RoundVerdict)>,
{
    let mut out = Vec::new();
    for (round, verdict) in per_round {
        match verdict {
            RoundVerdict::Agreed { .. } => {}
            RoundVerdict::Forked { clusters } => {
                let detail = clusters
                    .iter()
                    .map(|(d, ns)| format!("{} -> [{}]", hex_digest(d), ns.join(",")))
                    .collect::<Vec<_>>()
                    .join(" | ");
                out.push(Finding {
                    kind: FindingKind::Fork,
                    round,
                    detail: format!("fork: {detail}"),
                });
            }
            RoundVerdict::Insufficient { reporting } => {
                out.push(Finding {
                    kind: FindingKind::InsufficientCoverage,
                    round,
                    detail: format!(
                        "only {} node(s) reported: [{}]",
                        reporting.len(),
                        reporting.join(",")
                    ),
                });
            }
        }
    }
    out
}

/// Hex-encode the first 8 bytes of a digest for human-readable output.
fn hex_digest(d: &Digest) -> String {
    let bytes = &d.0[..8.min(d.0.len())];
    let mut s = String::with_capacity(18);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(byte: u8) -> Digest {
        let mut out = [0u8; 32];
        out[0] = byte;
        Digest(out)
    }

    #[test]
    fn agreed_when_all_same() {
        let mut by_node = DigestByNode::new();
        by_node.insert("a".into(), d(1));
        by_node.insert("b".into(), d(1));
        by_node.insert("c".into(), d(1));
        match compare_round(&by_node) {
            RoundVerdict::Agreed { digest, nodes } => {
                assert_eq!(digest, d(1));
                assert_eq!(nodes.len(), 3);
            }
            other => panic!("expected Agreed, got {other:?}"),
        }
    }

    #[test]
    fn forked_when_differ() {
        let mut by_node = DigestByNode::new();
        by_node.insert("a".into(), d(1));
        by_node.insert("b".into(), d(2));
        by_node.insert("c".into(), d(1));
        match compare_round(&by_node) {
            RoundVerdict::Forked { clusters } => {
                assert_eq!(clusters.len(), 2);
                let total_nodes: usize = clusters.iter().map(|(_, ns)| ns.len()).sum();
                assert_eq!(total_nodes, 3);
            }
            other => panic!("expected Forked, got {other:?}"),
        }
    }

    #[test]
    fn insufficient_when_under_two() {
        let mut by_node = DigestByNode::new();
        by_node.insert("a".into(), d(1));
        match compare_round(&by_node) {
            RoundVerdict::Insufficient { reporting } => {
                assert_eq!(reporting, vec!["a"]);
            }
            other => panic!("expected Insufficient, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_emits_findings_for_forks_only() {
        let verdicts = vec![
            (
                10,
                RoundVerdict::Agreed {
                    digest: d(1),
                    nodes: vec!["a".into(), "b".into()],
                },
            ),
            (
                11,
                RoundVerdict::Forked {
                    clusters: vec![(d(1), vec!["a".into()]), (d(2), vec!["b".into()])],
                },
            ),
            (
                12,
                RoundVerdict::Insufficient {
                    reporting: vec!["a".into()],
                },
            ),
        ];
        let findings = aggregate_findings(verdicts);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].kind, FindingKind::Fork);
        assert_eq!(findings[0].round, 11);
        assert_eq!(findings[1].kind, FindingKind::InsufficientCoverage);
        assert_eq!(findings[1].round, 12);
    }
}
