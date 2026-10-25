# aramidmain-consensus.json provenance

- Source: `docker/algod-relay/aramidmain/context-aramid/consensus.json` in https://github.com/scholtz/AlgorandNodes, commit `93bfe0d50376f64a52ec152c6e2146c74fe755f7` (fetched 2026-10-25), stored byte-for-byte.
- Defines the custom protocols `aramidmain-v1.0/1..3` (the chain runs `/3`; `/1` is the genesis protocol). The file also carries stale copies of the standard protocols (`future`, `v7`..`v12`, spec URLs) from an older go-algorand; algod-rust ignores those: the preset bundle only contributes protocols the binary does not already define (DIV-006).
- Embedded as `NetworkPreset::consensus_json` for `--network aramidmain` (`network_common.rs`); a `<data_dir>/consensus.json` is merged on top and wins per protocol version.
- Pinned by `crates/core/algo-types/tests/aramidmain_consensus_test.rs`.
- Line endings are pinned to LF (`.gitattributes` covers `bin/algod-rust/consensus/**`).
