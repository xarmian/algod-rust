//! Parity vs go-algorand `cmd/algokey/keyreg.go:93-98`.
//!
//! The four genesis hashes are part of the Algorand consensus
//! identity — any drift between Go's b64 strings and our in-memory
//! bytes would silently route keyreg transactions to the wrong
//! network. This fixture test pins the bytes by hex so a future typo
//! in the b64 source string shows up as a clear test failure.

use algo_types::{resolve_genesis_hash, Network};

/// Expected hex of each network's genesis hash. Computed as
/// `hex(base64_decode(b64))` where the b64 strings come from
/// `cmd/algokey/keyreg.go:93-98`.
const FIXTURES: &[(Network, &str)] = &[
    (
        Network::Mainnet,
        "c061c4d8fc1dbdded2d7604be4568e3f6d041987ac37bde4b620b5ab39248adf",
    ),
    (
        Network::Testnet,
        "4863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22",
    ),
    (
        Network::Betanet,
        "98581acc5fb6b914b5b4c88bf5db23d358491b248498f376f01fd38e3be9556d",
    ),
    (
        Network::Devnet,
        "b02dcfeded9275ba8a24ad2d6e209d2bdb5d4a96dee9778218a7683739a58f41",
    ),
];

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.to_ascii_lowercase()).expect("valid hex");
    bytes.try_into().expect("32 bytes")
}

#[test]
fn each_network_hash_matches_pinned_bytes() {
    for (net, expected_hex) in FIXTURES {
        let got = net.genesis_hash().0;
        let want = hex_to_32(expected_hex);
        assert_eq!(
            got,
            want,
            "genesis-hash divergence for {net:?}: \
             got {} expected {}",
            hex::encode(got),
            expected_hex
        );
    }
}

#[test]
fn resolve_returns_each_pinned_hash_by_name() {
    for (net, expected_hex) in FIXTURES {
        let resolved = resolve_genesis_hash(net.as_str()).expect("resolve");
        assert_eq!(resolved.0, hex_to_32(expected_hex));
    }
}
