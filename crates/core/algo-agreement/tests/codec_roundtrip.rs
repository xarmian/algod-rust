//! Agreement wire-codec roundtrip parity harness (Rust vs Go `msgp_gen`).
//!
//! For every Go-produced fixture under
//! `tests/fixtures/wire/<type>/*.msgpack` (captured by TASK-54 via
//! `tools/agreement-wire-capture`):
//!
//! 1. Decode through Rust's `algo_agreement::codec`.
//! 2. Re-encode via the same module.
//! 3. Assert the output bytes are **byte-identical** to the input.
//!
//! A divergence means canonical field ordering, `omitempty` handling,
//! or integer-width encoding has drifted between Rust and
//! `go-algorand/agreement/msgp_gen.go` — which silently changes vote /
//! cert hashes and breaks consensus. On mismatch the test fails with
//! fixture path, first diverging byte offset, the Rust-decoded struct
//! (Debug-printed), and a hex window around the divergence so the
//! encoder bug is localized without needing to regenerate the corpus.
//!
//! ## Coverage
//!
//! TASK-55 shipped roundtrip parity for the three outer envelope types
//! exposed by the initial public codec API:
//!   * `UnauthenticatedVote`       (`uvote/`)
//!   * `UnauthenticatedBundle`     (`ubundle/`)
//!   * `Certificate` (= UBundle)   (`cert/`)
//!
//! TASK-60 extends parity to every inner wire type captured in the
//! corpus:
//!   * `proposalValue`             (`proposalvalue/`)
//!   * `rawVote`                   (`rawvote/`)
//!   * authenticated `vote`        (`vote/`, uses `committee.Credential`)
//!   * authenticated `bundle`      (`bundle/`, wraps full `[]vote` / `[]equivocationVote`)
//!   * `unauthenticatedProposal`   (`uproposal/`)
//!   * `proposal`                  (`proposal/`, byte-identical to `uproposal`)
//!   * `transmittedPayload`        (`tpayload/`, = `uproposal` + `"pv"`)

use std::fs;
use std::path::{Path, PathBuf};

use algo_agreement::codec::{
    decode_authenticated_bundle, decode_authenticated_vote, decode_bundle, decode_compound_message,
    decode_proposalvalue, decode_rawvote, decode_unauthenticated_proposal, decode_vote,
    encode_authenticated_bundle, encode_authenticated_vote, encode_bundle, encode_compound_message,
    encode_proposalvalue, encode_rawvote, encode_unauthenticated_proposal, encode_vote,
};

/// Path to the committed fixture tree from TASK-54.
fn fixture_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/wire");
    p
}

/// First diverging byte offset, or `None` when `a` and `b` are
/// identical. When lengths differ AND the shared prefix is
/// identical, returns the shared-prefix length (the offset where
/// one side simply ran out). When the shared prefix already
/// disagrees, returns the earliest offset at which they differ —
/// so the panic report's hex window always frames the actual
/// divergence, not the tail truncation (Codex P2 on PR #229).
fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    let common = a.len().min(b.len());
    for i in 0..common {
        if a[i] != b[i] {
            return Some(i);
        }
    }
    if a.len() != b.len() {
        Some(common)
    } else {
        None
    }
}

#[cfg(test)]
mod first_diff_tests {
    use super::first_diff;

    #[test]
    fn identical_buffers_return_none() {
        assert_eq!(first_diff(&[1, 2, 3], &[1, 2, 3]), None);
        assert_eq!(first_diff(&[], &[]), None);
    }

    #[test]
    fn prefix_differs_first_returns_prefix_offset_even_if_lengths_differ() {
        // Codex P2 regression guard: lengths differ AND buffers
        // disagree at offset 1 — must report 1, not min(3,4)=3.
        assert_eq!(first_diff(&[0, 9, 2], &[0, 2, 2, 2]), Some(1));
    }

    #[test]
    fn equal_prefix_different_lengths_returns_shared_length() {
        assert_eq!(first_diff(&[1, 2, 3], &[1, 2, 3, 4]), Some(3));
        assert_eq!(first_diff(&[1, 2, 3, 4], &[1, 2, 3]), Some(3));
    }

    #[test]
    fn same_length_different_middle_returns_middle() {
        assert_eq!(first_diff(&[1, 2, 3, 4], &[1, 2, 9, 4]), Some(2));
    }

    #[test]
    fn differ_at_zero() {
        assert_eq!(first_diff(&[9], &[0]), Some(0));
        assert_eq!(first_diff(&[9, 0, 0], &[0, 0, 0, 0]), Some(0));
    }

    #[test]
    fn empty_vs_nonempty_returns_zero() {
        // Shared prefix length is 0, lengths differ → report 0.
        assert_eq!(first_diff(&[], &[1, 2]), Some(0));
        assert_eq!(first_diff(&[1, 2], &[]), Some(0));
    }
}

/// Format a hex window of `size` bytes centered on `offset` for
/// human-readable divergence reports — clamped to slice bounds.
fn hex_window(bytes: &[u8], offset: usize, size: usize) -> String {
    let half = size / 2;
    let start = offset.saturating_sub(half);
    let end = (offset + half).min(bytes.len());
    hex::encode(&bytes[start..end])
}

/// Run the decode → re-encode → byte-compare check on every
/// `<name>.msgpack` file under `<fixture_root>/<subdir>/`. `decoder`
/// is responsible for parsing to the Rust struct; `encoder`
/// serializes it back to bytes. On mismatch panics with enough
/// context to debug the codec bug without re-running any tools.
fn run_subdir_roundtrip<D: core::fmt::Debug>(
    subdir: &str,
    decoder: impl Fn(&[u8]) -> Result<D, String>,
    encoder: impl Fn(&D) -> Vec<u8>,
    min_fixtures: usize,
) -> usize {
    let dir = fixture_root().join(subdir);
    let entries = fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "cannot read fixture subdir {dir:?}: {e}. \
             Run `cd tools/agreement-wire-capture && go run .` to regenerate."
        )
    });

    let mut matched = 0usize;
    for entry in entries {
        let path = entry.expect("read_dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("msgpack") {
            continue;
        }

        let input = fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let decoded = decoder(&input).unwrap_or_else(|e| {
            panic!(
                "DECODE FAILED for {path:?}:\n  error: {e}\n  \
                 input_len: {len} bytes\n  input_head: {head}",
                len = input.len(),
                head = hex_window(&input, 0, 64),
            )
        });
        let re_encoded = encoder(&decoded);

        if let Some(off) = first_diff(&input, &re_encoded) {
            panic!(
                "ROUNDTRIP MISMATCH for {path:?}\n  \
                 go_bytes   = {go_hex}\n  \
                 rust_bytes = {rust_hex}\n  \
                 go_len     = {go_len}\n  \
                 rust_len   = {rust_len}\n  \
                 first diverging byte offset: {off}\n  \
                 go_window   (32 bytes around offset): {gow}\n  \
                 rust_window (32 bytes around offset): {rw}\n  \
                 decoded: {decoded:#?}",
                go_hex = hex_window(&input, 0, 80),
                rust_hex = hex_window(&re_encoded, 0, 80),
                go_len = input.len(),
                rust_len = re_encoded.len(),
                off = off,
                gow = hex_window(&input, off, 32),
                rw = hex_window(&re_encoded, off, 32),
            );
        }
        matched += 1;
    }

    assert!(
        matched >= min_fixtures,
        "subdir {subdir:?} has only {matched} fixtures (need \u{2265}{min_fixtures}). \
         Regenerate with `cd tools/agreement-wire-capture && go run .`."
    );
    matched
}

/// Convenience: wrap a `CodecError`-returning decoder so the
/// runner's uniform `Fn(&[u8]) -> Result<D, String>` signature
/// applies regardless of concrete error type.
fn as_string_err<T, E: core::fmt::Debug>(r: Result<T, E>) -> Result<T, String> {
    r.map_err(|e| format!("{e:?}"))
}

#[test]
fn uvote_roundtrip_vs_go() {
    let n = run_subdir_roundtrip("uvote", |b| as_string_err(decode_vote(b)), encode_vote, 20);
    eprintln!("uvote_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

#[test]
fn ubundle_roundtrip_vs_go() {
    let n = run_subdir_roundtrip(
        "ubundle",
        |b| as_string_err(decode_bundle(b)),
        encode_bundle,
        20,
    );
    eprintln!("ubundle_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

#[test]
fn cert_roundtrip_vs_go() {
    // Go: `type Certificate unauthenticatedBundle` — the named-type
    // conversion yields byte-identical msgpack. Rust's codec
    // doesn't have a distinct Certificate type (yet), so
    // round-tripping through the `UnauthenticatedBundle`
    // encode/decode pair is correct today.
    let n = run_subdir_roundtrip(
        "cert",
        |b| as_string_err(decode_bundle(b)),
        encode_bundle,
        20,
    );
    eprintln!("cert_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

// ── Inner wire types (TASK-60) ────────────────────────────────────────────

#[test]
fn proposalvalue_roundtrip_vs_go() {
    // Inner schema anchor — the TASK-54 capture intentionally ships a
    // small corpus here (3 fixtures). The broader ≥20-per-subdir
    // convention applies to envelope types only; proposalValue is
    // exercised transitively by rawvote/vote/bundle fixtures.
    let n = run_subdir_roundtrip(
        "proposalvalue",
        |b| as_string_err(decode_proposalvalue(b)),
        encode_proposalvalue,
        3,
    );
    eprintln!("proposalvalue_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

#[test]
fn rawvote_roundtrip_vs_go() {
    let n = run_subdir_roundtrip(
        "rawvote",
        |b| as_string_err(decode_rawvote(b)),
        encode_rawvote,
        20,
    );
    eprintln!("rawvote_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

#[test]
fn vote_roundtrip_vs_go() {
    // Authenticated vote: same top-level shape as unauthenticatedVote
    // ("cred", "r", "sig") but `cred` is a full committee.Credential
    // sub-map (ds/h/hc/pf/wt).
    let n = run_subdir_roundtrip(
        "vote",
        |b| as_string_err(decode_authenticated_vote(b)),
        encode_authenticated_vote,
        20,
    );
    eprintln!("vote_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

#[test]
fn bundle_roundtrip_vs_go() {
    // Authenticated bundle: wraps an UnauthenticatedBundle under "u"
    // plus full []vote / []equivocationVote arrays (each carrying its
    // own Credential and OTS signatures).
    let n = run_subdir_roundtrip(
        "bundle",
        |b| as_string_err(decode_authenticated_bundle(b)),
        encode_authenticated_bundle,
        20,
    );
    eprintln!("bundle_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

#[test]
fn uproposal_roundtrip_vs_go() {
    let n = run_subdir_roundtrip(
        "uproposal",
        |b| as_string_err(decode_unauthenticated_proposal(b)),
        encode_unauthenticated_proposal,
        20,
    );
    eprintln!("uproposal_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

#[test]
fn proposal_roundtrip_vs_go() {
    // Go: `type proposal struct { unauthenticatedProposal; ve; validatedAt }`
    // `ve` and `validatedAt` are unserialized, so the wire bytes are
    // byte-identical to `unauthenticatedProposal`. The Rust codec has
    // no distinct Proposal type — round-tripping via the uproposal
    // codec is correct.
    let n = run_subdir_roundtrip(
        "proposal",
        |b| as_string_err(decode_unauthenticated_proposal(b)),
        encode_unauthenticated_proposal,
        20,
    );
    eprintln!("proposal_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

#[test]
fn tpayload_roundtrip_vs_go() {
    // transmittedPayload embeds unauthenticatedProposal and adds a
    // `"pv"` key carrying an unauthenticatedVote (omitempty). The
    // existing encode/decode_compound_message pair already handles
    // both shapes (with and without a prior vote).
    let n = run_subdir_roundtrip(
        "tpayload",
        |b| as_string_err(decode_compound_message(b)),
        encode_compound_message,
        20,
    );
    eprintln!("tpayload_roundtrip_vs_go: {n} fixtures matched byte-for-byte");
}

/// Minimal sanity — every .msgpack file in a guarded subdir has
/// non-zero bytes (a zero-length fixture would indicate capture
/// corruption, and the current corpus has no such cases). This
/// runs against every `msgpack` file under the whole fixture tree
/// and is cheap.
#[test]
fn every_fixture_is_nonempty() {
    fn walk(dir: &Path, fixtures: &mut usize) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, fixtures);
            } else if path.extension().and_then(|s| s.to_str()) == Some("msgpack") {
                let meta = fs::metadata(&path).unwrap();
                assert!(
                    meta.len() >= 1,
                    "empty fixture: {path:?} (regeneration likely failed mid-way)"
                );
                *fixtures += 1;
            }
        }
    }
    let mut fixtures = 0usize;
    walk(&fixture_root(), &mut fixtures);
    assert!(
        fixtures >= 180,
        "whole-tree fixture count {fixtures} < 180 (expected 10 subdirs \u{00d7} ~20 each)"
    );
    eprintln!("every_fixture_is_nonempty: {fixtures} .msgpack files, all \u{2265}1 byte");
}
