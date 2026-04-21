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
//! ## Scope of THIS PR
//!
//! The Rust codec currently exposes a `pub` roundtrip API for:
//!
//!   * `UnauthenticatedVote`       (`uvote/`)
//!   * `UnauthenticatedBundle`     (`ubundle/`)
//!   * `Certificate` (= UBundle)   (`cert/`)
//!
//! Each is covered here with ≥20 fixtures.
//!
//! The remaining corpus subdirectories — `rawvote/`, `vote/`,
//! `bundle/`, `uproposal/`, `proposal/`, `tpayload/`,
//! `proposalvalue/` — require new encoders/decoders on the Rust
//! side that are out of scope for TASK-55. They're tracked as a
//! follow-up (see `SKIPPED_SUBDIRS_DOC`).

use std::fs;
use std::path::{Path, PathBuf};

use algo_agreement::codec::{decode_bundle, decode_vote, encode_bundle, encode_vote};

/// Path to the committed fixture tree from TASK-54.
fn fixture_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/wire");
    p
}

/// Documentation (rendered in the final test output) listing every
/// subdirectory whose roundtrip is NOT exercised yet and why.
/// Tracked as **TASK-60** — each subdir lights up here as its
/// encoder/decoder lands.
const SKIPPED_SUBDIRS_DOC: &str = "\
Roundtrip parity deferred to TASK-60 (extends agreement codec):
  rawvote/      — internal rawVote; no pub encoder/decoder in algo-agreement::codec.
  vote/         — authenticated Vote (committee::Credential); no Rust codec path.
  bundle/       — authenticated bundle; wraps authenticated votes + equivocationVotes.
  uproposal/    — UnauthenticatedProposal decode side not exposed (encode exists).
  proposal/     — same wire bytes as uproposal; same limitation.
  tpayload/     — transmittedPayload wraps uproposal + PriorVote; blocked on uproposal decode.
  proposalvalue/— private encode_proposal_value/decode_proposal_value helpers.
The fixture corpus is already committed from TASK-54 and each
subdir lights up here as TASK-60 adds the corresponding codec
path.";

/// First diverging byte offset, or `None` when equal.
fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    if a.len() != b.len() {
        return Some(a.len().min(b.len()));
    }
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
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

/// Documentation-as-test: a test that simply fails if somebody
/// silently deletes the follow-up-subdirs list. Keeping this as a
/// `#[test]` (instead of a doc comment) guarantees the note is
/// visible in `cargo test` output and in CI logs when the TASK-55
/// follow-up is scheduled.
#[test]
fn out_of_scope_subdirs_documented() {
    // Confirm every subdir documented as skipped actually exists
    // on disk — i.e. the corpus is there and ready for a future
    // codec expansion to light up. Missing a subdir listed here
    // fails loudly so we don't silently lose coverage by accident.
    let skipped = [
        "rawvote",
        "vote",
        "bundle",
        "uproposal",
        "proposal",
        "tpayload",
        "proposalvalue",
    ];
    for s in skipped {
        let p = fixture_root().join(s);
        assert!(
            p.is_dir(),
            "documented out-of-scope subdir {s:?} is missing from the fixture tree ({p:?}). \
             Regenerate with `cd tools/agreement-wire-capture && go run .`."
        );
    }
    eprintln!("codec_roundtrip scope:\n{SKIPPED_SUBDIRS_DOC}");
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
