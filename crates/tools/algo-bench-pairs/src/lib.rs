// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rust half of the paired Go/Rust micro-benchmark suite (issue #2103,
//! epic #2101).
//!
//! Every pair id of `benchmarks/pairs.toml` has one [`Case`] here and one in
//! the Go module `benchmarks/go-micro` (`micro/cases.go`). Both read the same
//! fixture from `benchmarks/fixtures/micro/` and run the production function
//! of their implementation on it. A case has two halves sharing one
//! implementation of the operation:
//!
//! * [`Case::run`] runs it once: the body criterion measures
//!   (`benches/pairs.rs`), setup excluded;
//! * [`Case::digest`] runs it once and describes the output in the same
//!   canonical text form the Go side uses (`sha256:<hex>` of re-encoded
//!   bytes, `hex:<digest>`, `valid:<verdict>`, `pass:..;cost:..;logs:..`).
//!   `micro-equiv` prints every digest and the micro tier fails when one
//!   differs from Go's; `tests/equivalence.rs` checks them against the
//!   Go-recorded `benchmarks/fixtures/micro/go-digests.json`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha256, Sha512_256};

use algo_agreement::codec::{
    decode_bundle, decode_compound_message, encode_bundle, encode_compound_message,
};
use algo_agreement::{Membership, Period, Seed, Selector, Step, UnauthenticatedCredential};
use algo_avm::eval::{run_approval_program, run_logicsig_program, AvmResult};
use algo_avm::logicsig_context::LogicSigAvmContext;
use algo_avm::GroupBudget;
use algo_codec::{
    canonical_encode_block, canonical_encode_signed_transaction, compute_block_digest,
    compute_txn_id, decode_block, decode_signed_txn_stream,
};
use algo_ledger::{LedgerAvmContext, LedgerState};
use algo_types::{
    consensus_params_for_version, Address, AppParams, Block, BoxRef, ConsensusParams, LogicSig,
    Round, SignedTransaction, StateSchema, TealValue, Transaction, CONSENSUS_CURRENT_VERSION,
};
use algo_validate::merkle::{compute_payset_merkle_root, compute_vector_commitment, HashAlgo};
use algo_validate::verify_single_sig;

/// Every pair id, sorted (the same list as Go's `micro.IDs()`).
pub const IDS: &[&str] = &[
    "agreement/credential-verify",
    "agreement/decode-cert",
    "agreement/decode-proposal",
    "agreement/sortition-select",
    "agreement/sortition-select-f128",
    "avm/app-state-box",
    "avm/lsig-arith-loop",
    "avm/lsig-bytes-ops",
    "avm/lsig-hash-loop",
    "codec/block-hash",
    "codec/decode-block-large",
    "codec/decode-block-small",
    "codec/decode-stxn",
    "codec/encode-block-large",
    "codec/encode-block-small",
    "codec/encode-stxn",
    "codec/txid",
    "commit/txn-merkle-sha512_256",
    "commit/txn-vc-sha256",
    "crypto/ed25519-batch-1024",
    "crypto/ed25519-batch-64",
    "crypto/ed25519-verify",
    "crypto/falcon-verify",
    "crypto/sha512_256-1KiB",
    "crypto/sha512_256-32B",
    "crypto/sha512_256-64KiB",
    "crypto/vrf-verify",
];

/// Application id of `avm/app-state-box` (Go: `micro.AppID`).
pub const APP_ID: u64 = 1001;
/// The box `avm/app-state-box` rewrites; it exists before every evaluation.
pub const APP_BOX_NAME: &[u8] = b"box";
/// Size of [`APP_BOX_NAME`].
pub const APP_BOX_SIZE: usize = 64;
/// Fixed addresses shared with the Go side (`micro.LsigSender` etc.).
pub const LSIG_SENDER: Address = Address([0x11; 32]);
/// Sender of the `avm/app-state-box` app call.
pub const APP_SENDER: Address = Address([0x22; 32]);
/// Creator of application [`APP_ID`].
pub const APP_CREATOR: Address = Address([0x33; 32]);

/// Every fallible call of this crate reports a rendered error.
pub type Result<T> = std::result::Result<T, String>;

/// One side of a pair.
pub struct Case {
    /// The pair id.
    pub id: &'static str,
    op: Box<dyn FnMut()>,
    digest: Box<dyn FnMut() -> Result<String>>,
    /// Restores the starting state of a stateful pair (only
    /// `avm/app-state-box`). Every benchmark iteration on both sides is
    /// reset + operation; see [`Case::bench_iteration`].
    reset: Option<Box<dyn FnMut()>>,
}

impl Case {
    /// Run the measured operation once (no reset). Panics if it fails: a
    /// failing benchmark measures nothing.
    pub fn run(&mut self) {
        (self.op)()
    }

    /// Whether this case has per-iteration state to restore.
    pub fn has_reset(&self) -> bool {
        self.reset.is_some()
    }

    /// Restore the case's starting state (no-op for stateless cases).
    pub fn reset(&mut self) {
        if let Some(r) = self.reset.as_mut() {
            r()
        }
    }

    /// One benchmark iteration exactly as both sides time it: reset, then
    /// the operation. The reset is inside the timed region on purpose, on
    /// both sides: it is tiny (an 8-entry map clear and a 64-byte zero)
    /// next to the ~15 us app call, while go's only way to exclude it,
    /// `b.StopTimer`/`StartTimer` with `ReportAllocs`, runs
    /// `runtime.ReadMemStats` twice per iteration and inflated the measured
    /// call by ~10-25%.
    pub fn bench_iteration(&mut self) {
        self.reset();
        self.run();
    }

    /// Evaluate once the way a benchmark iteration does (reset, then the
    /// operation) and describe its output.
    pub fn digest(&mut self) -> Result<String> {
        self.reset();
        (self.digest)()
    }
}

/// `benchmarks/fixtures/micro/`, or `$ALGOD_MICRO_FIXTURES` when set.
pub fn fixture_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("ALGOD_MICRO_FIXTURES") {
        return PathBuf::from(d);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../benchmarks/fixtures/micro")
}

/// Load the fixture of pair `id` from `dir` and return its case.
pub fn build(dir: &Path, id: &str) -> Result<Case> {
    let id: &'static str = IDS
        .iter()
        .copied()
        .find(|i| *i == id)
        .ok_or_else(|| format!("unknown pair {id:?}"))?;
    let mut reset: Option<Box<dyn FnMut()>> = None;
    let (op, digest) = match id {
        "codec/decode-block-small" => decode_block_case(dir, "block-small.msgpack")?,
        "codec/decode-block-large" => decode_block_case(dir, "block-large.msgpack")?,
        "codec/encode-block-small" => encode_block_case(dir, "block-small.msgpack")?,
        "codec/encode-block-large" => encode_block_case(dir, "block-large.msgpack")?,
        "codec/decode-stxn" => decode_stxn_case(dir)?,
        "codec/encode-stxn" => encode_stxn_case(dir)?,
        "codec/txid" => txid_case(dir)?,
        "codec/block-hash" => block_hash_case(dir)?,
        "crypto/sha512_256-32B" => sha512_256_case(dir, "bytes-32.bin")?,
        "crypto/sha512_256-1KiB" => sha512_256_case(dir, "bytes-1k.bin")?,
        "crypto/sha512_256-64KiB" => sha512_256_case(dir, "bytes-64k.bin")?,
        "crypto/ed25519-verify" => ed25519_verify_case(dir)?,
        "crypto/ed25519-batch-64" => ed25519_batch_case(dir, "stxns-64.msgpack")?,
        "crypto/ed25519-batch-1024" => ed25519_batch_case(dir, "stxns-1024.msgpack")?,
        "crypto/vrf-verify" => vrf_case(dir)?,
        "crypto/falcon-verify" => falcon_case(dir)?,
        "commit/txn-merkle-sha512_256" => merkle_case(dir)?,
        "commit/txn-vc-sha256" => vector_commitment_case(dir)?,
        "avm/lsig-arith-loop" => lsig_case(dir, "avm-arith.bin")?,
        "avm/lsig-hash-loop" => lsig_case(dir, "avm-hash.bin")?,
        "avm/lsig-bytes-ops" => lsig_case(dir, "avm-bytes.bin")?,
        "avm/app-state-box" => {
            let (op, digest, r) = app_case(dir, "avm-app.bin")?;
            reset = r;
            (op, digest)
        }
        "agreement/sortition-select" => sortition_case(dir, false)?,
        "agreement/sortition-select-f128" => sortition_case(dir, true)?,
        "agreement/credential-verify" => credential_case(dir)?,
        "agreement/decode-cert" => decode_cert_case(dir)?,
        "agreement/decode-proposal" => decode_proposal_case(dir)?,
        _ => return Err(format!("pair {id:?} has no Rust case")),
    };
    Ok(Case {
        id,
        op,
        digest,
        reset,
    })
}

/// Every pair's digest, keyed by id (what `micro-equiv` prints). A pair whose
/// digest changes after a few benchmark iterations reports `error:`.
pub fn all_digests(dir: &Path) -> BTreeMap<String, String> {
    IDS.iter()
        .map(|id| {
            let d = build(dir, id)
                .and_then(|mut c| {
                    let fresh = c.digest()?;
                    // The digest must not drift across benchmark iterations.
                    for _ in 0..3 {
                        c.bench_iteration();
                    }
                    let again = c.digest()?;
                    if again != fresh {
                        return Err(format!(
                            "digest drifts after repeated iterations: {again:?}, fresh {fresh:?}"
                        ));
                    }
                    Ok(fresh)
                })
                .unwrap_or_else(|e| format!("error:{e}"));
            (id.to_string(), d)
        })
        .collect()
}

type Pair = (Box<dyn FnMut()>, Box<dyn FnMut() -> Result<String>>);

// --- helpers -----------------------------------------------------------------

fn read(dir: &Path, name: &str) -> Result<Vec<u8>> {
    let p = dir.join(name);
    std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))
}

fn sha256_hex(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}

/// Split a framed fixture: a sequence of u32 little-endian length + bytes
/// (Go: `micro.Frames`).
pub fn frames(mut b: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 4 {
            return Err("truncated frame header".into());
        }
        let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        b = &b[4..];
        if b.len() < n {
            return Err("truncated frame".into());
        }
        out.push(b[..n].to_vec());
        b = &b[n..];
    }
    Ok(out)
}

fn current_proto() -> Result<ConsensusParams> {
    consensus_params_for_version(CONSENSUS_CURRENT_VERSION)
        .ok_or_else(|| format!("no consensus params for {CONSENSUS_CURRENT_VERSION}"))
}

fn load_block(dir: &Path, file: &str) -> Result<Block> {
    decode_block(&read(dir, file)?).map_err(|e| format!("{file}: {e}"))
}

fn load_stxn(dir: &Path) -> Result<SignedTransaction> {
    let mut v = decode_signed_txn_stream(&read(dir, "stxn-appl.msgpack")?)
        .map_err(|e| format!("stxn-appl.msgpack: {e}"))?;
    if v.len() != 1 {
        return Err(format!(
            "stxn-appl.msgpack: {} transactions, want 1",
            v.len()
        ));
    }
    Ok(v.remove(0))
}

fn unhex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.try_into()
        .map_err(|b: Vec<u8>| format!("hex field: want {N} bytes, got {}", b.len()))
}

// --- codec -------------------------------------------------------------------

fn decode_block_case(dir: &Path, file: &'static str) -> Result<Pair> {
    let data = read(dir, file)?;
    decode_block(&data).map_err(|e| format!("{file}: {e}"))?;
    let d2 = data.clone();
    Ok((
        Box::new(move || {
            let b = decode_block(black_box(&data)).expect("decode_block");
            black_box(b.round);
        }),
        Box::new(move || {
            let b = decode_block(&d2).map_err(|e| e.to_string())?;
            Ok(sha256_hex(&canonical_encode_block(&b)))
        }),
    ))
}

/// `canonical_encode_block` is the go-canonical encoder (stored block bytes,
/// `GET /v2/blocks`); `algo_codec::encode_block` is the rmp-serde debug path.
fn encode_block_case(dir: &Path, file: &'static str) -> Result<Pair> {
    let block = load_block(dir, file)?;
    let b2 = block.clone();
    Ok((
        Box::new(move || {
            black_box(canonical_encode_block(black_box(&block)));
        }),
        Box::new(move || Ok(sha256_hex(&canonical_encode_block(&b2)))),
    ))
}

/// Decode exactly one msgpack `SignedTransaction`, the way the gossip
/// transaction handler and the in-block payset decoder do
/// (`SignedTransaction::decode_from_reader`); the counterpart of go's
/// `protocol.Decode(b, &transactions.SignedTxn{})`, which also rejects
/// trailing bytes.
pub fn decode_one_stxn(data: &[u8]) -> Result<SignedTransaction> {
    let mut rd = data;
    let s = SignedTransaction::decode_from_reader(&mut rd).map_err(|e| e.to_string())?;
    if !rd.is_empty() {
        return Err(format!("{} trailing bytes after the transaction", rd.len()));
    }
    Ok(s)
}

fn decode_stxn_case(dir: &Path) -> Result<Pair> {
    let data = read(dir, "stxn-appl.msgpack")?;
    decode_one_stxn(&data)?;
    let d2 = data.clone();
    Ok((
        Box::new(move || {
            black_box(decode_one_stxn(black_box(&data)).expect("decode stxn"));
        }),
        Box::new(move || {
            let s = decode_one_stxn(&d2)?;
            Ok(sha256_hex(&canonical_encode_signed_transaction(&s)))
        }),
    ))
}

fn encode_stxn_case(dir: &Path) -> Result<Pair> {
    let s = load_stxn(dir)?;
    let s2 = s.clone();
    Ok((
        Box::new(move || {
            black_box(canonical_encode_signed_transaction(black_box(&s)));
        }),
        Box::new(move || Ok(sha256_hex(&canonical_encode_signed_transaction(&s2)))),
    ))
}

fn txid_case(dir: &Path) -> Result<Pair> {
    let s = load_stxn(dir)?;
    let t2 = s.txn.clone();
    let t = s.txn;
    Ok((
        Box::new(move || {
            black_box(compute_txn_id(black_box(&t)));
        }),
        Box::new(move || Ok(format!("hex:{}", hex::encode(compute_txn_id(&t2).0)))),
    ))
}

fn block_hash_case(dir: &Path) -> Result<Pair> {
    let block = load_block(dir, "block-large.msgpack")?;
    let b2 = block.clone();
    Ok((
        Box::new(move || {
            black_box(compute_block_digest(black_box(&block)));
        }),
        Box::new(move || Ok(format!("hex:{}", hex::encode(compute_block_digest(&b2).0)))),
    ))
}

// --- crypto ------------------------------------------------------------------

fn sha512_256_case(dir: &Path, file: &str) -> Result<Pair> {
    let data = read(dir, file)?;
    let d2 = data.clone();
    Ok((
        Box::new(move || {
            black_box(Sha512_256::digest(black_box(&data)));
        }),
        Box::new(move || Ok(format!("hex:{}", hex::encode(Sha512_256::digest(&d2))))),
    ))
}

fn ed25519_verify_case(dir: &Path) -> Result<Pair> {
    let s = load_stxn(dir)?;
    let s2 = s.clone();
    Ok((
        Box::new(move || verify_single_sig(black_box(&s)).expect("signature verifies")),
        Box::new(move || Ok(format!("valid:{}", verify_single_sig(&s2).is_ok()))),
    ))
}

/// Rust has no ed25519 batch verifier: the production path verifies each
/// transaction signature with `verify_single_sig` (go-algorand's default
/// `cgoBatchVerifier` also verifies one by one, `useSingleVerifierDefault`).
fn ed25519_batch_case(dir: &Path, file: &str) -> Result<Pair> {
    let stxns = decode_signed_txn_stream(&read(dir, file)?).map_err(|e| format!("{file}: {e}"))?;
    let s2 = stxns.clone();
    Ok((
        Box::new(move || {
            for s in black_box(&stxns) {
                verify_single_sig(s).expect("signature verifies");
            }
        }),
        Box::new(move || {
            let valid = s2.iter().filter(|s| verify_single_sig(s).is_ok()).count();
            Ok(format!("valid:{valid}/{}", s2.len()))
        }),
    ))
}

fn vrf_case(dir: &Path) -> Result<Pair> {
    let f = frames(&read(dir, "vrf.frames")?)?;
    if f.len() != 3 {
        return Err("vrf.frames: want pk, proof, alpha".into());
    }
    let pk: [u8; 32] = f[0].clone().try_into().map_err(|_| "vrf pk size")?;
    let proof: [u8; 80] = f[1].clone().try_into().map_err(|_| "vrf proof size")?;
    let alpha = f[2].clone();
    let a2 = alpha.clone();
    use algo_consensus_crypto::vrf::vrf_verify;
    Ok((
        Box::new(move || {
            black_box(vrf_verify(black_box(&pk), &proof, &alpha).expect("vrf proof verifies"));
        }),
        Box::new(move || {
            Ok(match vrf_verify(&pk, &proof, &a2) {
                Some(out) => format!("vrf:{}", hex::encode(out)),
                None => "vrf:invalid".into(),
            })
        }),
    ))
}

/// DIV-001: algod-rust's default Falcon backend is the pure-Rust det1024
/// port; go-algorand links the C library.
fn falcon_case(dir: &Path) -> Result<Pair> {
    let f = frames(&read(dir, "falcon.frames")?)?;
    if f.len() != 3 {
        return Err("falcon.frames: want pk, sig, msg".into());
    }
    let (pk, sig, msg) = (f[0].clone(), f[1].clone(), f[2].clone());
    let (pk2, sig2, msg2) = (pk.clone(), sig.clone(), msg.clone());
    Ok((
        Box::new(move || {
            assert!(
                algo_falcon::falcon_verify(black_box(&pk), &sig, &msg).expect("falcon inputs"),
                "falcon signature verifies"
            );
        }),
        Box::new(move || {
            let ok = algo_falcon::falcon_verify(&pk2, &sig2, &msg2).unwrap_or(false);
            Ok(format!("valid:{ok}"))
        }),
    ))
}

// --- commitments -------------------------------------------------------------

fn merkle_case(dir: &Path) -> Result<Pair> {
    let block = load_block(dir, "block-large.msgpack")?;
    let b2 = block.clone();
    Ok((
        Box::new(move || {
            black_box(compute_payset_merkle_root(black_box(&block)));
        }),
        Box::new(move || {
            Ok(format!(
                "hex:{}",
                hex::encode(compute_payset_merkle_root(&b2))
            ))
        }),
    ))
}

fn vector_commitment_case(dir: &Path) -> Result<Pair> {
    let block = load_block(dir, "block-large.msgpack")?;
    let b2 = block.clone();
    Ok((
        Box::new(move || {
            black_box(compute_vector_commitment(
                black_box(&block),
                HashAlgo::Sha256,
            ));
        }),
        Box::new(move || {
            Ok(format!(
                "hex:{}",
                hex::encode(compute_vector_commitment(&b2, HashAlgo::Sha256))
            ))
        }),
    ))
}

// --- AVM ---------------------------------------------------------------------

/// The one-transaction group whose logicsig is `program` (Go:
/// `micro.LsigGroup`).
pub fn lsig_group(program: &[u8]) -> Vec<SignedTransaction> {
    vec![SignedTransaction {
        lsig: Some(LogicSig {
            logic: ByteBuf::from(program.to_vec()),
            ..Default::default()
        }),
        txn: Transaction {
            txn_type: "pay".into(),
            sender: LSIG_SENDER,
            fee: 1000,
            first_valid: Round(1000),
            last_valid: Round(2000),
            receiver: APP_SENDER,
            amount: 1,
            ..Default::default()
        },
        ..Default::default()
    }]
}

/// Evaluate `program` as the logicsig of `group[0]` the way
/// `algo_validate::verify_logicsig` does: returns (pass, opcode cost).
///
/// `LogicSigAvmContext::new` takes `ConsensusParams` by value (including
/// its `approved_upgrades` map), so production (`signature.rs`,
/// `consensus.clone()`) clones it on every logicsig evaluation; the clone
/// stays in the timed body on purpose, as a real algod-rust cost (perf note
/// for #2110 in #2114). go-algorand's `NewSigEvalParams` takes `&proto`.
pub fn eval_lsig(
    group: &[SignedTransaction],
    program: &[u8],
    proto: &ConsensusParams,
) -> Result<(bool, i64)> {
    let mut ctx = LogicSigAvmContext::new(group, 0, program, Vec::new(), proto.clone());
    let mut budget = GroupBudget::for_logicsig(group.len());
    let before = budget.remaining();
    let pass = run_logicsig_program(program, &mut ctx, &mut budget).map_err(|e| e.to_string())?;
    Ok((pass, before - budget.remaining()))
}

fn lsig_case(dir: &Path, file: &str) -> Result<Pair> {
    let program = read(dir, file)?;
    let proto = current_proto()?;
    let group = lsig_group(&program);
    let (p2, pr2, g2) = (program.clone(), proto.clone(), group.clone());
    Ok((
        Box::new(move || {
            let (pass, _) = eval_lsig(black_box(&group), &program, &proto).expect("lsig eval");
            assert!(pass, "logicsig rejected");
        }),
        Box::new(move || {
            let (pass, cost) = eval_lsig(&g2, &p2, &pr2)?;
            Ok(format!("pass:{pass};cost:{cost}"))
        }),
    ))
}

/// The one-transaction app-call group of `avm/app-state-box` (Go:
/// `micro.AppGroup`).
pub fn app_group() -> Vec<SignedTransaction> {
    vec![SignedTransaction {
        txn: Transaction {
            txn_type: "appl".into(),
            sender: APP_SENDER,
            fee: 1000,
            first_valid: Round(1000),
            last_valid: Round(2000),
            application_id: APP_ID,
            boxes: Some(vec![BoxRef {
                index: 0,
                name: Some(ByteBuf::from(APP_BOX_NAME.to_vec())),
            }]),
            ..Default::default()
        },
        ..Default::default()
    }]
}

/// Evaluates the app program against an in-memory `LedgerState` holding the
/// application and its box (Go: `micro.AppRunner`).
///
/// `LedgerAvmContext::app_global_put` / `box_put` write straight into the
/// store, so every evaluation leaves global state and the box behind.
/// [`AppRunner::reset`] restores the starting state (empty global state, a
/// zeroed box) and every benchmark iteration starts with it
/// ([`Case::bench_iteration`]), exactly like the Go side's `Reset`.
pub struct AppRunner {
    program: Vec<u8>,
    proto: ConsensusParams,
    group: Vec<SignedTransaction>,
    store: LedgerState,
}

/// One evaluation of the app pair, in the shared digest vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppOutcome {
    /// Program approved.
    pub pass: bool,
    /// Opcode cost consumed.
    pub cost: i64,
    /// `globals=<n>,box=<sha256 prefix>`: the ledger state the evaluation
    /// started from.
    pub pre: String,
    /// The global-state delta, `<hex key>=u<n>|b<hex>|del`, sorted by key.
    pub gdelta: String,
    /// Logs, hex.
    pub logs: Vec<String>,
}

impl AppOutcome {
    /// The pair's digest (same format as the Go side's).
    pub fn digest(&self) -> String {
        format!(
            "pass:{};cost:{};pre:{};gdelta:{};logs:{}",
            self.pass,
            self.cost,
            self.pre,
            self.gdelta,
            self.logs.join(",")
        )
    }
}

impl AppRunner {
    /// Prepare `program` for repeated evaluation.
    pub fn new(program: Vec<u8>) -> Result<Self> {
        let mut store = LedgerState::new();
        store.app_params.insert(
            APP_ID,
            AppParams {
                creator: APP_CREATOR,
                approval_program: program.clone(),
                global_state_schema: StateSchema {
                    num_uint: 16,
                    num_byte_slice: 16,
                },
                ..Default::default()
            },
        );
        store
            .boxes
            .insert((APP_ID, APP_BOX_NAME.to_vec()), vec![0u8; APP_BOX_SIZE]);
        Ok(AppRunner {
            program,
            proto: current_proto()?,
            group: app_group(),
            store,
        })
    }

    /// Restore the starting state: no global state, a zeroed box.
    pub fn reset(&mut self) {
        if let Some(p) = self.store.app_params.get_mut(&APP_ID) {
            p.global_state.clear();
        }
        let b = self
            .store
            .boxes
            .entry((APP_ID, APP_BOX_NAME.to_vec()))
            .or_default();
        b.clear();
        b.resize(APP_BOX_SIZE, 0);
    }

    fn pre_state(&self) -> String {
        let globals = self
            .store
            .app_params
            .get(&APP_ID)
            .map_or(0, |p| p.global_state.len());
        let bx = self
            .store
            .boxes
            .get(&(APP_ID, APP_BOX_NAME.to_vec()))
            .map(|b| hex::encode(&Sha256::digest(b)[..8]))
            .unwrap_or_else(|| "none".into());
        format!("globals={globals},box={bx}")
    }

    /// Evaluate once, as `algo_ledger::apply` does for a top-level app call,
    /// from whatever state the store is in: the measured operation, no
    /// digest bookkeeping. Returns the AVM result and the opcode cost.
    ///
    /// `LedgerAvmContext::new` takes the group and the consensus params by
    /// value, so production (`apply.rs`, which builds the group with
    /// `build_avm_group` and passes `ctx.consensus.clone()`) pays both
    /// clones on every app call; they stay in the timed body on purpose
    /// (perf note for #2110 in #2114). go-algorand's `NewAppEvalParams`
    /// copies the group too (`copyWithClearAD`) but takes `&proto`.
    pub fn eval(&mut self) -> Result<(AvmResult, i64)> {
        let mut ctx = LedgerAvmContext::new(
            &mut self.store,
            self.group.clone(),
            0,
            1000,
            1_700_000_000,
            APP_ID,
            APP_CREATOR.0,
            true,
            program_hash(&self.program),
            [0u8; 32],
            self.proto.clone(),
            0,
        );
        ctx.set_program_version(self.program.first().copied().unwrap_or(0));
        ctx.init_top_level_sharing();
        let mut budget = GroupBudget::new(1);
        let before = budget.remaining();
        let r = run_approval_program(&self.program, &mut ctx, &mut budget)
            .map_err(|e| e.to_string())?;
        if let Some(e) = &r.error {
            return Err(e.clone());
        }
        let cost = before - budget.remaining();
        Ok((r, cost))
    }

    /// Evaluate once and describe the evaluation, including the state it
    /// started from.
    pub fn run(&mut self) -> Result<AppOutcome> {
        let pre = self.pre_state();
        let (r, cost) = self.eval()?;
        let mut gdelta: Vec<String> = r
            .global_delta
            .iter()
            .map(|(k, v)| {
                let v = match v {
                    Some(TealValue::Uint(u)) => format!("u{u}"),
                    Some(TealValue::Bytes(b)) => format!("b{}", hex::encode(b)),
                    None => "del".into(),
                };
                format!("{}={v}", hex::encode(k))
            })
            .collect();
        gdelta.sort();
        Ok(AppOutcome {
            pass: r.approved,
            cost,
            pre,
            gdelta: gdelta.join(","),
            logs: r.logs.iter().map(hex::encode).collect(),
        })
    }
}

fn program_hash(program: &[u8]) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(b"Program");
    h.update(program);
    h.finalize().into()
}

type AppPair = (
    Box<dyn FnMut()>,
    Box<dyn FnMut() -> Result<String>>,
    Option<Box<dyn FnMut()>>,
);

fn app_case(dir: &Path, file: &str) -> Result<AppPair> {
    // One runner shared by the op, the digest and the reset, so the
    // digest sees whatever state the benchmark iterations left behind.
    let runner = Rc::new(RefCell::new(AppRunner::new(read(dir, file)?)?));
    let (r_op, r_digest, r_reset) = (runner.clone(), runner.clone(), runner);
    Ok((
        Box::new(move || {
            let (r, _) = r_op.borrow_mut().eval().expect("app eval");
            assert!(r.approved, "app call rejected");
            black_box(r);
        }),
        Box::new(move || Ok(r_digest.borrow_mut().run()?.digest())),
        Some(Box::new(move || r_reset.borrow_mut().reset())),
    ))
}

// --- agreement ---------------------------------------------------------------

/// `benchmarks/fixtures/micro/sortition.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct SortitionInput {
    /// Account stake.
    pub money: u64,
    /// Total online stake.
    pub total_money: u64,
    /// Committee size.
    pub expected_size: u64,
    /// 32-byte VRF output digest, hex.
    pub vrf_output: String,
}

fn sortition_case(dir: &Path, f128: bool) -> Result<Pair> {
    let input: SortitionInput = serde_json::from_slice(&read(dir, "sortition.json")?)
        .map_err(|e| format!("sortition.json: {e}"))?;
    let vrf: [u8; 32] = unhex(&input.vrf_output)?;
    use algo_consensus_crypto::sortition::{select, select_f128};
    let sel = move || {
        if f128 {
            select_f128(input.money, input.total_money, input.expected_size, vrf)
        } else {
            select(
                input.money,
                input.total_money,
                input.expected_size as f64,
                vrf,
            )
        }
    };
    let sel2 = sel;
    Ok((
        Box::new(move || {
            black_box(sel());
        }),
        Box::new(move || Ok(format!("weight:{}", sel2()))),
    ))
}

/// `benchmarks/fixtures/micro/credential.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialInput {
    /// Voter address, hex.
    pub address: String,
    /// VRF selection public key, hex.
    pub selection_pk: String,
    /// VRF proof, hex.
    pub proof: String,
    /// Voting stake.
    pub balance: u64,
    /// Total online stake.
    pub total_money: u64,
    /// Selector seed, hex.
    pub seed: String,
    /// Selector round.
    pub round: u64,
    /// Selector period.
    pub period: u64,
    /// Selector step.
    pub step: u64,
}

fn credential_case(dir: &Path) -> Result<Pair> {
    let input: CredentialInput = serde_json::from_slice(&read(dir, "credential.json")?)
        .map_err(|e| format!("credential.json: {e}"))?;
    let cred = UnauthenticatedCredential::new(unhex(&input.proof)?);
    let membership = Membership {
        address: Address(unhex(&input.address)?),
        selection_id: unhex(&input.selection_pk)?,
        balance: input.balance,
        total_money: input.total_money,
        selector: Selector {
            seed: Seed(unhex(&input.seed)?),
            round: Round(input.round),
            period: Period(input.period),
            step: Step(input.step),
        },
    };
    let proto = current_proto()?;
    let (c2, m2, p2) = (cred.clone(), membership.clone(), proto.clone());
    Ok((
        Box::new(move || {
            let c = cred
                .verify(black_box(&proto), &membership)
                .expect("credential verifies");
            black_box(c.weight);
        }),
        Box::new(move || {
            Ok(match c2.verify(&p2, &m2) {
                Ok(c) => format!("weight:{};vrfout:{}", c.weight, hex::encode(c.vrf_out.0)),
                Err(_) => "credential:invalid".into(),
            })
        }),
    ))
}

fn decode_cert_case(dir: &Path) -> Result<Pair> {
    let data = read(dir, "cert-20.msgpack")?;
    decode_bundle(&data).map_err(|e| format!("cert-20.msgpack: {e:?}"))?;
    let d2 = data.clone();
    Ok((
        Box::new(move || {
            black_box(decode_bundle(black_box(&data)).expect("decode cert"));
        }),
        Box::new(move || {
            let b = decode_bundle(&d2).map_err(|e| format!("{e:?}"))?;
            Ok(sha256_hex(&encode_bundle(&b)))
        }),
    ))
}

fn decode_proposal_case(dir: &Path) -> Result<Pair> {
    let data = read(dir, "proposal.msgpack")?;
    decode_compound_message(&data).map_err(|e| format!("proposal.msgpack: {e:?}"))?;
    let d2 = data.clone();
    Ok((
        Box::new(move || {
            black_box(decode_compound_message(black_box(&data)).expect("decode proposal"));
        }),
        Box::new(move || {
            let m = decode_compound_message(&d2).map_err(|e| format!("{e:?}"))?;
            Ok(sha256_hex(&encode_compound_message(&m)))
        }),
    ))
}
