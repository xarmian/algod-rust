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

//! go's `transaction %+v invalid : <err>` frame (issue #2451).
//!
//! `verify.TxnGroup` (`data/transactions/verify/txn.go`, `txnGroupBatchPrep`)
//! reports a member that is not well formed, or whose signature format or
//! LogicSig fails, as `fmt.Errorf("transaction %+v invalid : %w", stxn, err)`.
//! That text reaches clients through `POST /v2/transactions` and, for the
//! signature-stage failures, simulate's `failure-message`. This module prints
//! the `%+v` of a `transactions.SignedTxn` the way go's `fmt` does:
//!
//! - a struct is `{Name:value Name:value}`, every field in declaration order,
//!   the unexported `_struct struct{}` marker included (`_struct:{}`), an
//!   embedded struct named by its type (`Header:{...}`);
//! - a type with a value-receiver `String()` prints that (`basics.Address`,
//!   `basics.MicroAlgos`, `crypto.Digest`, `basics.StateSchema`,
//!   `transactions.OnCompletion`, `protocol.PQScheme`, `stateproof.StateProof`);
//! - `[]byte` and `[N]byte` print as decimal bytes, `[1 2 3]`; other slices
//!   as `[a b]`; a nil slice as `[]`;
//! - the embedded `*HeartbeatTxnFields` is `<nil>` for every transaction but
//!   a heartbeat, for which go prints the pointer's address (`0xc000...`):
//!   the one token that differs from run to run in go itself. A heartbeat is
//!   printed here with the address of the Rust value, the same shape.
//!
//! go strings (`GenesisID`, `Type`, the asset names) are raw bytes; they are
//! printed the way go's `encoding/json` hands them to a client, every invalid
//! UTF-8 byte as U+FFFD.

use std::fmt::Write as _;

use algo_types::{
    Address, AssetParams, BoxRef, Digest, HeartbeatTxnFields, LogicSig, MultisigSig, PQSig,
    ResourceRef, SignedTransaction, StateProofBody, StateProofMessage, StateSchema, Transaction,
};

const ZERO_64: [u8; 64] = [0u8; 64];
const ZERO_32: [u8; 32] = [0u8; 32];

/// go's `fmt.Errorf("transaction %+v invalid : %w", stxn, err)` text.
pub fn frame_invalid_txn(stx: &SignedTransaction, reason: &str) -> String {
    format!("transaction {} invalid : {reason}", go_signed_txn_dump(stx))
}

/// go's reason for a member's `txnBatchPrep` failure, the `<err>` of its
/// frame: the error's own text (never `AlgoError::Validation`'s `validation
/// error: ` prefix), and for a LogicSig program that errors, `logicSigVerify`'s
/// `transaction <txid>: %w` of the program's `EvalError` (`rejected by logic
/// err=<err>. Details: pc=<pc>`).
pub fn verify_member_reason(stx: &SignedTransaction, e: &algo_error::AlgoError) -> String {
    member_reason(stx, e, false)
}

/// [`verify_member_reason`] as simulate prints it: simulate's tracer asks
/// for detailed eval errors (`DetailedEvalErrors`), so a LogicSig program's
/// error carries the failing instructions too, `Details: pc=<pc>,
/// opcodes=<pcDetails>` (`logic.(*EvalContext).evalError`).
pub fn simulate_member_reason(stx: &SignedTransaction, e: &algo_error::AlgoError) -> String {
    member_reason(stx, e, true)
}

fn member_reason(stx: &SignedTransaction, e: &algo_error::AlgoError, detailed: bool) -> String {
    match e {
        algo_error::AlgoError::Validation { message } => message.clone(),
        algo_error::AlgoError::AvmLogicSig {
            message,
            pc,
            app_index: None,
            ..
        } => {
            let opcodes = match (detailed, stx.lsig.as_ref()) {
                (true, Some(lsig)) => format!(
                    ", opcodes={}",
                    algo_avm::disassembler::pc_details(&lsig.logic, *pc)
                ),
                _ => String::new(),
            };
            format!(
                "transaction {}: rejected by logic err={}. Details: pc={pc}{opcodes}",
                algo_codec::compute_txn_id(&stx.txn),
                message.strip_prefix("AVM: ").unwrap_or(message),
            )
        }
        other => other.to_string(),
    }
}

/// Whether go reports `e`, a member's signature verdict, with the member's
/// frame. Every `txnBatchPrep` failure is framed; the batch verifier's own
/// failure is bare, except a delegated LogicSig's: `logicSigVerify` checks
/// that signature with a batch of its own, inside the framed prep
/// (`LogicSigSanityCheck`).
pub fn verify_failure_is_framed(stx: &SignedTransaction, e: &algo_error::AlgoError) -> bool {
    !e.is_batch_sig_failure() || stx.lsig.as_ref().is_some_and(|l| l.has_program())
}

/// go's `fmt.Sprintf("%+v", stxn)` of a `transactions.SignedTxn`.
pub fn go_signed_txn_dump(stx: &SignedTransaction) -> String {
    let mut w = String::with_capacity(4096);
    w.push_str("{_struct:{} Sig:");
    bytes(&mut w, &stx.sig);
    w.push_str(" Msig:");
    multisig(&mut w, stx.msig.as_ref());
    w.push_str(" Lsig:");
    logic_sig(&mut w, stx.lsig.as_ref());
    w.push_str(" PQsig:");
    pq_sig(&mut w, stx.pqsig.as_ref());
    w.push_str(" Txn:");
    transaction(&mut w, &stx.txn);
    w.push_str(" AuthAddr:");
    address(&mut w, stx.auth_addr.as_ref());
    w.push('}');
    w
}

/// `[]byte` / `[N]byte` under `%v`: `[1 2 3]`.
fn bytes(w: &mut String, b: &[u8]) {
    w.push('[');
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            w.push(' ');
        }
        let _ = write!(w, "{x}");
    }
    w.push(']');
}

fn opt_bytes(w: &mut String, b: Option<&[u8]>) {
    bytes(w, b.unwrap_or_default());
}

/// `[]uint64` (and the index types) under `%v`: `[1 2]`.
fn uints(w: &mut String, v: &[u64]) {
    w.push('[');
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            w.push(' ');
        }
        let _ = write!(w, "{x}");
    }
    w.push(']');
}

/// A go string's raw bytes as a client reads them: go's `encoding/json`
/// replaces every byte that does not start a valid UTF-8 sequence with U+FFFD.
fn go_str(w: &mut String, b: &[u8]) {
    let mut rest = b;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                w.push_str(s);
                return;
            }
            Err(e) => {
                let (valid, after) = rest.split_at(e.valid_up_to());
                w.push_str(std::str::from_utf8(valid).unwrap_or_default());
                w.push('\u{FFFD}');
                rest = &after[1..];
            }
        }
    }
}

fn address(w: &mut String, a: Option<&Address>) {
    let _ = write!(w, "{}", a.copied().unwrap_or(Address::ZERO));
}

fn digest(w: &mut String, d: &[u8; 32]) {
    let _ = write!(w, "{}", Digest(*d));
}

/// `basics.MicroAlgos.String()` (`data/basics/units.go`).
fn micro_algos(w: &mut String, raw: u64) {
    let _ = match raw {
        0 => write!(w, "0.0A"),
        1..=999 => write!(w, "{raw}uA"),
        1_000..=999_999 => match raw % 1_000 {
            0 => write!(w, "{}mA", raw / 1_000),
            f => write!(w, "{}.{f:03}mA", raw / 1_000),
        },
        _ => match raw % 1_000_000 {
            0 => write!(w, "{}A", raw / 1_000_000),
            f => write!(w, "{}.{f:06}A", raw / 1_000_000),
        },
    };
}

/// `transactions.OnCompletion.String()` (`application_string.go`).
fn on_completion(w: &mut String, oc: u64) {
    let _ = match oc {
        0 => write!(w, "NoOpOC"),
        1 => write!(w, "OptInOC"),
        2 => write!(w, "CloseOutOC"),
        3 => write!(w, "ClearStateOC"),
        4 => write!(w, "UpdateApplicationOC"),
        5 => write!(w, "DeleteApplicationOC"),
        // go formats the value as an int64.
        n => write!(w, "OnCompletion({})", n as i64),
    };
}

/// `basics.StateSchema.String()`.
fn state_schema(w: &mut String, s: Option<&StateSchema>) {
    let (u, b) = s.map_or((0, 0), |s| (s.num_uint, s.num_byte_slice));
    let _ = write!(w, "{{NumUint:{u} NumByteSlice:{b}}}");
}

fn multisig(w: &mut String, m: Option<&MultisigSig>) {
    let (v, t) = m.map_or((0, 0), |m| (m.version, m.threshold));
    let _ = write!(w, "{{_struct:{{}} Version:{v} Threshold:{t} Subsigs:[");
    for (i, s) in m
        .map(|m| m.subsigs.as_slice())
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        if i > 0 {
            w.push(' ');
        }
        w.push_str("{_struct:{} Key:");
        bytes(w, &s.public_key);
        w.push_str(" Sig:");
        bytes(w, &s.signature);
        w.push('}');
    }
    w.push_str("]}");
}

fn pq_sig(w: &mut String, p: Option<&PQSig>) {
    let scheme = p.map_or([0u8; 2], |p| p.scheme);
    w.push_str("{_struct:{} Scheme:");
    // `protocol.PQScheme.String()` is `string(s[:])`, raw bytes.
    go_str(w, &scheme);
    let _ = write!(w, " Salt:{} PublicKey:", p.map_or(0, |p| p.salt.0));
    opt_bytes(w, p.map(|p| p.public_key.as_slice()));
    w.push_str(" Signature:");
    opt_bytes(w, p.map(|p| p.signature.as_slice()));
    w.push('}');
}

fn logic_sig(w: &mut String, l: Option<&LogicSig>) {
    w.push_str("{_struct:{} Logic:");
    opt_bytes(w, l.map(|l| l.logic.as_slice()));
    w.push_str(" Sig:");
    bytes(w, l.map_or(&ZERO_64, |l| &l.sig));
    w.push_str(" Msig:");
    multisig(w, l.and_then(|l| l.msig.as_ref()));
    w.push_str(" LMsig:");
    multisig(w, l.and_then(|l| l.lmsig.as_ref()));
    w.push_str(" PQsig:");
    pq_sig(w, l.and_then(|l| l.pqsig.as_ref()));
    w.push_str(" Args:");
    byte_slices(w, l.and_then(|l| l.args.as_deref()));
    w.push('}');
}

/// `[][]byte` under `%v`: `[[1 2] []]`.
fn byte_slices(w: &mut String, v: Option<&[Option<serde_bytes::ByteBuf>]>) {
    w.push('[');
    for (i, b) in v.unwrap_or_default().iter().enumerate() {
        if i > 0 {
            w.push(' ');
        }
        opt_bytes(w, b.as_deref().map(|b| b.as_slice()));
    }
    w.push(']');
}

fn transaction(w: &mut String, t: &Transaction) {
    w.push_str("{_struct:{} Type:");
    go_str(w, t.txn_type.as_str().as_bytes());

    w.push_str(" Header:{_struct:{} Sender:");
    address(w, Some(&t.sender));
    w.push_str(" Fee:");
    micro_algos(w, t.fee);
    let _ = write!(
        w,
        " FirstValid:{} LastValid:{} Note:",
        t.first_valid.0, t.last_valid.0
    );
    bytes(w, &t.note);
    w.push_str(" GenesisID:");
    go_str(w, t.genesis_id.as_bytes());
    w.push_str(" GenesisHash:");
    digest(w, &t.genesis_hash);
    w.push_str(" Group:");
    digest(w, &t.group);
    w.push_str(" Lease:");
    bytes(w, &t.lease);
    w.push_str(" RekeyTo:");
    address(w, t.rekey_to.as_ref());
    w.push('}');

    w.push_str(" KeyregTxnFields:{_struct:{} VotePK:");
    bytes(w, t.vote_pk.as_ref().unwrap_or(&ZERO_32));
    w.push_str(" SelectionPK:");
    bytes(w, t.selection_pk.as_ref().unwrap_or(&ZERO_32));
    w.push_str(" StateProofPK:");
    bytes(w, t.state_proof_pk.as_ref().unwrap_or(&ZERO_64));
    let _ = write!(
        w,
        " VoteFirst:{} VoteLast:{} VoteKeyDilution:{} Nonparticipation:{}}}",
        t.vote_first, t.vote_last, t.vote_key_dilution, t.non_participation
    );

    w.push_str(" PaymentTxnFields:{_struct:{} Receiver:");
    address(w, Some(&t.receiver));
    w.push_str(" Amount:");
    micro_algos(w, t.amount);
    w.push_str(" CloseRemainderTo:");
    address(w, Some(&t.close_remainder_to));
    w.push('}');

    let _ = write!(
        w,
        " AssetConfigTxnFields:{{_struct:{{}} ConfigAsset:{} AssetParams:",
        t.config_asset
    );
    asset_params(w, t.asset_params.as_ref());
    w.push('}');

    let _ = write!(
        w,
        " AssetTransferTxnFields:{{_struct:{{}} XferAsset:{} AssetAmount:{} AssetSender:",
        t.xaid, t.asset_amount
    );
    address(w, t.asset_sender.as_ref());
    w.push_str(" AssetReceiver:");
    address(w, t.asset_receiver.as_ref());
    w.push_str(" AssetCloseTo:");
    address(w, t.asset_close_to.as_ref());
    w.push('}');

    w.push_str(" AssetFreezeTxnFields:{_struct:{} FreezeAccount:");
    address(w, t.freeze_account.as_ref());
    let _ = write!(
        w,
        " FreezeAsset:{} AssetFrozen:{}}}",
        t.freeze_asset, t.asset_frozen
    );

    application_call(w, t);

    let _ = write!(
        w,
        " StateProofTxnFields:{{_struct:{{}} StateProofType:{} StateProof:",
        t.state_proof_type
    );
    state_proof(w, t.state_proof.as_ref());
    w.push_str(" Message:");
    state_proof_message(w, t.state_proof_message.as_ref());
    w.push('}');

    w.push_str(" HeartbeatTxnFields:");
    heartbeat_pointer(w, t.heartbeat.as_ref());
    w.push('}');
}

fn asset_params(w: &mut String, p: Option<&AssetParams>) {
    let default = AssetParams::default();
    let p = p.unwrap_or(&default);
    let _ = write!(
        w,
        "{{_struct:{{}} Total:{} Decimals:{} DefaultFrozen:{} UnitName:",
        p.total, p.decimals, p.default_frozen
    );
    go_str(w, &p.unit_name);
    w.push_str(" AssetName:");
    go_str(w, &p.asset_name);
    w.push_str(" URL:");
    go_str(w, &p.url);
    w.push_str(" MetadataHash:");
    bytes(w, p.metadata_hash.as_ref().unwrap_or(&ZERO_32));
    w.push_str(" Manager:");
    address(w, p.manager.as_ref());
    w.push_str(" Reserve:");
    address(w, p.reserve.as_ref());
    w.push_str(" Freeze:");
    address(w, p.freeze.as_ref());
    w.push_str(" Clawback:");
    address(w, p.clawback.as_ref());
    w.push('}');
}

fn box_ref(w: &mut String, b: Option<&BoxRef>) {
    let _ = write!(w, "{{_struct:{{}} Index:{} Name:", b.map_or(0, |b| b.index));
    opt_bytes(w, b.and_then(|b| b.name.as_deref()).map(|n| n.as_slice()));
    w.push('}');
}

fn resource_ref(w: &mut String, r: &ResourceRef) {
    w.push_str("{_struct:{} Address:");
    address(w, Some(&r.address));
    let (ha, hs) = r.holding.as_ref().map_or((0, 0), |h| (h.address, h.asset));
    let (la, lp) = r.locals.as_ref().map_or((0, 0), |l| (l.address, l.app));
    let _ = write!(
        w,
        " Asset:{} App:{} Holding:{{_struct:{{}} Address:{ha} Asset:{hs}}} \
         Locals:{{_struct:{{}} Address:{la} App:{lp}}} Box:",
        r.asset, r.app
    );
    box_ref(w, r.box_ref.as_ref());
    w.push('}');
}

fn application_call(w: &mut String, t: &Transaction) {
    let _ = write!(
        w,
        " ApplicationCallTxnFields:{{_struct:{{}} ApplicationID:{} OnCompletion:",
        t.application_id
    );
    on_completion(w, t.on_completion);
    w.push_str(" ApplicationArgs:");
    byte_slices(w, t.app_arguments.as_deref());
    w.push_str(" Accounts:[");
    for (i, a) in t.accounts.as_deref().unwrap_or_default().iter().enumerate() {
        if i > 0 {
            w.push(' ');
        }
        address(w, Some(a));
    }
    w.push_str("] ForeignAssets:");
    uints(w, t.foreign_assets.as_deref().unwrap_or_default());
    w.push_str(" ForeignApps:");
    uints(w, t.foreign_apps.as_deref().unwrap_or_default());
    w.push_str(" Access:[");
    for (i, r) in t.access.as_deref().unwrap_or_default().iter().enumerate() {
        if i > 0 {
            w.push(' ');
        }
        resource_ref(w, r);
    }
    w.push_str("] Boxes:[");
    for (i, b) in t.boxes.as_deref().unwrap_or_default().iter().enumerate() {
        if i > 0 {
            w.push(' ');
        }
        box_ref(w, Some(b));
    }
    w.push_str("] LocalStateSchema:");
    state_schema(w, t.local_state_schema.as_ref());
    w.push_str(" GlobalStateSchema:");
    state_schema(w, t.global_state_schema.as_ref());
    w.push_str(" ApprovalProgram:");
    opt_bytes(w, t.approval_program.as_deref().map(|b| b.as_slice()));
    w.push_str(" ClearStateProgram:");
    opt_bytes(w, t.clear_state_program.as_deref().map(|b| b.as_slice()));
    let _ = write!(
        w,
        " ExtraProgramPages:{} RejectVersion:{}}}",
        t.extra_program_pages, t.reject_version
    );
}

/// `stateproof.StateProof.String()` (`crypto/stateproof/structs.go`):
/// `StateProof: {}` for the zero value (`MsgIsZero`), else `StateProof:
/// {<%v of SigCommit>, <SignedWeight>, <len(PositionsToReveal)>}`.
fn state_proof(w: &mut String, sp: Option<&StateProofBody>) {
    w.push_str("StateProof: {");
    if let Some(sp) = sp.filter(|sp| !state_proof_is_zero(sp)) {
        bytes(w, &sp.sig_commit);
        let _ = write!(
            w,
            ", {}, {}",
            sp.signed_weight,
            sp.positions_to_reveal.as_ref().map_or(0, Vec::len)
        );
    }
    w.push('}');
}

/// The msgp-generated `StateProof.MsgIsZero`: every field zero, the proofs
/// included (no path, hash type 0, depth 0), no reveal, no position.
fn state_proof_is_zero(sp: &StateProofBody) -> bool {
    let proof_is_zero = |p: Option<&algo_types::MerkleProof>| {
        p.is_none_or(|p| {
            p.path.as_ref().is_none_or(Vec::is_empty)
                && p.hash_factory.as_ref().is_none_or(|h| h.hash_type == 0)
                && p.tree_depth == 0
        })
    };
    sp.sig_commit.is_empty()
        && sp.signed_weight == 0
        && proof_is_zero(sp.sig_proofs.as_ref())
        && proof_is_zero(sp.part_proofs.as_ref())
        && sp.merkle_signature_salt_version == 0
        && sp.reveals.as_ref().is_none_or(|r| r.is_empty())
        && sp.positions_to_reveal.as_ref().is_none_or(Vec::is_empty)
}

fn state_proof_message(w: &mut String, m: Option<&StateProofMessage>) {
    let default = StateProofMessage::default();
    let m = m.unwrap_or(&default);
    w.push_str("{_struct:{} BlockHeadersCommitment:");
    bytes(w, &m.block_headers_commitment);
    w.push_str(" VotersCommitment:");
    bytes(w, &m.voters_commitment);
    let _ = write!(
        w,
        " LnProvenWeight:{} FirstAttestedRound:{} LastAttestedRound:{}}}",
        m.ln_proven_weight, m.first_attested_round, m.last_attested_round
    );
}

/// go prints the embedded `*HeartbeatTxnFields` (a pointer below the top
/// level) as `<nil>`, or as its address: not reproducible, in go or here.
fn heartbeat_pointer(w: &mut String, hb: Option<&HeartbeatTxnFields>) {
    match hb {
        None => w.push_str("<nil>"),
        Some(hb) => {
            let _ = write!(w, "{:p}", hb as *const HeartbeatTxnFields);
        }
    }
}

/// The text with every heartbeat pointer address (`HeartbeatTxnFields:0x<hex>`)
/// replaced by `HeartbeatTxnFields:0xPTR`, the token go oracles record in its
/// place (`tools/simulate-rewards-oracle`'s `maskPointers`): for comparing a
/// frame with go's, the address being the one part that is not reproducible.
pub fn mask_heartbeat_pointer(s: &str) -> String {
    const KEY: &str = "HeartbeatTxnFields:0x";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find(KEY) {
        let start = at + KEY.len();
        out.push_str(&rest[..start]);
        out.push_str("PTR");
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(s: &str) -> String {
        mask_heartbeat_pointer(s)
    }

    #[test]
    fn micro_algos_is_gos_string() {
        for (raw, want) in [
            (0, "0.0A"),
            (1, "1uA"),
            (999, "999uA"),
            (1_000, "1mA"),
            (1_001, "1.001mA"),
            (999_999, "999.999mA"),
            (1_000_000, "1A"),
            (1_000_001, "1.000001A"),
            (u64::MAX, "18446744073709.551615A"),
        ] {
            let mut w = String::new();
            micro_algos(&mut w, raw);
            assert_eq!(w, want);
        }
    }

    #[test]
    fn on_completion_is_gos_stringer() {
        let mut w = String::new();
        on_completion(&mut w, 5);
        on_completion(&mut w, 6);
        on_completion(&mut w, u64::MAX);
        assert_eq!(w, "DeleteApplicationOCOnCompletion(6)OnCompletion(-1)");
    }

    #[test]
    fn go_strings_replace_each_invalid_byte() {
        let mut w = String::new();
        go_str(&mut w, b"a\xE2\x82b\xFF\0");
        assert_eq!(w, "a\u{FFFD}\u{FFFD}b\u{FFFD}\0");
    }

    #[test]
    fn a_heartbeat_prints_an_address_and_others_nil() {
        let mut stx = SignedTransaction::default();
        assert!(go_signed_txn_dump(&stx).contains(" HeartbeatTxnFields:<nil>} AuthAddr:"));
        stx.txn.heartbeat = Some(HeartbeatTxnFields::default());
        let dump = go_signed_txn_dump(&stx);
        assert!(dump.contains(" HeartbeatTxnFields:0x"), "{dump}");
        assert!(mask(&dump).contains(" HeartbeatTxnFields:0xPTR} AuthAddr:"));
    }

    #[test]
    fn a_non_zero_state_proof_prints_its_summary() {
        let mut w = String::new();
        state_proof(
            &mut w,
            Some(&StateProofBody {
                sig_commit: serde_bytes::ByteBuf::from(vec![1, 2]),
                signed_weight: 7,
                positions_to_reveal: Some(vec![3, 4, 5]),
                ..Default::default()
            }),
        );
        assert_eq!(w, "StateProof: {[1 2], 7, 3}");
        let mut w = String::new();
        state_proof(&mut w, Some(&StateProofBody::default()));
        assert_eq!(w, "StateProof: {}");
    }
}
