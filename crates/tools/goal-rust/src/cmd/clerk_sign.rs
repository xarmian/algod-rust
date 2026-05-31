//! Shared LogicSig + multisig signing infrastructure for the `clerk` group.
//!
//! Ports the signing-helper surface of `../go-algorand/cmd/goal/clerk.go`
//! (`signCmd`, `sendCmd`'s logicsig/msig paths) and `tealsign.go`, factored out
//! so `clerk sign`, `clerk send`, `clerk tealsign`, and the forthcoming `clerk
//! multisig` subcommands (TASK-292 / T4) share one implementation of:
//!
//! - **LogicSig assembly** ([`lsig_from_args`]): build a [`LogicSig`] from a
//!   TEAL source file (`--program`/`-p`) or a msgpack LogicSig file
//!   (`--logic-sig`/`-L`), attaching base64 program args (`--argb64`).
//! - **Program → address** ([`program_address`]): `HashProgram` (the
//!   `"Program" || bytes` SHA-512/256 digest), used to derive the contract
//!   account address for a logicsig.
//! - **Multisig preimage parsing** ([`parse_msig_params`]): decode the
//!   `--msig-params` string (`"<threshold> <addr1> <addr2> ..."`) into a blank
//!   [`MultisigSig`] preimage plus the derived multisig [`Address`], matching
//!   Go's `sendCmd` handling (clerk.go:508-543).
//! - **TEAL data signing** ([`tealsign_payload`]): build the domain-separated
//!   `"ProgData" || program_hash || data` payload that `tealsign` signs
//!   (tealsign.go:200-203, `logic.Msg.ToBeHashed`).

use algo_avm::assembler::assemble_string;
use algo_consensus_crypto::multisig::{multisig_addr_gen, multisig_preimage_from_pks};
use algo_types::{Address, LogicSig, MultisigSig};
use base64::Engine;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha512_256};

/// Domain-separation prefix for the LogicSig program hash. Matches Go's
/// `protocol.Program` (`protocol/hash.go`) and `logic.Program.ToBeHashed`
/// (`data/transactions/logic/program.go:28`).
const PROGRAM_PREFIX: &[u8] = b"Program";

/// Domain-separation prefix for `tealsign`'s signed payload. Matches Go's
/// `protocol.ProgramData` (`protocol/hash.go:63`) used by `logic.Msg.ToBeHashed`
/// (`data/transactions/logic/crypto.go:163-165`).
pub const PROGRAM_DATA_PREFIX: &[u8] = b"ProgData";

/// Maximum number of LogicSig arguments. Matches Go's `transactions.EvalMaxArgs`
/// (`data/transactions/transaction.go`).
pub const EVAL_MAX_ARGS: usize = 255;

/// Compute the contract-account address for a program: the SHA-512/256 digest
/// of `"Program" || program`. Mirrors `logic.HashProgram`
/// (`data/transactions/logic/program.go:45`) wrapped as a `basics.Address`.
pub fn program_address(program: &[u8]) -> Address {
    Address(hash_program(program))
}

/// `logic.HashProgram(program)` — the raw 32-byte digest of `"Program" ||
/// program`.
pub fn hash_program(program: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(PROGRAM_PREFIX);
    hasher.update(program);
    hasher.finalize().into()
}

/// Decode the base64 program args (`--argb64`), mirroring Go's `getB64Args`
/// (clerk.go:290-308): an empty string decodes to an empty byte slice; any
/// other entry is standard-base64 decoded.
pub fn parse_arg_b64(args: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::with_capacity(args.len());
    for (i, arg) in args.iter().enumerate() {
        if arg.is_empty() {
            out.push(Vec::new());
            continue;
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(arg)
            .map_err(|e| format!("arg[{i}] decode error: {e}"))?;
        out.push(decoded);
    }
    Ok(out)
}

/// Build a [`LogicSig`] from the `--program`/`-p` (TEAL source) or
/// `--logic-sig`/`-L` (msgpack LogicSig) flags, attaching the `--argb64`
/// program args. Returns `Ok(None)` when neither source flag is set (the
/// caller falls back to wallet signing).
///
/// Mirrors the head of Go's `signCmd` (clerk.go:804-812) and `lsigFromArgs`
/// (clerk.go:748-758): at most one of `--program`/`--logic-sig` may be set; the
/// args always come from `--argb64` (overwriting any args already in a decoded
/// LogicSig file, matching Go's `lsig.Args = getProgramArgs()`).
pub fn lsig_from_args(
    program_source: Option<&str>,
    logic_sig_file: Option<&str>,
    arg_b64: &[String],
) -> Result<Option<LogicSig>, String> {
    let args = parse_arg_b64(arg_b64)?;
    let args_field = if args.is_empty() {
        None
    } else {
        Some(args.into_iter().map(ByteBuf::from).collect())
    };

    match (program_source, logic_sig_file) {
        (Some(_), Some(_)) => {
            Err("goal clerk sign should have at most one of --program/-p or --logic-sig/-L".into())
        }
        (Some(src), None) => {
            let text = std::fs::read_to_string(src).map_err(|e| format!("{src}: {e}"))?;
            let ops = assemble_string(&text).map_err(|errs| format_assembly_errors(src, &errs))?;
            Ok(Some(LogicSig {
                logic: ByteBuf::from(ops.program),
                args: args_field,
                ..LogicSig::default()
            }))
        }
        (None, Some(file)) => {
            let bytes = std::fs::read(file).map_err(|e| format!("{file}: read failed, {e}"))?;
            let mut lsig = algo_codec::decode_logicsig(&bytes)
                .map_err(|e| format!("{file}: decode failed, {e}"))?;
            // Go overwrites the file's args with --argb64 (clerk.go:757).
            lsig.args = args_field;
            Ok(Some(lsig))
        }
        (None, None) => Ok(None),
    }
}

/// Render assembler errors the way `assembleFileImpl` surfaces them
/// (clerk.go:998-1001): the file name followed by the joined error messages.
fn format_assembly_errors(fname: &str, errs: &[algo_avm::assembler::AssemblyError]) -> String {
    let joined = errs
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    format!("{fname}: {joined}")
}

/// The result of parsing `--msig-params`: the blank multisig preimage to attach
/// to the transaction plus the derived multisig address (the AuthAddr for a
/// rekeyed sender).
#[derive(Debug)]
pub struct MsigPreimage {
    /// The `MultisigSig` with public keys populated and all sigs blank.
    pub msig: MultisigSig,
    /// The 1-version multisig address derived from `(threshold, pks)`.
    pub address: Address,
}

/// Parse the `--msig-params` string `"<threshold> <addr1> <addr2> ..."` into a
/// blank multisig preimage and its derived address. Mirrors Go's `sendCmd`
/// msig-params handling (clerk.go:508-543): at least a threshold + 2 addresses,
/// threshold in `[1, 255]`, version fixed at 1.
pub fn parse_msig_params(params: &str) -> Result<MsigPreimage, String> {
    let parts: Vec<&str> = params.split(' ').filter(|p| !p.is_empty()).collect();
    if parts.len() < 3 {
        return Err(
            "Failed to parse the multisig parameters: Not enough arguments to create the \
             multisig address.\nPlease make sure to specify the threshold and at least 2 \
             addresses"
                .into(),
        );
    }

    let threshold: u64 = parts[0].parse().map_err(|_| {
        "Failed to parse the multisig parameters: Failed to parse the threshold. Make sure it's a \
         number between 1 and 255"
            .to_string()
    })?;
    if !(1..=255).contains(&threshold) {
        return Err(
            "Failed to parse the multisig parameters: Failed to parse the threshold. Make sure \
             it's a number between 1 and 255"
                .into(),
        );
    }
    let threshold = threshold as u8;

    let mut pks: Vec<[u8; 32]> = Vec::with_capacity(parts.len() - 1);
    for addr_str in &parts[1..] {
        let addr = Address::from_algorand_string(addr_str)
            .map_err(|e| format!("Cannot decode address {addr_str}: {e}"))?;
        pks.push(addr.0);
    }

    let address = multisig_addr_gen(1, threshold, &pks)
        .map_err(|e| format!("Failed to parse the multisig parameters: {e}"))?;
    let msig = multisig_preimage_from_pks(1, threshold, &pks);

    Ok(MsigPreimage { msig, address })
}

/// Build the domain-separated payload that `tealsign` signs: `"ProgData" ||
/// program_hash || data`. Mirrors `logic.Msg.ToBeHashed` (crypto.go:163-165)
/// wrapped by `crypto.HashRep` (the ed25519 message is signed verbatim — no
/// pre-hash — by `SignatureSecrets.Sign` → `SignBytes(HashRep(msg))`).
pub fn tealsign_payload(program_hash: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PROGRAM_DATA_PREFIX.len() + 32 + data.len());
    payload.extend_from_slice(PROGRAM_DATA_PREFIX);
    payload.extend_from_slice(program_hash);
    payload.extend_from_slice(data);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_arg_b64_handles_empty_and_values() {
        let args = vec!["".to_string(), "AQID".to_string()];
        let parsed = parse_arg_b64(&args).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].is_empty());
        assert_eq!(parsed[1], vec![1u8, 2, 3]);
    }

    #[test]
    fn parse_arg_b64_rejects_garbage() {
        let err = parse_arg_b64(&["!!!not-base64".to_string()]).unwrap_err();
        assert!(err.contains("arg[0] decode error"), "got: {err}");
    }

    #[test]
    fn hash_program_matches_program_prefix_digest() {
        // HashProgram(program) = SHA512/256("Program" || program).
        let program = [0x01u8, 0x20, 0x01, 0x01]; // #pragma version 1; int 1 -ish bytes
        let mut hasher = Sha512_256::new();
        hasher.update(b"Program");
        hasher.update(program);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash_program(&program), expected);
        assert_eq!(program_address(&program).0, expected);
    }

    #[test]
    fn lsig_from_args_none_when_no_source() {
        assert!(lsig_from_args(None, None, &[]).unwrap().is_none());
    }

    #[test]
    fn lsig_from_args_rejects_both_sources() {
        let err = lsig_from_args(Some("a.teal"), Some("b.lsig"), &[]).unwrap_err();
        assert!(err.contains("at most one of"), "got: {err}");
    }

    #[test]
    fn lsig_from_args_assembles_source_with_args() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("prog.teal");
        std::fs::write(&src, "#pragma version 2\nint 1\n").unwrap();
        let lsig = lsig_from_args(Some(src.to_str().unwrap()), None, &["AQ==".to_string()])
            .unwrap()
            .expect("lsig present");
        assert!(!lsig.logic.is_empty(), "program assembled");
        let args = lsig.args.expect("args present");
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].as_ref(), &[1u8]);
    }

    #[test]
    fn parse_msig_params_rejects_too_few_args() {
        let err = parse_msig_params("2 ABC").unwrap_err();
        assert!(err.contains("Not enough arguments"), "got: {err}");
    }

    #[test]
    fn parse_msig_params_rejects_bad_threshold() {
        // threshold 0 and 256 are out of range.
        assert!(parse_msig_params("0 A B")
            .unwrap_err()
            .contains("threshold"));
        assert!(parse_msig_params("256 A B")
            .unwrap_err()
            .contains("threshold"));
        assert!(parse_msig_params("x A B")
            .unwrap_err()
            .contains("threshold"));
    }

    #[test]
    fn parse_msig_params_derives_address_and_preimage() {
        // Three deterministic addresses (32-byte all-N), 2-of-3.
        let a = Address([1u8; 32]).to_algorand_string();
        let b = Address([2u8; 32]).to_algorand_string();
        let c = Address([3u8; 32]).to_algorand_string();
        let params = format!("2 {a} {b} {c}");
        let pre = parse_msig_params(&params).unwrap();
        assert_eq!(pre.msig.version, 1);
        assert_eq!(pre.msig.threshold, 2);
        assert_eq!(pre.msig.subsigs.len(), 3);
        assert_eq!(pre.msig.subsigs[0].public_key, [1u8; 32]);
        // Address must match the independent multisig_addr_gen computation.
        let expected = multisig_addr_gen(1, 2, &[[1u8; 32], [2u8; 32], [3u8; 32]]).unwrap();
        assert_eq!(pre.address, expected);
    }

    #[test]
    fn tealsign_payload_layout() {
        let prog_hash = [0xABu8; 32];
        let data = [0x10u8, 0x11, 0x12];
        let payload = tealsign_payload(&prog_hash, &data);
        assert_eq!(&payload[..8], b"ProgData");
        assert_eq!(&payload[8..40], &prog_hash);
        assert_eq!(&payload[40..], &data);
    }
}
