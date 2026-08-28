//! Complete AVM opcode table covering all opcodes from AVM v1 through v13.
//!
//! This table matches go-algorand v4.6.0's `data/transactions/logic/opcodes.go`.
//! Each opcode has metadata for parsing, validation, and (future) execution.

/// Maximum supported AVM version.
///
/// Matches `go-algorand/data/transactions/logic/opcodes.go:31`
/// (`const LogicVersion = 13`). Note that consensus-level acceptance of a v13
/// program is additionally gated on `ConsensusParams::logic_sig_version` via
/// [`crate::validator::check_program_version_allowed`]; under V41 that ceiling
/// is still 12.
pub const MAX_AVM_VERSION: u8 = 13;

/// Maximum byte string length in the AVM.
///
/// Matches go-algorand's `maxStringSize` / `config.MaxAVMBytesSize`
/// (`data/transactions/logic/eval.go:50-51`). Used both at assembly time
/// (unconditionally, for `byte`/`pushbytes`/`bytecblock`/`pushbytess`
/// literals) and, starting at `LogicSigVersion >= 13`, at parse/execution
/// time for the multi-constant `bytecblock`/`pushbytess` immediate forms
/// (go-algorand PR #6692, `EvalContext.byteImmArgs`).
pub const MAX_STRING_SIZE: usize = 4096;

/// Execution mode for an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Only valid in LogicSig programs.
    LogicSig,
    /// Only valid in Application (approval/clear-state) programs.
    Application,
    /// Valid in both modes.
    Any,
}

/// The kind of cost an opcode incurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostKind {
    /// Fixed cost known at compile time.
    Static(u64),
    /// Cost depends on the immediate field or runtime input.
    Dynamic,
}

/// Type of immediate argument following an opcode byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmKind {
    /// No immediates.
    None,
    /// Single uint8.
    Uint8,
    /// Two uint8 values.
    Uint8Uint8,
    /// Three uint8 values.
    Uint8Uint8Uint8,
    /// Signed int16 (big-endian) — branch offset.
    Int16,
    /// Varuint (unsigned LEB128).
    Varuint,
    /// Varuint length-prefixed byte array.
    VaruintBytes,
    /// intcblock: varuint count, then count varuint values.
    IntcBlock,
    /// bytecblock: varuint count, then count (varuint-length + bytes) entries.
    BytecBlock,
    /// pushints: varuint count, then count varuint values.
    PushInts,
    /// pushbytess: varuint count, then count (varuint-length + bytes) entries.
    PushBytess,
    /// switch/match: uint8 count, then count int16 offsets.
    Labels,
    /// Varint-encoded (zigzag + ULEB128) branch offset — used instead of
    /// `Int16` for `bnz`/`bz`/`b`/`callsub` at `LogicSigVersion >=
    /// VARINT_BRANCH_VERSION` (go-algorand PR #6600, `varintBranchVersion`).
    /// Not used as a static table entry (those four opcodes keep `Int16` in
    /// `OPCODE_TABLE` for the legacy encoding); the effective kind is
    /// resolved per-program-version by [`is_varint_branch_opcode`] at parse
    /// and assembly time.
    BranchVarint,
}

/// The AVM version at which `bnz`/`bz`/`b`/`callsub` switch from a fixed
/// 2-byte big-endian `int16` branch offset to a variable-length
/// (zigzag+ULEB128) `binary.Varint`-encoded offset.
///
/// Matches go-algorand's `varintBranchVersion` constant
/// (`data/transactions/logic/opcodes.go`). `switch`/`match` (0x8d/0x8e) are
/// unaffected at any version — they keep their fixed 2-byte-per-target
/// encoding.
pub const VARINT_BRANCH_VERSION: u8 = 13;

/// Returns `true` for the four opcodes whose branch-offset encoding is
/// version-gated by [`VARINT_BRANCH_VERSION`]: `bnz` (0x40), `bz` (0x41),
/// `b` (0x42), `callsub` (0x88). `switch`/`match` are deliberately excluded.
pub fn is_varint_branch_opcode(byte: u8) -> bool {
    matches!(byte, 0x40 | 0x41 | 0x42 | 0x88)
}

/// Maximum number of sub-opcodes a single "prefix" opcode family may
/// register. go-algorand's `OpSpec.SubOps` is a dynamically-grown slice
/// (`addToSubOps`, `opcodes.go:929-938`); Rust's `static` tables need a
/// fixed bound, so this is sized generously above any currently-planned
/// family (the `app_box_*` family sharing prefix byte `0xd4` uses 9).
/// Index 0 is always unused/`None`, mirroring go's documented "index 0 is
/// always a zero-value OpSpec sentinel" convention for `SubOps`.
pub const MAX_SUB_OPCODES: usize = 32;

/// Sub-opcode table for a multi-byte "prefix" opcode family. Indexed by the
/// second byte of the instruction (the sub-opcode).
pub type SubOpTable = [Option<OpSpec>; MAX_SUB_OPCODES];

/// The AVM version at which the multi-byte "prefix opcode" dispatch
/// mechanism and its first consumers (`app_params_set`, and the
/// `app_box_*` family) were introduced.
///
/// Matches go-algorand's `foreignBoxVersion = 13` (`opcodes.go:83`).
pub const FOREIGN_BOX_VERSION: u8 = 13;

/// Static metadata for a single opcode.
#[derive(Debug, Clone)]
pub struct OpSpec {
    /// The opcode byte value (0x00..0xFF).
    pub opcode: u8,
    /// Human-readable mnemonic (e.g. "sha256", "intcblock").
    pub name: &'static str,
    /// Minimum AVM version that supports this opcode.
    pub version: u8,
    /// Execution cost.
    pub cost: CostKind,
    /// Number of values popped from the stack (approximate; -1 means dynamic).
    pub stack_pops: i8,
    /// Number of values pushed onto the stack (approximate; -1 means dynamic).
    pub stack_pushes: i8,
    /// Execution mode restriction.
    pub mode: Mode,
    /// Immediate argument encoding.
    pub imm: ImmKind,
    /// Nonzero when this `OpSpec` is itself a sub-opcode entry inside a
    /// prefix family (mirrors go's `OpDetails.SubOpcode`, `opcodes.go:162`).
    /// `0` for ordinary single-byte opcodes and for the prefix entry itself.
    pub sub_opcode: u8,
    /// Set on the *prefix* entry (e.g. `0xd4`) to mark this opcode byte as
    /// the shared first byte of a multi-byte opcode family (mirrors go's
    /// `OpSpec.SubOps`, `opcodes.go:164-166`). `None` for ordinary,
    /// single-byte opcodes.
    pub sub_ops: Option<&'static SubOpTable>,
}

/// Lookup table indexed by opcode byte. `None` means the byte is unused/invalid.
static OPCODE_TABLE: [Option<OpSpec>; 256] = {
    // We build this with a const initializer. Since OpSpec contains &'static str
    // we need a macro to keep it readable.
    const EMPTY: Option<OpSpec> = Option::None;
    let mut table: [Option<OpSpec>; 256] = [EMPTY; 256];

    macro_rules! op {
        ($byte:expr, $name:expr, $ver:expr, $cost:expr, $pops:expr, $pushes:expr, $mode:expr, $imm:expr) => {
            table[$byte as usize] = Some(OpSpec {
                opcode: $byte,
                name: $name,
                version: $ver,
                cost: $cost,
                stack_pops: $pops,
                stack_pushes: $pushes,
                mode: $mode,
                imm: $imm,
                sub_opcode: 0,
                // `Option::None` spelled out: this macro body expands in a
                // scope with `use ImmKind::*;` (for the bare `None` immediate
                // kind used by many opcodes above), which would otherwise
                // shadow the prelude's `Option::None` with `ImmKind::None`.
                sub_ops: Option::None,
            });
        };
    }

    use CostKind::*;
    use ImmKind::*;
    use Mode::*;

    // ---- Error ----
    op!(0x00, "err", 1, Static(1), 0, 0, Any, None);

    // ---- Crypto ----
    op!(0x01, "sha256", 1, Static(35), 1, 1, Any, None);
    op!(0x02, "keccak256", 1, Static(130), 1, 1, Any, None);
    op!(0x03, "sha512_256", 1, Static(45), 1, 1, Any, None);
    op!(0x04, "ed25519verify", 1, Static(1900), 3, 1, Any, None);
    op!(0x05, "ecdsa_verify", 5, Dynamic, 5, 1, Any, Uint8);
    op!(0x06, "ecdsa_pk_decompress", 5, Dynamic, 1, 2, Any, Uint8);
    op!(0x07, "ecdsa_pk_recover", 5, Static(2000), 4, 2, Any, Uint8);

    // ---- Arithmetic ----
    op!(0x08, "+", 1, Static(1), 2, 1, Any, None);
    op!(0x09, "-", 1, Static(1), 2, 1, Any, None);
    op!(0x0a, "/", 1, Static(1), 2, 1, Any, None);
    op!(0x0b, "*", 1, Static(1), 2, 1, Any, None);
    op!(0x0c, "<", 1, Static(1), 2, 1, Any, None);
    op!(0x0d, ">", 1, Static(1), 2, 1, Any, None);
    op!(0x0e, "<=", 1, Static(1), 2, 1, Any, None);
    op!(0x0f, ">=", 1, Static(1), 2, 1, Any, None);
    op!(0x10, "&&", 1, Static(1), 2, 1, Any, None);
    op!(0x11, "||", 1, Static(1), 2, 1, Any, None);
    op!(0x12, "==", 1, Static(1), 2, 1, Any, None);
    op!(0x13, "!=", 1, Static(1), 2, 1, Any, None);
    op!(0x14, "!", 1, Static(1), 1, 1, Any, None);
    op!(0x15, "len", 1, Static(1), 1, 1, Any, None);
    op!(0x16, "itob", 1, Static(1), 1, 1, Any, None);
    op!(0x17, "btoi", 1, Static(1), 1, 1, Any, None);
    op!(0x18, "%", 1, Static(1), 2, 1, Any, None);
    op!(0x19, "|", 1, Static(1), 2, 1, Any, None);
    op!(0x1a, "&", 1, Static(1), 2, 1, Any, None);
    op!(0x1b, "^", 1, Static(1), 2, 1, Any, None);
    op!(0x1c, "~", 1, Static(1), 1, 1, Any, None);
    op!(0x1d, "mulw", 1, Static(1), 2, 2, Any, None);
    op!(0x1e, "addw", 2, Static(1), 2, 2, Any, None);
    op!(0x1f, "divmodw", 4, Static(20), 4, 4, Any, None);

    // ---- Constants ----
    op!(0x20, "intcblock", 1, Static(1), 0, 0, Any, IntcBlock);
    op!(0x21, "intc", 1, Static(1), 0, 1, Any, Uint8);
    op!(0x22, "intc_0", 1, Static(1), 0, 1, Any, None);
    op!(0x23, "intc_1", 1, Static(1), 0, 1, Any, None);
    op!(0x24, "intc_2", 1, Static(1), 0, 1, Any, None);
    op!(0x25, "intc_3", 1, Static(1), 0, 1, Any, None);
    op!(0x26, "bytecblock", 1, Static(1), 0, 0, Any, BytecBlock);
    op!(0x27, "bytec", 1, Static(1), 0, 1, Any, Uint8);
    op!(0x28, "bytec_0", 1, Static(1), 0, 1, Any, None);
    op!(0x29, "bytec_1", 1, Static(1), 0, 1, Any, None);
    op!(0x2a, "bytec_2", 1, Static(1), 0, 1, Any, None);
    op!(0x2b, "bytec_3", 1, Static(1), 0, 1, Any, None);

    // ---- Arg (LogicSig only) ----
    op!(0x2c, "arg", 1, Static(1), 0, 1, LogicSig, Uint8);
    op!(0x2d, "arg_0", 1, Static(1), 0, 1, LogicSig, None);
    op!(0x2e, "arg_1", 1, Static(1), 0, 1, LogicSig, None);
    op!(0x2f, "arg_2", 1, Static(1), 0, 1, LogicSig, None);
    op!(0x30, "arg_3", 1, Static(1), 0, 1, LogicSig, None);

    // ---- Txn / Global / Gtxn ----
    op!(0x31, "txn", 1, Static(1), 0, 1, Any, Uint8);
    op!(0x32, "global", 1, Static(1), 0, 1, Any, Uint8);
    op!(0x33, "gtxn", 1, Static(1), 0, 1, Any, Uint8Uint8);
    op!(0x34, "load", 1, Static(1), 0, 1, Any, Uint8);
    op!(0x35, "store", 1, Static(1), 1, 0, Any, Uint8);
    op!(0x36, "txna", 2, Static(1), 0, 1, Any, Uint8Uint8);
    op!(0x37, "gtxna", 2, Static(1), 0, 1, Any, Uint8Uint8Uint8);
    op!(0x38, "gtxns", 3, Static(1), 1, 1, Any, Uint8);
    op!(0x39, "gtxnsa", 3, Static(1), 1, 1, Any, Uint8Uint8);
    op!(0x3a, "gload", 4, Static(1), 0, 1, Application, Uint8Uint8);
    op!(0x3b, "gloads", 4, Static(1), 1, 1, Application, Uint8);
    op!(0x3c, "gaid", 4, Static(1), 0, 1, Application, Uint8);
    op!(0x3d, "gaids", 4, Static(1), 1, 1, Application, None);
    op!(0x3e, "loads", 5, Static(1), 1, 1, Any, None);
    op!(0x3f, "stores", 5, Static(1), 2, 0, Any, None);

    // ---- Branching ----
    op!(0x40, "bnz", 1, Static(1), 1, 0, Any, Int16);
    op!(0x41, "bz", 2, Static(1), 1, 0, Any, Int16);
    op!(0x42, "b", 2, Static(1), 0, 0, Any, Int16);
    op!(0x43, "return", 2, Static(1), 1, 0, Any, None);
    op!(0x44, "assert", 3, Static(1), 1, 0, Any, None);

    // ---- Stack manipulation (v8) ----
    op!(0x45, "bury", 8, Static(1), 1, 0, Any, Uint8);
    op!(0x46, "popn", 8, Static(1), -1, 0, Any, Uint8);
    op!(0x47, "dupn", 8, Static(1), 1, -1, Any, Uint8);

    // ---- Stack manipulation (older) ----
    op!(0x48, "pop", 1, Static(1), 1, 0, Any, None);
    op!(0x49, "dup", 1, Static(1), 1, 2, Any, None);
    op!(0x4a, "dup2", 2, Static(1), 2, 4, Any, None);
    op!(0x4b, "dig", 3, Static(1), -1, -1, Any, Uint8);
    op!(0x4c, "swap", 3, Static(1), 2, 2, Any, None);
    op!(0x4d, "select", 3, Static(1), 3, 1, Any, None);
    op!(0x4e, "cover", 5, Static(1), -1, -1, Any, Uint8);
    op!(0x4f, "uncover", 5, Static(1), -1, -1, Any, Uint8);

    // ---- Byte string ops ----
    op!(0x50, "concat", 2, Static(1), 2, 1, Any, None);
    op!(0x51, "substring", 2, Static(1), 1, 1, Any, Uint8Uint8);
    op!(0x52, "substring3", 2, Static(1), 3, 1, Any, None);
    op!(0x53, "getbit", 3, Static(1), 2, 1, Any, None);
    op!(0x54, "setbit", 3, Static(1), 3, 1, Any, None);
    op!(0x55, "getbyte", 3, Static(1), 2, 1, Any, None);
    op!(0x56, "setbyte", 3, Static(1), 3, 1, Any, None);
    op!(0x57, "extract", 5, Static(1), 1, 1, Any, Uint8Uint8);
    op!(0x58, "extract3", 5, Static(1), 3, 1, Any, None);
    op!(0x59, "extract_uint16", 5, Static(1), 2, 1, Any, None);
    op!(0x5a, "extract_uint32", 5, Static(1), 2, 1, Any, None);
    op!(0x5b, "extract_uint64", 5, Static(1), 2, 1, Any, None);
    op!(0x5c, "replace2", 7, Static(1), 2, 1, Any, Uint8);
    op!(0x5d, "replace3", 7, Static(1), 3, 1, Any, None);

    // ---- Encoding ----
    op!(0x5e, "base64_decode", 7, Dynamic, 1, 1, Any, Uint8);
    op!(0x5f, "json_ref", 7, Dynamic, 2, 1, Any, Uint8);

    // ---- App state ----
    op!(0x60, "balance", 2, Static(1), 1, 1, Application, None);
    op!(0x61, "app_opted_in", 2, Static(1), 2, 1, Application, None);
    op!(0x62, "app_local_get", 2, Static(1), 2, 1, Application, None);
    op!(
        0x63,
        "app_local_get_ex",
        2,
        Static(1),
        3,
        2,
        Application,
        None
    );
    op!(
        0x64,
        "app_global_get",
        2,
        Static(1),
        1,
        1,
        Application,
        None
    );
    op!(
        0x65,
        "app_global_get_ex",
        2,
        Static(1),
        2,
        2,
        Application,
        None
    );
    op!(0x66, "app_local_put", 2, Static(1), 3, 0, Application, None);
    op!(
        0x67,
        "app_global_put",
        2,
        Static(1),
        2,
        0,
        Application,
        None
    );
    op!(0x68, "app_local_del", 2, Static(1), 2, 0, Application, None);
    op!(
        0x69,
        "app_global_del",
        2,
        Static(1),
        1,
        0,
        Application,
        None
    );

    // ---- Asset / App / Account queries ----
    op!(
        0x70,
        "asset_holding_get",
        2,
        Static(1),
        2,
        2,
        Application,
        Uint8
    );
    op!(
        0x71,
        "asset_params_get",
        2,
        Static(1),
        1,
        2,
        Application,
        Uint8
    );
    op!(
        0x72,
        "app_params_get",
        5,
        Static(1),
        1,
        2,
        Application,
        Uint8
    );
    op!(
        0x73,
        "acct_params_get",
        6,
        Static(1),
        1,
        2,
        Application,
        Uint8
    );
    op!(
        0x74,
        "voter_params_get",
        11,
        Static(1),
        1,
        2,
        Application,
        Uint8
    );
    op!(0x75, "online_stake", 11, Static(1), 0, 1, Application, None);
    // `app_params_set` (v5.0.0 / foreignBoxVersion=13): pops a uint64,
    // sets a settable `AppParamsField` on the *current* app. Not itself a
    // multi-byte/prefix opcode -- go-algorand's `opcodes.go:691`:
    //   {0x76, "app_params_set", opAppParamsSet, proto("i:"), foreignBoxVersion,
    //    field("f", &AppParamsSettableFields).only(ModeApp).assembler(asmAppParamsSet)}
    op!(
        0x76,
        "app_params_set",
        FOREIGN_BOX_VERSION,
        Static(1),
        1,
        0,
        Application,
        Uint8
    );

    // ---- Min balance ----
    op!(0x78, "min_balance", 3, Static(1), 1, 1, Application, None);

    // ---- Push immediates ----
    op!(0x80, "pushbytes", 3, Static(1), 0, 1, Any, VaruintBytes);
    op!(0x81, "pushint", 3, Static(1), 0, 1, Any, Varuint);
    op!(0x82, "pushbytess", 8, Static(1), 0, -1, Any, PushBytess);
    op!(0x83, "pushints", 8, Static(1), 0, -1, Any, PushInts);

    // ---- Crypto (v7+) ----
    op!(0x84, "ed25519verify_bare", 7, Static(1900), 3, 1, Any, None);
    // `falcon_verify`'s stack args are typed `Any` here deliberately: its
    // middle argument (the Falcon signature) is a variable-length byte
    // string, not a fixed `[1232]byte`. go-algorand's real `proto()` string
    // for opcode 0x85 has always been `"bbb{1793}:T"` (plain variable-length
    // `b`) -- only the *generated docs*
    // (TEAL_opcodes_v12.md/v13.md, langspec_v12/v13.json) wrongly documented
    // it as a fixed 1232-byte type, and go-algorand commit `3920d70d0`
    // ("docs: fix falcon_verify opcode documentation", PR #6629) fixed the
    // docs only -- eval.go/opcodes.go never had this bug. Do not "fix" this
    // to a fixed-size type by analogy with the old docs; see
    // `ops/crypto.rs::op_falcon_verify` and
    // `FALCON_DET1024_SIG_COMPRESSED_MAXSIZE` (1423 bytes) in algo-falcon,
    // which already implement the correct variable-length behavior.
    op!(0x85, "falcon_verify", 12, Static(1700), 3, 1, Any, None);
    op!(0x86, "sumhash512", 13, Dynamic, 1, 1, Any, None);
    op!(0x87, "sha512", 13, Dynamic, 1, 1, Any, None);

    // ---- Subroutines / Frames ----
    op!(0x88, "callsub", 4, Static(1), 0, 0, Any, Int16);
    op!(0x89, "retsub", 4, Static(1), 0, 0, Any, None);
    op!(0x8a, "proto", 8, Static(1), 0, 0, Any, Uint8Uint8);
    op!(0x8b, "frame_dig", 8, Static(1), 0, 1, Any, Uint8);
    op!(0x8c, "frame_bury", 8, Static(1), 1, 0, Any, Uint8);
    op!(0x8d, "switch", 8, Static(1), 1, 0, Any, Labels);
    op!(0x8e, "match", 8, Static(1), -1, 0, Any, Labels);

    // ---- Bit/math ops (v4+) ----
    op!(0x90, "shl", 4, Static(1), 2, 1, Any, None);
    op!(0x91, "shr", 4, Static(1), 2, 1, Any, None);
    op!(0x92, "sqrt", 4, Static(4), 1, 1, Any, None);
    op!(0x93, "bitlen", 4, Static(1), 1, 1, Any, None);
    op!(0x94, "exp", 4, Static(1), 2, 1, Any, None);
    op!(0x95, "expw", 4, Static(10), 2, 2, Any, None);
    op!(0x96, "bsqrt", 6, Static(40), 1, 1, Any, None);
    op!(0x97, "divw", 6, Static(1), 3, 1, Any, None);
    op!(0x98, "sha3_256", 7, Static(130), 1, 1, Any, None);

    // ---- Big-int byte ops (v4+) ----
    op!(0xa0, "b+", 4, Static(10), 2, 1, Any, None);
    op!(0xa1, "b-", 4, Static(10), 2, 1, Any, None);
    op!(0xa2, "b/", 4, Static(20), 2, 1, Any, None);
    op!(0xa3, "b*", 4, Static(20), 2, 1, Any, None);
    op!(0xa4, "b<", 4, Static(1), 2, 1, Any, None);
    op!(0xa5, "b>", 4, Static(1), 2, 1, Any, None);
    op!(0xa6, "b<=", 4, Static(1), 2, 1, Any, None);
    op!(0xa7, "b>=", 4, Static(1), 2, 1, Any, None);
    op!(0xa8, "b==", 4, Static(1), 2, 1, Any, None);
    op!(0xa9, "b!=", 4, Static(1), 2, 1, Any, None);
    op!(0xaa, "b%", 4, Static(20), 2, 1, Any, None);
    op!(0xab, "b|", 4, Static(6), 2, 1, Any, None);
    op!(0xac, "b&", 4, Static(6), 2, 1, Any, None);
    op!(0xad, "b^", 4, Static(6), 2, 1, Any, None);
    op!(0xae, "b~", 4, Static(4), 1, 1, Any, None);
    op!(0xaf, "bzero", 4, Static(1), 1, 1, Any, None);

    // ---- Inner transactions & logging (App only) ----
    op!(0xb0, "log", 5, Static(1), 1, 0, Application, None);
    op!(0xb1, "itxn_begin", 5, Static(1), 0, 0, Application, None);
    op!(0xb2, "itxn_field", 5, Static(1), 1, 0, Application, Uint8);
    op!(0xb3, "itxn_submit", 5, Static(1), 0, 0, Application, None);
    op!(0xb4, "itxn", 5, Static(1), 0, 1, Application, Uint8);
    op!(0xb5, "itxna", 5, Static(1), 0, 1, Application, Uint8Uint8);
    op!(0xb6, "itxn_next", 6, Static(1), 0, 0, Application, None);
    op!(0xb7, "gitxn", 6, Static(1), 0, 1, Application, Uint8Uint8);
    op!(
        0xb8,
        "gitxna",
        6,
        Static(1),
        0,
        1,
        Application,
        Uint8Uint8Uint8
    );

    // ---- Box operations (v8, App only) ----
    op!(0xb9, "box_create", 8, Static(1), 2, 1, Application, None);
    op!(0xba, "box_extract", 8, Static(1), 3, 1, Application, None);
    op!(0xbb, "box_replace", 8, Static(1), 3, 0, Application, None);
    op!(0xbc, "box_del", 8, Static(1), 1, 1, Application, None);
    op!(0xbd, "box_len", 8, Static(1), 1, 2, Application, None);
    op!(0xbe, "box_get", 8, Static(1), 1, 2, Application, None);
    op!(0xbf, "box_put", 8, Static(1), 2, 0, Application, None);

    // ---- Dynamic txn array access (v5+) ----
    op!(0xc0, "txnas", 5, Static(1), 1, 1, Any, Uint8);
    op!(0xc1, "gtxnas", 5, Static(1), 1, 1, Any, Uint8Uint8);
    op!(0xc2, "gtxnsas", 5, Static(1), 2, 1, Any, Uint8);
    op!(0xc3, "args", 5, Static(1), 1, 1, LogicSig, None);
    op!(0xc4, "gloadss", 6, Static(1), 2, 1, Application, None);
    op!(0xc5, "itxnas", 6, Static(1), 1, 1, Application, Uint8);
    op!(0xc6, "gitxnas", 6, Static(1), 1, 1, Application, Uint8Uint8);

    // ---- VRF / Block (v7) ----
    op!(0xd0, "vrf_verify", 7, Static(5700), 3, 2, Any, Uint8);
    op!(0xd1, "block", 7, Static(1), 1, 1, Any, Uint8);

    // ---- Box splice/resize (v10) ----
    op!(0xd2, "box_splice", 10, Static(1), 4, 0, Application, None);
    op!(0xd3, "box_resize", 10, Static(1), 2, 0, Application, None);

    // ---- Elliptic curve ops (v10) ----
    op!(0xe0, "ec_add", 10, Dynamic, 2, 1, Any, Uint8);
    op!(0xe1, "ec_scalar_mul", 10, Dynamic, 2, 1, Any, Uint8);
    op!(0xe2, "ec_pairing_check", 10, Dynamic, 2, 1, Any, Uint8);
    op!(0xe3, "ec_multi_scalar_mul", 10, Dynamic, 2, 1, Any, Uint8);
    op!(0xe4, "ec_subgroup_check", 10, Dynamic, 1, 1, Any, Uint8);
    op!(0xe5, "ec_map_to", 10, Dynamic, 1, 1, Any, Uint8);

    // ---- MiMC hash (v11) ----
    op!(0xe6, "mimc", 11, Dynamic, 1, 1, Any, Uint8);

    // ---- Poseidon2 hash (v13) ----
    op!(0xe7, "poseidon2", 13, Dynamic, 1, 1, Any, Uint8);

    // ---- Foreign box opcodes (v13, App only, multi-byte prefix 0xd4) ----
    // Registered below via `APP_BOX_SUB_OPS`; the prefix entry here only
    // marks byte 0xd4 as a multi-byte family (go-algorand opcodes.go:787-795).
    table[0xd4] = Some(OpSpec {
        opcode: 0xd4,
        name: "app_box",
        version: FOREIGN_BOX_VERSION,
        cost: Static(1),
        stack_pops: 0,
        stack_pushes: 0,
        mode: Application,
        imm: None,
        sub_opcode: 0,
        sub_ops: Some(&APP_BOX_SUB_OPS),
    });

    table
};

/// Sub-opcode table for the `app_box_*` "foreign box" opcode family sharing
/// prefix byte `0xd4` (go-algorand `opcodes.go:787-795`, `foreignBoxVersion =
/// 13`). Each opcode is the "foreign" counterpart of an existing `box_*`
/// opcode, taking an extra leading app-id stack argument (see
/// `data/transactions/logic/box.go:311-321` `popDeepAppID`).
static APP_BOX_SUB_OPS: SubOpTable = {
    const EMPTY: Option<OpSpec> = Option::None;
    let mut subs: SubOpTable = [EMPTY; MAX_SUB_OPCODES];

    macro_rules! sub_op {
        ($sub:expr, $name:expr, $pops:expr, $pushes:expr) => {
            subs[$sub as usize] = Some(OpSpec {
                opcode: 0xd4,
                name: $name,
                version: FOREIGN_BOX_VERSION,
                cost: CostKind::Static(1),
                stack_pops: $pops,
                stack_pushes: $pushes,
                mode: Mode::Application,
                imm: ImmKind::None,
                sub_opcode: $sub,
                sub_ops: Option::None,
            });
        };
    }

    // proto("iNi:T")   -- app_id, name, size -> created
    sub_op!(0x01, "app_box_create", 3, 1);
    // proto("iNii:b")  -- app_id, name, start, length -> bytes
    sub_op!(0x02, "app_box_extract", 4, 1);
    // proto("iNib:")   -- app_id, name, start, replacement ->
    sub_op!(0x03, "app_box_replace", 4, 0);
    // proto("iN:T")    -- app_id, name -> existed
    sub_op!(0x04, "app_box_del", 2, 1);
    // proto("iN:iT")   -- app_id, name -> length, exists
    sub_op!(0x05, "app_box_len", 2, 2);
    // proto("iN:bT")   -- app_id, name -> value, exists
    sub_op!(0x06, "app_box_get", 2, 2);
    // proto("iNb:")    -- app_id, name, value ->
    sub_op!(0x07, "app_box_put", 3, 0);
    // proto("iNiib:")  -- app_id, name, start, length, replacement ->
    sub_op!(0x08, "app_box_splice", 5, 0);
    // proto("iNi:")    -- app_id, name, size ->
    sub_op!(0x09, "app_box_resize", 3, 0);

    subs
};

/// Look up an opcode spec by its byte value. Returns `None` for undefined opcodes.
pub fn lookup(byte: u8) -> Option<&'static OpSpec> {
    OPCODE_TABLE[byte as usize].as_ref()
}

/// Resolve the effective [`OpSpec`] for an already-parsed instruction's
/// `(opcode, sub_opcode)` pair, following multi-byte "prefix opcode"
/// dispatch (e.g. the `app_box_*` family at `0xd4`) when `sub_opcode` is
/// `Some`.
///
/// `lookup(opcode_byte)` alone is not enough for a prefix byte: it returns
/// the synthetic prefix-family entry (whose `name`/`mode`/`stack_pops`/
/// `stack_pushes` are placeholders, not the real per-sub-opcode values), so
/// any caller that needs the *actual* opcode's metadata after parsing --
/// the disassembler's mnemonic, the validator's mode/stack-effect checks --
/// must resolve through the sub-opcode table instead. This differs from
/// [`resolve`], which parses a `(prefix_byte, sub_byte)` pair fresh out of
/// raw program bytes; this function instead re-resolves an already-decoded
/// [`crate::bytecode::Instruction`]'s two fields.
pub fn resolve_spec(opcode_byte: u8, sub_opcode: Option<u8>) -> Option<&'static OpSpec> {
    let top = lookup(opcode_byte)?;
    match (top.sub_ops, sub_opcode) {
        (Some(subs), Some(sub)) => subs.get(sub as usize).and_then(|o| o.as_ref()),
        _ => Some(top),
    }
}

/// Resolve the [`OpSpec`] for the instruction starting at `code[pc]`,
/// including multi-byte "prefix opcode" dispatch: if the byte at `code[pc]`
/// names a prefix entry (`sub_ops.is_some()`), the following byte selects
/// the sub-opcode.
///
/// Mirrors go-algorand's `EvalContext.GetOpSpec` / `getOpSpecError`
/// (`data/transactions/logic/eval.go:797-822`), including its exact error
/// text: `"illegal opcode 0x%02x"`, `"prefix opcode 0x%02x missing
/// sub-opcode"`, `"prefix opcode 0x%02x with improper sub-opcode 0x%02x"`.
///
/// Returns `(spec, header_len)` on success, where `header_len` is `1` for
/// an ordinary opcode or `2` for a resolved sub-opcode (prefix byte +
/// sub-opcode byte) -- the number of bytes the caller must advance past
/// before parsing any immediates.
pub fn resolve(code: &[u8], pc: usize) -> Result<(&'static OpSpec, usize), String> {
    resolve_in(&OPCODE_TABLE, code, pc)
}

/// Same as [`resolve`], but against an explicit table. Exists so tests can
/// exercise the prefix/sub-opcode resolution logic against a small,
/// purpose-built table without needing a real multi-byte opcode family
/// registered in the production [`OPCODE_TABLE`].
fn resolve_in<'a>(
    table: &'a [Option<OpSpec>; 256],
    code: &[u8],
    pc: usize,
) -> Result<(&'a OpSpec, usize), String> {
    let byte = code[pc];
    let spec = table[byte as usize]
        .as_ref()
        .ok_or_else(|| format!("illegal opcode 0x{byte:02x}"))?;

    match spec.sub_ops {
        None => Ok((spec, 1)),
        Some(sub_ops) => {
            if pc + 1 >= code.len() {
                return Err(format!("prefix opcode 0x{byte:02x} missing sub-opcode"));
            }
            let sub = code[pc + 1];
            match sub_ops.get(sub as usize).and_then(|o| o.as_ref()) {
                Some(sub_spec) => Ok((sub_spec, 2)),
                None => Err(format!(
                    "prefix opcode 0x{byte:02x} with improper sub-opcode 0x{sub:02x}"
                )),
            }
        }
    }
}

/// Look up an opcode spec by mnemonic name. Linear scan — use for debugging/
/// assembler use. Also searches inside any registered `sub_ops` family (e.g.
/// `app_box_create`), so the assembler can resolve a sub-opcode's own
/// two-byte-header spec by its distinct mnemonic, not just the shared prefix
/// byte's synthetic entry.
pub fn lookup_by_name(name: &str) -> Option<&'static OpSpec> {
    for entry in OPCODE_TABLE.iter().filter_map(|o| o.as_ref()) {
        if entry.name == name {
            return Some(entry);
        }
        if let Some(sub_ops) = entry.sub_ops {
            if let Some(sub) = sub_ops
                .iter()
                .filter_map(|o| o.as_ref())
                .find(|s| s.name == name)
            {
                return Some(sub);
            }
        }
    }
    None
}

/// Return all defined opcodes as `(byte, name)` pairs, sorted by byte value.
pub fn all_opcodes() -> Vec<(u8, &'static str)> {
    OPCODE_TABLE
        .iter()
        .filter_map(|o| o.as_ref().map(|spec| (spec.opcode, spec.name)))
        .collect()
}

/// Return the total number of defined opcodes (the coverage denominator).
pub fn defined_opcode_count() -> usize {
    OPCODE_TABLE.iter().filter(|o| o.is_some()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_err_opcode() {
        let spec = lookup(0x00).unwrap();
        assert_eq!(spec.name, "err");
        assert_eq!(spec.version, 1);
        assert_eq!(spec.mode, Mode::Any);
    }

    #[test]
    fn test_intcblock() {
        let spec = lookup(0x20).unwrap();
        assert_eq!(spec.name, "intcblock");
        assert_eq!(spec.imm, ImmKind::IntcBlock);
    }

    #[test]
    fn test_bytecblock() {
        let spec = lookup(0x26).unwrap();
        assert_eq!(spec.name, "bytecblock");
        assert_eq!(spec.imm, ImmKind::BytecBlock);
    }

    #[test]
    fn test_branch_opcodes() {
        for (byte, name) in [(0x40, "bnz"), (0x41, "bz"), (0x42, "b"), (0x88, "callsub")] {
            let spec = lookup(byte).unwrap();
            assert_eq!(spec.name, name);
            assert_eq!(spec.imm, ImmKind::Int16, "expected Int16 for {name}");
        }
    }

    #[test]
    fn test_pushint_pushbytes() {
        let pi = lookup(0x81).unwrap();
        assert_eq!(pi.name, "pushint");
        assert_eq!(pi.imm, ImmKind::Varuint);

        let pb = lookup(0x80).unwrap();
        assert_eq!(pb.name, "pushbytes");
        assert_eq!(pb.imm, ImmKind::VaruintBytes);
    }

    #[test]
    fn test_switch_match() {
        let sw = lookup(0x8d).unwrap();
        assert_eq!(sw.name, "switch");
        assert_eq!(sw.imm, ImmKind::Labels);

        let ma = lookup(0x8e).unwrap();
        assert_eq!(ma.name, "match");
        assert_eq!(ma.imm, ImmKind::Labels);
    }

    #[test]
    fn test_logicsig_only() {
        let spec = lookup(0x2c).unwrap();
        assert_eq!(spec.name, "arg");
        assert_eq!(spec.mode, Mode::LogicSig);
    }

    #[test]
    fn test_app_only() {
        let spec = lookup(0xb0).unwrap();
        assert_eq!(spec.name, "log");
        assert_eq!(spec.mode, Mode::Application);
    }

    #[test]
    fn test_undefined_opcode() {
        // 0x99 is not assigned
        assert!(lookup(0x99).is_none());
    }

    #[test]
    fn test_lookup_by_name() {
        let spec = lookup_by_name("sha256").unwrap();
        assert_eq!(spec.opcode, 0x01);
        assert!(lookup_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_divmodw_cost_is_20() {
        // Matches go-algorand data/transactions/logic/opcodes.go:545:
        // `{0x1f, "divmodw", opDivModw, proto("iiii:iiii"), 4, costly(20)}`
        let spec = lookup(0x1f).unwrap();
        assert_eq!(spec.name, "divmodw");
        assert_eq!(spec.cost, CostKind::Static(20));
    }

    #[test]
    fn test_ec_ops_are_dynamic_cost() {
        for byte in [0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5] {
            let spec = lookup(byte).unwrap();
            assert_eq!(
                spec.cost,
                CostKind::Dynamic,
                "expected Dynamic for 0x{byte:02x}"
            );
        }
    }

    #[test]
    fn test_total_defined_opcodes() {
        let count = OPCODE_TABLE.iter().filter(|o| o.is_some()).count();
        // We expect roughly 150+ opcodes defined
        assert!(
            count >= 140,
            "only {count} opcodes defined, expected >= 140"
        );
    }

    #[test]
    fn test_all_opcodes() {
        let all = all_opcodes();
        assert!(
            all.len() >= 140,
            "expected >= 140 opcodes, got {}",
            all.len()
        );
        // Should be sorted by byte value (since we iterate 0..255).
        for pair in all.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "not sorted: {} >= {}",
                pair[0].0,
                pair[1].0
            );
        }
        // First opcode should be err (0x00).
        assert_eq!(all[0], (0x00, "err"));
    }

    #[test]
    fn test_defined_opcode_count() {
        let count = defined_opcode_count();
        let all = all_opcodes();
        assert_eq!(count, all.len());
    }

    #[test]
    fn test_app_params_set_opcode() {
        let spec = lookup(0x76).unwrap();
        assert_eq!(spec.name, "app_params_set");
        assert_eq!(spec.version, FOREIGN_BOX_VERSION);
        assert_eq!(spec.mode, Mode::Application);
        assert_eq!(spec.imm, ImmKind::Uint8);
        assert_eq!(spec.sub_opcode, 0);
        assert!(spec.sub_ops.is_none());
    }

    // -----------------------------------------------------------------------
    // Multi-byte "prefix opcode" dispatch (go-algorand opcodes.go SubOpcode/
    // SubOps/subOp/GetOpSpec/getOpSpecError, v5.0.0-stable). No production
    // opcode registers `sub_ops` yet (the first consumer, the `app_box_*`
    // family at prefix byte 0xd4, lands in the companion box-opcodes issue),
    // so these tests build a small private table to exercise the generic
    // resolution logic in isolation.
    // -----------------------------------------------------------------------

    fn test_sub_op_table() -> SubOpTable {
        const EMPTY: Option<OpSpec> = None;
        let mut subs: SubOpTable = [EMPTY; MAX_SUB_OPCODES];
        subs[1] = Some(OpSpec {
            opcode: 0xf0,
            name: "test_sub_one",
            version: 13,
            cost: CostKind::Static(1),
            stack_pops: 0,
            stack_pushes: 0,
            mode: Mode::Any,
            imm: ImmKind::None,
            sub_opcode: 1,
            sub_ops: None,
        });
        // A sub-opcode gated to a version higher than the family's own
        // introduction, to exercise per-sub-opcode version gating
        // independent of the prefix byte's own version.
        subs[2] = Some(OpSpec {
            opcode: 0xf0,
            name: "test_sub_two",
            version: 20,
            cost: CostKind::Static(1),
            stack_pops: 0,
            stack_pushes: 0,
            mode: Mode::Any,
            imm: ImmKind::None,
            sub_opcode: 2,
            sub_ops: None,
        });
        subs
    }

    fn test_table_with_prefix() -> [Option<OpSpec>; 256] {
        const EMPTY: Option<OpSpec> = None;
        let mut table: [Option<OpSpec>; 256] = [EMPTY; 256];
        // Leak the sub-op table to get a `'static` reference for the test
        // table's prefix entry (mirrors how the real OPCODE_TABLE's prefix
        // entries reference a named `static SubOpTable`).
        let subs: &'static SubOpTable = Box::leak(Box::new(test_sub_op_table()));
        table[0xf0] = Some(OpSpec {
            opcode: 0xf0,
            name: "test_prefix",
            version: 13,
            cost: CostKind::Static(1),
            stack_pops: 0,
            stack_pushes: 0,
            mode: Mode::Any,
            imm: ImmKind::None,
            sub_opcode: 0,
            sub_ops: Some(subs),
        });
        table[0x01] = Some(OpSpec {
            opcode: 0x01,
            name: "ordinary",
            version: 1,
            cost: CostKind::Static(1),
            stack_pops: 0,
            stack_pushes: 0,
            mode: Mode::Any,
            imm: ImmKind::None,
            sub_opcode: 0,
            sub_ops: None,
        });
        table
    }

    #[test]
    fn test_resolve_ordinary_opcode_is_unaffected() {
        let table = test_table_with_prefix();
        let (spec, len) = resolve_in(&table, &[0x01], 0).unwrap();
        assert_eq!(spec.name, "ordinary");
        assert_eq!(len, 1);
    }

    #[test]
    fn test_resolve_prefix_with_valid_sub_opcode() {
        let table = test_table_with_prefix();
        let (spec, len) = resolve_in(&table, &[0xf0, 0x01], 0).unwrap();
        assert_eq!(spec.name, "test_sub_one");
        assert_eq!(spec.opcode, 0xf0);
        assert_eq!(spec.sub_opcode, 1);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_resolve_prefix_missing_sub_opcode_byte() {
        let table = test_table_with_prefix();
        // Program ends right after the prefix byte -- no second byte.
        let err = resolve_in(&table, &[0xf0], 0).unwrap_err();
        assert_eq!(err, "prefix opcode 0xf0 missing sub-opcode");
    }

    #[test]
    fn test_resolve_prefix_improper_sub_opcode() {
        let table = test_table_with_prefix();
        // 0x09 is within MAX_SUB_OPCODES bounds but not registered.
        let err = resolve_in(&table, &[0xf0, 0x09], 0).unwrap_err();
        assert_eq!(err, "prefix opcode 0xf0 with improper sub-opcode 0x09");
    }

    #[test]
    fn test_resolve_prefix_sub_opcode_out_of_table_bounds() {
        let table = test_table_with_prefix();
        // 0xff is beyond MAX_SUB_OPCODES -- must still be "improper", not panic.
        let err = resolve_in(&table, &[0xf0, 0xff], 0).unwrap_err();
        assert_eq!(err, "prefix opcode 0xf0 with improper sub-opcode 0xff");
    }

    #[test]
    fn test_resolve_illegal_opcode() {
        let table = test_table_with_prefix();
        let err = resolve_in(&table, &[0x99], 0).unwrap_err();
        assert_eq!(err, "illegal opcode 0x99");
    }

    #[test]
    fn test_resolve_prefix_sub_opcode_carries_independent_version() {
        // The sub-opcode's own `version` (not the prefix's) is what a
        // caller must check for version gating -- go-algorand's per-version
        // table cloning means an individual sub-opcode can be introduced
        // later than the family itself.
        let table = test_table_with_prefix();
        let (spec, _) = resolve_in(&table, &[0xf0, 0x02], 0).unwrap();
        assert_eq!(spec.version, 20);
    }

    #[test]
    fn test_resolve_against_real_table_no_registered_prefixes_yet() {
        // Sanity check against the *production* OPCODE_TABLE: every
        // currently-defined byte other than the `app_box_*` family's prefix
        // (0xd4, registered in the companion box-opcodes issue) resolves as
        // an ordinary single-byte opcode.
        for (byte, _) in all_opcodes() {
            if byte == 0xd4 {
                // The app_box_* prefix needs a second (sub-opcode) byte.
                let (spec, len) = resolve(&[byte, 0x01], 0).unwrap();
                assert_eq!(spec.opcode, byte);
                assert_eq!(len, 2);
                assert!(lookup(byte).unwrap().sub_ops.is_some());
                continue;
            }
            let (spec, len) = resolve(&[byte], 0).unwrap();
            assert_eq!(spec.opcode, byte);
            assert_eq!(len, 1);
            assert!(spec.sub_ops.is_none());
        }
    }

    // -----------------------------------------------------------------------
    // app_box_* foreign-box opcode family (prefix byte 0xd4, issue #662).
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_box_prefix_registered() {
        let spec = lookup(0xd4).unwrap();
        assert_eq!(spec.version, FOREIGN_BOX_VERSION);
        assert_eq!(spec.mode, Mode::Application);
        assert!(spec.sub_ops.is_some());
    }

    #[test]
    fn test_app_box_sub_opcodes_resolve() {
        let expected = [
            (0x01u8, "app_box_create", 3i8, 1i8),
            (0x02, "app_box_extract", 4, 1),
            (0x03, "app_box_replace", 4, 0),
            (0x04, "app_box_del", 2, 1),
            (0x05, "app_box_len", 2, 2),
            (0x06, "app_box_get", 2, 2),
            (0x07, "app_box_put", 3, 0),
            (0x08, "app_box_splice", 5, 0),
            (0x09, "app_box_resize", 3, 0),
        ];
        for (sub, name, pops, pushes) in expected {
            let (spec, len) = resolve(&[0xd4, sub], 0).unwrap();
            assert_eq!(spec.name, name, "sub-opcode 0x{sub:02x}");
            assert_eq!(spec.opcode, 0xd4);
            assert_eq!(spec.sub_opcode, sub);
            assert_eq!(spec.version, FOREIGN_BOX_VERSION);
            assert_eq!(spec.mode, Mode::Application);
            assert_eq!(spec.imm, ImmKind::None);
            assert_eq!(spec.stack_pops, pops);
            assert_eq!(spec.stack_pushes, pushes);
            assert_eq!(len, 2);
            // Also reachable by mnemonic (assembler lookup path).
            assert_eq!(lookup_by_name(name).unwrap().sub_opcode, sub);
        }
    }

    #[test]
    fn test_app_box_missing_sub_opcode_byte() {
        let err = resolve(&[0xd4], 0).unwrap_err();
        assert_eq!(err, "prefix opcode 0xd4 missing sub-opcode");
    }

    #[test]
    fn test_app_box_improper_sub_opcode() {
        let err = resolve(&[0xd4, 0x0a], 0).unwrap_err();
        assert_eq!(err, "prefix opcode 0xd4 with improper sub-opcode 0x0a");
    }
}
