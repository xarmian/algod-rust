//! Integration tests: execute TEAL programs through the AVM against real LedgerState.
//!
//! These tests verify the full stack: bytecode -> machine -> context -> ledger.
//! Each test constructs raw TEAL bytecode, sets up a LedgerState with appropriate
//! accounts/assets/apps, creates a LedgerAvmContext, and runs through AvmMachine.

use std::collections::BTreeMap;

use serde_bytes::ByteBuf;

use algo_avm::{parse, AvmMachine, ExecMode};
use algo_ledger::{LedgerAvmContext, LedgerState};
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParams, AssetParamsRecord,
    SignedTransaction, StateSchema, TealValue, Transaction,
};

// ===========================================================================
// Helpers
// ===========================================================================

/// Build a raw AVM program: version byte + opcode stream.
fn prog(version: u8, code: &[u8]) -> Vec<u8> {
    let mut p = vec![version];
    p.extend_from_slice(code);
    p
}

/// Create a minimal appl SignedTransaction suitable for AVM execution.
fn make_appl_txn(sender: [u8; 32], app_id: u64) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".to_string(),
            sender: Address(sender),
            fee: 1000,
            first_valid: 100.into(),
            last_valid: 200.into(),
            application_id: app_id,
            on_completion: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Create an appl txn with application args.
fn make_appl_txn_with_args(sender: [u8; 32], app_id: u64, args: Vec<Vec<u8>>) -> SignedTransaction {
    let app_arguments: Vec<Option<ByteBuf>> =
        args.into_iter().map(|a| Some(ByteBuf::from(a))).collect();
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".to_string(),
            sender: Address(sender),
            fee: 1000,
            first_valid: 100.into(),
            last_valid: 200.into(),
            application_id: app_id,
            on_completion: 0,
            app_arguments: if app_arguments.is_empty() {
                None
            } else {
                Some(app_arguments)
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Create an appl txn with foreign assets and accounts.
fn make_appl_txn_with_refs(
    sender: [u8; 32],
    app_id: u64,
    accounts: Vec<Address>,
    foreign_assets: Vec<u64>,
) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: "appl".to_string(),
            sender: Address(sender),
            fee: 1000,
            first_valid: 100.into(),
            last_valid: 200.into(),
            application_id: app_id,
            on_completion: 0,
            accounts: if accounts.is_empty() {
                None
            } else {
                Some(accounts)
            },
            foreign_assets: if foreign_assets.is_empty() {
                None
            } else {
                Some(foreign_assets)
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Build a LedgerAvmContext in app mode with round=100, app_id=42, creator=[1;32].
fn make_context<'a>(
    store: &'a mut LedgerState,
    group: Vec<SignedTransaction>,
) -> LedgerAvmContext<'a, LedgerState> {
    LedgerAvmContext::new(
        store, group, 0,         // group_index
        100,       // round
        50000,     // latest_timestamp
        42,        // app_id
        [1u8; 32], // creator
        true,      // app_mode
        [0u8; 32], // program_hash
        [0u8; 32], // genesis_hash
    )
}

/// Build a LedgerAvmContext in LogicSig mode.
fn make_lsig_context<'a>(
    store: &'a mut LedgerState,
    group: Vec<SignedTransaction>,
) -> LedgerAvmContext<'a, LedgerState> {
    LedgerAvmContext::new(
        store, group, 0,         // group_index
        100,       // round
        50000,     // latest_timestamp
        0,         // app_id (not used in lsig mode)
        [0u8; 32], // creator
        false,     // app_mode = false for LogicSig
        [0u8; 32], // program_hash
        [0u8; 32], // genesis_hash
    )
}

/// Run a program through the AVM using the given context. Returns Ok(pass/reject).
fn run_with_context(
    version: u8,
    code: &[u8],
    ctx: &mut dyn algo_avm::AvmContext,
) -> Result<bool, algo_error::AlgoError> {
    let raw = prog(version, code);
    let program = parse(&raw)?;
    let mut machine = AvmMachine::new(program, ExecMode::Application, 20_000);
    machine.run(ctx)
}

/// Seed a LedgerState with a default app_params for app_id=42.
fn seed_app(store: &mut LedgerState) {
    store.app_params.insert(
        42,
        AppParams {
            creator: Address([1u8; 32]),
            approval_program: vec![],
            clear_state_program: vec![],
            global_state: BTreeMap::new(),
            local_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 4,
            },
            global_state_schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 4,
            },
            extra_program_pages: 0,
        },
    );
}

/// Opt an account into app_id=42 with empty local state.
fn opt_in_account(store: &mut LedgerState, addr: Address) {
    store.app_local_states.insert(
        (addr, 42),
        AppLocalState {
            schema: StateSchema {
                num_uint: 4,
                num_byte_slice: 4,
            },
            key_value: BTreeMap::new(),
        },
    );
}

// ===========================================================================
// Test Group 1: Transaction Field Access
// ===========================================================================

/// txn Sender; len; int 32; ==; return
/// Verifies: txn Sender returns a 32-byte address.
#[test]
fn txn_sender_is_32_bytes() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    // txn Sender (field 0) -> 32 bytes
    let code: &[u8] = &[
        0x31, 0x00, // txn Sender
        0x15, // len
        0x81, 0x20, // pushint 32
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "txn Sender should be 32 bytes");
}

/// txn Fee; int 1000; ==; return
/// Verifies: txn Fee returns correct value.
#[test]
fn txn_fee_value() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x31, 0x01, // txn Fee
        0x81, 0xE8, 0x07, // pushint 1000
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "txn Fee should be 1000");
}

/// txn TypeEnum; int 6; ==; return
/// Verifies: TypeEnum for appl = 6.
#[test]
fn txn_type_enum_appl() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x31, 0x0F, // txn TypeEnum (field 15)
        0x81, 0x06, // pushint 6
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "TypeEnum for appl should be 6");
}

/// txna ApplicationArgs 0; byte "hello"; ==; return
/// Verifies: array field access works.
#[test]
fn txna_application_args() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn_with_args(sender, 42, vec![b"hello".to_vec()]);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x36, 25, 0x00, // txna ApplicationArgs 0
        0x80, 0x05, b'h', b'e', b'l', b'l', b'o', // pushbytes "hello"
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "txna ApplicationArgs 0 should return 'hello'");
}

/// Verify txn FirstValid and LastValid.
#[test]
fn txn_first_last_valid() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    // txn FirstValid; int 100; ==; txn LastValid; int 200; ==; &&; return
    let code: &[u8] = &[
        0x31, 0x02, // txn FirstValid
        0x81, 0x64, // pushint 100
        0x12, // ==
        0x31, 0x03, // txn LastValid
        0x81, 0xC8, 0x01, // pushint 200
        0x12, // ==
        0x10, // &&
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "FirstValid=100 and LastValid=200");
}

/// Verify txn ApplicationID reads the app id from the transaction.
#[test]
fn txn_application_id() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x31, 23, // txn ApplicationID (field 23)
        0x81, 0x2A, // pushint 42
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "txn ApplicationID should be 42");
}

// ===========================================================================
// Test Group 2: Global Field Access
// ===========================================================================

/// global MinTxnFee; int 1000; ==; return
#[test]
fn global_min_txn_fee() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x32, 0x00, // global MinTxnFee (field 0)
        0x81, 0xE8, 0x07, // pushint 1000
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global MinTxnFee should be 1000");
}

/// global Round; int 100; ==; return
/// (round is set to 100 in our context)
#[test]
fn global_round() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x32, 0x06, // global Round (field 6)
        0x81, 0x64, // pushint 100
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global Round should be 100");
}

/// global GroupSize; int 1; ==; return
#[test]
fn global_group_size() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x32, 0x04, // global GroupSize (field 4)
        0x81, 0x01, // pushint 1
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global GroupSize should be 1");
}

/// global CurrentApplicationID; int 42; ==; return
#[test]
fn global_current_app_id() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x32, 0x08, // global CurrentApplicationID (field 8)
        0x81, 0x2A, // pushint 42
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global CurrentApplicationID should be 42");
}

/// global LatestTimestamp; int 50000; ==; return
#[test]
fn global_latest_timestamp() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    // 50000 varuint = 0xD0, 0x86, 0x03
    let code: &[u8] = &[
        0x32, 0x07, // global LatestTimestamp (field 7)
        0x81, 0xD0, 0x86, 0x03, // pushint 50000
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global LatestTimestamp should be 50000");
}

/// global LogicSigVersion; int 11; ==; return
#[test]
fn global_logicsig_version() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x32, 0x05, // global LogicSigVersion (field 5)
        0x81, 0x0B, // pushint 11
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global LogicSigVersion should be 11");
}

// ===========================================================================
// Test Group 3: State Read/Write
// ===========================================================================

/// app_global_put: byte "counter"; int 42; app_global_put; int 1; return
/// Then verify global state has key "counter" = 42.
#[test]
fn app_global_put_and_verify() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x80, 0x07, b'c', b'o', b'u', b'n', b't', b'e', b'r', // pushbytes "counter"
        0x81, 0x2A, // pushint 42
        0x67, // app_global_put
        0x81, 0x01, // pushint 1
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "program should approve after app_global_put");

    // Verify the global state was written.
    let params = ctx.store.app_params.get(&42).expect("app 42 should exist");
    let val = params
        .global_state
        .get(b"counter".as_slice())
        .expect("key 'counter' should exist");
    assert_eq!(*val, TealValue::Uint(42));
}

/// app_global_get with pre-loaded state:
/// byte "counter"; app_global_get; int 42; ==; return
#[test]
fn app_global_get_preloaded() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    // Pre-load global state.
    store
        .app_params
        .get_mut(&42)
        .unwrap()
        .global_state
        .insert(b"counter".to_vec(), TealValue::Uint(42));

    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x80, 0x07, b'c', b'o', b'u', b'n', b't', b'e', b'r', // pushbytes "counter"
        0x64, // app_global_get
        0x81, 0x2A, // pushint 42
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(
        result,
        "app_global_get should return 42 for pre-loaded 'counter'"
    );
}

/// app_global_get for missing key returns 0 (default).
#[test]
fn app_global_get_missing_key_returns_zero() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x80, 0x06, b'n', b'o', b's', b'u', b'c', b'h', // pushbytes "nosuch"
        0x64, // app_global_get -> should be 0 (missing)
        0x81, 0x00, // pushint 0
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "app_global_get for missing key should return 0");
}

/// app_local_put and verify:
/// int 0; byte "mykey"; int 99; app_local_put; int 1; return
/// Account 0 = sender, opted in.
#[test]
fn app_local_put_and_verify() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    opt_in_account(&mut store, Address(sender));
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (account index: sender)
        0x80, 0x05, b'm', b'y', b'k', b'e', b'y', // pushbytes "mykey"
        0x81, 0x63, // pushint 99
        0x66, // app_local_put
        0x81, 0x01, // pushint 1
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "program should approve after app_local_put");

    // Verify local state was written.
    let local = ctx
        .store
        .app_local_states
        .get(&(Address(sender), 42))
        .expect("local state should exist");
    let val = local
        .key_value
        .get(b"mykey".as_slice())
        .expect("key 'mykey' should exist");
    assert_eq!(*val, TealValue::Uint(99));
}

/// app_local_get with pre-loaded state:
/// int 0; byte "mykey"; app_local_get; int 99; ==; return
#[test]
fn app_local_get_preloaded() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    opt_in_account(&mut store, Address(sender));
    // Pre-load local state.
    store
        .app_local_states
        .get_mut(&(Address(sender), 42))
        .unwrap()
        .key_value
        .insert(b"mykey".to_vec(), TealValue::Uint(99));

    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (sender)
        0x80, 0x05, b'm', b'y', b'k', b'e', b'y', // pushbytes "mykey"
        0x62, // app_local_get
        0x81, 0x63, // pushint 99
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(
        result,
        "app_local_get should return 99 for pre-loaded 'mykey'"
    );
}

/// Round-trip: put a bytes value in global state, read it back.
#[test]
fn app_global_put_bytes_round_trip() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    let mut ctx = make_context(&mut store, vec![txn]);

    // byte "name"; byte "alice"; app_global_put;
    // byte "name"; app_global_get; byte "alice"; ==; return
    let code: &[u8] = &[
        0x80, 0x04, b'n', b'a', b'm', b'e', // pushbytes "name"
        0x80, 0x05, b'a', b'l', b'i', b'c', b'e', // pushbytes "alice"
        0x67, // app_global_put
        0x80, 0x04, b'n', b'a', b'm', b'e', // pushbytes "name"
        0x64, // app_global_get
        0x80, 0x05, b'a', b'l', b'i', b'c', b'e', // pushbytes "alice"
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global state round-trip for bytes should work");
}

// ===========================================================================
// Test Group 4: Account / Asset / App Query
// ===========================================================================

/// balance: int 0; balance; int 1000000; ==; return
/// Sender has 1M microalgos.
#[test]
fn balance_query() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    store.accounts.insert(
        Address(sender),
        AccountData {
            micro_algos: 1_000_000,
            ..Default::default()
        },
    );
    let mut ctx = make_context(&mut store, vec![txn]);

    // 1000000 varuint = 0xC0, 0x84, 0x3D
    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (account index: sender)
        0x60, // balance
        0x81, 0xC0, 0x84, 0x3D, // pushint 1000000
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "balance should be 1000000 microalgos");
}

/// balance of zero for account not in ledger.
#[test]
fn balance_zero_for_unknown_account() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    // Don't insert sender account -- balance should be 0.
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (sender)
        0x60, // balance
        0x81, 0x00, // pushint 0
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "balance should be 0 for unknown account");
}

/// asset_holding_get AssetBalance:
/// int 0; asset_holding_get AssetBalance; assert; int 500; ==; return
/// Sender holds 500 of asset 7.
#[test]
fn asset_holding_get_balance() {
    let sender = [0xAA; 32];
    // Need foreign_assets to reference asset 7 (index 0 -> implied via xaid or index 1 -> foreign).
    // We'll set xaid=7 on the txn so asset index 0 resolves to 7.
    let mut txn = make_appl_txn_with_refs(sender, 42, vec![], vec![7]);
    txn.txn.xaid = 7;
    let mut store = LedgerState::new();
    seed_app(&mut store);
    store.accounts.insert(
        Address(sender),
        AccountData {
            micro_algos: 100_000,
            ..Default::default()
        },
    );
    store.asset_holdings.insert(
        (Address(sender), 7),
        AssetHolding {
            amount: 500,
            frozen: false,
        },
    );
    store.asset_params.insert(
        7,
        AssetParamsRecord {
            params: AssetParams::default(),
            creator: Address(sender),
        },
    );
    let mut ctx = make_context(&mut store, vec![txn]);

    // The opcode: pop account (index), then the asset comes from the immediate field.
    // asset_holding_get (0x70) has a uint8 immediate (holding field index).
    // Stack: push account(0), then asset_holding_get needs (account, asset_id) from stack.
    // Actually in the AVM: asset_holding_get takes an account from stack, then the
    // asset ID from the second stack position. Let me read the opcode.
    //
    // Looking at state.rs: op_asset_holding_get pops asset_ref then account_ref:
    //   let asset_val = machine.pop_any()?;
    //   let acct_val = machine.pop_any()?;
    // So stack order is: push account, push asset, then call asset_holding_get.
    // Account index 0 = sender. Asset index 0 = implied (xaid=7).
    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (account index: sender)
        0x81, 0x00, // pushint 0  (asset index: implied, xaid=7)
        0x70, 0x00, // asset_holding_get AssetBalance (field 0)
        0x44, // assert (exists flag)
        0x81, 0xF4, 0x03, // pushint 500
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "asset_holding_get AssetBalance should be 500");
}

/// asset_holding_get returns (0, false) for non-existent holding.
#[test]
fn asset_holding_get_nonexistent() {
    let sender = [0xAA; 32];
    let mut txn = make_appl_txn_with_refs(sender, 42, vec![], vec![7]);
    txn.txn.xaid = 7;
    let mut store = LedgerState::new();
    seed_app(&mut store);
    // Don't insert any asset holding.
    store.asset_params.insert(
        7,
        AssetParamsRecord {
            params: AssetParams::default(),
            creator: Address(sender),
        },
    );
    let mut ctx = make_context(&mut store, vec![txn]);

    // asset_holding_get returns (value, exists_flag) where exists_flag is on top.
    // If not opted in, exists_flag = 0.
    // pushint 0; pushint 0; asset_holding_get AssetBalance; !; return
    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (account: sender)
        0x81, 0x00, // pushint 0  (asset: implied)
        0x70, 0x00, // asset_holding_get AssetBalance
        0x14, // ! (negate exists flag: 0 -> 1)
        0x43, // return
              // Note: the value is still on stack below but return only checks top.
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(
        result,
        "asset_holding_get should return exists=false for non-opted-in account"
    );
}

/// asset_holding_get AssetFrozen field.
#[test]
fn asset_holding_get_frozen() {
    let sender = [0xAA; 32];
    let mut txn = make_appl_txn_with_refs(sender, 42, vec![], vec![7]);
    txn.txn.xaid = 7;
    let mut store = LedgerState::new();
    seed_app(&mut store);
    store.asset_holdings.insert(
        (Address(sender), 7),
        AssetHolding {
            amount: 100,
            frozen: true,
        },
    );
    store.asset_params.insert(
        7,
        AssetParamsRecord {
            params: AssetParams::default(),
            creator: Address(sender),
        },
    );
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (account: sender)
        0x81, 0x00, // pushint 0  (asset: implied)
        0x70, 0x01, // asset_holding_get AssetFrozen (field 1)
        0x44, // assert (exists)
        0x81, 0x01, // pushint 1
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "asset_holding_get AssetFrozen should be 1 (true)");
}

// ===========================================================================
// Test Group 5: Log Opcode
// ===========================================================================

/// byte "hello world"; log; int 1; return
/// Verify: context.logs contains "hello world".
#[test]
fn log_opcode() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x80, 0x0B, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd',
        // pushbytes "hello world"
        0xb0, // log
        0x81, 0x01, // pushint 1
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "program should approve after log");

    let logs = ctx.logs();
    assert_eq!(logs.len(), 1, "should have exactly 1 log entry");
    assert_eq!(logs[0], b"hello world", "log entry should be 'hello world'");
}

/// Multiple log calls.
#[test]
fn log_multiple() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x80, 0x01, b'A', // pushbytes "A"
        0xb0, // log
        0x80, 0x01, b'B', // pushbytes "B"
        0xb0, // log
        0x80, 0x01, b'C', // pushbytes "C"
        0xb0, // log
        0x81, 0x01, // pushint 1
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result);

    let logs = ctx.logs();
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[0], b"A");
    assert_eq!(logs[1], b"B");
    assert_eq!(logs[2], b"C");
}

// ===========================================================================
// Test Group 6: Inner Transaction Construction
// ===========================================================================

/// itxn_begin; int 1; itxn_field TypeEnum; itxn_submit; int 1; return
/// Verify: an inner transaction was built with type "pay".
#[test]
fn itxn_basic_construction() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0xb1, // itxn_begin
        0x81, 0x01, // pushint 1  (TypeEnum for "pay")
        0xb2, 15,   // itxn_field TypeEnum (field 15)
        0xb3, // itxn_submit
        0x81, 0x01, // pushint 1
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "program should approve after itxn_submit");

    // Verify an inner transaction was recorded.
    let inner = ctx.inner_txns();
    assert!(
        !inner.is_empty(),
        "should have at least one inner txn group"
    );
    let itxn = &inner[0][0];
    assert_eq!(itxn.txn.txn_type, "pay", "inner txn type should be 'pay'");
}

/// Inner transaction with multiple fields set.
#[test]
fn itxn_with_multiple_fields() {
    let sender = [0xAA; 32];
    let receiver = [0xBB; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    let mut ctx = make_context(&mut store, vec![txn]);

    // Build a pay inner txn with receiver and amount.
    let mut code: Vec<u8> = Vec::new();
    code.push(0xb1); // itxn_begin

    // TypeEnum = 1 (pay)
    code.extend_from_slice(&[0x81, 0x01]); // pushint 1
    code.extend_from_slice(&[0xb2, 15]); // itxn_field TypeEnum

    // Receiver
    code.push(0x80); // pushbytes
    code.push(32); // length
    code.extend_from_slice(&receiver);
    code.extend_from_slice(&[0xb2, 6]); // itxn_field Receiver (field 6)

    // Amount = 5000
    code.extend_from_slice(&[0x81, 0x88, 0x27]); // pushint 5000
    code.extend_from_slice(&[0xb2, 7]); // itxn_field Amount (field 7)

    code.push(0xb3); // itxn_submit
    code.extend_from_slice(&[0x81, 0x01]); // pushint 1
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result);

    let inner = ctx.inner_txns();
    assert_eq!(inner.len(), 1);
    let itxn = &inner[0][0];
    assert_eq!(itxn.txn.txn_type, "pay");
    assert_eq!(itxn.txn.receiver, Address(receiver));
    assert_eq!(itxn.txn.amount, 5000);
}

// ===========================================================================
// Test Group 7: Arg Access (LogicSig mode)
// ===========================================================================

/// arg 0; byte "secret"; ==; return
/// LogicSig mode with lsig_args = [b"secret"].
#[test]
fn arg_access_logicsig() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 0);
    let mut store = LedgerState::new();
    let mut ctx = make_lsig_context(&mut store, vec![txn]);
    ctx.set_lsig_args(vec![b"secret".to_vec()]);

    let code: &[u8] = &[
        0x2c, 0x00, // arg 0
        0x80, 0x06, b's', b'e', b'c', b'r', b'e', b't', // pushbytes "secret"
        0x12, // ==
        0x43, // return
    ];
    // Use LogicSig mode for running.
    let raw = prog(6, code);
    let program = parse(&raw).unwrap();
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    let result = machine.run(&mut ctx).unwrap();
    assert!(result, "arg 0 should equal 'secret'");
}

/// arg 0 and arg 1 with multiple arguments.
#[test]
fn arg_access_multiple() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 0);
    let mut store = LedgerState::new();
    let mut ctx = make_lsig_context(&mut store, vec![txn]);
    ctx.set_lsig_args(vec![b"alpha".to_vec(), b"beta".to_vec()]);

    // arg 0; byte "alpha"; ==; arg 1; byte "beta"; ==; &&; return
    let code: &[u8] = &[
        0x2c, 0x00, // arg 0
        0x80, 0x05, b'a', b'l', b'p', b'h', b'a', // pushbytes "alpha"
        0x12, // ==
        0x2c, 0x01, // arg 1
        0x80, 0x04, b'b', b'e', b't', b'a', // pushbytes "beta"
        0x12, // ==
        0x10, // &&
        0x43, // return
    ];
    let raw = prog(6, code);
    let program = parse(&raw).unwrap();
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    let result = machine.run(&mut ctx).unwrap();
    assert!(result, "arg 0 = 'alpha' and arg 1 = 'beta'");
}

// ===========================================================================
// Test Group 8: Combined / Multi-step Programs
// ===========================================================================

/// A program that reads a global field, performs arithmetic, writes to global state,
/// reads it back, and verifies the result.
/// round * 2 => 200; store in global "doubled_round"; read back; verify.
#[test]
fn combined_global_field_and_state() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        // Write: global Round * 2 -> global state "dr"
        0x80, 0x02, b'd', b'r', // pushbytes "dr"
        0x32, 0x06, // global Round (= 100)
        0x81, 0x02, // pushint 2
        0x0b, // * (100 * 2 = 200)
        0x67, // app_global_put ("dr" = 200)
        // Read back and verify.
        0x80, 0x02, b'd', b'r', // pushbytes "dr"
        0x64, // app_global_get
        0x81, 0xC8, 0x01, // pushint 200
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "Round*2 written and read back should equal 200");
}

/// A program that writes to both global and local state, then reads both.
#[test]
fn combined_global_and_local_state() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    opt_in_account(&mut store, Address(sender));
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        // Global put: "gk" = 10
        0x80, 0x02, b'g', b'k', // pushbytes "gk"
        0x81, 0x0A, // pushint 10
        0x67, // app_global_put
        // Local put: sender's "lk" = 20
        0x81, 0x00, // pushint 0  (sender)
        0x80, 0x02, b'l', b'k', // pushbytes "lk"
        0x81, 0x14, // pushint 20
        0x66, // app_local_put
        // Read global "gk" and local "lk", add them, verify == 30
        0x80, 0x02, b'g', b'k', // pushbytes "gk"
        0x64, // app_global_get -> 10
        0x81, 0x00, // pushint 0
        0x80, 0x02, b'l', b'k', // pushbytes "lk"
        0x62, // app_local_get -> 20
        0x08, // + -> 30
        0x81, 0x1E, // pushint 30
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global(10) + local(20) should equal 30");
}

/// A program that checks the sender address against the txn sender.
#[test]
fn verify_sender_address_bytes() {
    let sender = [0x42; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    // txn Sender; pushbytes <sender>; ==; return
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x31, 0x00]); // txn Sender
    code.push(0x80); // pushbytes
    code.push(32); // length
    code.extend_from_slice(&sender);
    code.push(0x12); // ==
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "txn Sender should match expected sender bytes");
}

/// Verify that the GroupSize matches when there are 2 txns in the group.
#[test]
fn global_group_size_two_txns() {
    let sender = [0xAA; 32];
    let txn1 = make_appl_txn(sender, 42);
    let txn2 = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn1, txn2]);

    let code: &[u8] = &[
        0x32, 0x04, // global GroupSize
        0x81, 0x02, // pushint 2
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "GroupSize should be 2 with two txns in group");
}

/// Verify app_opted_in opcode: sender is opted in to app 42.
#[test]
fn app_opted_in_check() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    opt_in_account(&mut store, Address(sender));
    let mut ctx = make_context(&mut store, vec![txn]);

    // int 0 (sender); int 0 (current app); app_opted_in; return
    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (sender)
        0x81, 0x00, // pushint 0  (app index 0 = current app = 42)
        0x61, // app_opted_in
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "sender should be opted in to app 42");
}

/// Verify app_opted_in returns false when not opted in.
#[test]
fn app_opted_in_false() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    // Don't opt in the sender.
    let mut ctx = make_context(&mut store, vec![txn]);

    let code: &[u8] = &[
        0x81, 0x00, // pushint 0  (sender)
        0x81, 0x00, // pushint 0  (current app)
        0x61, // app_opted_in
        0x14, // ! (negate: false -> true)
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(
        result,
        "sender should NOT be opted in (negated check passes)"
    );
}

/// Verify a program that logs, writes state, and checks balance in one flow.
#[test]
fn combined_log_state_balance() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    store.accounts.insert(
        Address(sender),
        AccountData {
            micro_algos: 500_000,
            ..Default::default()
        },
    );
    let mut ctx = make_context(&mut store, vec![txn]);

    // Log "start"; global put "bal" = balance(sender); global get "bal"; int 500000; ==; return
    // 500000 varuint = 0xA0, 0xC2, 0x1E
    let code: &[u8] = &[
        // log "start"
        0x80, 0x05, b's', b't', b'a', b'r', b't', // pushbytes "start"
        0xb0, // log
        // Write balance to global state
        0x80, 0x03, b'b', b'a', b'l', // pushbytes "bal"
        0x81, 0x00, // pushint 0 (sender)
        0x60, // balance
        0x67, // app_global_put
        // Read back and verify
        0x80, 0x03, b'b', b'a', b'l', // pushbytes "bal"
        0x64, // app_global_get
        0x81, 0xA0, 0xC2, 0x1E, // pushint 500000
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "balance read/write/verify should pass");

    let logs = ctx.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0], b"start");

    let params = ctx.store.app_params.get(&42).unwrap();
    let stored = params.global_state.get(b"bal".as_slice()).unwrap();
    assert_eq!(*stored, TealValue::Uint(500_000));
}

/// A program using a branch loop to compute sum 1..10 = 55 and store in global state.
#[test]
fn loop_compute_and_store_global() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    seed_app(&mut store);
    let mut ctx = make_context(&mut store, vec![txn]);

    // scratch[0] = accumulator, scratch[1] = counter (start=10)
    // loop: if counter == 0, goto done
    //   acc += counter; counter -= 1; goto loop
    // done: global put "sum" = acc; global get "sum"; int 55; ==; return
    //
    // Offsets (from code start, not including version byte):
    //   0: pushint 0     (0x81 0x00)  2b
    //   2: store 0       (0x35 0x00)  2b
    //   4: pushint 10    (0x81 0x0a)  2b
    //   6: store 1       (0x35 0x01)  2b
    // loop @ 8:
    //   8: load 1        (0x34 0x01)  2b
    //  10: bz done       (0x41 xx xx) 3b -> done @ 28, after_bz = 13, offset = 28-13 = 15
    //  13: load 0        (0x34 0x00)  2b
    //  15: load 1        (0x34 0x01)  2b
    //  17: +             (0x08)       1b
    //  18: store 0       (0x35 0x00)  2b
    //  20: load 1        (0x34 0x01)  2b
    //  22: pushint 1     (0x81 0x01)  2b
    //  24: -             (0x09)       1b
    //  25: store 1       (0x35 0x01)  2b
    //  27: b loop        (0x42 xx xx) 3b -> loop @ 8, after_b = 30, offset = 8-30 = -22
    // done @ 30:
    //  30: pushbytes "sum" (0x80 0x03 s u m) 5b
    //  35: load 0        (0x34 0x00)  2b
    //  37: app_global_put (0x67)      1b
    //  38: pushbytes "sum" (0x80 0x03 s u m) 5b
    //  43: app_global_get (0x64)      1b
    //  44: pushint 55    (0x81 0x37)  2b
    //  46: ==            (0x12)       1b
    //  47: return        (0x43)       1b

    let code: &[u8] = &[
        // 0:  pushint 0
        0x81, 0x00, // 2:  store 0
        0x35, 0x00, // 4:  pushint 10
        0x81, 0x0a, // 6:  store 1
        0x35, 0x01, // 8:  load 1         (loop start)
        0x34, 0x01, // 10: bz +17         (after=13, target=30=done)
        0x41, 0x00, 17, // 13: load 0
        0x34, 0x00, // 15: load 1
        0x34, 0x01, // 17: +
        0x08, // 18: store 0
        0x35, 0x00, // 20: load 1
        0x34, 0x01, // 22: pushint 1
        0x81, 0x01, // 24: -
        0x09, // 25: store 1
        0x35, 0x01, // 27: b -22          (after=30, target=8)
        0x42, 0xFF, 0xEA, // 30: pushbytes "sum"
        0x80, 0x03, b's', b'u', b'm', // 35: load 0
        0x34, 0x00, // 37: app_global_put
        0x67, // 38: pushbytes "sum"
        0x80, 0x03, b's', b'u', b'm', // 43: app_global_get
        0x64, // 44: pushint 55
        0x81, 0x37, // 46: ==
        0x12, // 47: return
        0x43,
    ];

    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "sum(1..10)=55 written and read back should pass");

    let params = ctx.store.app_params.get(&42).unwrap();
    let val = params.global_state.get(b"sum".as_slice()).unwrap();
    assert_eq!(*val, TealValue::Uint(55));
}

/// Verify global ZeroAddress is 32 zero bytes.
#[test]
fn global_zero_address() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    // global ZeroAddress; len; int 32; ==; return
    let code: &[u8] = &[
        0x32, 0x03, // global ZeroAddress (field 3)
        0x15, // len
        0x81, 0x20, // pushint 32
        0x12, // ==
        0x43, // return
    ];
    let result = run_with_context(6, code, &mut ctx).unwrap();
    assert!(result, "global ZeroAddress should be 32 bytes");
}

/// Verify global CreatorAddress matches the configured creator.
#[test]
fn global_creator_address() {
    let sender = [0xAA; 32];
    let txn = make_appl_txn(sender, 42);
    let mut store = LedgerState::new();
    let mut ctx = make_context(&mut store, vec![txn]);

    // global CreatorAddress (field 9); pushbytes [1;32]; ==; return
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0x32, 0x09]); // global CreatorAddress
    code.push(0x80); // pushbytes
    code.push(32); // length
    code.extend_from_slice(&[1u8; 32]); // creator = [1;32] in make_context
    code.push(0x12); // ==
    code.push(0x43); // return

    let result = run_with_context(6, &code, &mut ctx).unwrap();
    assert!(result, "global CreatorAddress should be [1;32]");
}
