#![no_main]

//! Fuzz target for AVM execution with a ledger-backed context.
//!
//! Generates random TEAL programs and runs them against a `LedgerAvmContext`
//! populated with random accounts, app state, asset holdings, and boxes.
//!
//! Invariant: **no panics**. Any error return is acceptable.

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use algo_avm::{parse, AvmMachine, ExecMode};
use algo_ledger::{LedgerAvmContext, LedgerState};
use algo_types::{
    AccountData, Address, AppLocalState, AppParams, AssetHolding, AssetParams,
    AssetParamsRecord, Round, SignedTransaction, StateSchema, TealValue, Transaction,
};

/// Maximum number of accounts to generate.
const MAX_ACCOUNTS: u8 = 4;
/// Maximum number of app global state keys.
const MAX_STATE_KEYS: u8 = 4;
/// Maximum number of assets.
const MAX_ASSETS: u8 = 3;
/// Maximum number of boxes.
const MAX_BOXES: u8 = 3;

/// Fuzz input: a program plus a minimal execution environment.
#[derive(Debug)]
struct FuzzInput {
    /// Raw TEAL bytecode (version header + instructions).
    program: Vec<u8>,
    /// Accounts to populate in the ledger: (address_bytes, balance).
    accounts: Vec<([u8; 32], u64)>,
    /// App global state (key-value pairs for the current app).
    global_state: Vec<(Vec<u8>, TealValue)>,
    /// App local state entries: (account_index, key-values).
    local_state: Vec<(usize, Vec<(Vec<u8>, TealValue)>)>,
    /// Asset holdings: (account_index, asset_id, amount, frozen).
    asset_holdings: Vec<(usize, u64, u64, bool)>,
    /// Asset params: (asset_id, total, decimals, creator_index).
    asset_params: Vec<(u64, u64, u8, usize)>,
    /// Boxes: (name, contents).
    boxes: Vec<(Vec<u8>, Vec<u8>)>,
    /// Whether to run in app mode or logicsig mode.
    app_mode: bool,
    /// The app ID to use.
    app_id: u64,
    /// Current round.
    round: u64,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // --- Generate a small TEAL program ---
        let program = generate_program(u)?;

        // --- Accounts ---
        let num_accounts: u8 = u.int_in_range(1..=MAX_ACCOUNTS)?;
        let mut accounts = Vec::with_capacity(num_accounts as usize);
        for _ in 0..num_accounts {
            let addr: [u8; 32] = u.arbitrary()?;
            let balance: u64 = u.int_in_range(0..=10_000_000_000u64)?;
            accounts.push((addr, balance));
        }

        // --- App global state ---
        let num_global: u8 = u.int_in_range(0..=MAX_STATE_KEYS)?;
        let mut global_state = Vec::with_capacity(num_global as usize);
        for _ in 0..num_global {
            let key_len: u8 = u.int_in_range(1..=8)?;
            let key: Vec<u8> = (0..key_len).map(|_| u.arbitrary()).collect::<Result<_, _>>()?;
            let value = gen_teal_value(u)?;
            global_state.push((key, value));
        }

        // --- App local state ---
        let num_local_accounts: u8 = u.int_in_range(0..=2.min(num_accounts))?;
        let mut local_state = Vec::new();
        for i in 0..num_local_accounts {
            let num_keys: u8 = u.int_in_range(0..=MAX_STATE_KEYS)?;
            let mut kvs = Vec::new();
            for _ in 0..num_keys {
                let key_len: u8 = u.int_in_range(1..=8)?;
                let key: Vec<u8> =
                    (0..key_len).map(|_| u.arbitrary()).collect::<Result<_, _>>()?;
                let value = gen_teal_value(u)?;
                kvs.push((key, value));
            }
            local_state.push((i as usize, kvs));
        }

        // --- Asset holdings ---
        let num_holdings: u8 = u.int_in_range(0..=MAX_ASSETS)?;
        let mut asset_holdings = Vec::new();
        for _ in 0..num_holdings {
            let acct_idx = u.choose_index(accounts.len())?;
            let asset_id: u64 = u.int_in_range(1..=100)?;
            let amount: u64 = u.int_in_range(0..=1_000_000)?;
            let frozen: bool = u.arbitrary()?;
            asset_holdings.push((acct_idx, asset_id, amount, frozen));
        }

        // --- Asset params ---
        let num_asset_params: u8 = u.int_in_range(0..=MAX_ASSETS)?;
        let mut asset_params = Vec::new();
        for _ in 0..num_asset_params {
            let asset_id: u64 = u.int_in_range(1..=100)?;
            let total: u64 = u.int_in_range(1..=1_000_000_000)?;
            let decimals: u8 = u.int_in_range(0..=19)?;
            let creator_idx = u.choose_index(accounts.len())?;
            asset_params.push((asset_id, total, decimals, creator_idx));
        }

        // --- Boxes ---
        let num_boxes: u8 = u.int_in_range(0..=MAX_BOXES)?;
        let mut boxes = Vec::new();
        for _ in 0..num_boxes {
            let name_len: u8 = u.int_in_range(1..=16)?;
            let name: Vec<u8> =
                (0..name_len).map(|_| u.arbitrary()).collect::<Result<_, _>>()?;
            let val_len: u8 = u.int_in_range(0..=32)?;
            let val: Vec<u8> =
                (0..val_len).map(|_| u.arbitrary()).collect::<Result<_, _>>()?;
            boxes.push((name, val));
        }

        let app_mode: bool = u.arbitrary()?;
        let app_id: u64 = if app_mode {
            u.int_in_range(1..=1000)?
        } else {
            0
        };
        let round: u64 = u.int_in_range(1..=100_000)?;

        Ok(FuzzInput {
            program,
            accounts,
            global_state,
            local_state,
            asset_holdings,
            asset_params,
            boxes,
            app_mode,
            app_id,
            round,
        })
    }
}

/// Generate a small structurally valid TEAL program.
fn generate_program(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(128);

    // Version byte
    let version: u8 = u.int_in_range(2..=10)?;
    bytes.push(version);

    // intcblock with a few constants
    let num_ints: u8 = u.int_in_range(1..=4)?;
    bytes.push(0x20); // intcblock
    bytes.push(num_ints);
    for _ in 0..num_ints {
        let val: u8 = u.arbitrary()?;
        bytes.push(val & 0x7f); // single-byte varuint
    }

    // bytecblock
    let num_byte_entries: u8 = u.int_in_range(0..=2)?;
    bytes.push(0x26); // bytecblock
    bytes.push(num_byte_entries);
    for _ in 0..num_byte_entries {
        let blen: u8 = u.int_in_range(0..=8)?;
        bytes.push(blen);
        for _ in 0..blen {
            bytes.push(u.arbitrary()?);
        }
    }

    // Instruction body: mix of state ops, pure ops, and stack ops
    let num_instructions: u8 = u.int_in_range(1..=30)?;
    let body_start = bytes.len();

    // Opcodes that are interesting for context testing (with uint8 immediates)
    const CONTEXT_OPS_WITH_IMM: &[u8] = &[
        0x31, // txn (uint8 field)
        0x32, // global (uint8 field)
        0x70, // asset_holding_get (uint8 field)
        0x71, // asset_params_get (uint8 field)
        0x72, // app_params_get (uint8 field)
    ];

    // Context opcodes without immediates
    const CONTEXT_OPS_NO_IMM: &[u8] = &[
        0x60, // balance
        0x61, // app_opted_in
        0x62, // app_local_get
        0x63, // app_local_get_ex
        0x64, // app_global_get
        0x65, // app_global_get_ex
        0x66, // app_local_put
        0x67, // app_local_del
        0x68, // app_global_put
        0x69, // app_global_del
        0x78, // min_balance
        0xb0, // log
    ];

    const PURE_OPCODES: &[u8] = &[
        0x08, // +
        0x09, // -
        0x0a, // /
        0x0b, // *
        0x12, // ==
        0x14, // !
        0x15, // len
        0x16, // itob
        0x17, // btoi
        0x48, // pop
        0x49, // dup
        0x4c, // swap
        0x43, // return
    ];

    struct BranchPatch {
        offset: usize,
    }
    let mut branch_patches: Vec<BranchPatch> = Vec::new();

    for _ in 0..num_instructions {
        let choice: u8 = u.int_in_range(0..=12)?;
        match choice {
            // Push int constant
            0..=2 => {
                let idx = u.int_in_range(0..=num_ints.saturating_sub(1))?;
                if idx < 4 {
                    bytes.push(0x22 + idx); // intc_0..intc_3
                } else {
                    bytes.push(0x21);
                    bytes.push(idx);
                }
            }
            // Push byte constant
            3 => {
                if num_byte_entries > 0 {
                    let idx = u.int_in_range(0..=num_byte_entries.saturating_sub(1))?;
                    if idx < 4 {
                        bytes.push(0x28 + idx);
                    } else {
                        bytes.push(0x27);
                        bytes.push(idx);
                    }
                } else {
                    bytes.push(0x22); // intc_0 fallback
                }
            }
            // pushint
            4 => {
                bytes.push(0x81);
                let val: u8 = u.arbitrary()?;
                bytes.push(val & 0x7f);
            }
            // Pure opcode
            5..=7 => {
                let idx = u.choose_index(PURE_OPCODES.len())?;
                bytes.push(PURE_OPCODES[idx]);
            }
            // Context opcode with uint8 immediate
            8 => {
                let idx = u.choose_index(CONTEXT_OPS_WITH_IMM.len())?;
                bytes.push(CONTEXT_OPS_WITH_IMM[idx]);
                let field: u8 = u.arbitrary()?;
                bytes.push(field);
            }
            // Context opcode without immediate
            9 => {
                let idx = u.choose_index(CONTEXT_OPS_NO_IMM.len())?;
                bytes.push(CONTEXT_OPS_NO_IMM[idx]);
            }
            // Branch
            10 => {
                let branch_op = match u.int_in_range(0..=2)? {
                    0 => 0x40u8,
                    1 => 0x41,
                    _ => 0x42,
                };
                bytes.push(branch_op);
                branch_patches.push(BranchPatch {
                    offset: bytes.len(),
                });
                bytes.push(0);
                bytes.push(0);
            }
            // store/load scratch
            11 => {
                let slot: u8 = u.int_in_range(0..=15)?;
                if u.arbitrary()? {
                    bytes.push(0x35);
                } else {
                    bytes.push(0x34);
                }
                bytes.push(slot);
            }
            // box ops (v8+)
            _ => {
                if version >= 8 {
                    let box_op: u8 = match u.int_in_range(0..=4)? {
                        0 => 0xb8, // box_create
                        1 => 0xb9, // box_extract
                        2 => 0xba, // box_replace
                        3 => 0xbb, // box_del
                        _ => 0xbc, // box_len
                    };
                    bytes.push(box_op);
                } else {
                    bytes.push(0x81); // pushint
                    bytes.push(1);
                }
            }
        }
    }

    // Patch branch targets
    let body_len = bytes.len() - body_start;
    for patch in &branch_patches {
        let after_branch = patch.offset + 2;
        let after_branch_rel = after_branch - body_start;
        let target_rel = if body_len > 0 {
            let raw: u16 = u.arbitrary().unwrap_or(0);
            (raw as usize) % body_len
        } else {
            0
        };
        let offset_val = (target_rel as isize - after_branch_rel as isize) as i16;
        let offset_bytes = offset_val.to_be_bytes();
        bytes[patch.offset] = offset_bytes[0];
        bytes[patch.offset + 1] = offset_bytes[1];
    }

    Ok(bytes)
}

/// Generate a random TealValue.
fn gen_teal_value(u: &mut Unstructured) -> arbitrary::Result<TealValue> {
    if u.arbitrary()? {
        Ok(TealValue::Uint(u.int_in_range(0..=1_000_000)?))
    } else {
        let len: u8 = u.int_in_range(0..=16)?;
        let data: Vec<u8> = (0..len).map(|_| u.arbitrary()).collect::<Result<_, _>>()?;
        Ok(TealValue::Bytes(data))
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input = match FuzzInput::arbitrary(&mut u) {
        Ok(i) => i,
        Err(_) => return,
    };

    // Parse the program
    let program = match parse(&input.program) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Build a LedgerState with the generated data
    let mut state = LedgerState::default();
    state.fee_sink = Address([0xFF; 32]);
    state.genesis_hash = [0xAA; 32];
    state.protocol = "future".to_string();

    // Fund fee sink
    let mut fee_sink_acct = AccountData::default();
    fee_sink_acct.micro_algos = 100_000_000_000;
    state.accounts.insert(state.fee_sink, fee_sink_acct);

    // Insert accounts
    for &(addr_bytes, balance) in &input.accounts {
        let addr = Address(addr_bytes);
        let mut acct = AccountData::default();
        acct.micro_algos = balance;
        state.accounts.insert(addr, acct);
    }

    // Insert asset params
    for &(asset_id, total, decimals, creator_idx) in &input.asset_params {
        let creator_addr = if creator_idx < input.accounts.len() {
            Address(input.accounts[creator_idx].0)
        } else {
            Address::ZERO
        };
        state.asset_params.insert(
            asset_id,
            AssetParamsRecord {
                params: AssetParams {
                    total,
                    decimals: decimals as u32,
                    default_frozen: false,
                    unit_name: String::new(),
                    asset_name: String::new(),
                    url: String::new(),
                    metadata_hash: None,
                    manager: None,
                    reserve: None,
                    freeze: None,
                    clawback: None,
                },
                creator: creator_addr,
            },
        );
    }

    // Insert asset holdings
    for &(acct_idx, asset_id, amount, frozen) in &input.asset_holdings {
        if acct_idx < input.accounts.len() {
            let addr = Address(input.accounts[acct_idx].0);
            state.asset_holdings.insert(
                (addr, asset_id),
                AssetHolding { amount, frozen },
            );
        }
    }

    // Insert app params with global state
    if input.app_id > 0 {
        let mut global_kv = BTreeMap::new();
        for (key, val) in &input.global_state {
            global_kv.insert(key.clone(), val.clone());
        }
        let creator = if !input.accounts.is_empty() {
            Address(input.accounts[0].0)
        } else {
            Address::ZERO
        };
        state.app_params.insert(
            input.app_id,
            AppParams {
                creator,
                approval_program: input.program.clone(),
                clear_state_program: vec![0x02, 0x81, 0x01], // v2 pushint 1
                global_state: global_kv,
                local_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 4,
                },
                global_state_schema: StateSchema {
                    num_uint: 8,
                    num_byte_slice: 8,
                },
                extra_program_pages: 0,
            },
        );

        // Insert local state for accounts
        for (acct_idx, kvs) in &input.local_state {
            if *acct_idx < input.accounts.len() {
                let addr = Address(input.accounts[*acct_idx].0);
                let mut kv_map = BTreeMap::new();
                for (key, val) in kvs {
                    kv_map.insert(key.clone(), val.clone());
                }
                state.app_local_states.insert(
                    (addr, input.app_id),
                    AppLocalState {
                        schema: StateSchema {
                            num_uint: 4,
                            num_byte_slice: 4,
                        },
                        key_value: kv_map,
                    },
                );
            }
        }
    }

    // Insert boxes
    for (name, contents) in &input.boxes {
        state
            .boxes
            .insert((input.app_id, name.clone()), contents.clone());
    }

    // Build a minimal SignedTransaction for the group
    let sender = if !input.accounts.is_empty() {
        Address(input.accounts[0].0)
    } else {
        Address::ZERO
    };
    let mut txn = Transaction::default();
    txn.sender = sender;
    txn.txn_type = if input.app_mode {
        "appl".to_string()
    } else {
        "pay".to_string()
    };
    txn.application_id = if input.app_mode { input.app_id } else { 0 };
    txn.first_valid = Round(input.round.saturating_sub(10));
    txn.last_valid = Round(input.round + 10);
    txn.genesis_hash = serde_bytes::ByteBuf::from(state.genesis_hash.to_vec());

    let stxn = SignedTransaction {
        txn,
        ..Default::default()
    };

    let creator = if !input.accounts.is_empty() {
        input.accounts[0].0
    } else {
        [0u8; 32]
    };

    let exec_mode = if input.app_mode {
        ExecMode::Application
    } else {
        ExecMode::LogicSig
    };

    // Create the context
    let mut ctx = LedgerAvmContext::new(
        &mut state,
        vec![stxn],
        0,               // group_index
        input.round,
        1_000_000,       // latest_timestamp
        input.app_id,
        creator,
        input.app_mode,
        [0u8; 32],       // program_hash
        [0xAA; 32],      // genesis_hash
        algo_types::ConsensusParams::default(),
    );

    // Run the program -- must not panic
    let mut machine = AvmMachine::new(program, exec_mode, 20_000);
    let _ = machine.run(&mut ctx);
});
