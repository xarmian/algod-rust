//! End-to-end integration tests for the AVM.
//!
//! Each test assembles raw bytecode, parses, and runs through the full machine pipeline.

use algo_avm::{parse, AvmMachine, ExecMode, NullContext};

/// Helper: prepend version byte, parse, and run. Returns Ok(true) for pass, Ok(false) for reject.
fn run_program(version: u8, code: &[u8]) -> Result<bool, algo_error::AlgoError> {
    let mut raw = vec![version];
    raw.extend_from_slice(code);
    let program = parse(&raw)?;
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    machine.run(&mut NullContext)
}

// ---------------------------------------------------------------------------
// 1. Arithmetic chain: pushint 10, pushint 3, +, pushint 13, ==, return
// ---------------------------------------------------------------------------
#[test]
fn test_arithmetic_chain() {
    let code: &[u8] = &[
        0x81, 0x0a, // pushint 10
        0x81, 0x03, // pushint 3
        0x08, // +
        0x81, 0x0d, // pushint 13
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "10 + 3 == 13 should pass");
}

// ---------------------------------------------------------------------------
// 2. Fibonacci via scratch: compute fib(10) = 55 using store/load and branch loop
// ---------------------------------------------------------------------------
#[test]
fn test_fibonacci_via_scratch() {
    // Algorithm:
    //   scratch[0] = 0 (a)
    //   scratch[1] = 1 (b)
    //   scratch[2] = 10 (counter)
    // loop:
    //   if counter == 0, branch to done
    //   tmp = a + b
    //   a = b
    //   b = tmp
    //   counter -= 1
    //   branch to loop
    // done:
    //   load a, return
    //
    // We'll use version 3 (has pushint, store, load, bnz, bz, b).
    //
    // Instruction layout (byte offsets):
    //   0: pushint 0       (0x81, 0x00)  2 bytes
    //   2: store 0          (0x35, 0x00)  2 bytes
    //   4: pushint 1       (0x81, 0x01)  2 bytes
    //   6: store 1          (0x35, 0x01)  2 bytes
    //   8: pushint 10      (0x81, 0x0a)  2 bytes
    //  10: store 2          (0x35, 0x02)  2 bytes
    // loop (offset 12):
    //  12: load 2           (0x34, 0x02)  2 bytes
    //  14: bz done          (0x41, XX, XX) 3 bytes  -> done is at offset 37
    //      target = offset_after_bz + int16 = 17 + 20 = 37
    //  17: load 0           (0x34, 0x00)  2 bytes
    //  19: load 1           (0x34, 0x01)  2 bytes
    //  21: +                (0x08)        1 byte
    //  22: load 1           (0x34, 0x01)  2 bytes
    //  24: store 0          (0x35, 0x00)  2 bytes
    //  26: store 1          (0x35, 0x01)  2 bytes  (tmp from stack)
    //  28: load 2           (0x34, 0x02)  2 bytes
    //  30: pushint 1       (0x81, 0x01)  2 bytes
    //  32: -                (0x09)        1 byte
    //  33: store 2          (0x35, 0x02)  2 bytes
    //  35: b loop           (0x42, XX, XX) 3 bytes -> loop is at offset 12
    //      target = offset_after_b + int16 = 38 + (-26) = 12
    //      -26 = 0xFF, 0xE6
    // done (offset 38):
    //  38: load 0           (0x34, 0x00) 2 bytes
    //  40: pushint 55      (0x81, 0x37)  2 bytes
    //  42: ==               (0x12)       1 byte
    //  43: return           (0x43)       1 byte

    // Wait, let me recalculate carefully. The `b tmp` result goes on stack before store 1.
    // Actually: after `+`, the sum (tmp) is on stack. Then load 1 pushes b.
    // We need: store 0 <- b (= old scratch[1]), store 1 <- tmp (= a+b).
    // So: load 0, load 1, + => stack: [a+b]
    //     load 1           => stack: [a+b, b]
    //     store 0          => scratch[0] = b, stack: [a+b]
    //     store 1          => scratch[1] = a+b, stack: []
    // That's correct.

    // Recalculate offsets:
    //   offset  0: pushint 0  (2 bytes)
    //   offset  2: store 0    (2 bytes)
    //   offset  4: pushint 1  (2 bytes)
    //   offset  6: store 1    (2 bytes)
    //   offset  8: pushint 10 (2 bytes)
    //   offset 10: store 2    (2 bytes)
    // loop @ offset 12:
    //   offset 12: load 2     (2 bytes)
    //   offset 14: bz +24     (3 bytes) -> target = 17 + 24 = 41 [to "done"]
    //                                      Actually let me compute where "done" is...
    //   offset 17: load 0     (2 bytes)
    //   offset 19: load 1     (2 bytes)
    //   offset 21: +          (1 byte)
    //   offset 22: load 1     (2 bytes)
    //   offset 24: store 0    (2 bytes)
    //   offset 26: store 1    (2 bytes)
    //   offset 28: load 2     (2 bytes)
    //   offset 30: pushint 1  (2 bytes)
    //   offset 32: -          (1 byte)
    //   offset 33: store 2    (2 bytes)
    //   offset 35: b -26      (3 bytes) -> target = 38 + (-26) = 12 [loop]
    // done @ offset 38:
    //   offset 38: load 0     (2 bytes)
    //   offset 40: pushint 55 (2 bytes)
    //   offset 42: ==         (1 byte)
    //   offset 43: return     (1 byte)

    // bz target: after_bz = 14 + 3 = 17, need target = 38, offset = 38 - 17 = 21
    // b target:  after_b  = 35 + 3 = 38, need target = 12, offset = 12 - 38 = -26

    let code: &[u8] = &[
        0x81, 0x00, // pushint 0
        0x35, 0x00, // store 0  (a = 0)
        0x81, 0x01, // pushint 1
        0x35, 0x01, // store 1  (b = 1)
        0x81, 0x0a, // pushint 10
        0x35, 0x02, // store 2  (counter = 10)
        // loop @ offset 12
        0x34, 0x02, // load 2
        0x41, 0x00, 21, // bz +21  -> offset 38 ("done")
        0x34, 0x00, // load 0
        0x34, 0x01, // load 1
        0x08, // +  (a + b)
        0x34, 0x01, // load 1
        0x35, 0x00, // store 0  (a = old b)
        0x35, 0x01, // store 1  (b = a + b)
        0x34, 0x02, // load 2
        0x81, 0x01, // pushint 1
        0x09, // -  (counter - 1)
        0x35, 0x02, // store 2
        0x42, 0xFF, 0xE6, // b -26  -> offset 12 ("loop")
        // done @ offset 38
        0x34, 0x00, // load 0
        0x81, 0x37, // pushint 55
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "fib(10) should be 55");
}

// ---------------------------------------------------------------------------
// 3. Byte manipulation: pushbytes "hello", len, pushint 5, ==, return
// ---------------------------------------------------------------------------
#[test]
fn test_byte_len() {
    let code: &[u8] = &[
        0x80, 0x05, b'h', b'e', b'l', b'l', b'o', // pushbytes "hello"
        0x15, // len
        0x81, 0x05, // pushint 5
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "len(\"hello\") == 5 should pass");
}

// ---------------------------------------------------------------------------
// 4. String concat + extract: concat two byte strings, extract substring, verify
// ---------------------------------------------------------------------------
#[test]
fn test_concat_and_extract() {
    // concat "hel" + "lo" = "hello", then extract3(offset=1, length=3) = "ell"
    // Then compare with pushbytes "ell"
    let code: &[u8] = &[
        0x80, 0x03, b'h', b'e', b'l', // pushbytes "hel"
        0x80, 0x02, b'l', b'o', // pushbytes "lo"
        0x50, // concat -> "hello"
        0x81, 0x01, // pushint 1 (start)
        0x81, 0x03, // pushint 3 (length)
        0x58, // extract3 -> "ell"
        0x80, 0x03, b'e', b'l', b'l', // pushbytes "ell"
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(5, code).unwrap();
    assert!(
        result,
        "extract3(concat(\"hel\",\"lo\"),1,3) == \"ell\" should pass"
    );
}

// ---------------------------------------------------------------------------
// 5. Wide math: pushint MAX, pushint 1, addw -> high=1, low=0
// ---------------------------------------------------------------------------
#[test]
fn test_addw_overflow() {
    // addw: pops A, B; pushes (A+B) as (high, low) with carry.
    // u64::MAX + 1 = (1, 0)
    // addw pushes high first, then low.
    // Stack after addw: [..., high, low] (low on top).
    //
    // Verify: low == 0 and high == 1
    // pop low, assert == 0, pop high, assert == 1
    //
    // Code: pushint MAX, pushint 1, addw, pushint 0, ==, swap, pushint 1, ==, &&, return
    //
    // u64::MAX in varuint: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0x01
    let code: &[u8] = &[
        0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, // pushint u64::MAX
        0x81, 0x01, // pushint 1
        0x1e, // addw  -> stack: [high=1, low=0]
        // Check low == 0
        0x81, 0x00, // pushint 0
        0x12, // ==     -> stack: [1, 1]  (high, low==0)
        // swap to get high on top
        0x4c, // swap   -> stack: [1, 1]
        // Check high == 1
        0x81, 0x01, // pushint 1
        0x12, // ==     -> stack: [1, 1]
        // Both must be true
        0x10, // &&     -> stack: [1]
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "u64::MAX + 1 should produce (high=1, low=0)");
}

// ---------------------------------------------------------------------------
// 6. Subroutine call: callsub to a function that doubles a value, retsub, verify
// ---------------------------------------------------------------------------
#[test]
fn test_callsub_double() {
    // Program: pushint 21, callsub double, pushint 42, ==, return
    //          double: dup, +, retsub
    //
    // Offsets:
    //   0: pushint 21    (0x81, 0x15)  2 bytes
    //   2: callsub +5    (0x88, 0x00, 0x05)  3 bytes -> target = 5 + 5 = 10
    //   5: pushint 42    (0x81, 0x2a)  2 bytes
    //   7: ==             (0x12)       1 byte
    //   8: return         (0x43)       1 byte
    //   9: (end of main path)
    // double @ offset 9:
    //   9: dup            (0x49)       1 byte
    //  10: +              (0x08)       1 byte
    //  11: retsub         (0x89)       1 byte

    // callsub offset: after_callsub = 2 + 3 = 5, target = 9, delta = 9 - 5 = 4
    let code: &[u8] = &[
        0x81, 0x15, // pushint 21
        0x88, 0x00, 0x04, // callsub +4 -> offset 9
        0x81, 0x2a, // pushint 42
        0x12, // ==
        0x43, // return
        // double subroutine @ offset 9
        0x49, // dup
        0x08, // +
        0x89, // retsub
    ];
    let result = run_program(4, code).unwrap();
    assert!(result, "callsub double(21) == 42 should pass");
}

// ---------------------------------------------------------------------------
// 7. Cost budget exhaustion: loop that exceeds budget
// ---------------------------------------------------------------------------
#[test]
fn test_budget_exhaustion() {
    // Tight loop: pushint 1, b -4 (back to pushint)
    // Each iteration costs at least 2 (pushint + b).
    // With budget 20000, this should eventually exhaust or stack overflow.
    //
    // Actually, pushint 1 pushes onto stack each time -- stack overflow at 1000.
    // But let's make it properly loop: pushint 1, pop, b -5
    //
    // Offsets:
    //   0: pushint 1  (0x81, 0x01)  2 bytes
    //   2: pop         (0x48)        1 byte
    //   3: b -6        (0x42, 0xFF, 0xFA)  3 bytes -> target = 6 + (-6) = 0
    let mut raw = vec![3u8]; // version
    raw.extend_from_slice(&[
        0x81, 0x01, // pushint 1
        0x48, // pop
        0x42, 0xFF, 0xFA, // b -6 -> offset 0
    ]);
    let program = parse(&raw).unwrap();
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 100); // small budget
    let result = machine.run(&mut NullContext);
    assert!(result.is_err(), "should exhaust cost budget");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("cost budget exceeded"),
        "error should mention budget: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// 8. Scratch space round-trip: store values, load them back, verify
// ---------------------------------------------------------------------------
#[test]
fn test_scratch_round_trip() {
    let code: &[u8] = &[
        0x81, 0x2a, // pushint 42
        0x35, 0x00, // store 0
        0x81, 0x63, // pushint 99
        0x35, 0x01, // store 1
        // load both back and verify sum
        0x34, 0x00, // load 0 -> 42
        0x34, 0x01, // load 1 -> 99
        0x08, // + -> 141
        0x81, 0x8D, 0x01, // pushint 141
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "scratch round-trip: 42 + 99 == 141 should pass");
}

// ---------------------------------------------------------------------------
// 9. Select opcode: pushint 10, pushint 20, pushint 1, select -> 20
// ---------------------------------------------------------------------------
#[test]
fn test_select_opcode() {
    let code: &[u8] = &[
        0x81, 0x0a, // pushint 10
        0x81, 0x14, // pushint 20
        0x81, 0x01, // pushint 1
        0x4d, // select -> 20 (c=1 != 0, pick b=20)
        0x81, 0x14, // pushint 20
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "select with c=1 should pick 20");
}

// ---------------------------------------------------------------------------
// 10. Pushints/pushbytess: push multiple constants at once, verify all on stack
// ---------------------------------------------------------------------------
#[test]
fn test_pushints() {
    // pushints [10, 20, 30] -> stack: [10, 20, 30]
    // 30 on top; verify 30 + 20 + 10 == 60
    let code: &[u8] = &[
        0x83, // pushints
        0x03, // count = 3
        0x0a, // 10
        0x14, // 20
        0x1e, // 30
        0x08, // + (20 + 30 = 50)
        0x08, // + (10 + 50 = 60)
        0x81, 0x3c, // pushint 60
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(8, code).unwrap();
    assert!(result, "pushints [10, 20, 30]: sum should be 60");
}

#[test]
fn test_pushbytess() {
    // pushbytess ["AB", "CD"] -> stack: ["AB", "CD"]
    // "CD" on top; concat -> "ABCD"; len == 4
    let code: &[u8] = &[
        0x82, // pushbytess
        0x02, // count = 2
        0x02, b'A', b'B', // len=2, "AB"
        0x02, b'C', b'D', // len=2, "CD"
        0x50, // concat -> "ABCD"
        0x15, // len -> 4
        0x81, 0x04, // pushint 4
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(8, code).unwrap();
    assert!(result, "pushbytess concat len should be 4");
}

// ---------------------------------------------------------------------------
// 11. Bitwise operations chain
// ---------------------------------------------------------------------------
#[test]
fn test_bitwise_chain() {
    // Compute: (0xFF & 0x0F) | 0xF0 == 0xFF
    // pushint 0xFF, pushint 0x0F, bitwise_and -> 0x0F
    // pushint 0xF0, bitwise_or -> 0xFF
    // pushint 0xFF, ==, return
    let code: &[u8] = &[
        0x81, 0xFF, 0x01, // pushint 255 (0xFF)
        0x81, 0x0F, // pushint 15  (0x0F)
        0x1a, // bitwise_and -> 0x0F
        0x81, 0xF0, 0x01, // pushint 240 (0xF0)
        0x19, // bitwise_or  -> 0xFF
        0x81, 0xFF, 0x01, // pushint 255
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(
        result,
        "bitwise chain (0xFF & 0x0F) | 0xF0 == 0xFF should pass"
    );
}

#[test]
fn test_bitwise_xor_and_not() {
    // ~(0xFF ^ 0x0F) -> ~(0xF0) -> 0xFFFFFFFFFFFFFF0F
    // But that's big. Let's do something simpler:
    // 5 ^ 3 = 6, then bitwise_not -> ~6 = u64::MAX - 6
    let code: &[u8] = &[
        0x81, 0x05, // pushint 5
        0x81, 0x03, // pushint 3
        0x1b, // bitwise_xor -> 6
        0x1c, // bitwise_not -> u64::MAX - 6
        // Verify: result == u64::MAX - 6 = 18446744073709551609
        // That's awkward to encode. Let's re-xor with ~0 to get 6 back.
        // Actually, let's just do: bitwise_not(bitwise_not(6)) == 6
        0x1c, // bitwise_not -> 6
        0x81, 0x06, // pushint 6
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "~~(5^3) == 6 should pass");
}

// ---------------------------------------------------------------------------
// 12. Big-int byte math: b+ with large numbers, verify result
// ---------------------------------------------------------------------------
#[test]
fn test_big_int_byte_add() {
    // b+ adds two big-endian byte strings as unsigned big integers.
    // 0x00FF + 0x0001 = 0x0100
    let code: &[u8] = &[
        0x80, 0x02, 0x00, 0xFF, // pushbytes [0x00, 0xFF]
        0x80, 0x02, 0x00, 0x01, // pushbytes [0x00, 0x01]
        0xa0, // b+ -> [0x01, 0x00]
        0x80, 0x02, 0x01, 0x00, // pushbytes [0x01, 0x00]
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(4, code).unwrap();
    assert!(result, "b+(0x00FF, 0x0001) == 0x0100 should pass");
}

#[test]
fn test_big_int_byte_mul() {
    // b* : 0x10 * 0x10 = 0x0100
    let code: &[u8] = &[
        0x80, 0x01, 0x10, // pushbytes [0x10]
        0x80, 0x01, 0x10, // pushbytes [0x10]
        0xa3, // b* -> [0x01, 0x00]
        0x80, 0x02, 0x01, 0x00, // pushbytes [0x01, 0x00]
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(4, code).unwrap();
    assert!(result, "b*(0x10, 0x10) == 0x0100 should pass");
}

// ---------------------------------------------------------------------------
// Additional: stores/loads (dynamic scratch access)
// ---------------------------------------------------------------------------
#[test]
fn test_stores_and_loads() {
    // Use stores (dynamic) to write, loads (dynamic) to read back.
    // pushint 5, pushint 99, stores -> scratch[5] = 99
    // pushint 5, loads -> 99
    // pushint 99, ==, return
    let code: &[u8] = &[
        0x81, 0x05, // pushint 5    (index)
        0x81, 0x63, // pushint 99   (value)
        0x3f, // stores       -> scratch[5] = 99
        0x81, 0x05, // pushint 5    (index)
        0x3e, // loads        -> 99
        0x81, 0x63, // pushint 99
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(5, code).unwrap();
    assert!(result, "stores/loads round-trip should pass");
}

// ---------------------------------------------------------------------------
// Additional: scratch space inspection via machine
// ---------------------------------------------------------------------------
#[test]
fn test_scratch_bytes() {
    // Store bytes in scratch, load them back.
    let code: &[u8] = &[
        0x80, 0x03, b'f', b'o', b'o', // pushbytes "foo"
        0x35, 0x0A, // store 10
        0x34, 0x0A, // load 10
        0x80, 0x03, b'f', b'o', b'o', // pushbytes "foo"
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "scratch bytes round-trip should pass");
}

// ---------------------------------------------------------------------------
// Additional: stores out-of-range should error
// ---------------------------------------------------------------------------
#[test]
fn test_stores_out_of_range() {
    let code: &[u8] = &[
        0x81, 0x80, 0x02, // pushint 256 (out of range)
        0x81, 0x01, // pushint 1
        0x3f, // stores
    ];
    let mut raw = vec![5u8];
    raw.extend_from_slice(code);
    let program = parse(&raw).unwrap();
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    let result = machine.run(&mut NullContext);
    assert!(result.is_err(), "stores with index 256 should error");
}

// ---------------------------------------------------------------------------
// Additional: pushints with large values
// ---------------------------------------------------------------------------
#[test]
fn test_pushints_large_values() {
    // pushints [1000, 2000], add them, verify 3000
    let code: &[u8] = &[
        0x83, // pushints
        0x02, // count = 2
        0xE8, 0x07, // 1000 (varuint)
        0xD0, 0x0F, // 2000 (varuint)
        0x08, // + -> 3000
        0x81, 0xB8, 0x17, // pushint 3000
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(8, code).unwrap();
    assert!(result, "pushints [1000, 2000] sum should be 3000");
}

// ---------------------------------------------------------------------------
// Additional: verify scratch default is 0
// ---------------------------------------------------------------------------
#[test]
fn test_scratch_default_zero() {
    let code: &[u8] = &[
        0x34, 0xFF, // load 255 (last slot, should be 0)
        0x81, 0x00, // pushint 0
        0x12, // ==
        0x43, // return
    ];
    let result = run_program(3, code).unwrap();
    assert!(result, "scratch default should be Uint64(0)");
}
