#![no_main]

use libfuzzer_sys::fuzz_target;

use algo_avm::opcode::Mode;
use algo_avm::{check_program, parse, AvmMachine, ExecMode};

fuzz_target!(|data: &[u8]| {
    // Try parsing
    let program = match parse(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Try validating
    let _ = check_program(&program, Mode::Any, data.len());

    // Try executing with limited budget (prevent infinite loops)
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    let _ = machine.run(); // Must not panic
});
