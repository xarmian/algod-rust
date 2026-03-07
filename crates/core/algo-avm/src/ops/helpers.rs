//! Shared helper functions used across opcode modules.

use algo_error::AlgoError;
use algo_types::TealValue;

use crate::bytecode::{Immediates, Instruction};
use crate::machine::AvmValue;

/// Convert a [`TealValue`] (external state representation) to an [`AvmValue`]
/// (stack representation).
pub fn teal_to_avm(tv: TealValue) -> AvmValue {
    match tv {
        TealValue::Uint(v) => AvmValue::Uint64(v),
        TealValue::Bytes(b) => AvmValue::Bytes(b),
    }
}

/// Convert an [`AvmValue`] (stack representation) to a [`TealValue`]
/// (external state representation).
pub fn avm_to_teal(av: AvmValue) -> TealValue {
    match av {
        AvmValue::Uint64(v) => TealValue::Uint(v),
        AvmValue::Bytes(b) => TealValue::Bytes(b),
    }
}

/// Extract the single Uint8 immediate from an instruction.
pub fn get_uint8(instruction: &Instruction) -> Result<u8, AlgoError> {
    if let Immediates::Uint8(v) = instruction.immediates {
        Ok(v)
    } else {
        Err(AlgoError::Avm {
            message: format!("expected Uint8 immediate, got {:?}", instruction.immediates),
        })
    }
}

/// Extract the Uint8Pair immediate from an instruction.
pub fn get_uint8_pair(instruction: &Instruction) -> Result<(u8, u8), AlgoError> {
    if let Immediates::Uint8Pair(a, b) = instruction.immediates {
        Ok((a, b))
    } else {
        Err(AlgoError::Avm {
            message: format!(
                "expected Uint8Pair immediate, got {:?}",
                instruction.immediates
            ),
        })
    }
}

/// Extract the Uint8Triple immediate from an instruction.
pub fn get_uint8_triple(instruction: &Instruction) -> Result<(u8, u8, u8), AlgoError> {
    if let Immediates::Uint8Triple(a, b, c) = instruction.immediates {
        Ok((a, b, c))
    } else {
        Err(AlgoError::Avm {
            message: format!(
                "expected Uint8Triple immediate, got {:?}",
                instruction.immediates
            ),
        })
    }
}

/// Build raw program bytes from version + code (test helper).
#[cfg(test)]
pub fn prog(version: u8, code: &[u8]) -> Vec<u8> {
    let mut p = vec![version];
    p.extend_from_slice(code);
    p
}
