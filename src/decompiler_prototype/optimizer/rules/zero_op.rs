use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};
///
/// V + 0 => V, V - 0 => V, V * 0 => 0
pub struct RuleZeroOp;

impl OptimizationRule for RuleZeroOp {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd, OpCode::IntSub, OpCode::IntMult, OpCode::IntOr, OpCode::IntXor]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        let is_zero_1 = op.inputs[1].space == AddressSpace::Const && op.inputs[1].offset == 0;

        match op.opcode {
            OpCode::IntAdd | OpCode::IntSub | OpCode::IntOr | OpCode::IntXor => {
                // V op 0 => V
                if is_zero_1 {
                    *op = PcodeOp::unary(
                        OpCode::Copy,
                        op.output.clone().unwrap(),
                        op.inputs[0].clone(),
                        op.address,
                    );
                    return true;
                }
            }
            OpCode::IntMult => {
                // V * 0 => 0
                if is_zero_1 {
                    *op = PcodeOp::unary(
                        OpCode::Copy,
                        op.output.clone().unwrap(),
                        Varnode::constant(0, op.inputs[0].size),
                        op.address,
                    );
                    return true;
                }
            }
            _ => {}
        }

        false
    }

    fn name(&self) -> &str {
        "RuleZeroOp"
    }
}
