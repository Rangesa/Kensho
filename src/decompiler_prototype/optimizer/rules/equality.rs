use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};



///
/// V == V => true
/// V != V => false
pub struct RuleEquality;

impl OptimizationRule for RuleEquality {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotEqual]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }


        if op.inputs[0] == op.inputs[1] {
            let result = if op.opcode == OpCode::IntEqual { 1 } else { 0 };

            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                Varnode::constant(result, 1),
                op.address,
            );
            return true;
        }

        false
    }

    fn name(&self) -> &str {
        "RuleEquality"
    }
}
