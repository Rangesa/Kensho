use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};

pub struct RuleLessOne;
impl OptimizationRule for RuleLessOne {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntLess]
    }
    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }
        // V < 1 pattern
        if op.inputs[1].space == AddressSpace::Const && op.inputs[1].offset == 1 {
            *op = PcodeOp::binary(
                OpCode::IntEqual,
                op.output.clone().unwrap(),
                op.inputs[0].clone(),
                Varnode::constant(0, op.inputs[0].size),
                op.address,
            );
            return true;
        }
        false
    }
    fn name(&self) -> &str {
        "RuleLessOne"
    }
}
