use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, AddressSpace};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};
pub struct RuleTermOrder;

impl OptimizationRule for RuleTermOrder {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![
            OpCode::IntEqual,
            OpCode::IntNotEqual,
            OpCode::IntAdd,
            OpCode::IntXor,
            OpCode::IntAnd,
            OpCode::IntOr,
            OpCode::IntMult,
            OpCode::BoolXor,
            OpCode::BoolAnd,
            OpCode::BoolOr,
        ]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        let vn1 = &op.inputs[0];
        let vn2 = &op.inputs[1];

        if vn1.space == AddressSpace::Const && vn2.space != AddressSpace::Const {
            op.inputs.swap(0, 1);
            return true;
        }

        false
    }

    fn name(&self) -> &str {
        "RuleTermOrder"
    }
}
