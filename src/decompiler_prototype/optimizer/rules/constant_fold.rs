use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};



///
/// const op const => const
pub struct RuleConstantFold;

impl OptimizationRule for RuleConstantFold {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![
            OpCode::IntAdd,
            OpCode::IntSub,
            OpCode::IntMult,
            OpCode::IntAnd,
            OpCode::IntOr,
            OpCode::IntXor,
            OpCode::IntLeft,
            OpCode::IntRight,
        ]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        // Only if both inputs are constant
        if op.inputs[0].space != AddressSpace::Const
            || op.inputs[1].space != AddressSpace::Const
        {
            return false;
        }

        let val1 = op.inputs[0].offset;
        let val2 = op.inputs[1].offset;
        let size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
        let mask = OptimizerContext::calc_mask(size);

        let result = match op.opcode {
            OpCode::IntAdd => (val1.wrapping_add(val2)) & mask,
            OpCode::IntSub => (val1.wrapping_sub(val2)) & mask,
            OpCode::IntMult => (val1.wrapping_mul(val2)) & mask,
            OpCode::IntAnd => val1 & val2,
            OpCode::IntOr => val1 | val2,
            OpCode::IntXor => val1 ^ val2,
            OpCode::IntLeft => (val1 << val2) & mask,
            OpCode::IntRight => val1 >> val2,
            _ => return false,
        };

        *op = PcodeOp::unary(
            OpCode::Copy,
            op.output.clone().unwrap(),
            Varnode::constant(result, size),
            op.address,
        );

        true
    }

    fn name(&self) -> &str {
        "RuleConstantFold"
    }
}
