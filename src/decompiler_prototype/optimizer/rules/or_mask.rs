use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};
pub struct RuleOrMask;

impl OptimizationRule for RuleOrMask {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }

    fn apply(&self, op: &mut PcodeOp, context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        let output_size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
        if output_size > 8 {
            return false;
        }

        if op.inputs[1].space != AddressSpace::Const {
            return false;
        }

        let val = op.inputs[1].offset;
        let full_mask = OptimizerContext::calc_mask(output_size);

        if (val & full_mask) == full_mask {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                Varnode::constant(full_mask, output_size),
                op.address,
            );
            return true;
        }

        let mask = context.nzmask.get_nzmask(&op.inputs[0]);
        if (mask | val) == val {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                op.inputs[1].clone(),
                op.address,
            );
            return true;
        }

        false
    }

    fn name(&self) -> &str {
        "RuleOrMask"
    }
}
