use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};



///
/// - V & 0 => 0
/// - V & ALL_BITS => V
/// - V & c => 0 if (nzmask(V) & c) == 0
/// - V & c => V if (nzmask(V) & c) == nzmask(V)
pub struct RuleAndMask;

impl OptimizationRule for RuleAndMask {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }

    fn apply(&self, op: &mut PcodeOp, context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        let output_size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
        if output_size > 8 {
            return false; // > u64 not supported
        }

        let mask1 = context.nzmask.get_nzmask(&op.inputs[0]);
        let mask2 = context.nzmask.get_nzmask(&op.inputs[1]);
        let and_mask = mask1 & mask2;

        let full_mask = OptimizerContext::calc_mask(output_size);

        // Result always 0
        if and_mask == 0 {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                Varnode::constant(0, output_size),
                op.address,
            );
            return true;
        }

        // Result same as input (if input1 is const...)
        if op.inputs[1].space == AddressSpace::Const && and_mask == mask1 {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                op.inputs[0].clone(),
                op.address,
            );
            return true;
        }

        // V & ALL_BITS => V (if input1 is const)
        if op.inputs[1].space == AddressSpace::Const
            && (op.inputs[1].offset & full_mask) == full_mask
        {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                op.inputs[0].clone(),
                op.address,
            );
            return true;
        }

        false
    }

    fn name(&self) -> &str {
        "RuleAndMask"
    }
}
