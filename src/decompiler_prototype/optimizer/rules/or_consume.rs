use crate::decompiler_prototype::pcode::{OpCode, PcodeOp};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};



///
/// V = A | B => V = B if (nzmask(A) & consume(V)) == 0
pub struct RuleOrConsume;

impl OptimizationRule for RuleOrConsume {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr, OpCode::IntXor]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 || op.output.is_none() {
            return false;
        }

        let output_size = op.output.as_ref().unwrap().size;
        if output_size > 8 {
            return false;
        }

        let mask0 = _context.nzmask.get_nzmask(&op.inputs[0]);
        let mask1 = _context.nzmask.get_nzmask(&op.inputs[1]);

        if mask0 == 0 {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                op.inputs[1].clone(),
                op.address,
            );
            return true;
        }
        if mask1 == 0 {
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
        "RuleOrConsume"
    }
}
