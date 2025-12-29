use crate::decompiler_prototype::pcode::{OpCode, PcodeOp};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};
pub struct RuleNegateIdentity;

impl OptimizationRule for RuleNegateIdentity {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntNegate]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.is_empty() {
            return false;
        }

        false
    }

    fn name(&self) -> &str {
        "RuleNegateIdentity"
    }
}
