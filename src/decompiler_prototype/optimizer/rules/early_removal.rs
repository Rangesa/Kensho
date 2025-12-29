use crate::decompiler_prototype::pcode::{OpCode, PcodeOp};
use crate::decompiler_prototype::optimizer::{OptimizationRule, OptimizerContext};



///


pub struct RuleEarlyRemoval;

impl OptimizationRule for RuleEarlyRemoval {
    fn target_opcodes(&self) -> Vec<OpCode> {
        // All ops targeted
        vec![]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        // If output is missing, remove (unless side effect)
        if op.output.is_none() {
            return false;
        }

        // Call/Store/Branch have side effects
        if matches!(
            op.opcode,
            OpCode::Call | OpCode::CallInd | OpCode::Store | OpCode::Branch | OpCode::CBranch
        ) {
            return false;
        }

        // Actual liveness check required (TODO)

        false
    }

    fn name(&self) -> &str {
        "RuleEarlyRemoval"
    }
}
