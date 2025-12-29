//! Advanced Optimizer (Phase 12)
//!
//! 高度な最適化パスを提供：
//! - CSE (Common Subexpression Elimination)
//! - LICM (Loop-Invariant Code Motion)
//! - Strength Reduction
//! - Induction Variable Analysis
//! - Advanced Copy Propagation

use crate::decompiler_prototype::pcode::PcodeOp;
use crate::decompiler_prototype::cfg::ControlFlowGraph;
use super::rules::*;

/// 高度な最適化統計
#[derive(Debug, Default, Clone)]
pub struct AdvancedOptimizationStats {
    pub cse_eliminated: usize,
    pub licm_moved: usize,
    pub strength_reduced: usize,
    pub induction_vars_optimized: usize,
    pub copies_propagated: usize,
    pub total_passes: usize,
}

/// 高度な最適化エンジン
pub struct AdvancedOptimizer {
    cse: RuleCSE,
    licm: RuleLICM,
    strength_reduction: RuleStrengthReduction,
    induction_variable: RuleInductionVariable,
    copy_propagation: RuleCopyPropagationAdvanced,
}

impl AdvancedOptimizer {
    pub fn new() -> Self {
        Self {
            cse: RuleCSE::new(),
            licm: RuleLICM::new(),
            strength_reduction: RuleStrengthReduction::new(),
            induction_variable: RuleInductionVariable::new(),
            copy_propagation: RuleCopyPropagationAdvanced::new(),
        }
    }

    /// P-code列に対して高度な最適化を適用
    pub fn optimize_pcode(&mut self, ops: &mut Vec<PcodeOp>) -> AdvancedOptimizationStats {
        let mut stats = AdvancedOptimizationStats::default();
        let mut changed = true;
        let max_iterations = 10;

        while changed && stats.total_passes < max_iterations {
            changed = false;
            stats.total_passes += 1;

            // Pass 1: Strength Reduction (演算強度削減)
            if self.strength_reduction.apply(ops) {
                stats.strength_reduced += self.strength_reduction.reduced_count();
                changed = true;
            }

            // Pass 2: Copy Propagation (コピー伝播)
            if self.copy_propagation.apply(ops) {
                stats.copies_propagated += self.copy_propagation.propagated_count();
                changed = true;
            }

            // Pass 3: CSE (共通部分式削除)
            if self.cse.apply(ops) {
                stats.cse_eliminated += self.cse.eliminated_count();
                changed = true;
            }

            // Pass 4: Induction Variable Analysis (帰納変数解析)
            if self.induction_variable.apply(ops) {
                stats.induction_vars_optimized += self.induction_variable.optimized_count();
                changed = true;
            }
        }

        stats
    }

    /// CFGに対して高度な最適化を適用
    pub fn optimize_cfg(&mut self, cfg: &mut ControlFlowGraph) -> AdvancedOptimizationStats {
        let mut stats = AdvancedOptimizationStats::default();

        // LICM (ループ不変式移動)
        if self.licm.apply(cfg) {
            stats.licm_moved += self.licm.moved_count();
        }

        // 各基本ブロックに対してP-code最適化を適用
        for block in cfg.blocks.values_mut() {
            let block_stats = self.optimize_pcode(&mut block.ops);
            stats.cse_eliminated += block_stats.cse_eliminated;
            stats.strength_reduced += block_stats.strength_reduced;
            stats.induction_vars_optimized += block_stats.induction_vars_optimized;
            stats.copies_propagated += block_stats.copies_propagated;
        }

        stats
    }

    /// 最適化統計をリセット
    pub fn reset(&mut self) {
        self.cse = RuleCSE::new();
        self.licm = RuleLICM::new();
        self.strength_reduction = RuleStrengthReduction::new();
        self.induction_variable = RuleInductionVariable::new();
        self.copy_propagation = RuleCopyPropagationAdvanced::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::pcode::{AddressSpace, OpCode, Varnode};

    #[test]
    fn test_advanced_optimizer_basic() {
        let mut optimizer = AdvancedOptimizer::new();

        let v_x = Varnode::new(AddressSpace::Register, 0, 8);
        let v_4 = Varnode::constant(4, 8);
        let v_out = Varnode::new(AddressSpace::Unique, 0, 8);

        let mut ops = vec![
            // x * 4 (should be strength reduced to x << 2)
            PcodeOp {
                opcode: OpCode::IntMult,
                inputs: vec![v_x, v_4],
                output: Some(v_out),
            },
        ];

        let stats = optimizer.optimize_pcode(&mut ops);

        assert!(stats.strength_reduced > 0);
        assert_eq!(ops[0].opcode, OpCode::IntLeft);
    }
}
