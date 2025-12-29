use crate::decompiler_prototype::pcode::{OpCode, PcodeOp};
use crate::decompiler_prototype::nzmask::NZMaskAnalyzer;
use std::collections::HashSet;

pub mod rules;
pub mod advanced;

use rules::*;
pub use advanced::{AdvancedOptimizer, AdvancedOptimizationStats};
pub trait OptimizationRule {
    fn target_opcodes(&self) -> Vec<OpCode>;
    fn apply(&self, op: &mut PcodeOp, context: &mut OptimizerContext) -> bool;
    fn name(&self) -> &str;
}
pub struct OptimizerContext {
    pub nzmask: NZMaskAnalyzer,
    ops_to_remove: HashSet<usize>,
}

impl OptimizerContext {
    pub fn new(nzmask: NZMaskAnalyzer) -> Self {
        Self {
            nzmask,
            ops_to_remove: HashSet::new(),
        }
    }
    pub fn mark_for_removal(&mut self, op_index: usize) {
        self.ops_to_remove.insert(op_index);
    }
    #[inline]
    pub fn calc_mask(size: usize) -> u64 {
        if size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        }
    }
}
pub struct Optimizer {
    rules: Vec<Box<dyn OptimizationRule>>,
}

impl Optimizer {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn OptimizationRule>> = vec![
            Box::new(RuleTermOrder),
            Box::new(RuleConstantFold),
            Box::new(RuleZeroOp),
            Box::new(RuleAndMask),
            Box::new(RuleOrMask),
            Box::new(RuleOrConsume),
            Box::new(RuleEquality),
            Box::new(RuleLessOne),
            Box::new(RuleNegateIdentity), 
            Box::new(RuleShiftBitops),
            Box::new(RuleAndOrLump),
            Box::new(RuleEarlyRemoval),
        ];

        Self { rules }
    }
    pub fn optimize(&self, ops: &mut Vec<PcodeOp>) -> OptimizationStats {
        let mut stats = OptimizationStats::default();
        let mut nzmask = NZMaskAnalyzer::new();
        nzmask.analyze_ops(ops);
        let mut context = OptimizerContext::new(nzmask);
        for iteration in 0..10 {
            let mut changed = false;
            for op in ops.iter_mut() {
                for rule in &self.rules {
                    let targets = rule.target_opcodes();
                    if !targets.is_empty() && !targets.contains(&op.opcode) {
                        continue;
                    }
                    if rule.apply(op, &mut context) {
                        changed = true;
                        stats.total_applications += 1;
                        stats.applications_per_rule
                            .entry(rule.name().to_string())
                            .and_modify(|c| *c += 1)
                            .or_insert(1);
                    }
                }
            }
            stats.iterations = iteration + 1;
            if !changed {
                break;
            }
        }
        stats
    }
}
impl Default for Optimizer {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, Clone, Default)]
pub struct OptimizationStats {
    pub iterations: usize,
    pub total_applications: usize,
    pub applications_per_rule: std::collections::HashMap<String, usize>,
}
impl OptimizationStats {
    pub fn report(&self) -> String {
        let mut report = format!(
            "Optimization completed in {} iteration(s)\n",
            self.iterations
        );
        report.push_str(&format!(
            "Total rule applications: {}\n",
            self.total_applications
        ));

        if !self.applications_per_rule.is_empty() {
            report.push_str("\nApplications per rule:\n");
            let mut rules: Vec<_> = self.applications_per_rule.iter().collect();
            rules.sort_by_key(|(_, &count)| std::cmp::Reverse(count));

            for (rule, count) in rules {
                report.push_str(&format!("  {}: {}\n", rule, count));
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::pcode::{Varnode, AddressSpace};

    #[test]
    fn test_rule_and_mask_zero() {
        let mut context = OptimizerContext::new(NZMaskAnalyzer::new());

        let v1 = Varnode::register(0, 4);
        let v2 = Varnode::constant(0, 4);
        let output = Varnode::unique(100, 4);

        let mut op = PcodeOp::binary(OpCode::IntAnd, output.clone(), v1, v2, 0x1000);

        let rule = RuleAndMask;
        assert!(rule.apply(&mut op, &mut context));
        assert_eq!(op.opcode, OpCode::Copy);
    }

    #[test]
    fn test_rule_term_order() {
        let mut context = OptimizerContext::new(NZMaskAnalyzer::new());
        let const_vn = Varnode::constant(10, 4);
        let reg_vn = Varnode::register(0, 4);
        let output = Varnode::unique(100, 4);
        let mut op = PcodeOp::binary(OpCode::IntAdd, output.clone(), const_vn.clone(), reg_vn.clone(), 0x1000);
        let rule = RuleTermOrder;
        assert!(rule.apply(&mut op, &mut context));
        assert_eq!(op.inputs[0], reg_vn);
        assert_eq!(op.inputs[1], const_vn);
    }
}
