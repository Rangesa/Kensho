/// P-code最適化ルールエンジン
///
/// Ghidraのruleaction.ccに基づく実装
/// パターンマッチングによる代数的簡約化と定数畳み込み

use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
use crate::decompiler_prototype::nzmask::NZMaskAnalyzer;
use std::collections::HashSet;

/// 最適化ルールの基底トレイト
pub trait OptimizationRule {
    /// このルールが適用可能なOpCodeのリスト
    fn target_opcodes(&self) -> Vec<OpCode>;

    /// ルールを適用して、変更があったらtrue
    fn apply(&self, op: &mut PcodeOp, context: &mut OptimizerContext) -> bool;

    /// ルール名（デバッグ用）
    fn name(&self) -> &str;
}

/// 最適化コンテキスト
pub struct OptimizerContext {
    pub nzmask: NZMaskAnalyzer,
    ops_to_remove: HashSet<usize>, // 削除対象のP-code操作インデックス
}

impl OptimizerContext {
    pub fn new(nzmask: NZMaskAnalyzer) -> Self {
        Self {
            nzmask,
            ops_to_remove: HashSet::new(),
        }
    }

    /// 操作を削除対象としてマーク
    pub fn mark_for_removal(&mut self, op_index: usize) {
        self.ops_to_remove.insert(op_index);
    }

    /// 指定されたサイズの全ビットマスクを計算
    #[inline]
    fn calc_mask(size: usize) -> u64 {
        if size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        }
    }
}

/// Rule 1: 未使用出力の削除
///
/// 出力が使用されていない操作を削除
pub struct RuleEarlyRemoval;

impl OptimizationRule for RuleEarlyRemoval {
    fn target_opcodes(&self) -> Vec<OpCode> {
        // すべての操作が対象
        vec![]
    }

    fn apply(&self, op: &mut PcodeOp, context: &mut OptimizerContext) -> bool {
        // 出力がない操作は削除しない（副作用がある可能性）
        if op.output.is_none() {
            return false;
        }

        // Call/Store/Branchなど副作用のある操作は削除しない
        if matches!(
            op.opcode,
            OpCode::Call | OpCode::CallInd | OpCode::Store | OpCode::Branch | OpCode::CBranch
        ) {
            return false;
        }

        // 実際の使用検査はパス全体で行う必要があるため、ここではfalse
        // （後続の実装で改善）
        false
    }

    fn name(&self) -> &str {
        "RuleEarlyRemoval"
    }
}

/// Rule 2: AND最適化
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
            return false; // u64より大きいサイズは未対応
        }

        let mask1 = context.nzmask.get_nzmask(&op.inputs[0]);
        let mask2 = context.nzmask.get_nzmask(&op.inputs[1]);
        let and_mask = mask1 & mask2;

        let full_mask = OptimizerContext::calc_mask(output_size);

        // 結果が常に0
        if and_mask == 0 {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                Varnode::constant(0, output_size),
                op.address,
            );
            return true;
        }

        // 結果が入力0と同じ（入力1が定数でない場合はスキップ）
        if op.inputs[1].space == AddressSpace::Const && and_mask == mask1 {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                op.inputs[0].clone(),
                op.address,
            );
            return true;
        }

        // V & ALL_BITS => V（入力1が定数の場合）
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

/// Rule 3: OR最適化
///
/// - V | ALL_BITS => ALL_BITS
/// - V | c => c if (nzmask(V) | c) == c
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

        // 入力1が定数でない場合はスキップ
        if op.inputs[1].space != AddressSpace::Const {
            return false;
        }

        let val = op.inputs[1].offset;
        let full_mask = OptimizerContext::calc_mask(output_size);

        // V | ALL_BITS => ALL_BITS
        if (val & full_mask) == full_mask {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                Varnode::constant(full_mask, output_size),
                op.address,
            );
            return true;
        }

        // V | c => c if (nzmask(V) | c) == c
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

/// Rule 4: 未消費入力の削除
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

        // Consume maskの計算は全操作を参照する必要があるため、
        // ここでは簡易版（定数0との演算を検出）
        let mask0 = _context.nzmask.get_nzmask(&op.inputs[0]);
        let mask1 = _context.nzmask.get_nzmask(&op.inputs[1]);

        // 入力0が常に0
        if mask0 == 0 {
            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                op.inputs[1].clone(),
                op.address,
            );
            return true;
        }

        // 入力1が常に0
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

/// Rule 5: 可換演算の項順序正規化
///
/// 定数を常に右側に配置: c + V => V + c
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

        // 入力0が定数で入力1が非定数なら交換
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

/// Rule 6: AND/OR定数の統合
///
/// (V & c1) & c2 => V & (c1 & c2)
/// (V | c1) | c2 => V | (c1 | c2)
pub struct RuleAndOrLump;

impl OptimizationRule for RuleAndOrLump {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd, OpCode::IntOr, OpCode::IntXor]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        // 入力1が定数でない場合はスキップ
        if op.inputs[1].space != AddressSpace::Const {
            return false;
        }

        let output_size = op.output.as_ref().map(|v| v.size).unwrap_or(8);

        // 入力0が書き込まれた値かチェック（実際にはSSA形式で追跡が必要）
        // ここでは同じ種類の演算が連鎖しているパターンを簡易検出
        // （完全実装には操作の定義元を追跡する必要がある）

        false // 簡易版では未実装
    }

    fn name(&self) -> &str {
        "RuleAndOrLump"
    }
}

/// Rule 7: 比較演算の簡略化
///
/// V == V => true
/// V != V => false
pub struct RuleEquality;

impl OptimizationRule for RuleEquality {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotEqual]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        // 2つの入力が同じVarnode
        if op.inputs[0] == op.inputs[1] {
            let result = if op.opcode == OpCode::IntEqual { 1 } else { 0 };

            *op = PcodeOp::unary(
                OpCode::Copy,
                op.output.clone().unwrap(),
                Varnode::constant(result, 1),
                op.address,
            );
            return true;
        }

        false
    }

    fn name(&self) -> &str {
        "RuleEquality"
    }
}

/// Rule 8: ビット否定の恒等式
///
/// ~(~V) => V
pub struct RuleNegateIdentity;

impl OptimizationRule for RuleNegateIdentity {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntNegate]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.is_empty() {
            return false;
        }

        // 入力がVarnodeで、それがIntNegate操作の出力かチェック
        // （実際にはSSA形式で操作の定義元を追跡する必要がある）
        // 簡易版では同じアドレスの連続するIntNegateのみ検出
        false // 完全実装にはdef-use chain が必要
    }

    fn name(&self) -> &str {
        "RuleNegateIdentity"
    }
}

/// Rule 9: 定数畳み込み
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

        // 両方の入力が定数の場合のみ
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

/// Rule 10: V < 1 の最適化
///
/// V < 1 => V == 0 (符号なし)
pub struct RuleLessOne;

impl OptimizationRule for RuleLessOne {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntLess]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        // V < 1 のパターン
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

/// Rule 11: シフト後のマスクの最適化
///
/// (V << c) & mask => より効率的な形に変換
pub struct RuleShiftBitops;

impl OptimizationRule for RuleShiftBitops {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        // (V << c) & mask のパターン検出
        // 完全実装にはdef-use chain が必要
        false
    }

    fn name(&self) -> &str {
        "RuleShiftBitops"
    }
}

/// Rule 12: 0との演算の簡略化
///
/// V + 0 => V, V - 0 => V, V * 0 => 0
pub struct RuleZeroOp;

impl OptimizationRule for RuleZeroOp {
    fn target_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd, OpCode::IntSub, OpCode::IntMult, OpCode::IntOr, OpCode::IntXor]
    }

    fn apply(&self, op: &mut PcodeOp, _context: &mut OptimizerContext) -> bool {
        if op.inputs.len() < 2 {
            return false;
        }

        let is_zero_1 = op.inputs[1].space == AddressSpace::Const && op.inputs[1].offset == 0;

        match op.opcode {
            OpCode::IntAdd | OpCode::IntSub | OpCode::IntOr | OpCode::IntXor => {
                // V op 0 => V
                if is_zero_1 {
                    *op = PcodeOp::unary(
                        OpCode::Copy,
                        op.output.clone().unwrap(),
                        op.inputs[0].clone(),
                        op.address,
                    );
                    return true;
                }
            }
            OpCode::IntMult => {
                // V * 0 => 0
                if is_zero_1 {
                    *op = PcodeOp::unary(
                        OpCode::Copy,
                        op.output.clone().unwrap(),
                        Varnode::constant(0, op.inputs[0].size),
                        op.address,
                    );
                    return true;
                }
            }
            _ => {}
        }

        false
    }

    fn name(&self) -> &str {
        "RuleZeroOp"
    }
}

/// 最適化エンジン
pub struct Optimizer {
    rules: Vec<Box<dyn OptimizationRule>>,
}

impl Optimizer {
    /// デフォルトルールセットで最適化エンジンを作成
    pub fn new() -> Self {
        let rules: Vec<Box<dyn OptimizationRule>> = vec![
            Box::new(RuleTermOrder),       // 1. 項順序正規化（他のルールの前提）
            Box::new(RuleConstantFold),    // 2. 定数畳み込み
            Box::new(RuleZeroOp),          // 3. 0との演算
            Box::new(RuleAndMask),         // 4. AND最適化
            Box::new(RuleOrMask),          // 5. OR最適化
            Box::new(RuleOrConsume),       // 6. 未消費入力削除
            Box::new(RuleEquality),        // 7. 比較簡略化
            Box::new(RuleLessOne),         // 8. V < 1 最適化
            Box::new(RuleNegateIdentity),  // 9. 二重否定
            Box::new(RuleShiftBitops),     // 10. シフト&ビット演算
            Box::new(RuleAndOrLump),       // 11. 定数統合
            Box::new(RuleEarlyRemoval),    // 12. 未使用削除
        ];

        Self { rules }
    }

    /// P-code操作列に最適化を適用
    pub fn optimize(&self, ops: &mut Vec<PcodeOp>) -> OptimizationStats {
        let mut stats = OptimizationStats::default();

        // NZMask解析を実行
        let mut nzmask = NZMaskAnalyzer::new();
        nzmask.analyze_ops(ops);

        let mut context = OptimizerContext::new(nzmask);

        // 収束するまで繰り返し適用（最大10イテレーション）
        for iteration in 0..10 {
            let mut changed = false;

            for op in ops.iter_mut() {
                for rule in &self.rules {
                    // ターゲットOpCodeが指定されている場合はチェック
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
                break; // 収束
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

/// 最適化統計情報
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
