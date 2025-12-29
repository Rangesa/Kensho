//! kensho SMT-based MBA Simplification
//!
//! kensho SMTソルバーを使用してMBA式を数学的に検証・簡約化します。
//!
//! 従来のz3ベースの実装と同等の機能をkensho SMTで提供し、
//! 外部依存を削減しつつ高速なMBA deobfuscationを実現します。

use super::super::pcode::{OpCode, PcodeOp, Varnode, AddressSpace};
use super::simplifier::{SimplifiedExpression, VerificationMethod, SimplificationRule};
use crate::kensho_smt::{Expr, Solver};
use std::collections::HashMap;
use std::time::Instant;

/// kensho SMTベースのMBA簡約化エンジン
pub struct KenshoMBASimplifier {
    solver: Solver,
    /// 等価性検証のキャッシュ（パフォーマンス最適化）
    equivalence_cache: HashMap<String, bool>,
    /// 統計情報
    stats: KenshoSimplificationStats,
}

/// 統計情報
#[derive(Debug, Default, Clone)]
pub struct KenshoSimplificationStats {
    /// kensho SMT検証の実行回数
    pub verifications: usize,
    /// キャッシュヒット回数
    pub cache_hits: usize,
    /// 成功した簡約化の数
    pub successful_simplifications: usize,
    /// 合計検証時間（ミリ秒）
    pub total_verification_time_ms: f64,
}

impl KenshoMBASimplifier {
    pub fn new() -> Self {
        Self {
            solver: Solver::new(),
            equivalence_cache: HashMap::new(),
            stats: KenshoSimplificationStats::default(),
        }
    }

    /// MBA式を簡約化（kensho SMT検証付き）
    ///
    /// 手順:
    /// 1. 候補となる単純な式を生成
    /// 2. kensho SMTで元の式と候補が等価かチェック
    /// 3. 等価なら簡約化を適用
    pub fn simplify_with_kensho(&mut self, ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        if ops.is_empty() {
            return None;
        }

        let start = Instant::now();

        // 最終的な出力を持つ演算を見つける
        let final_op = ops.last()?;
        let output = final_op.output.as_ref()?;

        // 使用されている変数を抽出
        let vars = self.extract_variables(ops);
        if vars.len() < 2 {
            return None; // MBA式には通常2つ以上の変数が必要
        }

        // 元の式をkensho SMT Exprに変換
        let original_expr = self.ops_to_kensho_expr(ops)?;

        // 候補となる単純な式を生成して検証
        let candidates = self.generate_simple_candidates(&vars, output);

        for (candidate_ops, rule) in candidates {
            let candidate_expr = self.ops_to_kensho_expr(&candidate_ops)?;

            // キャッシュキーを生成
            let cache_key = format!("{:?}:{:?}", ops, candidate_ops);

            // キャッシュチェック
            let is_equivalent = if let Some(&cached) = self.equivalence_cache.get(&cache_key) {
                self.stats.cache_hits += 1;
                cached
            } else {
                self.stats.verifications += 1;

                // kensho SMTのare_equivalent_sat()を使用
                let equiv = self.solver.are_equivalent_sat(&original_expr, &candidate_expr);

                self.equivalence_cache.insert(cache_key, equiv);
                equiv
            };

            if is_equivalent {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                self.stats.total_verification_time_ms += elapsed;
                self.stats.successful_simplifications += 1;

                return Some(SimplifiedExpression {
                    expression: self.ops_to_expression_string(&candidate_ops),
                    pcode_ops: candidate_ops,
                    verification: VerificationMethod::SmtProven {
                        solving_time_ms: elapsed,
                    },
                    rules_applied: vec![rule],
                });
            }
        }

        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        self.stats.total_verification_time_ms += elapsed;

        None
    }

    /// P-code演算列をkensho SMT Exprに変換
    fn ops_to_kensho_expr(&mut self, ops: &[PcodeOp]) -> Option<Expr> {
        // 各演算の結果をマップに保存
        let mut results: HashMap<Varnode, Expr> = HashMap::new();

        for op in ops {
            let kensho_expr = self.pcode_to_kensho_single(op, &results)?;

            if let Some(output) = &op.output {
                results.insert(output.clone(), kensho_expr);
            }
        }

        // 最後の演算の結果を返す
        ops.last()?.output.as_ref().and_then(|out| results.get(out).cloned())
    }

    /// 単一のP-code演算をkensho SMT Exprに変換
    fn pcode_to_kensho_single(&self, op: &PcodeOp, results: &HashMap<Varnode, crate::kensho_smt::Expr>) -> Option<crate::kensho_smt::Expr> {
        match op.opcode {
            OpCode::IntAdd => {
                if op.inputs.len() == 2 {
                    let left = self.varnode_to_expr(&op.inputs[0], results)?;
                    let right = self.varnode_to_expr(&op.inputs[1], results)?;
                    Some(Expr::add(left, right))
                } else {
                    None
                }
            }
            OpCode::IntSub => {
                if op.inputs.len() == 2 {
                    let left = self.varnode_to_expr(&op.inputs[0], results)?;
                    let right = self.varnode_to_expr(&op.inputs[1], results)?;
                    Some(Expr::sub(left, right))
                } else {
                    None
                }
            }
            OpCode::IntMult => {
                if op.inputs.len() == 2 {
                    let left = self.varnode_to_expr(&op.inputs[0], results)?;
                    let right = self.varnode_to_expr(&op.inputs[1], results)?;
                    Some(Expr::mul(left, right))
                } else {
                    None
                }
            }
            OpCode::IntXor => {
                if op.inputs.len() == 2 {
                    let left = self.varnode_to_expr(&op.inputs[0], results)?;
                    let right = self.varnode_to_expr(&op.inputs[1], results)?;
                    Some(Expr::xor(left, right))
                } else {
                    None
                }
            }
            OpCode::IntAnd => {
                if op.inputs.len() == 2 {
                    let left = self.varnode_to_expr(&op.inputs[0], results)?;
                    let right = self.varnode_to_expr(&op.inputs[1], results)?;
                    Some(Expr::and(left, right))
                } else {
                    None
                }
            }
            OpCode::IntOr => {
                if op.inputs.len() == 2 {
                    let left = self.varnode_to_expr(&op.inputs[0], results)?;
                    let right = self.varnode_to_expr(&op.inputs[1], results)?;
                    Some(Expr::or(left, right))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// VarnodeをExprに変換
    fn varnode_to_expr(&self, vn: &Varnode, results: &HashMap<Varnode, crate::kensho_smt::Expr>) -> Option<crate::kensho_smt::Expr> {
        // 既に計算済みの結果があればそれを返す
        if let Some(expr) = results.get(vn) {
            return Some(expr.clone());
        }

        // 定数の場合
        if vn.space == AddressSpace::Const {
            return Some(Expr::const_bv(vn.offset, (vn.size * 8) as u32));
        }

        // 変数の場合
        let name = self.varnode_to_name(vn);
        Some(Expr::var(&name, (vn.size * 8) as u32))
    }

    /// 使用されている変数を抽出
    fn extract_variables(&self, ops: &[PcodeOp]) -> Vec<Varnode> {
        let mut vars = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for op in ops {
            for input in &op.inputs {
                if input.space != AddressSpace::Const && !seen.contains(input) {
                    seen.insert(input.clone());
                    vars.push(input.clone());
                }
            }
        }

        vars
    }

    /// 単純な候補式を生成
    ///
    /// 一般的な算術・ビット演算の組み合わせを生成:
    /// - x + y
    /// - x - y
    /// - x ^ y
    /// - x & y
    /// - x | y
    /// - x * y
    fn generate_simple_candidates(
        &self,
        vars: &[Varnode],
        output: &Varnode,
    ) -> Vec<(Vec<PcodeOp>, SimplificationRule)> {
        if vars.len() < 2 {
            return Vec::new();
        }

        let x = &vars[0];
        let y = &vars[1];

        vec![
            // x + y
            (
                vec![PcodeOp {
                    opcode: OpCode::IntAdd,
                    inputs: vec![x.clone(), y.clone()],
                    output: Some(output.clone()),
                    address: 0,
                }],
                SimplificationRule::XorAndAdd,
            ),
            // x - y
            (
                vec![PcodeOp {
                    opcode: OpCode::IntSub,
                    inputs: vec![x.clone(), y.clone()],
                    output: Some(output.clone()),
                    address: 0,
                }],
                SimplificationRule::OrMinusAnd,
            ),
            // x ^ y
            (
                vec![PcodeOp {
                    opcode: OpCode::IntXor,
                    inputs: vec![x.clone(), y.clone()],
                    output: Some(output.clone()),
                    address: 0,
                }],
                SimplificationRule::MaskedXor,
            ),
            // x & y
            (
                vec![PcodeOp {
                    opcode: OpCode::IntAnd,
                    inputs: vec![x.clone(), y.clone()],
                    output: Some(output.clone()),
                    address: 0,
                }],
                SimplificationRule::OrMinusXor,
            ),
            // x | y
            (
                vec![PcodeOp {
                    opcode: OpCode::IntOr,
                    inputs: vec![x.clone(), y.clone()],
                    output: Some(output.clone()),
                    address: 0,
                }],
                SimplificationRule::AddXorAnd,
            ),
        ]
    }

    /// P-code演算列を式文字列に変換
    fn ops_to_expression_string(&self, ops: &[PcodeOp]) -> String {
        if ops.is_empty() {
            return String::from("(empty)");
        }

        let op = &ops[0];
        if op.inputs.len() != 2 {
            return String::from("(complex)");
        }

        let x = self.varnode_to_name(&op.inputs[0]);
        let y = self.varnode_to_name(&op.inputs[1]);

        let operator = match op.opcode {
            OpCode::IntAdd => "+",
            OpCode::IntSub => "-",
            OpCode::IntMult => "*",
            OpCode::IntXor => "^",
            OpCode::IntAnd => "&",
            OpCode::IntOr => "|",
            _ => "?",
        };

        format!("{} {} {}", x, operator, y)
    }

    /// Varnodeを名前に変換
    fn varnode_to_name(&self, v: &Varnode) -> String {
        match v.space {
            AddressSpace::Register => format!("r{}", v.offset),
            AddressSpace::Unique => format!("u{}", v.offset),
            AddressSpace::Const => format!("{}", v.offset),
            _ => format!("v{}", v.offset),
        }
    }

    /// 統計情報を取得
    pub fn stats(&self) -> &KenshoSimplificationStats {
        &self.stats
    }

    /// 統計情報をリセット
    pub fn reset_stats(&mut self) {
        self.stats = KenshoSimplificationStats::default();
    }

    /// キャッシュをクリア
    pub fn clear_cache(&mut self) {
        self.equivalence_cache.clear();
    }

    /// kensho SMT Expr → P-code逆変換
    ///
    /// 簡約化されたkensho SMT式を再びP-code中間表現に変換します。
    /// これにより、難読化された複雑なMBA式を単純なP-code（例: x+y）として出力できます。
    ///
    /// # 引数
    /// - `expr`: 変換するkensho SMT式
    /// - `output_size`: 出力のサイズ（バイト単位）
    ///
    /// # 戻り値
    /// P-code演算列。最後の演算の出力が全体の結果を表します。
    ///
    /// # 例
    /// ```
    /// use kensho_mcp::decompiler_prototype::{KenshoMBASimplifier, Expr};
    ///
    /// let mut simplifier = KenshoMBASimplifier::new();
    /// let x = Expr::var("x", 32);
    /// let y = Expr::var("y", 32);
    /// let expr = Expr::add(x, y);  // x + y
    ///
    /// let pcode_ops = simplifier.kensho_expr_to_pcode(&expr, 4);
    /// // 結果: [PcodeOp { opcode: IntAdd, inputs: [x, y], output: u0 }]
    /// ```
    pub fn kensho_expr_to_pcode(&self, expr: &Expr, output_size: usize) -> Vec<PcodeOp> {
        let mut ops = Vec::new();
        let mut unique_counter = 0u64;

        // 再帰的に変換
        let _ = self.expr_to_pcode_recursive(
            expr,
            &mut ops,
            &mut unique_counter,
            output_size,
            0, // address
        );

        ops
    }

    /// Expr → P-code再帰的変換（内部関数）
    ///
    /// # 戻り値
    /// 変換結果のVarnode（次の演算の入力として使用）
    fn expr_to_pcode_recursive(
        &self,
        expr: &Expr,
        ops: &mut Vec<PcodeOp>,
        unique_counter: &mut u64,
        output_size: usize,
        address: u64,
    ) -> Option<Varnode> {
        match expr {
            // 定数: Const空間のVarnodeとして表現
            Expr::BV { value, width: _ } => {
                Some(Varnode::constant(*value, output_size))
            }

            // 変数: 名前を解析してVarnodeに変換
            Expr::Var { name, width: _ } => {
                Some(self.name_to_varnode(name, output_size))
            }

            // 加算: IntAdd
            Expr::Add(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntAdd,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // 減算: IntSub
            Expr::Sub(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntSub,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // 乗算: IntMult
            Expr::Mul(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntMult,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // ビット論理積: IntAnd
            Expr::And(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntAnd,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // ビット論理和: IntOr
            Expr::Or(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntOr,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // 排他的論理和: IntXor
            Expr::Xor(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntXor,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // 左シフト: IntLeft
            Expr::Shl(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntLeft,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // 論理右シフト: IntRight
            Expr::Lshr(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntRight,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // 算術右シフト: IntSRight
            Expr::Ashr(left, right) => {
                let left_vn = self.expr_to_pcode_recursive(left, ops, unique_counter, output_size, address)?;
                let right_vn = self.expr_to_pcode_recursive(right, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntSRight,
                    inputs: vec![left_vn, right_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // ビット否定: IntNegate
            Expr::Not(expr) => {
                let input_vn = self.expr_to_pcode_recursive(expr, ops, unique_counter, output_size, address)?;

                let output = Varnode::unique(*unique_counter, output_size);
                *unique_counter += 1;

                ops.push(PcodeOp {
                    opcode: OpCode::IntNegate,
                    inputs: vec![input_vn],
                    output: Some(output.clone()),
                    address,
                });

                Some(output)
            }

            // その他の演算は未サポート
            _ => None,
        }
    }

    /// 変数名文字列をVarnodeに逆変換
    ///
    /// varnode_to_name()の逆操作。
    /// "r0" → Register, "u1" → Unique, "42" → Const
    fn name_to_varnode(&self, name: &str, size: usize) -> Varnode {
        if name.starts_with('r') {
            // レジスタ: "r0" → Register(0)
            let offset = name[1..].parse::<u64>().unwrap_or(0);
            Varnode::register(offset, size)
        } else if name.starts_with('u') {
            // Unique: "u1" → Unique(1)
            let offset = name[1..].parse::<u64>().unwrap_or(0);
            Varnode::unique(offset, size)
        } else if name.starts_with('v') {
            // 汎用変数: "v10" → Unique(10)
            let offset = name[1..].parse::<u64>().unwrap_or(0);
            Varnode::unique(offset, size)
        } else if let Ok(value) = name.parse::<u64>() {
            // 数値文字列: "42" → Const(42)
            Varnode::constant(value, size)
        } else {
            // デフォルト: 変数名のハッシュ値をオフセットとして使用
            let offset = name.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
            Varnode::unique(offset, size)
        }
    }
}

impl Default for KenshoMBASimplifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kensho_simplifier_creation() {
        let simplifier = KenshoMBASimplifier::new();
        assert_eq!(simplifier.stats().verifications, 0);
    }

    #[test]
    fn test_variable_extraction() {
        let simplifier = KenshoMBASimplifier::new();

        let x = Varnode::new(AddressSpace::Register, 0, 4);
        let y = Varnode::new(AddressSpace::Register, 4, 4);

        let ops = vec![
            PcodeOp {
                opcode: OpCode::IntXor,
                inputs: vec![x.clone(), y.clone()],
                output: Some(Varnode::new(AddressSpace::Unique, 0, 4)),
                address: 0,
            },
            PcodeOp {
                opcode: OpCode::IntAnd,
                inputs: vec![x.clone(), y.clone()],
                output: Some(Varnode::new(AddressSpace::Unique, 1, 4)),
                address: 0,
            },
        ];

        let vars = simplifier.extract_variables(&ops);
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_candidate_generation() {
        let simplifier = KenshoMBASimplifier::new();

        let x = Varnode::new(AddressSpace::Register, 0, 4);
        let y = Varnode::new(AddressSpace::Register, 4, 4);
        let output = Varnode::new(AddressSpace::Unique, 10, 4);

        let candidates = simplifier.generate_simple_candidates(&vec![x, y], &output);

        // x+y, x-y, x^y, x&y, x|y
        assert_eq!(candidates.len(), 5);
    }
}
