//! SMTソルバー
//!
//! 等価性判定と制約解決を提供。
//! kenshoのMBA難読化解除に特化した軽量実装。

use crate::kensho_smt::bitmask::{compute_bitmask, BitMask};
use crate::kensho_smt::bitblast::{BitBlaster, BoolExpr};
use crate::kensho_smt::context::Context;
use crate::kensho_smt::expr::Expr;
use crate::kensho_smt::mba_patterns::MBAPatternSet;
use crate::kensho_smt::sat_solver::{CNF, DPLLSolver, SatSolverResult};
use crate::kensho_smt::simplify::simplify;
use std::collections::HashMap;

/// SMTソルバー
pub struct Solver {
    /// コンテキスト
    context: Context,

    /// 制約リスト
    constraints: Vec<Expr>,

    /// モデル（SATの場合の変数割り当て）
    model: Option<HashMap<String, u64>>,

    /// MBAパターンセット
    mba_patterns: MBAPatternSet,
}

/// SAT/SMTの結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SatResult {
    /// 充足可能
    Sat,
    /// 充足不可能
    Unsat,
    /// 判定不可
    Unknown,
}

impl Solver {
    /// 新しいソルバーを作成
    pub fn new() -> Self {
        Self {
            context: Context::new(),
            constraints: Vec::new(),
            model: None,
            mba_patterns: MBAPatternSet::new(),
        }
    }

    /// 制約を追加
    ///
    /// # Arguments
    /// * `constraint` - 追加する制約式（1が真、0が偽）
    pub fn add_constraint(&mut self, constraint: Expr) {
        self.constraints.push(constraint);
    }

    /// すべての制約をクリア
    pub fn clear_constraints(&mut self) {
        self.constraints.clear();
        self.model = None;
    }

    /// 制約の充足可能性をチェック
    ///
    /// 現在の実装では、簡約化による構造的チェックのみ。
    /// 完全なSAT solverは将来実装予定。
    pub fn check_sat(&mut self) -> SatResult {
        // 全ての制約を簡約化
        let simplified_constraints: Vec<Expr> = self
            .constraints
            .iter()
            .map(|c| simplify(c))
            .collect();

        // 明らかな矛盾をチェック
        for constraint in &simplified_constraints {
            if let Expr::BV { value: 0, .. } = constraint {
                // 0（偽）の制約があれば充足不可能
                return SatResult::Unsat;
            }
        }

        // すべてが1（真）なら充足可能
        if simplified_constraints
            .iter()
            .all(|c| matches!(c, Expr::BV { value: 1, .. }))
        {
            return SatResult::Sat;
        }

        // それ以外は判定不可
        SatResult::Unknown
    }

    /// 2つの式が等価か判定
    ///
    /// # Arguments
    /// * `expr1` - 式1
    /// * `expr2` - 式2
    ///
    /// # Returns
    /// 等価ならtrue、そうでないまたは判定不可の場合はfalse
    pub fn are_equivalent(&mut self, expr1: &Expr, expr2: &Expr) -> bool {
        // ステップ1: 構造的等価性チェック
        if expr1 == expr2 {
            return true;
        }

        // ステップ2: 簡約化後の比較
        let simp1 = simplify(expr1);
        let simp2 = simplify(expr2);

        if simp1 == simp2 {
            return true;
        }

        // ステップ3: expr1 != expr2 の充足可能性をチェック
        // expr1 != expr2が充足不可能なら、expr1 == expr2が常に真
        let neq = Expr::eq(simp1.clone(), simp2.clone());
        let not_eq = Expr::not(neq);

        // 一時的に制約を追加してチェック
        let saved_constraints = self.constraints.clone();
        self.constraints.clear();
        self.add_constraint(not_eq);

        let result = self.check_sat();

        // 制約を元に戻す
        self.constraints = saved_constraints;

        // Unsatなら等価
        matches!(result, SatResult::Unsat)
    }

    /// 式を簡約化
    ///
    /// # Arguments
    /// * `expr` - 簡約化する式
    ///
    /// # Returns
    /// 簡約化された式
    pub fn simplify(&self, expr: &Expr) -> Expr {
        simplify(expr)
    }

    /// 一意な変数を生成
    ///
    /// # Arguments
    /// * `width` - ビット幅
    ///
    /// # Returns
    /// 新しい変数式
    pub fn fresh_var(&mut self, width: u32) -> Expr {
        self.context.fresh_var(width)
    }

    /// モデルを取得（SATの場合）
    pub fn get_model(&self) -> Option<&HashMap<String, u64>> {
        self.model.as_ref()
    }

    /// ソルバーをリセット
    pub fn reset(&mut self) {
        self.context.reset();
        self.constraints.clear();
        self.model = None;
    }

    /// キャッシュをクリア
    pub fn clear_cache(&mut self) {
        self.context.clear_cache();
    }

    /// 制約の数を取得
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// MBA難読化を簡約化
    ///
    /// MBAパターンマッチングと代数的簡約化を組み合わせて、
    /// MBA難読化された式を元の単純な形に戻す。
    ///
    /// # Arguments
    /// * `expr` - 簡約化する式
    ///
    /// # Returns
    /// 簡約化された式
    ///
    /// # Example
    /// ```
    /// # use ghidra_mcp::kensho_smt::{Solver, Expr};
    /// let mut solver = Solver::new();
    /// let x = Expr::var("x", 32);
    /// let y = Expr::var("y", 32);
    ///
    /// // (x ^ y) + 2 * (x & y) = x + y
    /// let xor = Expr::xor(x.clone(), y.clone());
    /// let and = Expr::and(x.clone(), y.clone());
    /// let mul = Expr::mul(Expr::const_bv(2, 32), and);
    /// let mba_expr = Expr::add(xor, mul);
    ///
    /// let simplified = solver.simplify_mba(&mba_expr);
    /// let expected = Expr::add(x, y);
    /// assert_eq!(solver.simplify(&simplified), solver.simplify(&expected));
    /// ```
    pub fn simplify_mba(&self, expr: &Expr) -> Expr {
        self.mba_patterns.simplify_recursive(expr)
    }

    /// ビットマスク解析を実行
    ///
    /// 式の各ビット位置について、known_zeros（必ず0）とknown_ones（必ず1）を計算。
    ///
    /// # Arguments
    /// * `expr` - 解析する式
    ///
    /// # Returns
    /// ビットマスク情報
    ///
    /// # Example
    /// ```
    /// # use ghidra_mcp::kensho_smt::{Solver, Expr};
    /// let solver = Solver::new();
    /// let x = Expr::const_bv(0b1100, 4);
    /// let y = Expr::const_bv(0b1010, 4);
    /// let and_expr = Expr::and(x, y);
    ///
    /// let bitmask = solver.compute_bitmask(&and_expr);
    /// assert_eq!(bitmask.constant_value(), Some(0b1000));
    /// ```
    pub fn compute_bitmask(&self, expr: &Expr) -> BitMask {
        compute_bitmask(expr)
    }

    /// ビットマスク解析を使った簡約化
    ///
    /// ビットマスク情報を使って、定数ビットを検出し簡約化を強化。
    ///
    /// # Arguments
    /// * `expr` - 簡約化する式
    ///
    /// # Returns
    /// 簡約化された式
    pub fn simplify_with_bitmask(&self, expr: &Expr) -> Expr {
        let bitmask = compute_bitmask(expr);

        // 完全に定数と判明した場合
        if let Some(value) = bitmask.constant_value() {
            return Expr::const_bv(value, bitmask.width);
        }

        // それ以外は通常の簡約化
        simplify(expr)
    }

    /// 完全な簡約化（MBA + ビットマスク + 代数的簡約化）
    ///
    /// すべての簡約化手法を組み合わせて、最大限の簡約化を試みる。
    ///
    /// # Arguments
    /// * `expr` - 簡約化する式
    ///
    /// # Returns
    /// 簡約化された式
    ///
    /// # Example
    /// ```
    /// # use ghidra_mcp::kensho_smt::{Solver, Expr};
    /// let mut solver = Solver::new();
    /// let x = Expr::var("x", 32);
    /// let y = Expr::var("y", 32);
    ///
    /// // 複雑なMBA式
    /// let xor = Expr::xor(x.clone(), y.clone());
    /// let and = Expr::and(x.clone(), y.clone());
    /// let mul = Expr::mul(Expr::const_bv(2, 32), and);
    /// let mba_expr = Expr::add(xor, mul);
    ///
    /// let simplified = solver.simplify_full(&mba_expr);
    /// // x + y に簡約化される
    /// ```
    pub fn simplify_full(&self, expr: &Expr) -> Expr {
        let mut current = expr.clone();
        let mut changed = true;
        let max_iterations = 10;
        let mut iteration = 0;

        while changed && iteration < max_iterations {
            iteration += 1;

            // Step 1: MBA pattern simplification
            let mba_simplified = self.mba_patterns.simplify_recursive(&current);

            // Step 2: Algebraic simplification
            let alg_simplified = simplify(&mba_simplified);

            // Step 3: Bitmask-based simplification
            let bitmask_simplified = self.simplify_with_bitmask(&alg_simplified);

            changed = bitmask_simplified != current;
            current = bitmask_simplified;
        }

        current
    }

    /// 非ゼロマスク（NZMask）を計算
    ///
    /// 0でない可能性があるビット位置を示すマスクを返す。
    ///
    /// # Arguments
    /// * `expr` - 解析する式
    ///
    /// # Returns
    /// 非ゼロマスク（1のビット = 0でない可能性あり）
    pub fn compute_nzmask(&self, expr: &Expr) -> u64 {
        let bitmask = compute_bitmask(expr);
        bitmask.nzmask()
    }

    /// ビットブラスティングとSATソルバーを使った等価性判定
    ///
    /// 簡約化では判定できない場合に、ビットベクトルをBoolean式に変換して
    /// SATソルバーで厳密に判定する。
    ///
    /// # Arguments
    /// * `expr1` - 式1
    /// * `expr2` - 式2
    ///
    /// # Returns
    /// 等価ならtrue、そうでない場合はfalse
    ///
    /// # Example
    /// ```
    /// # use ghidra_mcp::kensho_smt::{Solver, Expr};
    /// let mut solver = Solver::new();
    /// let x = Expr::var("x", 8);
    /// let y = Expr::var("y", 8);
    ///
    /// // MBA obfuscated vs. original
    /// let xor = Expr::xor(x.clone(), y.clone());
    /// let and = Expr::and(x.clone(), y.clone());
    /// let mul = Expr::mul(Expr::const_bv(2, 8), and);
    /// let mba_expr = Expr::add(xor, mul);
    /// let original = Expr::add(x, y);
    ///
    /// // Use SAT-based equivalence checking
    /// assert!(solver.are_equivalent_sat(&mba_expr, &original));
    /// ```
    pub fn are_equivalent_sat(&mut self, expr1: &Expr, expr2: &Expr) -> bool {
        // Step 1: Structural equality
        if expr1 == expr2 {
            return true;
        }

        // Step 2: Simplification-based equality
        let simp1 = self.simplify_full(expr1);
        let simp2 = self.simplify_full(expr2);

        if simp1 == simp2 {
            return true;
        }

        // Step 3: Bit-blasting + SAT solving
        // Check if (expr1 != expr2) is UNSAT
        // If UNSAT, then expr1 == expr2 is always true

        let mut blaster = BitBlaster::new();

        // Blast both expressions
        let bits1 = blaster.blast(&simp1);
        let bits2 = blaster.blast(&simp2);

        // Build formula: expr1 != expr2 (at least one bit differs)
        let mut neq_formula = BoolExpr::False;
        for (b1, b2) in bits1.iter().zip(bits2.iter()) {
            // b1 != b2 = (b1 ⊕ b2)
            let bit_neq = BoolExpr::xor(b1.clone(), b2.clone());
            neq_formula = BoolExpr::or(neq_formula, bit_neq);
        }

        // Simplify before converting to CNF to avoid complex unsimplified formulas
        // This resolves cases like Or(False, X) -> X and Xor(Not(x), x) -> True
        neq_formula = neq_formula.simplify();

        // Convert to CNF and solve
        let cnf = CNF::from_bool_expr(&neq_formula);
        let mut sat_solver = DPLLSolver::new(cnf);

        match sat_solver.solve() {
            SatSolverResult::Unsat => true,  // expr1 == expr2
            SatSolverResult::Sat(_) => false, // expr1 != expr2
            SatSolverResult::Unknown => {
                // Fallback to simplification-based check
                simp1 == simp2
            }
        }
    }

    /// ビットブラスティングを使ったSAT判定
    ///
    /// Boolean式をビットベクトル式から生成してSATソルバーで解く。
    ///
    /// # Arguments
    /// * `expr` - 判定する式（1ビット、0でなければSAT）
    ///
    /// # Returns
    /// SAT判定結果
    pub fn check_sat_bitblast(&mut self, expr: &Expr) -> SatResult {
        // Simplify first
        let simplified = self.simplify_full(expr);

        // Check if constant
        if let Some(value) = simplified.const_value() {
            return if value != 0 {
                SatResult::Sat
            } else {
                SatResult::Unsat
            };
        }

        // Bit-blast and solve
        let mut blaster = BitBlaster::new();
        let bits = blaster.blast(&simplified);

        // For 1-bit expressions, check if the single bit is satisfiable
        if bits.len() == 1 {
            let cnf = CNF::from_bool_expr(&bits[0]);
            let mut sat_solver = DPLLSolver::new(cnf);

            match sat_solver.solve() {
                SatSolverResult::Sat(_) => SatResult::Sat,
                SatSolverResult::Unsat => SatResult::Unsat,
                SatSolverResult::Unknown => SatResult::Unknown,
            }
        } else {
            // Multi-bit: check if any bit can be 1
            let mut any_bit_true = BoolExpr::False;
            for bit in bits {
                any_bit_true = BoolExpr::or(any_bit_true, bit);
            }

            let cnf = CNF::from_bool_expr(&any_bit_true);
            let mut sat_solver = DPLLSolver::new(cnf);

            match sat_solver.solve() {
                SatSolverResult::Sat(_) => SatResult::Sat,
                SatSolverResult::Unsat => SatResult::Unsat,
                SatSolverResult::Unknown => SatResult::Unknown,
            }
        }
    }

    /// 高度な等価性判定（全手法を組み合わせ）
    ///
    /// 1. 構造的等価性
    /// 2. MBA簡約化 + 代数的簡約化
    /// 3. ビットマスク解析
    /// 4. ビットブラスティング + SAT（必要時）
    ///
    /// # Arguments
    /// * `expr1` - 式1
    /// * `expr2` - 式2
    ///
    /// # Returns
    /// 等価ならtrue
    pub fn are_equivalent_advanced(&mut self, expr1: &Expr, expr2: &Expr) -> bool {
        // Fast path: structural equality
        if expr1 == expr2 {
            return true;
        }

        // Medium path: full simplification
        let simp1 = self.simplify_full(expr1);
        let simp2 = self.simplify_full(expr2);

        if simp1 == simp2 {
            return true;
        }

        // Slow path: SAT-based equivalence (only for small expressions)
        let width1 = simp1.width();
        let width2 = simp2.width();

        if width1 != width2 {
            return false;
        }

        // Only use SAT for reasonably-sized expressions (≤ 32 bits)
        if width1 <= 32 {
            self.are_equivalent_sat(&simp1, &simp2)
        } else {
            // For large expressions, rely on simplification
            false
        }
    }
}

impl Default for Solver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solver_creation() {
        let solver = Solver::new();
        assert_eq!(solver.num_constraints(), 0);
    }

    #[test]
    fn test_add_constraint() {
        let mut solver = Solver::new();
        let constraint = Expr::const_bv(1, 1);
        solver.add_constraint(constraint);
        assert_eq!(solver.num_constraints(), 1);
    }

    #[test]
    fn test_clear_constraints() {
        let mut solver = Solver::new();
        solver.add_constraint(Expr::const_bv(1, 1));
        solver.clear_constraints();
        assert_eq!(solver.num_constraints(), 0);
    }

    #[test]
    fn test_check_sat_true() {
        let mut solver = Solver::new();
        solver.add_constraint(Expr::const_bv(1, 1));
        assert_eq!(solver.check_sat(), SatResult::Sat);
    }

    #[test]
    fn test_check_sat_false() {
        let mut solver = Solver::new();
        solver.add_constraint(Expr::const_bv(0, 1));
        assert_eq!(solver.check_sat(), SatResult::Unsat);
    }

    #[test]
    fn test_are_equivalent_same() {
        let mut solver = Solver::new();
        let x = Expr::var("x", 32);
        assert!(solver.are_equivalent(&x, &x));
    }

    #[test]
    fn test_are_equivalent_simplified() {
        let mut solver = Solver::new();
        let x = Expr::var("x", 32);
        let zero = Expr::const_bv(0, 32);
        let expr1 = Expr::add(x.clone(), zero);
        assert!(solver.are_equivalent(&expr1, &x));
    }

    #[test]
    fn test_are_equivalent_constants() {
        let mut solver = Solver::new();
        let expr1 = Expr::add(Expr::const_bv(2, 32), Expr::const_bv(3, 32));
        let expr2 = Expr::const_bv(5, 32);
        assert!(solver.are_equivalent(&expr1, &expr2));
    }

    #[test]
    fn test_simplify() {
        let solver = Solver::new();
        let x = Expr::var("x", 32);
        let expr = Expr::add(x.clone(), Expr::const_bv(0, 32));
        let simplified = solver.simplify(&expr);
        assert_eq!(simplified, x);
    }

    #[test]
    fn test_fresh_var() {
        let mut solver = Solver::new();
        let var1 = solver.fresh_var(32);
        let var2 = solver.fresh_var(64);
        assert_eq!(var1.width(), 32);
        assert_eq!(var2.width(), 64);
        assert_ne!(var1, var2);
    }

    #[test]
    fn test_reset() {
        let mut solver = Solver::new();
        solver.add_constraint(Expr::const_bv(1, 1));
        solver.fresh_var(32);
        solver.reset();
        assert_eq!(solver.num_constraints(), 0);
    }

    #[test]
    fn test_bug_repro_x_plus_1() {
        let mut solver = Solver::new();
        // Use small width to be fast, but large enough (check 8 bits)
        let x = Expr::var("x", 8);
        let one = Expr::const_bv(1, 8);
        let x_plus_1 = Expr::add(x.clone(), one);
        
        // x + 1 != x, so are_equivalent should return false
        assert_eq!(solver.are_equivalent_sat(&x_plus_1, &x), false, "x + 1 should not be equivalent to x");
    }
}
