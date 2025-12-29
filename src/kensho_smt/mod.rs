//! kensho SMT Solver
//!
//! kenshoのバイナリ解析用途に特化した軽量SMTソルバー。
//! MBA難読化解除とP-code等価性チェックに最適化。
//!
//! # 主な機能
//!
//! - ビットベクトル演算の式表現
//! - 代数的簡約化（constant folding, 恒等式）
//! - **MBA難読化解除**（パターンマッチングベース）
//! - **ビットマスク伝播**（定数ビット検出、NZMask計算）
//! - **ビットブラスティング**（BV式→Boolean式変換）
//! - **DPLL SATソルバー**（Boolean充足可能性判定）
//! - **ルールベース書き換え**（カスタマイズ可能な変換規則）
//! - 等価性判定（構造的 + 簡約化 + SAT）
//! - 制約解決（SAT判定）
//!
//! # 使用例
//!
//! ```
//! use ghidra_mcp::kensho_smt::{Solver, Expr};
//!
//! let mut solver = Solver::new();
//!
//! // 式の作成
//! let x = Expr::var("x", 32);
//! let y = Expr::var("y", 32);
//! let expr1 = Expr::add(x.clone(), y.clone());
//!
//! // 簡約化
//! let zero = Expr::const_bv(0, 32);
//! let expr2 = Expr::add(x.clone(), zero);
//! let simplified = solver.simplify(&expr2);
//! assert_eq!(simplified, x);
//!
//! // 等価性チェック
//! let mul_by_2 = Expr::mul(x.clone(), Expr::const_bv(2, 32));
//! let add_self = Expr::add(x.clone(), x.clone());
//! assert!(solver.are_equivalent(&mul_by_2, &add_self));
//! ```
//!
//! # MBA難読化解除の例
//!
//! ```
//! use ghidra_mcp::kensho_smt::{Solver, Expr};
//!
//! let mut solver = Solver::new();
//! let x = Expr::var("x", 32);
//! let y = Expr::var("y", 32);
//!
//! // MBA難読化: (x ^ y) + 2 * (x & y) = x + y
//! let xor = Expr::xor(x.clone(), y.clone());
//! let and = Expr::and(x.clone(), y.clone());
//! let mul = Expr::mul(Expr::const_bv(2, 32), and);
//! let mba_expr = Expr::add(xor, mul);
//!
//! // MBAパターンで簡約化
//! let simplified = solver.simplify_mba(&mba_expr);
//! // 結果: x + y
//! ```
//!
//! # ビットマスク解析の例
//!
//! ```
//! use ghidra_mcp::kensho_smt::{Solver, Expr};
//!
//! let solver = Solver::new();
//! let x = Expr::const_bv(0b1100, 4);
//! let y = Expr::const_bv(0b1010, 4);
//! let expr = Expr::and(x, y);
//!
//! // ビットマスク計算
//! let bitmask = solver.compute_bitmask(&expr);
//! assert_eq!(bitmask.constant_value(), Some(0b1000));
//!
//! // 非ゼロマスク
//! let nzmask = solver.compute_nzmask(&expr);
//! assert_eq!(nzmask, 0b1000);
//! ```
//!
//! # SATベースの等価性判定
//!
//! ```
//! use ghidra_mcp::kensho_smt::{Solver, Expr};
//!
//! let mut solver = Solver::new();
//! let x = Expr::var("x", 8);
//! let y = Expr::var("y", 8);
//!
//! // Original expression
//! let original = Expr::add(x.clone(), y.clone());
//!
//! // MBA obfuscated expression
//! let xor = Expr::xor(x.clone(), y.clone());
//! let and = Expr::and(x, y);
//! let mul = Expr::mul(Expr::const_bv(2, 8), and);
//! let obfuscated = Expr::add(xor, mul);
//!
//! // Prove equivalence using SAT solver
//! assert!(solver.are_equivalent_sat(&original, &obfuscated));
//! ```
//!
//! # アーキテクチャ
//!
//! - **expr**: ビットベクトル式のAST表現
//! - **context**: 変数管理とキャッシュ
//! - **simplify**: ルールベース簡約化エンジン
//! - **mba_patterns**: MBA難読化パターンの定義とマッチング
//! - **bitmask**: ビットレベル解析（known_zeros, known_ones, NZMask）
//! - **bitblast**: ビットベクトル→Boolean変換
//! - **sat_solver**: DPLL SATソルバー
//! - **rewrite**: ルールベース書き換えシステム
//! - **solver**: 等価性判定とSAT判定
//!
//! # 設計原則
//!
//! 1. **シンプルさ**: Z3のような汎用性より、kenshoの用途に特化
//! 2. **外部依存ゼロ**: 純Rust実装、Cライブラリ不要
//! 3. **段階的拡張**: 基本機能から始め、必要に応じて高度化
//!
//! # 制限事項
//!
//! - CDCL SATソルバーは未実装（現在はDPLLのみ）
//! - 学習・ヒューリスティックは未実装（基本的なDPLLのみ）
//! - 理論ソルバー（配列、浮動小数点）は未対応
//! - 大きなビット幅（>32ビット）のSAT判定は性能制限あり

pub mod bitmask;
pub mod bitblast;
pub mod context;
pub mod expr;
pub mod mba_patterns;
pub mod rewrite;
pub mod sat_solver;
pub mod simplify;
pub mod solver;

pub use bitmask::{compute_bitmask, BitMask};
pub use bitblast::{BitBlaster, BoolExpr};
pub use context::Context;
pub use expr::Expr;
pub use mba_patterns::{MBAMatch, MBAPattern, MBAPatternSet};
pub use rewrite::{BinOpKind, Pattern, RewriteRule, RewriteSystem, UnaryOpKind};
pub use sat_solver::{Assignment, CNF, Clause, DPLLSolver, Literal, SatSolverResult};
pub use simplify::simplify;
pub use solver::{SatResult, Solver};
