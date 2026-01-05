# kensho SMTソルバー バグ修正セッション記録

**日付**: 2025年12月27日
**目的**: Demo 3のTest 2で発見されたSAT等価性判定のバグを修正

---

## 発見された問題

### 症状
- **Demo 3のTest 2**: `x + 1`と`x`が等価だと誤判定
- **実行結果**: "Equivalence: ✓ EQUIVALENT" と表示
- **期待動作**: "Equivalence: ✗ NOT EQUIVALENT (correct)" と表示

### 影響範囲
- **限定的**: MBA deobfuscation機能は100%正常動作
- **影響箇所**: SAT-based equivalence checking機能の一部のみ

---

## 根本原因分析（計画書より）

### 問題の特定
`src/kensho_smt/solver.rs`の`are_equivalent_sat()`メソッド（行355-399）:

1. **ビットブラスティング**で`x + 1`と`x`の各ビットを生成
2. **neq_formula構築**時に`Or(False, Xor(Not(x[0]), x[0]))`のような簡約化されていない式を生成
3. **問題**: neq_formulaが簡約化されずにCNFに変換される
4. **本来**: `Xor(Not(x), x)` → `True`と簡約化されるべき

### 修正方針
- neq_formulaをCNFに変換する前に`BoolExpr::simplify()`を呼ぶ
- これにより`Or(False, X)` → `X`、`Xor(Not(x), x)` → `True`が簡約化される

---

## 実施した修正

### ✅ 1. 根本修正（完了）

**ファイル**: `src/kensho_smt/solver.rs`
**変更箇所**: 行388-389

**修正内容**:
```rust
// 修正前（行379-388）:
let mut neq_formula = BoolExpr::False;
for (b1, b2) in bits1.iter().zip(bits2.iter()) {
    let bit_neq = BoolExpr::xor(b1.clone(), b2.clone());
    neq_formula = BoolExpr::or(neq_formula, bit_neq);
}
let cnf = CNF::from_bool_expr(&neq_formula);

// 修正後:
let mut neq_formula = BoolExpr::False;
for (b1, b2) in bits1.iter().zip(bits2.iter()) {
    let bit_neq = BoolExpr::xor(b1.clone(), b2.clone());
    neq_formula = BoolExpr::or(neq_formula, bit_neq);
}
// Simplify before converting to CNF to avoid complex unsimplified formulas
neq_formula = neq_formula.simplify();
let cnf = CNF::from_bool_expr(&neq_formula);
```

**状態**: ✅ 適用済み

---

### ✅ 2. テスト追加（完了）

**ファイル**: `tests/kensho_smt_phase3.rs`
**追加テスト**: `test_equivalence_sat_simple_non_equivalent()`（行355-373）

**テスト内容**:
```rust
#[test]
fn test_equivalence_sat_simple_non_equivalent() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 4);

    // x + 1 ≠ x
    let expr1 = Expr::add(x.clone(), Expr::const_bv(1, 4));
    assert!(!solver.are_equivalent_sat(&expr1, &x));

    // x + 2 ≠ x + 1
    let expr2 = Expr::add(x.clone(), Expr::const_bv(2, 4));
    let expr3 = Expr::add(x.clone(), Expr::const_bv(1, 4));
    assert!(!solver.are_equivalent_sat(&expr2, &expr3));

    // x * 2 ≠ x + 1
    let expr4 = Expr::mul(x.clone(), Expr::const_bv(2, 4));
    let expr5 = Expr::add(x.clone(), Expr::const_bv(1, 4));
    assert!(!solver.are_equivalent_sat(&expr4, &expr5));
}
```

**状態**: ✅ 適用済み

---

### ✅ 3. クレート名修正（完了）

**問題**: テストファイルで`ghidra_mcp`を使用していたが、正しくは`kensho_mcp`

**修正ファイル**:
- `tests/kensho_smt_phase3.rs`: `use ghidra_mcp::` → `use kensho_mcp::`
- `tests/kensho_smt_integration.rs`: 同様に修正
- リテラル生成部分も修正（`kensho_mcp::kensho_smt::Literal::pos(0)`）

**状態**: ✅ 適用済み

---

### ⚠️ 4. 型推論エラー修正（部分的）

**問題**: 複数箇所で型推論エラーが発生

**修正箇所**:
1. **`src/decompiler_prototype/mba/kensho_simplifier.rs`**:
   - `varnode_to_expr()`の戻り値型を`crate::kensho_smt::Expr`に明示
   - `pcode_to_kensho_single()`の戻り値型も同様に修正

2. **`src/decompiler_prototype/symbolic_execution/symbolic_executor.rs`**:
   - `simplify_constraints_with_kensho()`でクロージャパラメータに型アノテーション追加
   - `Clause`型を明示的にインポート
   - `build_cnf_from_constraints()`で中間変数に型アノテーション追加

**状態**: ⚠️ 部分的に完了（まだエラーが残っている）

---

## 現在の状況

### ✅ 成功していること
- ✅ ライブラリ本体（`cargo build --lib --release`）は正常にビルド可能
- ✅ kensho SMTソルバーの核心部分は修正済み
- ✅ 計画書に記載された修正は全て適用済み

### ❌ 未解決の問題
- ❌ テストビルドでコンパイルエラーが発生
- ❌ ライブラリ内の他のモジュール（decompiler_prototype内）に型推論エラーが残存
- ❌ Phase 3テストの実行が完了していない
- ❌ Demo実行による動作確認が未完了

### エラー詳細
```
error[E0282]: type annotations needed
 --> src\decompiler_prototype\mba\kensho_simplifier.rs:198:25
  |
198 |             return Some(expr.clone());
    |                         ^^^^ cannot infer type

error[E0282]: type annotations needed
 --> src\decompiler_prototype\symbolic_execution\symbolic_executor.rs:599:44
  |
599 |                 let clause_clone: Clause = clause.clone();
    |                                            ^^^^^^ cannot infer type
```

---

## 次のステップ（優先順位順）

### 🔴 優先度：高
1. **残りの型推論エラーを修正**
   - `kensho_simplifier.rs:198`の型を明示
   - `symbolic_executor.rs:599`の`Clause`型の問題を解決

2. **Phase 3テストを実行**
   ```bash
   cargo test --release kensho_smt_phase3
   ```

3. **デモ実行で動作確認**
   ```bash
   cargo run --release --example kensho_smt_demo
   ```
   - Demo 3のTest 2が"✗ NOT EQUIVALENT (correct)"と表示されることを確認

### 🟡 優先度：中
4. **全Phase 3テストの成功確認**
   - 他のテストケースも正常に動作することを検証

5. **パフォーマンス確認**
   - MBA deobfuscation機能が引き続き100%成功率を維持

### 🟢 優先度：低
6. **コード整理**
   - 未使用のwarningを修正（103件）
   - テストコード内の型アノテーションを統一

---

## 技術的メモ

### BoolExpr::simplify()の動作
- `Or(False, X)` → `X`
- `Xor(Not(x), x)` → `True`（二重否定除去と組み合わせ）
- 論理的に等価だがより単純なBoolean式を生成

### テストの期待動作
```
修正前:
  Test 2: Detecting non-equivalent expressions
    Expression 1: x + 1
    Expression 2: x
    Equivalence:  ✓ EQUIVALENT       ← 誤り

修正後:
  Test 2: Detecting non-equivalent expressions
    Expression 1: x + 1
    Expression 2: x
    Equivalence:  ✗ NOT EQUIVALENT (correct)  ← 正しい
```

---

## リスク評価

### 変更の影響範囲
- **変更箇所**: 1ファイル、1メソッド、1行追加（本質的修正）
- **影響**: SAT-based equivalence checking機能のみ
- **既存機能**: MBA deobfuscation、bitmask解析、rewrite systemには影響なし

### 修正の安全性
- **High**: `BoolExpr::simplify()`は既存の実装で、テスト済み
- **修正の本質**: 簡約化のタイミングを追加するだけ
- **副作用**: なし（簡約化は論理的等価性を保つ）

---

## 参考資料

- **計画書**: `C:\Users\Administrator\.claude\plans\zippy-jingling-fountain.md`
- **修正対象**: `src/kensho_smt/solver.rs`
- **テストファイル**: `tests/kensho_smt_phase3.rs`
- **デモファイル**: `examples/kensho_smt_demo.rs`

---

## セッション終了時の状態

- **ライブラリビルド**: ✅ 成功
- **テストビルド**: ❌ 失敗（型推論エラー）
- **コア修正**: ✅ 完了
- **動作確認**: ⏸️ 保留中

**次回セッション**: 型推論エラーの解決から再開
