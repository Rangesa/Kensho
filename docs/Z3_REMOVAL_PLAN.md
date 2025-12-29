# Z3削除とkensho SMT一本化計画

## 概要

z3依存を完全に削除し、kensho SMT solverに一本化します。
kensho SMTで処理できない複雑な制約は、将来の拡張項目として本ドキュメントに記録します。

**実施日**: 2025-12-27

---

## 現状分析

### z3の実使用箇所

#### 1. `src/decompiler_prototype/z3_solver/mod.rs`
**機能**: Z3Solverのラッパークラス
- P-codeをZ3ビットベクトルに変換
- 式の等価性チェック (`are_equivalent()`)
- 式の簡約化 (`simplify()`)
- モデル生成 (`get_model()`)
- SAT/UNSAT判定 (`check_sat()`)

**使用状況**:
- `Z3MBASimplifier`から使用されている
- テストコードに2つのテストケース

#### 2. `src/decompiler_prototype/mba/z3_simplifier.rs`
**機能**: Z3ベースのMBA簡約化エンジン
- MBA式を単純な候補式と等価性検証
- `solver.are_equivalent()` で検証
- 5種類の候補生成（x+y, x-y, x^y, x&y, x|y）

**使用状況**:
- 実際に動作しているコード
- テストコードに3つのテストケース

### z3の未使用箇所（削除のみ）

#### 3. `src/decompiler_prototype/z3_solver/symbolic_executor.rs`
- `solver: Z3Solver` フィールドが**未使用**（警告済み）
- 実際にはkensho SMTを使用中

#### 4. `src/decompiler_prototype/z3_solver/vulnerability_detector.rs`
- `solver: Z3Solver` フィールドが**未使用**（警告済み）

---

## 削除・置き換え計画

### Phase 1: 未使用フィールド削除（即座に可能）

**対象ファイル**:
1. `src/decompiler_prototype/z3_solver/symbolic_executor.rs`
   - 行206: `solver: Z3Solver,` を削除
   - 行25: `use super::Z3Solver;` を削除
   - 行248: `solver: Z3Solver::new(),` を削除

2. `src/decompiler_prototype/z3_solver/vulnerability_detector.rs`
   - 行83: `solver: Z3Solver,` を削除
   - 行14: `use super::Z3Solver;` を削除
   - 行90: `solver: Z3Solver::new(),` を削除

**影響**: なし（既に未使用として警告が出ている）

### Phase 2: Z3MBASimplifierのkensho SMT置き換え

**対象ファイル**: `src/decompiler_prototype/mba/z3_simplifier.rs`

**置き換え方針**:

#### Before (z3使用):
```rust
pub struct Z3MBASimplifier {
    solver: Z3Solver,  // z3依存
    equivalence_cache: HashMap<String, bool>,
    stats: Z3SimplificationStats,
}

// 等価性検証（行86）
let equiv = self.solver.are_equivalent(&original_expr, &candidate_expr);
```

#### After (kensho SMT使用):
```rust
pub struct KenshoMBASimplifier {
    solver: kensho_smt::Solver,  // kensho SMT
    equivalence_cache: HashMap<String, bool>,
    stats: KenshoSimplificationStats,
}

// 等価性検証
// P-codeからkensho SMT Exprに変換
let original_expr = self.ops_to_kensho_expr(ops)?;
let candidate_expr = self.ops_to_kensho_expr(&candidate_ops)?;

// kensho SMTのare_equivalent_sat()を使用
let equiv = self.solver.are_equivalent_sat(&original_expr, &candidate_expr);
```

**必要な実装**:
1. `ops_to_kensho_expr()` - P-codeをkensho SMT Exprに変換
   - OpCode::IntAdd → Expr::add()
   - OpCode::IntSub → Expr::sub()
   - OpCode::IntXor → Expr::xor()
   - OpCode::IntAnd → Expr::and()
   - OpCode::IntOr → Expr::or()
   - OpCode::IntMult → Expr::mul()

2. `are_equivalent_sat()` を使用（既に実装済み）

**置き換え可能性**: ✅ **100%可能**
- kensho SMTの`are_equivalent_sat()`が既に実装済み
- kensho SMT demoで動作確認済み（前回のバグ修正で検証）

### Phase 3: Z3Solverモジュール削除

**対象ファイル**: `src/decompiler_prototype/z3_solver/mod.rs`

**削除方針**:
- `Z3Solver`構造体全体を削除
- `MBASimplifier`構造体を削除（未使用かつkensho SMTで代替）
- テストコードも削除

**影響**:
- z3_solverモジュール全体が不要になる
- symbolic_executor.rsやvulnerability_detector.rsはkensho SMTのみ使用

### Phase 4: モジュール構造変更

#### 変更1: `src/decompiler_prototype/mod.rs`

**Before**:
```rust
#[cfg(feature = "z3-solver")]
pub mod z3_solver;

#[cfg(feature = "z3-solver")]
pub use z3_solver::{
    Z3Solver,
    SymbolicExecutor, SymbolicState, ...
};
```

**After**:
```rust
pub mod symbolic_execution;  // z3_solverから改名

pub use symbolic_execution::{
    SymbolicExecutor, SymbolicState, ...
    // Z3Solverは削除
};
```

#### 変更2: `src/decompiler_prototype/mba/mod.rs`

**Before**:
```rust
#[cfg(feature = "z3-solver")]
pub use z3_simplifier::{Z3MBASimplifier, Z3SimplificationStats};
```

**After**:
```rust
pub use kensho_simplifier::{KenshoMBASimplifier, KenshoSimplificationStats};
```

### Phase 5: Cargo.toml変更

**削除**:
```toml
# SMTソルバ（Phase 11-13: 難読化解析 + シンボリック実行）
z3 = { version = "0.19", features = ["gh-release"], optional = true }

[features]
z3-solver = ["z3"]
```

**影響**:
- ビルド時間が大幅短縮（z3は重い依存関係）
- 配布バイナリサイズが削減

---

## kensho SMTで処理できない複雑な制約（MD記録）

以下の機能はz3でしか提供されていませんが、現在のkensho decompilerでは**使用していない**ため、
将来の拡張項目として記録します。

### 1. モデル生成 (Model Generation)

**z3の機能**:
```rust
pub fn get_model(&self) -> Option<z3::Model>
```

**用途**:
- SAT問題が充足可能な場合、具体的な変数の値を取得
- 例: `x + y = 10 かつ x > 5` の解として `x=6, y=4` を生成

**kensho SMTでの代替**:
- 現在未実装
- DPLLソルバーはSAT/UNSATのみ判定、モデル生成はしない

**必要性**:
- **低** - 現在のdecompilerでは等価性検証のみ使用
- 将来、テストケース生成や具体的な入力値生成に必要になる可能性

### 2. 高度な式簡約化 (Advanced Simplification)

**z3の機能**:
```rust
pub fn simplify(&mut self, expr: &BV) -> BV
```

**用途**:
- Z3の強力な書き換えエンジンによる式の簡約化
- 例: `(x + 0) * 1` → `x`
- 例: `(x & 0xFF) | (x & 0xFF00)` → `x & 0xFFFF`

**kensho SMTでの代替**:
- `BoolExpr::simplify()` で基本的な簡約化は可能
- `RewriteSystem` で代数的書き換えが可能
- ただしz3ほど高度ではない

**必要性**:
- **低** - MBA deobfuscationでは等価性検証のみ使用
- 現在の実装（mod.rs:285）でも`simplified`は未使用

### 3. ビットベクトル演算の完全サポート

**z3の機能**:
- ビット回転 (rotate left/right)
- ビット抽出 (extract)
- ビット連結 (concat)
- 符号拡張 (sign_extend)
- ゼロ拡張 (zero_extend)

**kensho SMTでの代替**:
- 基本的な演算のみサポート（add, sub, mul, xor, and, or）
- 高度なビット操作は未実装

**必要性**:
- **中** - 将来的にARM/RISC-Vなど他アーキテクチャ対応時に必要
- 現在はx86-64のみで基本演算で十分

### 4. 量化子 (Quantifiers)

**z3の機能**:
- ∀x, ∃x などの量化子のサポート
- 例: `∀x. x + 0 = x` （全ての x について x + 0 = x）

**kensho SMTでの代替**:
- 未実装（量化子なしのQF_BV理論のみ）

**必要性**:
- **非常に低** - decompilerでは不要
- 形式検証ツールで必要になる可能性

---

## 実装手順

### Step 1: 未使用フィールド削除
1. symbolic_executor.rs から Z3Solver削除
2. vulnerability_detector.rs から Z3Solver削除
3. ビルド確認

### Step 2: KenshoMBASimplifier実装
1. `src/decompiler_prototype/mba/kensho_simplifier.rs` 新規作成
2. `ops_to_kensho_expr()` 実装
3. z3_simplifier.rsのロジックをコピー＆修正
4. テストコード移植

### Step 3: MBA統合
1. `mba/mod.rs` を更新
2. z3_simplifierからkensho_simplifierに切り替え
3. ビルド確認

### Step 4: z3_solver削除
1. `z3_solver/mod.rs` 削除
2. `z3_solver/` ディレクトリをリネーム（`symbolic_execution/`）
3. `decompiler_prototype/mod.rs` 更新

### Step 5: 依存関係削除
1. Cargo.toml から z3削除
2. z3-solver feature削除
3. 全ビルド確認

### Step 6: 検証
1. symbolic execution demo実行
2. kensho SMT demo実行
3. MBA deobfuscation動作確認

---

## リスク評価

### 低リスク
- ✅ symbolic_executor.rs, vulnerability_detector.rs の未使用フィールド削除
- ✅ MBA等価性検証の置き換え（kensho SMTで既に動作実績あり）

### 中リスク
- ⚠️ z3_solver/mod.rs のテストケースが失われる
  - 対策: kensho SMT版のテストケースを新規作成

### 高リスク
- なし

---

## 期待される効果

### ビルド時間短縮
- z3のコンパイルが不要（約30-60秒削減）
- 依存関係の単純化

### バイナリサイズ削減
- z3ライブラリ（約10-20MB）が不要

### コードの一貫性
- SMTソルバーがkensho SMT一本化
- メンテナンス性向上

### パフォーマンス
- kensho SMTのDPLLソルバーは軽量
- MBA等価性検証が高速化する可能性

---

## 完了基準

- [ ] z3への全てのimport/useが削除されている
- [ ] Cargo.tomlにz3依存がない
- [ ] `cargo build --release` が成功
- [ ] `cargo run --example symbolic_execution_demo` が成功
- [ ] `cargo run --example kensho_smt_demo` が成功
- [ ] 警告がz3関連で出ていない

---

## 次のステップ

本計画書をユーザーに確認し、承認後に実装を開始します。
