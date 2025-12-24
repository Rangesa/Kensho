# Ghidra デコンパイラコア 移植計画書

## 調査日時
2025-12-14

## 調査概要
GhidraのC++デコンパイラコア (`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`) をRustに移植し、AIフレンドリーなデコンパイラを構築する実現可能性を調査。

---

## 1. Ghidraデコンパイラコアの規模

### ファイル統計
- **C++ファイル総数**: 227ファイル (.cc + .hh)
- **総行数**: 約146,488行
- **ライセンス**: Apache 2.0 (移植可能)

### 主要コンポーネント（行数順）

| ファイル名 | 行数 | 機能 |
|-----------|------|------|
| ruleaction.cc | 10,998 | デコンパイル最適化ルール |
| fspec.cc | 5,976 | 関数仕様管理 |
| coreaction.cc | 5,736 | コア変換アクション |
| type.cc | 4,674 | 型システム |
| subflow.cc | 4,130 | サブフロー解析 |
| slgh_compile.cc | 4,081 | SLEIGH コンパイラ |
| slghparse.cc | 3,871 | SLEIGH パーサー |
| block.cc | 3,723 | 基本ブロック構築 |
| ifacedecomp.cc | 3,687 | デコンパイラインターフェース |
| printc.cc | 3,401 | C言語出力 |
| heritage.cc | 2,872 | SSA変換・データフロー解析 |
| jumptable.cc | 2,861 | ジャンプテーブル解析 |
| typeop.cc | 2,549 | 型演算 |
| varnode.cc | 2,053 | 変数ノード管理 |

---

## 2. P-code中間表現の詳細

### P-codeとは
Ghidraの独自中間表現（IR）。アセンブリ命令を74種類の汎用命令に変換し、アーキテクチャ非依存の解析を可能にする。

### P-code命令一覧（全74種類）

#### 基本操作 (1-3)
- `CPUI_COPY` - 代入
- `CPUI_LOAD` - メモリ読み込み
- `CPUI_STORE` - メモリ書き込み

#### 制御フロー (4-10)
- `CPUI_BRANCH` - 無条件分岐
- `CPUI_CBRANCH` - 条件分岐
- `CPUI_BRANCHIND` - 間接分岐（ジャンプテーブル）
- `CPUI_CALL` - 関数呼び出し（絶対アドレス）
- `CPUI_CALLIND` - 関数呼び出し（間接アドレス）
- `CPUI_CALLOTHER` - ユーザー定義操作
- `CPUI_RETURN` - 関数戻り

#### 整数演算 (11-36)
- 比較: `INT_EQUAL`, `INT_NOTEQUAL`, `INT_SLESS`, `INT_LESS` 等
- 拡張: `INT_ZEXT` (ゼロ拡張), `INT_SEXT` (符号拡張)
- 算術: `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`, `INT_SDIV`
- ビット: `INT_AND`, `INT_OR`, `INT_XOR`, `INT_NEGATE`
- シフト: `INT_LEFT`, `INT_RIGHT`, `INT_SRIGHT`
- キャリー: `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`

#### ブール演算 (37-40)
- `BOOL_NEGATE`, `BOOL_XOR`, `BOOL_AND`, `BOOL_OR`

#### 浮動小数点 (41-59)
- 比較: `FLOAT_EQUAL`, `FLOAT_NOTEQUAL`, `FLOAT_LESS`, `FLOAT_NAN`
- 算術: `FLOAT_ADD`, `FLOAT_SUB`, `FLOAT_MULT`, `FLOAT_DIV`, `FLOAT_NEG`, `FLOAT_ABS`, `FLOAT_SQRT`
- 丸め: `FLOAT_TRUNC`, `FLOAT_CEIL`, `FLOAT_FLOOR`, `FLOAT_ROUND`
- 変換: `FLOAT_INT2FLOAT`, `FLOAT_FLOAT2FLOAT`

#### SSA特殊命令 (60-61)
- `CPUI_MULTIEQUAL` - Phi-node (SSA合流点)
- `CPUI_INDIRECT` - 間接効果を持つコピー

#### データ操作 (62-73)
- `CPUI_PIECE` - 連結
- `CPUI_SUBPIECE` - 切り出し
- `CPUI_CAST` - 型キャスト
- `CPUI_PTRADD` - ポインタ加算 (配列インデックス)
- `CPUI_PTRSUB` - ポインタ減算 (構造体フィールド)
- `CPUI_INSERT` - ビット範囲挿入
- `CPUI_EXTRACT` - ビット範囲抽出
- `CPUI_POPCOUNT` - 1ビットカウント
- `CPUI_LZCOUNT` - 先頭ゼロビットカウント

---

## 3. コアデータ構造

### Varnode（変数ノード）
SSA形式の変数を表現。以下の情報を保持：
- **Address**: レジスタ/メモリ/定数の識別子
- **Size**: バイト数
- **Def**: 定義するPcodeOp（SSA形式）
- **Flags**: 約20種類（constant, input, written, typelock 等）

### PcodeOp（P-code命令）
P-code命令の実体。以下を保持：
- **Opcode**: 命令種別（74種類のいずれか）
- **Output**: 出力Varnode（1個のみ）
- **Inputs**: 入力Varnode配列（可変長）
- **Flags**: 約30種類（branch, call, dead, marker 等）
- **Parent**: 所属する基本ブロック

### BlockBasic（基本ブロック）
制御フローの基本単位。以下を管理：
- PcodeOp列
- 後続ブロック（Successors）
- 前行ブロック（Predecessors）
- 支配木情報

---

## 4. 主要アルゴリズム

### 4.1 P-code生成
**ファイル**: `slgh_compile.cc`, `slghparse.cc`, `slghscan.cc`
**行数**: 約12,000行
**機能**: SLEIGH言語でアーキテクチャを定義し、機械語からP-codeを生成

**移植の難易度**: ★★★★☆（高い）
- SLEIGH仕様の完全理解が必要
- 複雑なパーサー実装
- 代替案: x86-64のみ手動実装、他アーキは後回し

### 4.2 SSA変換
**ファイル**: `heritage.cc`, `merge.cc`
**行数**: 約4,500行
**機能**: データフロー解析、Phi-node挿入、到達定義解析

**移植の難易度**: ★★★☆☆（中）
- 標準的なSSAアルゴリズム（文献多数）
- 実装パターンが確立されている

### 4.3 型推論
**ファイル**: `type.cc`, `typeop.cc`, `cast.cc`
**行数**: 約8,100行
**機能**: データフロー解析から型情報を推論

**移植の難易度**: ★★★★☆（高い）
- Ghidra独自のヒューリスティック多数
- C言語の複雑な型システム対応

### 4.4 制御フロー解析
**ファイル**: `block.cc`, `blockaction.cc`, `jumptable.cc`
**行数**: 約9,000行
**機能**: if/while/for構造の検出、ジャンプテーブル解析

**移植の難易度**: ★★★☆☆（中）
- グラフアルゴリズムの組み合わせ
- ジャンプテーブルは複雑

### 4.5 最適化パス
**ファイル**: `coreaction.cc`, `ruleaction.cc`
**行数**: 約16,700行（最大）
**機能**: 200以上の最適化ルール適用

**移植の難易度**: ★★★★★（超高い）
- ルール数が膨大
- 品質を上げるには全ルールが必要

### 4.6 C言語出力
**ファイル**: `printc.cc`
**行数**: 約3,400行
**機能**: P-code + 型情報 → C疑似コード変換

**移植の難易度**: ★★☆☆☆（低）
- 比較的独立したコンポーネント
- 優先順位高

---

## 5. 移植戦略

### 戦略A: 段階的フルポート（推奨）

#### フェーズ1: P-code生成（2-3週間）
**目標**: アセンブリ → P-code変換
**範囲**: x86-64のみサポート
**成果物**:
```rust
pub enum PcodeOp {
    Copy, Load, Store,
    Branch, CBranch, BranchInd,
    Call, CallInd, Return,
    IntAdd, IntSub, IntMult, IntDiv,
    // ... 全74種類
}

pub struct Varnode {
    space: AddressSpace,  // Register/Memory/Const
    offset: u64,
    size: usize,
}
```

**メリット**:
- この段階で既に価値あり（P-code出力は解析に有用）
- 後続フェーズの土台

#### フェーズ2: SSA変換 + 基本ブロック（2-3週間）
**目標**: 制御フロー解析、SSA形式変換
**範囲**:
- 基本ブロック構築
- 支配木解析
- Phi-node挿入

**成果物**:
```rust
pub struct BasicBlock {
    ops: Vec<PcodeOp>,
    successors: Vec<BlockId>,
    predecessors: Vec<BlockId>,
}

pub struct ControlFlowGraph {
    blocks: Vec<BasicBlock>,
    entry: BlockId,
}
```

#### フェーズ3: 型推論 + 簡易最適化（3-4週間）
**目標**: 型情報の推論、基本的な最適化
**範囲**:
- データフロー解析
- 型推論エンジン
- 定数畳み込み、不要コード削除

**成果物**:
```rust
pub struct TypeEngine {
    // 型推論ロジック
}
```

#### フェーズ4: C言語出力（1-2週間）
**目標**: P-code → C疑似コード
**範囲**:
- if/while/for構造の検出
- C言語プリンター

**成果物**:
```rust
pub fn decompile_to_c(cfg: &ControlFlowGraph) -> String {
    // C言語出力
}
```

#### フェーズ5: AIフレンドリー拡張（1-2週間）
**目標**: LLM向け最適化
**範囲**:
- JSON出力フォーマット
- 意味的アノテーション
- 自然言語説明生成

**成果物**:
```rust
pub struct DecompilationResult {
    pcode: Vec<PcodeOp>,
    cfg: ControlFlowGraph,
    c_code: String,
    semantic_info: SemanticAnnotations,
    llm_friendly_desc: String,
}
```

---

## 6. 実装優先度マトリクス

| コンポーネント | 優先度 | 難易度 | 工数 | 価値 |
|--------------|-------|--------|------|------|
| P-code生成(x86) | ★★★★★ | ★★★☆☆ | 2-3週 | ★★★★★ |
| 基本ブロック構築 | ★★★★☆ | ★★☆☆☆ | 1週 | ★★★★☆ |
| SSA変換 | ★★★★☆ | ★★★☆☆ | 2週 | ★★★★★ |
| 型推論（基礎） | ★★★☆☆ | ★★★★☆ | 3週 | ★★★★☆ |
| C言語出力 | ★★★★★ | ★★☆☆☆ | 1-2週 | ★★★★★ |
| 最適化パス | ★★☆☆☆ | ★★★★★ | 4-8週 | ★★★☆☆ |
| SLEIGH対応 | ★☆☆☆☆ | ★★★★★ | 8週+ | ★★☆☆☆ |
| AIフレンドリー | ★★★★☆ | ★★☆☆☆ | 1-2週 | ★★★★★ |

---

## 7. 最小実装（MVP）の提案

### 目標
Ghidra Headless統合を維持しつつ、**x86-64専用の軽量デコンパイラ**を実装

### 範囲
- x86-64機械語 → P-code変換（手動実装、約2000行）
- 基本ブロック構築
- SSA変換（簡易版）
- C言語出力（シンプル版、複雑な構造は未対応）

### 期間
**4-6週間**

### メリット
1. **完全ネイティブ**: プロセス起動なし、0.1秒以下
2. **カスタマイズ可能**: AI向けに自由に改変可能
3. **学習価値**: デコンパイラの仕組みを完全理解
4. **段階的拡張**: 後からGhidraの最適化パスを移植可能

### デメリット
1. **品質**: 初期段階ではGhidraより低品質
2. **対応アーキ**: x86-64のみ（ARM等は後回し）
3. **開発コスト**: 短期的には工数がかかる

---

## 8. ハイブリッド戦略（推奨）

### 提案内容
1. **MVP実装**: 上記の最小実装を完成（4-6週間）
2. **Ghidra統合維持**: 高品質が必要な場合はGhidra Headless使用
3. **段階的置き換え**: MVPの品質向上に応じて徐々にGhidraから移行

### 実装例
```rust
pub enum DecompilerBackend {
    Native,          // 自作Rust実装（高速、中品質）
    GhidraHeadless,  // Ghidra連携（低速、高品質）
}

pub struct HybridDecompiler {
    native: NativeDecompiler,
    ghidra: Option<GhidraHeadless>,
}

impl HybridDecompiler {
    pub fn decompile(&self, binary: &[u8], addr: u64, quality: QualityLevel) -> Result<String> {
        match quality {
            QualityLevel::Fast => self.native.decompile(binary, addr),
            QualityLevel::High => {
                if let Some(ghidra) = &self.ghidra {
                    ghidra.decompile(binary, addr)
                } else {
                    self.native.decompile(binary, addr)
                }
            }
        }
    }
}
```

### メリット
- **短期**: Ghidraで高品質を維持
- **中期**: ネイティブ実装で高速化
- **長期**: 完全Rust移植でAIフレンドリー化

---

## 9. 次のアクション

### オプション1: MVP実装を開始
1. P-code定義をRustで実装
2. x86-64デコーダ作成
3. 基本ブロック構築
4. シンプルなC出力

**期間**: 4-6週間
**リスク**: 低（段階的にコミット可能）

### オプション2: プロトタイプ作成
1. P-code定義のみ実装（1週間）
2. 簡単な命令でテスト（`mov`, `add`, `jmp`程度）
3. フィージビリティ確認後に本格実装判断

**期間**: 1週間
**リスク**: 極低

### オプション3: 現状維持 + 調査継続
Ghidra Headless統合を継続し、将来的な移植のために調査を続ける

---

## 10. まとめ

### 実現可能性
**高い**。P-codeの仕様は明確で、基本的なデコンパイラは実装可能。

### 推奨戦略
**ハイブリッド戦略（オプション1）**:
1. MVP実装（4-6週間）
2. Ghidra統合維持
3. 段階的品質向上

### 期待される成果
- **ネイティブRust実装**: 超高速（<0.1秒）
- **AIフレンドリー**: LLM最適化された出力
- **拡張性**: 段階的にGhidraの機能を移植可能

### 次のステップ
ユーザーの判断：
- **プロトタイプ作成**（1週間）で実現可能性を体感
- **MVP実装開始**（4-6週間）で本格的なデコンパイラ構築
- **現状維持** + Ghidra Headless継続使用

---

調査完了。移植計画の詳細設計が完了しました。
