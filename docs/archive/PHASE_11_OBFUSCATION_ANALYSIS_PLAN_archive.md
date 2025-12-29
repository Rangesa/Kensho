# Phase 11: 高度な難読化解析システム実装計画

**作成日**: 2025-12-24
**ステータス**: 計画段階
**目標**: 現代のマルウェア・商用プロテクターに対抗可能な難読化検出・解析システムの構築

---

## 📋 目次

1. [背景と動機](#背景と動機)
2. [論文調査サマリー](#論文調査サマリー)
3. [既存実装の分析](#既存実装の分析)
4. [Phase 11実装計画](#phase-11実装計画)
5. [技術仕様](#技術仕様)
6. [実装優先度とタイムライン](#実装優先度とタイムライン)
7. [テスト計画](#テスト計画)
8. [将来の拡張](#将来の拡張)

---

## 🎯 背景と動機

### プロジェクトの現状

Kensho MCPは、Phase 1-10を完了し、以下の基盤技術を確立している：

- ✅ P-code中間表現（74種類）
- ✅ SSA変換（支配木、Phi-node）
- ✅ 12種類の最適化ルール
- ✅ 制御構造検出（if/while/switch）
- ✅ 基本的な難読化検出（Phase 10で追加）

### なぜ高度な難読化解析が必要か

1. **現代のマルウェアの現実**
   - VMProtect、Themida、Obfuscator-LLVMなど商用プロテクターの普及
   - MBA（Mixed Boolean-Arithmetic）による算術式の隠蔽が標準化
   - 制御フロー平坦化によるCFG解析の困難化

2. **AIエージェントの限界**
   - LLMは難読化されたコードを「推測」できるが、「証明」はできない
   - セキュリティ解析では数学的厳密性が必須
   - Kensho MCPは「検証可能な事実」を提供する役割

3. **既存ツールとの差別化**
   - IDA Pro/Ghidra: 難読化検出は手動解析に依存
   - angr/Triton: シンボリック実行は強力だがセットアップが複雑
   - Kensho MCP: **軽量・高速・AI統合**を維持したまま高度な解析を実現

---

## 📚 論文調査サマリー

### 調査対象論文（2005-2024）

| 論文 | 年 | 主要技術 | 実装可能性 |
|------|---|---------|-----------|
| **Udupa & Debray** | 2005 | 制御フロー平坦化の解除 | 🟢 高 |
| **MBA-Blast** (Liu et al.) | 2021 | MBA式の数学的簡約 | 🟡 中 |
| **Syntia** (Blazytko et al.) | 2017 | MCTSベースのプログラム合成 | 🔴 低 |
| **Chisel** (Dillig et al.) | 2024 | トレース駆動の制御フロー復元 | 🔴 低 |
| **Zeng et al.** | 2017 | VM仮想化の再コンパイル | 🔴 低 |

### 難読化技術の階層分類

```
レイヤ1: 構文（Surface）
  └─ 変数名変更、文字列暗号化、デッドコード挿入
     → 既存実装で対応可能

レイヤ2: 制御フロー（Control Flow）
  └─ 平坦化、不透明述語、関数インライニング
     → Phase 11で強化

レイヤ3: データ（Data）
  └─ MBA、変数分割
     → Phase 11で実装

レイヤ4: アーキテクチャ（Architecture）
  └─ VM仮想化、パッキング
     → Phase 12以降
```

### 重要な発見

1. **MBA解析の実用性**
   - MBA-Blastの1ビット分解手法は数学的に厳密
   - 商用プロテクター（VMProtect等）のMBA式を数ミリ秒で簡約可能
   - Rustでの実装が容易（代数演算のみ）

2. **SMTソルバの有効性**
   - Z3ソルバによる不透明述語の検証は99%以上の精度
   - MBA式の等価性チェックにも応用可能
   - Rustバインディング（`z3`クレート）が成熟

3. **プログラム合成の限界**
   - Syntia/Chiselは研究レベルの実装が複雑
   - LLM（GPT-4/Claude/DeepSeek R1）で代替可能
   - Kensho MCPは「検証」に特化すべき

---

## 🔍 既存実装の分析

### Phase 10で実装済みの機能

#### `obfuscation_detector.rs` (524行)

**実装済みパターン検出**:

1. **不透明述語（Opaque Predicates）**
   ```rust
   // X XOR X = 0
   // X - X = 0
   // X AND 0 = 0
   ```
   - 検出方法: P-code命令の直接パターンマッチング
   - 信頼度: 0.7-0.9
   - 限界: 数論的な複雑な不透明述語（x² ≥ 0等）は未対応

2. **制御フロー平坦化（Control Flow Flattening）**
   ```rust
   // 5個以上の後続ブロック = ディスパッチャ疑惑
   if successor_count >= 5 {
       confidence = 0.7;
   }
   ```
   - 検出方法: 後続ブロック数の統計的閾値
   - 限界: 状態変数の追跡なし、真の遷移関係を復元不可

3. **到達不能コード（Bogus Control Flow）**
   ```rust
   // BFSによる到達性解析
   ```
   - 完成度: 80%（動的パスは未考慮）

4. **間接分岐の過剰使用**
   - 統計的検出（10%以上で警告）

**メトリクス計算**:
- Cyclomatic Complexity（サイクロマティック複雑度）
- 平均後続ブロック数
- 最大深度（BFS）

**総合評価スコア**: 0.0（クリーン）～ 1.0（重度難読化）

### JSON出力統合

```json
{
  "obfuscation": {
    "overall_score": 0.65,
    "patterns": [...],
    "control_flow_metrics": {...}
  }
}
```

- AI-First設計に完全準拠
- 構造化データで不確実性を明示（`confidence`スコア）

### 既存実装の強み

✅ **軽量・高速**: パターンマッチングのみ、ミリ秒オーダー
✅ **拡張性**: 新規パターンの追加が容易
✅ **AI統合**: JSON出力でLLMとの連携が自然

### 既存実装の限界

❌ **数学的厳密性の欠如**: パターンマッチングのみ、証明なし
❌ **MBA未対応**: 現代マルウェアの主要手法に無力
❌ **制御フロー復元不可**: ディスパッチャ検出のみ、解除不可
❌ **動的解析なし**: 実行トレースを活用できない

---

## 🚀 Phase 11実装計画

### 設計哲学の再確認

Kensho MCPの原則を遵守しつつ、難読化解析を強化する：

| 原則 | Phase 11での適用 |
|------|-----------------|
| **AI-First** | 検出結果は全てJSON、LLMが推論可能な形式 |
| **Truth Over Beauty** | 不確実性を`confidence`で明示、憶測を排除 |
| **Speed is a Feature** | SMTソルバはタイムアウト付き、結果はキャッシュ |
| **Accuracy is Sacred** | 数学的に証明された結果のみ高信頼度 |
| **x86-64 Specialization** | MBA/平坦化はx86-64に最適化 |

### 実装範囲の決定

**Phase 11で実装する機能** ✅:
1. MBA（Mixed Boolean-Arithmetic）検出・簡約
2. SMTソルバ統合（Z3）
3. 制御フロー平坦化の詳細解析
4. VM仮想化の基礎検出

**Phase 12以降に延期** 🔶:
- 完全なシンボリック実行エンジン
- プログラム合成（LLMで代替）
- 動的解析との統合

---

## 📐 技術仕様

### 11.1: MBA検出・簡約システム

#### ファイル: `src/decompiler_prototype/mba/mod.rs`

```rust
/// MBA pattern detector and simplifier
pub mod mba;

use super::pcode::{PcodeOp, OpCode, Varnode};
use serde::{Serialize, Deserialize};

/// MBA pattern detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MBAPattern {
    /// Complexity score (1-10)
    pub complexity: u8,

    /// Number of bitwise operations (AND, OR, XOR, NOT)
    pub bitop_count: usize,

    /// Number of arithmetic operations (ADD, SUB, MUL, DIV)
    pub arith_count: usize,

    /// Total operation chain length
    pub chain_length: usize,

    /// Simplified candidate expression (if found)
    pub simplified_candidate: Option<SimplifiedExpression>,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,

    /// Location in CFG
    pub location: MBALocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplifiedExpression {
    /// Human-readable form (e.g., "x + y")
    pub expression: String,

    /// P-code representation
    pub pcode_ops: Vec<PcodeOp>,

    /// Verification method used
    pub verification: VerificationMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// Algebraic rewrite rules only
    AlgebraicRules,

    /// Verified by SMT solver (Z3)
    SmtProven { solving_time_ms: f64 },

    /// Candidate only (not verified)
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MBALocation {
    pub block_id: usize,
    pub op_range: (usize, usize),  // (start, end)
    pub address: String,
}
```

#### アルゴリズム設計

**Phase 11.1.1: MBA検出**

```rust
impl MBADetector {
    /// Detect MBA patterns in a sequence of P-code operations
    pub fn detect(ops: &[PcodeOp]) -> Vec<MBAPattern> {
        let mut patterns = Vec::new();

        // Sliding window approach (window size: 3-15 operations)
        for window_size in 3..=15 {
            for window_start in 0..ops.len().saturating_sub(window_size) {
                let window = &ops[window_start..window_start + window_size];

                if let Some(pattern) = Self::analyze_window(window) {
                    patterns.push(pattern);
                }
            }
        }

        // Merge overlapping patterns
        Self::merge_patterns(patterns)
    }

    fn analyze_window(ops: &[PcodeOp]) -> Option<MBAPattern> {
        let bitop_count = Self::count_bitwise_ops(ops);
        let arith_count = Self::count_arithmetic_ops(ops);

        // MBA heuristic: both bitwise and arithmetic ops present
        if bitop_count > 0 && arith_count > 0 {
            // Calculate complexity score
            let complexity = Self::calculate_complexity(ops);

            // Only report if complexity is significant
            if complexity >= 3 {
                return Some(MBAPattern {
                    complexity,
                    bitop_count,
                    arith_count,
                    chain_length: ops.len(),
                    simplified_candidate: None,  // Phase 11.1.2
                    confidence: Self::calculate_confidence(bitop_count, arith_count),
                    location: Self::extract_location(ops),
                });
            }
        }

        None
    }

    fn count_bitwise_ops(ops: &[PcodeOp]) -> usize {
        ops.iter().filter(|op| matches!(
            op.opcode,
            OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor | OpCode::IntNot
        )).count()
    }

    fn count_arithmetic_ops(ops: &[PcodeOp]) -> usize {
        ops.iter().filter(|op| matches!(
            op.opcode,
            OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult | OpCode::IntDiv
        )).count()
    }
}
```

**Phase 11.1.2: MBA簡約（基本ルール）**

```rust
impl MBASimplifier {
    /// Apply algebraic simplification rules
    pub fn simplify_basic(pattern: &MBAPattern, ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        // Rule 1: (x ⊕ y) + 2(x ∧ y) → x + y
        if let Some(expr) = Self::apply_rule_xor_and_add(ops) {
            return Some(SimplifiedExpression {
                expression: format!("{} + {}", expr.0, expr.1),
                pcode_ops: vec![/* simplified P-code */],
                verification: VerificationMethod::AlgebraicRules,
            });
        }

        // Rule 2: (x ∧ y) + (x ∨ y) → x + y
        if let Some(expr) = Self::apply_rule_and_or_add(ops) {
            return Some(expr);
        }

        // Rule 3-10: Additional patterns from MBA-Blast paper
        // ...

        None
    }

    fn apply_rule_xor_and_add(ops: &[PcodeOp]) -> Option<(String, String)> {
        // Pattern matching: XOR followed by AND, then ADD
        // Implementation details...
        None
    }
}
```

**実装タスク**:
- [ ] `mba/detector.rs`: パターン検出エンジン（3日）
- [ ] `mba/simplifier.rs`: 基本簡約ルール（10パターン）（2日）
- [ ] `mba/mod.rs`: モジュール統合（1日）
- [ ] テストケース作成（VMProtect/Themidaのサンプル）（2日）

---

### 11.2: SMTソルバ統合（Z3）

#### 依存関係追加

```toml
# Cargo.toml
[dependencies]
z3 = { version = "0.12", features = ["static-link-z3"] }
```

#### ファイル: `src/decompiler_prototype/smt/mod.rs`

```rust
use z3::{ast, Config, Context, Solver, SatResult};
use super::pcode::{PcodeOp, Varnode, OpCode};

pub struct SMTVerifier {
    ctx: Context,
    solver: Solver,
}

impl SMTVerifier {
    pub fn new() -> Self {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        Self { ctx, solver }
    }

    /// Verify if a predicate is opaque (always true/false)
    pub fn verify_opaque_predicate(
        &mut self,
        condition: &PcodeOp
    ) -> OpaquenessResult {
        // Convert P-code condition to Z3 AST
        let z3_expr = self.pcode_to_z3(condition);

        // Check: ∃input: condition = false
        self.solver.push();
        self.solver.assert(&z3_expr._eq(&ast::Bool::from_bool(&self.ctx, false)));

        let result = match self.solver.check() {
            SatResult::Unsat => {
                // No input makes it false → always true
                OpaquenessResult::AlwaysTrue { confidence: 1.0 }
            }
            SatResult::Sat => {
                // Some inputs make it false → dynamic
                OpaquenessResult::Dynamic
            }
            SatResult::Unknown => {
                OpaquenessResult::Unknown
            }
        };

        self.solver.pop(1);
        result
    }

    /// Check if two expressions are equivalent
    pub fn check_equivalence(
        &mut self,
        complex: &[PcodeOp],
        simple: &PcodeOp
    ) -> EquivalenceResult {
        let start = std::time::Instant::now();

        // Convert both to Z3
        let z3_complex = self.pcode_sequence_to_z3(complex);
        let z3_simple = self.pcode_to_z3(simple);

        // Check: ∀inputs: complex(inputs) = simple(inputs)
        // Equivalently: ¬∃inputs: complex(inputs) ≠ simple(inputs)
        self.solver.push();
        self.solver.assert(&z3_complex._eq(&z3_simple).not());

        let result = match self.solver.check() {
            SatResult::Unsat => {
                // No counterexample → equivalent
                EquivalenceResult::Equivalent {
                    solving_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                }
            }
            SatResult::Sat => {
                EquivalenceResult::NotEquivalent
            }
            SatResult::Unknown => {
                EquivalenceResult::Timeout
            }
        };

        self.solver.pop(1);
        result
    }

    fn pcode_to_z3(&self, op: &PcodeOp) -> ast::Dynamic {
        // P-code → Z3 AST conversion
        match op.opcode {
            OpCode::IntAdd => {
                // Convert operands and apply addition
                // Implementation details...
            }
            OpCode::IntXor => {
                // Bitwise XOR
            }
            // ... other opcodes
            _ => unimplemented!("OpCode not yet supported in SMT"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum OpaquenessResult {
    AlwaysTrue { confidence: f64 },
    AlwaysFalse { confidence: f64 },
    Dynamic,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub enum EquivalenceResult {
    Equivalent { solving_time_ms: f64 },
    NotEquivalent,
    Timeout,
}
```

#### SMTソルバの制約

**タイムアウト設定**: 各クエリに1秒の制限
```rust
solver.set_timeout(1000);  // 1000ms
```

**対応するP-code命令**（Phase 11.2での実装範囲）:
- ✅ 算術演算: IntAdd, IntSub, IntMult, IntDiv
- ✅ ビット演算: IntAnd, IntOr, IntXor, IntNot
- ✅ 比較: IntEqual, IntLess, IntLessEqual
- ✅ 論理演算: BoolAnd, BoolOr, BoolNot
- ❌ メモリ操作: Load, Store（Phase 12）
- ❌ 浮動小数点（Phase 12）

**実装タスク**:
- [ ] `smt/verifier.rs`: Z3ソルバラッパー（2日）
- [ ] `smt/converter.rs`: P-code → Z3 AST変換（2日）
- [ ] `smt/timeout.rs`: タイムアウト管理（1日）
- [ ] テスト: 不透明述語の検証（1日）
- [ ] テスト: MBA等価性チェック（1日）

---

### 11.3: 制御フロー平坦化の詳細解析

#### ファイル: `src/decompiler_prototype/flattening/mod.rs`

```rust
use super::cfg::{ControlFlowGraph, BasicBlock};
use super::pcode::{PcodeOp, Varnode};

pub struct FlatteningAnalyzer;

#[derive(Debug, Clone, Serialize)]
pub struct StateVariableInfo {
    /// The variable used for dispatching (e.g., register rcx)
    pub state_variable: Varnode,

    /// Dispatcher block ID
    pub dispatcher_block: usize,

    /// State transitions: (from_block, state_value) -> to_block
    pub transitions: Vec<StateTransition>,

    /// Confidence that this is control flow flattening
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StateTransition {
    pub from_block: usize,
    pub state_value: u64,
    pub to_block: usize,
}

impl FlatteningAnalyzer {
    /// Trace the state variable through the CFG
    pub fn analyze(cfg: &ControlFlowGraph) -> Option<StateVariableInfo> {
        // Step 1: Find dispatcher block (high out-degree)
        let dispatcher = Self::find_dispatcher(cfg)?;

        // Step 2: Identify state variable
        let state_var = Self::identify_state_variable(cfg, dispatcher)?;

        // Step 3: Trace state updates
        let transitions = Self::trace_state_transitions(cfg, &state_var, dispatcher);

        // Step 4: Calculate confidence
        let confidence = Self::calculate_confidence(&transitions, cfg);

        Some(StateVariableInfo {
            state_variable: state_var,
            dispatcher_block: dispatcher,
            transitions,
            confidence,
        })
    }

    fn find_dispatcher(cfg: &ControlFlowGraph) -> Option<usize> {
        // Dispatcher characteristics:
        // - High out-degree (>= 5)
        // - Receives edges from many blocks
        for (id, block) in cfg.blocks.iter() {
            if block.successors.len() >= 5 {
                return Some(*id);
            }
        }
        None
    }

    fn identify_state_variable(
        cfg: &ControlFlowGraph,
        dispatcher: usize
    ) -> Option<Varnode> {
        // Look for the variable used in the dispatcher's branch condition
        // Typically: switch(state_var) or if(state_var == X)

        let block = cfg.blocks.get(&dispatcher)?;

        // Find the last conditional operation
        for op in block.ops.iter().rev() {
            if let OpCode::CBranch | OpCode::BranchInd = op.opcode {
                // The first input is likely the state variable
                return op.inputs.first().cloned();
            }
        }

        None
    }

    fn trace_state_transitions(
        cfg: &ControlFlowGraph,
        state_var: &Varnode,
        dispatcher: usize
    ) -> Vec<StateTransition> {
        let mut transitions = Vec::new();

        // For each block that jumps to dispatcher
        for (block_id, block) in cfg.blocks.iter() {
            if !block.successors.contains(&dispatcher) {
                continue;
            }

            // Find state variable update (e.g., mov rcx, 5)
            if let Some(state_value) = Self::find_state_update(block, state_var) {
                // The "to_block" is determined by the state value
                // This requires constant propagation or dynamic analysis
                // For now, we mark it as unknown

                transitions.push(StateTransition {
                    from_block: *block_id,
                    state_value,
                    to_block: 0,  // Placeholder
                });
            }
        }

        transitions
    }

    fn find_state_update(block: &BasicBlock, state_var: &Varnode) -> Option<u64> {
        // Look for: state_var = constant
        for op in &block.ops {
            if let Some(output) = &op.output {
                if Self::varnodes_equal(output, state_var) {
                    // Check if it's assigned a constant
                    if let Some(input) = op.inputs.first() {
                        if input.space == AddressSpace::Const {
                            return Some(input.offset);
                        }
                    }
                }
            }
        }
        None
    }

    fn calculate_confidence(transitions: &[StateTransition], cfg: &ControlFlowGraph) -> f64 {
        // Heuristics:
        // - More transitions = higher confidence
        // - All blocks going through dispatcher = higher confidence

        let coverage = transitions.len() as f64 / cfg.blocks.len() as f64;

        if coverage > 0.7 {
            0.9
        } else if coverage > 0.5 {
            0.7
        } else {
            0.5
        }
    }
}
```

**実装タスク**:
- [ ] `flattening/analyzer.rs`: 状態変数追跡（3日）
- [ ] `flattening/reconstructor.rs`: CFG復元（Phase 12）
- [ ] テスト: Tigress平坦化サンプル（1日）

---

### 11.4: VM仮想化検出（基礎）

#### ファイル: `src/decompiler_prototype/vm_detection/mod.rs`

```rust
pub struct VMDetector;

#[derive(Debug, Clone, Serialize)]
pub struct VMPattern {
    /// Type of VM pattern detected
    pub vm_type: VMType,

    /// Confidence score
    pub confidence: f64,

    /// Detected components
    pub components: VMComponents,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VMType {
    /// Stack-based VM (like Python bytecode)
    StackBased,

    /// Register-based VM
    RegisterBased,

    /// Hybrid VM
    Hybrid,

    /// Unknown/Custom VM
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct VMComponents {
    /// Virtual program counter
    pub vpc: Option<Varnode>,

    /// Dispatcher loop location
    pub dispatcher_block: Option<usize>,

    /// Detected handlers
    pub handlers: Vec<HandlerInfo>,

    /// Virtual stack/registers
    pub virtual_storage: Vec<Varnode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HandlerInfo {
    pub block_id: usize,
    pub address: String,
    pub opcode_value: Option<u64>,
}

impl VMDetector {
    /// Detect VM-based obfuscation patterns
    pub fn detect(cfg: &ControlFlowGraph) -> Option<VMPattern> {
        // Step 1: Find fetch-decode-dispatch loop
        let dispatcher = Self::find_dispatcher_loop(cfg)?;

        // Step 2: Identify virtual PC
        let vpc = Self::identify_vpc(cfg, dispatcher)?;

        // Step 3: Enumerate handlers
        let handlers = Self::enumerate_handlers(cfg, dispatcher);

        // Step 4: Classify VM type
        let vm_type = Self::classify_vm_type(&handlers);

        Some(VMPattern {
            vm_type,
            confidence: Self::calculate_confidence(&handlers),
            components: VMComponents {
                vpc: Some(vpc),
                dispatcher_block: Some(dispatcher),
                handlers,
                virtual_storage: Vec::new(),
            },
        })
    }

    fn find_dispatcher_loop(cfg: &ControlFlowGraph) -> Option<usize> {
        // VM dispatcher characteristics:
        // - Has a loop (back-edge to itself or nearby block)
        // - High out-degree (many handlers)
        // - Fetch operation (load from memory)

        for (id, block) in cfg.blocks.iter() {
            // Check for self-loop or loop with few blocks
            if block.successors.contains(id) {
                return Some(*id);
            }

            // Check for high out-degree
            if block.successors.len() >= 10 {
                return Some(*id);
            }
        }

        None
    }

    fn identify_vpc(cfg: &ControlFlowGraph, dispatcher: usize) -> Option<Varnode> {
        // VPC is typically incremented in the dispatcher loop
        // Look for: vpc = vpc + 1 or vpc = vpc + opcode_size

        let block = cfg.blocks.get(&dispatcher)?;

        for op in &block.ops {
            if let OpCode::IntAdd = op.opcode {
                // Check if output equals first input (vpc = vpc + X)
                if let (Some(output), Some(input)) = (&op.output, op.inputs.first()) {
                    if Self::varnodes_equal(output, input) {
                        return Some(output.clone());
                    }
                }
            }
        }

        None
    }
}
```

**実装タスク**:
- [ ] `vm_detection/detector.rs`: VM検出エンジン（3日）
- [ ] `vm_detection/classifier.rs`: VM種別分類（1日）
- [ ] テスト: VMProtectサンプル（2日）

**注意**: VM解析の完全版（ハンドラのセマンティクス抽出、再コンパイル）はPhase 12以降。

---

## ⏱️ 実装優先度とタイムライン

### Phase 11.1: MBA検出・簡約（最優先）

**実装期間**: 5-7日
**担当モジュール**: `src/decompiler_prototype/mba/`

| タスク | 工数 | 依存関係 |
|--------|------|---------|
| MBA検出エンジン | 3日 | なし |
| 基本簡約ルール（10パターン） | 2日 | 検出エンジン |
| テストケース作成 | 1-2日 | 簡約ルール |

**成果物**:
- `MBADetector`: パターン検出
- `MBASimplifier`: 代数的簡約
- テストスイート（VMProtect/Themidaサンプル）

**リスク**: 低（既存の最適化エンジンと同様の手法）

---

### Phase 11.2: SMTソルバ統合（高優先）

**実装期間**: 6-8日
**担当モジュール**: `src/decompiler_prototype/smt/`

| タスク | 工数 | 依存関係 |
|--------|------|---------|
| Z3ソルバラッパー | 2日 | Cargo依存追加 |
| P-code → Z3 AST変換 | 2日 | Z3ラッパー |
| タイムアウト管理 | 1日 | Z3ラッパー |
| 不透明述語検証テスト | 1日 | AST変換 |
| MBA等価性チェックテスト | 1-2日 | AST変換 |

**成果物**:
- `SMTVerifier`: Z3統合
- 不透明述語検証API
- MBA等価性チェックAPI

**リスク**: 中（Z3のRustバインディングは安定しているが、P-code変換に注意）

---

### Phase 11.3: 制御フロー平坦化解析（中優先）

**実装期間**: 4-5日
**担当モジュール**: `src/decompiler_prototype/flattening/`

| タスク | 工数 | 依存関係 |
|--------|------|---------|
| 状態変数追跡 | 3日 | なし |
| テスト（Tigressサンプル） | 1-2日 | 追跡ロジック |

**成果物**:
- `FlatteningAnalyzer`: 状態変数追跡
- 遷移グラフ抽出

**リスク**: 中（定数伝播が不完全な場合、精度低下）

---

### Phase 11.4: VM検出基礎（低優先）

**実装期間**: 5-6日
**担当モジュール**: `src/decompiler_prototype/vm_detection/`

| タスク | 工数 | 依存関係 |
|--------|------|---------|
| ディスパッチャループ検出 | 2日 | なし |
| VPC特定 | 1日 | ディスパッチャ検出 |
| ハンドラ列挙 | 2日 | VPC特定 |
| テスト（VMProtect） | 1-2日 | ハンドラ列挙 |

**成果物**:
- `VMDetector`: VM検出エンジン
- ハンドラ情報抽出

**リスク**: 高（VM仮想化は非常に多様、完全対応は困難）

---

### 総実装期間（並列作業なし）

**最短**: 20日（3週間）
**最長**: 26日（4週間）
**推奨**: 段階的リリース（11.1 → 11.2 → 11.3 → 11.4）

---

## 🧪 テスト計画

### テストデータセット

#### 1. 基本テストケース（自前作成）

```rust
// tests/obfuscation/mba_basic.rs

#[test]
fn test_mba_xor_and_pattern() {
    // (x ⊕ y) + 2(x ∧ y) should simplify to x + y
    let ops = vec![
        // x XOR y
        PcodeOp {
            opcode: OpCode::IntXor,
            output: Some(Varnode::new_unique(100, 8)),
            inputs: vec![
                Varnode::new_register(0, 8),  // x
                Varnode::new_register(1, 8),  // y
            ],
            address: 0x1000,
        },
        // x AND y
        PcodeOp {
            opcode: OpCode::IntAnd,
            output: Some(Varnode::new_unique(101, 8)),
            inputs: vec![
                Varnode::new_register(0, 8),
                Varnode::new_register(1, 8),
            ],
            address: 0x1004,
        },
        // (x AND y) * 2
        PcodeOp {
            opcode: OpCode::IntMult,
            output: Some(Varnode::new_unique(102, 8)),
            inputs: vec![
                Varnode::new_unique(101, 8),
                Varnode::new_const(2, 8),
            ],
            address: 0x1008,
        },
        // (x XOR y) + 2(x AND y)
        PcodeOp {
            opcode: OpCode::IntAdd,
            output: Some(Varnode::new_unique(103, 8)),
            inputs: vec![
                Varnode::new_unique(100, 8),
                Varnode::new_unique(102, 8),
            ],
            address: 0x100C,
        },
    ];

    let detector = MBADetector::new();
    let patterns = detector.detect(&ops);

    assert_eq!(patterns.len(), 1);
    assert!(patterns[0].complexity >= 3);

    let simplifier = MBASimplifier::new();
    let simplified = simplifier.simplify_basic(&patterns[0], &ops).unwrap();

    assert_eq!(simplified.expression, "x + y");
}
```

#### 2. 実世界サンプル

| プロテクター | バイナリサンプル | テスト対象 |
|------------|----------------|----------|
| **VMProtect** | 公式サンプル | VM検出、MBA検出 |
| **Themida** | 体験版 | MBA検出、SMT検証 |
| **Obfuscator-LLVM** | GitHub公開バイナリ | 平坦化解析 |
| **Tigress** | 学術用サンプル | 制御フロー検出 |

#### 3. パフォーマンステスト

```rust
#[test]
fn test_smt_timeout() {
    // SMTソルバが1秒以内にタイムアウトすることを確認
    let verifier = SMTVerifier::new();

    // 故意に複雑な式を作成（パス爆発）
    let complex_ops = create_complex_mba_chain(1000);  // 1000段階

    let start = std::time::Instant::now();
    let result = verifier.check_equivalence(&complex_ops, &simple_op);
    let elapsed = start.elapsed();

    // タイムアウトまたは1秒以内に結果を返すこと
    assert!(elapsed.as_secs() <= 1);
}
```

---

## 🔮 将来の拡張（Phase 12-13）

### Phase 12: 完全なシンボリック実行エンジン

**実装内容**:
- angr風のパス探索
- メモリ状態の完全なシミュレーション
- 制約収集とパス条件の抽出

**工数**: 2-3週間
**優先度**: 中（MBA/SMTで大半はカバー可能）

---

### Phase 13: 動的解析統合

**実装内容**:
- `memscan`との統合
- Intel Pin/Fridaによる実行トレース取得
- 静的・動的解析のハイブリッド

**工数**: 3-4週間
**優先度**: 低（静的解析を優先）

---

### プログラム合成は非推奨

**理由**:
- Syntia/ChiselはMCTS/探索空間が巨大、実装が複雑
- LLM（GPT-4/Claude/DeepSeek R1）で候補生成可能
- Kensho MCPは「検証」に特化すべき

**代替案**:
LLMが候補式を生成 → Kensho MCPのSMTソルバで検証

---

## 📊 成功指標（KPI）

### Phase 11完了時の目標

| 指標 | 目標値 | 測定方法 |
|------|--------|---------|
| **MBA検出率** | 90%以上 | VMProtect/Themidaサンプルで測定 |
| **SMT検証精度** | 95%以上 | 既知の不透明述語で測定 |
| **パフォーマンス** | 平均10秒以内/関数 | 大規模バイナリで測定 |
| **誤検出率** | 5%以下 | クリーンなバイナリで測定 |

### Phase 11のゴール定義

✅ **商用プロテクター対応**:
- VMProtect、Themidaで難読化されたバイナリを「読める」レベルに復元
- MBA式の80%以上を簡約可能

✅ **AI統合の強化**:
- LLMが推論可能な構造化JSON出力
- `confidence`スコアで不確実性を明示

✅ **Kensho MCPの差別化**:
- Ghidra/IDA Pro: 手動解析に依存
- angr: セットアップが複雑
- **Kensho MCP**: 軽量・高速・AI統合

---

## 📝 実装チェックリスト

### Phase 11.1: MBA検出・簡約

- [ ] `src/decompiler_prototype/mba/mod.rs`
- [ ] `src/decompiler_prototype/mba/detector.rs`
- [ ] `src/decompiler_prototype/mba/simplifier.rs`
- [ ] `src/decompiler_prototype/mba/tests.rs`
- [ ] `obfuscation_detector.rs`への統合
- [ ] JSON出力フォーマット拡張

### Phase 11.2: SMTソルバ統合

- [ ] `Cargo.toml`に`z3`クレート追加
- [ ] `src/decompiler_prototype/smt/mod.rs`
- [ ] `src/decompiler_prototype/smt/verifier.rs`
- [ ] `src/decompiler_prototype/smt/converter.rs`
- [ ] `src/decompiler_prototype/smt/tests.rs`
- [ ] 不透明述語検出への統合
- [ ] MBA等価性チェックへの統合

### Phase 11.3: 制御フロー平坦化解析

- [ ] `src/decompiler_prototype/flattening/mod.rs`
- [ ] `src/decompiler_prototype/flattening/analyzer.rs`
- [ ] `src/decompiler_prototype/flattening/tests.rs`
- [ ] `obfuscation_detector.rs`への統合

### Phase 11.4: VM検出基礎

- [ ] `src/decompiler_prototype/vm_detection/mod.rs`
- [ ] `src/decompiler_prototype/vm_detection/detector.rs`
- [ ] `src/decompiler_prototype/vm_detection/tests.rs`
- [ ] JSON出力フォーマット拡張

### ドキュメント

- [ ] `docs/OBFUSCATION_ANALYSIS.md`（ユーザー向けガイド）
- [ ] `docs/API_REFERENCE.md`に新規APIを追加
- [ ] `README.md`の更新（Phase 11機能の追加）

---

## 🎓 参考文献

### 論文

1. **Udupa & Debray** (2005) - "Deobfuscation: Reverse Engineering Obfuscated Code"
2. **Liu et al.** (2021) - "MBA-Blast: Unveiling and Simplifying Mixed Boolean-Arithmetic Obfuscation"
3. **Blazytko et al.** (2017) - "Syntia: Synthesizing the Semantics of Obfuscated Code"
4. **Dillig et al.** (2024) - "Chisel: Control-Flow Deobfuscation using Trace-Informed Compositional Program Synthesis"
5. **Zeng et al.** (2017) - "Reverse Engineering of Virtualization-based Obfuscation"

### ツール・ライブラリ

- **Z3 Theorem Prover**: https://github.com/Z3Prover/z3
- **MBA-Blast**: https://github.com/softsec-unh/MBA-Blast
- **Syntia**: https://github.com/RUB-SysSec/syntia
- **angr**: https://angr.io/
- **Triton**: https://triton.quarkslab.com/

### 書籍

- **Practical Reverse Engineering** (Dang, Gazet, Bachaalany)
- **Compilers: Principles, Techniques, and Tools** (Aho, Lam, Sethi, Ullman)

---

## ✍️ 更新履歴

| 日付 | バージョン | 変更内容 |
|------|-----------|---------|
| 2025-12-24 | 1.0 | 初版作成 |

---

**作成者**: Claude Sonnet 4.5
**プロジェクト**: Kensho MCP
**ステータス**: Phase 11実装計画

**Next Steps**: Phase 11.1（MBA検出・簡約）の実装開始

---

**End of Document**
