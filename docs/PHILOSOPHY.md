# Kensho MCP 設計哲学

**Philosophy Document v1.0**
**作成日**: 2025年12月17日

---

## 🎯 プロジェクトの存在意義

**このツールは人間のためのものではない。**

既存のリバースエンジニアリングツールは全て人間を前提に設計されている。
- GUI中心のインターフェース
- 「可読性の高い」C疑似コード
- 手動解析を支援する機能

**我々は違う道を行く。**

このプロジェクトは**AIエージェントが自律的にバイナリを解析するため**に存在する。
人間が読むことは想定していない。AIが理解できる正確な構造化データを提供する。

---

## 💀 Core Principles

### 1. AI-First, Not Human-First
**「可読性は豚にでも食わせておけ」**

```c
// 従来のデコンパイラ - 美しいが「推測」だらけ
void process_player(Player *player) {
    if (player->health > 0) {
        update_position(player);
    }
}
```

```json
// Kensho MCP - 醜いが「正確」
{
  "function": "0x140001000",
  "cfg": {
    "block_0": {
      "ops": [
        {"type": "Load", "dest": "unique_123", "src": "reg_rax+0x10"},
        {"type": "IntSLess", "dest": "unique_124", "op1": "const_0", "op2": "unique_123"}
      ],
      "successors": ["block_1", "block_2"]
    }
  },
  "confidence": {
    "control_flow": 1.0,
    "data_types": 0.3,
    "semantics": 0.0
  }
}
```

**哲学**: AIは`unique_123`を理解できる。重要なのはデータフローの正確性であり、変数名の美しさではない。

---

### 2. Truth Over Beauty
**「美しい嘘より、醜い真実」**

従来のデコンパイラは「もっともらしい推測」を提供する。
- 型が不明なら`void*`にする
- 関数の目的が不明なら`func_140001000`と命名
- 構造体が分からなければでっち上げる

**我々は嘘をつかない。**

```json
{
  "return_type": {
    "known": false,
    "inferred": "pointer",
    "confidence": 0.4
  },
  "note": "型情報不明。デバッグシンボルなし。"
}
```

**哲学**: 分からないものは「分からない」と明示する。AIは不確実性を扱える。

---

### 3. Speed is a Feature
**「2回目の解析は0.1msで返す」**

Ghidra Headlessの起動: 5-10秒
Kensho MCP: <100ms

キャッシュヒット時: **0.089ms**（実測値、247MBバイナリ）

```rust
// xxHash3ベースのキャッシュシステム
pub struct ParallelDecompiler {
    cache: HashMap<XXH3Hash, DecompileResult>,
    strategy: HashStrategy::Metadata,  // ~1ms
}
```

**哲学**: 速度は機能である。AIエージェントは何千回も解析を繰り返す。毎回5秒待てない。

---

### 4. Accuracy is Sacred
**「正確性は神聖不可侵」**

優先順位:
1. **正確性** - 間違った情報を返すくらいなら何も返すな
2. **速度** - 正確な情報を高速に返せ
3. **可読性** - どうでもいい

P-codeの74種類のOpcodeは全てGhidraの定義に厳密に従う。
独自拡張はしない。独自解釈もしない。

**哲学**: 正確性で妥協した瞬間、このツールは無価値になる。

---

### 5. x86-64 Specialization
**「ARM64は排除。x86-64に全てを賭ける」**

**なぜx86-64だけなのか？**

- PCゲームMod開発: 99% x86-64
- Windowsマルウェア解析: 99% x86-64
- サーバーアプリ解析: 99% x86-64

ARM64対応には膨大なリソースが必要：
- 完全に異なる命令セット
- 異なるABI（呼び出し規約）
- 異なるSIMD（NEON vs AVX）

**哲学**: 「何でも屋」は「何もできない奴」と同じ。x86-64で世界最高を目指す。

---

### 6. Neutrality with Responsibility
**「技術は中立。ただし他人に迷惑をかけるな」**

このツールは以下の用途を想定する:
- ✅ マルウェア解析（防御側）
- ✅ 脆弱性診断（セキュリティ研究）
- ✅ ゲームMod開発
- ✅ レガシーソフトウェアの理解
- ✅ チート開発（個人的趣味の範囲）
- ✅ DRM解析（学術研究）

規制はしない。使い手の良心に任せる。

**ただし、他人に迷惑をかけるな。**
- オンラインゲームでのチート利用 → 他のプレイヤーに迷惑
- マルウェア作成 → 社会に迷惑

**哲学**: 包丁は人を殺せるが、包丁自体は悪ではない。使い方の問題だ。

---

### 7. Automation is the Goal
**「最終目標はMod開発の完全自動化」**

```
従来:
人間 → Ghidra起動（5秒）→ 手動解析（数時間）→ 手動でコード書く

理想:
AI → Kensho MCP → 自動解析 → 自動Modコード生成
    (<100ms)              (数分)
```

ただし、**このプロジェクトは解析のみ**に徹する。

Mod生成・ビルド・インジェクションは**別のツール**の仕事。
我々は「最高の解析MCP」であればいい。

**哲学**: Unix哲学「一つのことをうまくやれ」。解析に特化する。

---

## 🏗️ アーキテクチャ哲学

### P-code至上主義

```
x86-64命令 → P-code → 解析パイプライン
              ↑
        普遍的な中間表現
```

P-codeはGhidraが10年以上かけて磨き上げた設計。
これを車輪の再発明せず、そのまま使う。

**理由**:
- アーキテクチャ非依存（将来の拡張性）
- 実績がある（Ghidraで検証済み）
- 最適化しやすい（SSA変換等）

---

### 階層的解析 - コンテキスト長への配慮

AIエージェントには**コンテキスト長の制限**がある。

```
Layer 1: get_binary_summary
  → 統計のみ（関数数、セクション数）
  → 数百バイト

Layer 2: list_functions, list_sections
  → ページネーション対応
  → 数KB単位

Layer 3: decompile_function_native
  → 詳細解析
  → 数十KB～数MB
```

**哲学**: 必要な情報を必要な粒度で提供する。最初から全部は返さない。

---

### 不確実性の定量化

全ての解析結果に**confidence score**を付与する。

```json
{
  "function": "0x140001000",
  "analysis": {
    "control_flow": {
      "confidence": 1.0,
      "note": "確定。分岐命令から構築"
    },
    "data_types": {
      "confidence": 0.65,
      "note": "推測。演算子からの型推論"
    },
    "function_purpose": {
      "confidence": 0.1,
      "note": "不明。デバッグシンボルなし"
    }
  }
}
```

**哲学**: AIは確率論的推論を扱える。「確実な情報」と「推測」を区別せよ。

---

## 📊 出力フォーマット設計

### C疑似コードの廃止

**従来の出力**:
```c
void function_140001000() {
    rax = rax + rbx;
    if (rax > 10) {
        return rax * 2;
    }
}
```

**新しい出力**:
```json
{
  "format_version": "1.0",
  "function": {
    "address": "0x140001000",
    "size": 245,
    "entry_point": "0x140001000",
    "exit_points": ["0x140001010", "0x140001018"]
  },
  "cfg": {
    "blocks": [
      {
        "id": 0,
        "address": "0x140001000",
        "ops": [
          {
            "opcode": "IntAdd",
            "output": {"space": "register", "offset": 0, "size": 8},
            "inputs": [
              {"space": "register", "offset": 0, "size": 8},
              {"space": "register", "offset": 24, "size": 8}
            ],
            "address": "0x140001000"
          }
        ],
        "successors": [1, 2],
        "predecessors": []
      }
    ],
    "entry_block": 0
  },
  "dataflow": {
    "def_use_chains": [
      {
        "definition": {"block": 0, "op": 0},
        "uses": [{"block": 1, "op": 2}]
      }
    ]
  },
  "metadata": {
    "optimizations_applied": ["RuleTermOrder", "RuleConstantFold"],
    "analysis_time_ms": 12.3,
    "cache_hit": false
  }
}
```

**理由**:
- 構造化データはAIが解析しやすい
- 複数の解析結果を統合可能
- 機械学習に直接投入可能

---

## 🚫 Anti-Patterns - やってはいけないこと

### 1. ❌ 人間に媚びるな
```c
// 悪い例
int playerHealth = ...;  // 推測で名前をつける
```

```json
// 良い例
{"varnode": "unique_123", "inferred_name": null}
```

---

### 2. ❌ 勝手に推測するな
```c
// 悪い例
void* mystery_func(void* a1) {  // 勝手にvoid*
    return a1;
}
```

```json
// 良い例
{
  "return_type": {"known": false},
  "parameters": [{"type": {"known": false}}]
}
```

---

### 3. ❌ 遅いAPIを作るな
```rust
// 悪い例
pub fn analyze_everything(binary: &[u8]) -> HugeResult {
    // 全部解析して返す（10秒かかる）
}

// 良い例
pub fn get_summary(binary: &[u8]) -> Summary {
    // 統計のみ（10msで返す）
}

pub fn decompile_function(addr: u64) -> FunctionAnalysis {
    // 必要な関数だけ（100msで返す）
}
```

---

### 4. ❌ マルチアーキテクチャの罠
```rust
// 悪い例
pub enum Architecture {
    X86_64,
    ARM64,
    MIPS,
    RISCV,
    // 全部対応！（でも全部中途半端）
}

// 良い例
// x86-64だけ。完璧に。
```

---

## 🎓 設計判断の指針

新機能を追加する際、以下の質問に答えよ：

### Q1: これはAIが使うか？
**NO** → 実装するな

### Q2: これは正確性を向上させるか？
**NO** → 優先度低い

### Q3: これは速度を犠牲にするか？
**YES** → キャッシュで補えるか？補えないなら再考

### Q4: これは複雑性を増すか？
**YES** → その価値はあるか？

### Q5: x86-64以外のアーキテクチャが必要か？
**YES** → 実装するな

---

## 📐 実装の美学

### コードは正直であれ

```rust
// 悪い例
fn get_function_name(&self, addr: u64) -> String {
    self.symbols.get(&addr)
        .cloned()
        .unwrap_or_else(|| format!("func_{:x}", addr))  // 嘘をつく
}

// 良い例
fn get_function_name(&self, addr: u64) -> Option<String> {
    self.symbols.get(&addr).cloned()  // 知らないことは知らないと言う
}
```

---

### パフォーマンスは測定せよ

```rust
// 悪い例
fn optimize_something(&self) {
    // たぶん速い...？
}

// 良い例
fn optimize_something(&self) {
    let start = Instant::now();
    // 処理
    let duration = start.elapsed();
    log::debug!("optimize_something: {:?}", duration);  // 実測
}
```

---

### 早期最適化は悪ではない

「早期最適化は諸悪の根源」はWebアプリの話。

解析エンジンでは:
- xxHash3を最初から使え
- キャッシュを最初から実装しろ
- メモリアロケーションを最初から考えろ

**哲学**: 後から最適化するのは10倍難しい。最初から速く作れ。

---

## 🌟 成功の定義

このプロジェクトは以下を満たせば成功:

### 1. ✅ AI単独でバイナリ解析が完了
人間の介入なしにModが作れる

### 2. ✅ キャッシュヒットで0.1ms
何千回呼ばれても高速

### 3. ✅ 正確性100%（制御フロー）
嘘をつかない

### 4. ✅ x86-64で世界最高レベル
中途半端なマルチアーキテクチャより、完璧なx86-64

### 5. ✅ 他のツールと統合可能
解析特化。Mod生成は別ツール。

---

## 🔮 将来の方向性

### Phase 1: 解析の完成 (現在)
- x86-64完全対応
- DWARF/PDB完全対応
- JSON出力フォーマット確立

### Phase 2: 動的解析統合 (将来)
- memscanとの統合API
- 静的+動的のハイブリッド解析

### Phase 3: エコシステム (究極)
```
Kensho MCP (解析)
    ↓
mod-generator-ai (生成)
    ↓
dll-injector (実行)
```

**ただし、このプロジェクトは「解析」のみに徹する。**

---

## 💬 引用集

プロジェクトの魂を表す言葉:

> **「可読性は豚にでも食わせておけ。重要なのは正確性だ。」**

> **「美しい嘘より、醜い真実。」**

> **「2回目の解析は0.1msで返す。これは贅沢ではなく必須。」**

> **「x86-64で世界最高を目指す。ARM64は別の誰かに任せろ。」**

> **「分からないものは分からないと言え。AIは不確実性を扱える。」**

> **「他人に迷惑をかけるな。それ以外は自由だ。」**

> **「一つのことをうまくやれ。解析に特化する。」**

---

## ✍️ 結語

このプロジェクトは**革命**である。

リバースエンジニアリングは長らく人間の職人芸だった。
Ghidraは素晴らしいが、GUIを前提とした設計は古い。

我々は**AIの時代**に生きている。

バイナリ解析もAIに任せられる時代が来た。
このツールはその最初の一歩だ。

**美しさではなく、正確性を。**
**汎用性ではなく、特化を。**
**推測ではなく、真実を。**

これがKensho MCPの生きる道だ。

---

**Document Version**: 1.0
**Last Updated**: 2025-12-17
**Status**: Living Document - プロジェクトと共に進化する

---

**著者より**:
> このドキュメントは、将来の開発者（人間であれAIであれ）がプロジェクトの方向性を見失わないためのコンパスである。技術的判断に迷ったら、このPHILOSOPHY.mdに立ち返れ。

**End of Philosophy Document**
