# Kensho MCP 🦀

**Rust製の超軽量・高速バイナリ解析MCPサーバー**

GhidraのコアロジックをRustでネイティブ実装し、AIエージェント（Claude Code等）専用に最適化したModel Context Protocol (MCP) サーバーです。

## 🎯 特徴

- **⚡ 超高速起動**: Ghidra Headlessの数秒に対し、ミリ秒オーダーで起動
- **🪶 軽量**: JVM不要、単一バイナリで動作（数MB程度）
- **🔧 Ghidra非依存**: 完全ネイティブ実装、外部依存なし
- **🤖 AIフレンドリー**: Claude Codeなどのエージェントから簡単に利用可能
- **🔒 メモリセーフ**: Rustによる安全な実装
- **💾 高速キャッシュ**: xxHash3ベースのキャッシュシステム（最大1000倍高速化）

## 💭 プロジェクト哲学

**このツールは人間のためのものではない。AIエージェントのために設計されている。**

詳細な設計思想は [PHILOSOPHY.md](PHILOSOPHY.md) を参照。

### Core Principles

1. **AI-First, Not Human-First** - 可読性より正確性
2. **Truth Over Beauty** - 美しい嘘より醜い真実
3. **x86-64 Specialization** - ARM64は排除、x86-64に全てを賭ける
4. **JSON Structured Output** - C疑似コードではなく構造化データ
5. **Analysis Tool Only** - Mod生成等は別ツールの責務

## 📦 技術スタック

- **goblin**: ELF/PE/Mach-Oパーサー（超高速）
- **capstone**: マルチアーキテクチャ逆アセンブラ
- **tokio**: 非同期ランタイム
- **xxhash-rust**: 超高速ハッシュアルゴリズム
- **MCP**: Model Context Protocol実装

## 🚀 クイックスタート

### 1. ビルド

```bash
cd kensho-mcp
cargo build --release
```

### 2. MCPサーバーとして起動

```bash
./target/release/kensho-mcp
# stdin/stdoutでMCPプロトコル通信開始
```

### 3. Claude Codeに統合

`~/.config/claude-code/mcp.json`:

```json
{
  "mcpServers": {
    "kensho-mcp": {
      "command": "/path/to/MCP/target/release/kensho-mcp",
      "args": []
    }
  }
}
```

## 🛠️ 利用可能なツール

### 基本解析（階層1）

#### 1. `get_binary_summary`
バイナリの概要情報を取得（超軽量、統計のみ）。**最初に必ずこれを呼んで全体像を把握する**

```json
{
  "name": "get_binary_summary",
  "arguments": {
    "path": "/path/to/binary"
  }
}
```

**出力例**:
```json
{
  "file_size": "247302512 bytes (247 MB)",
  "format": "PE",
  "architecture": "x86-64",
  "entry_point": "0x14D5A1AA0",
  "sections_count": 18,
  "functions_count": 4563,
  "strings_count": 12345
}
```

### 詳細解析（階層2）

#### 2. `list_sections`
セクション一覧を取得（ページネーション対応）

```json
{
  "name": "list_sections",
  "arguments": {
    "path": "/path/to/binary",
    "page": 0,
    "page_size": 20
  }
}
```

#### 3. `list_functions`
関数一覧を取得（ページネーション + 名前フィルタ対応）

**大規模バイナリでは必ずフィルタ使用を推奨**

```json
{
  "name": "list_functions",
  "arguments": {
    "path": "/path/to/binary",
    "page": 0,
    "page_size": 50,
    "name_filter": "update"
  }
}
```

#### 4. `list_strings`
バイナリ内の文字列を取得（ページネーション対応）

```json
{
  "name": "list_strings",
  "arguments": {
    "path": "/path/to/binary",
    "page": 0,
    "page_size": 100,
    "min_length": 4
  }
}
```

#### 5. `list_imports`
インポート関数一覧（通常は数百〜数千件なので全件返す）

```json
{
  "name": "list_imports",
  "arguments": {
    "path": "/path/to/binary"
  }
}
```

### デコンパイル（階層3）

#### 6. `decompile_function_native`
ネイティブデコンパイラで関数を解析（P-code生成、SSA変換、型推論、制御構造検出）

```json
{
  "name": "decompile_function_native",
  "arguments": {
    "path": "/path/to/binary",
    "function_address": "0x140001000",
    "max_instructions": 1000
  }
}
```

**出力例**:
```c
// P-code operations: 245
// Basic blocks: 12
// Type inferences: 34
// Loops detected: 2

function_140001000() {
    if (condition) {
        while (loop_condition) {
            // loop body
        }
    } else {
        // else branch
    }
}
```

#### 7. `analyze_function_detail`
特定の関数を詳細解析（逆アセンブル + デコンパイル）

**コンテキスト消費大なので、本当に必要な関数のみ実行**

```json
{
  "name": "analyze_function_detail",
  "arguments": {
    "path": "/path/to/binary",
    "function_address": "0x140001000"
  }
}
```

### 高度な機能

#### 8. `detect_export_functions`
PEファイルからエクスポート関数を検出

```json
{
  "name": "detect_export_functions",
  "arguments": {
    "path": "/path/to/binary.exe"
  }
}
```

#### 9. `decompile_function_cached` ⚡
**キャッシュ機能付き高速デコンパイル**

2回目以降は即座に結果を返す（最大1000倍高速化）

```json
{
  "name": "decompile_function_cached",
  "arguments": {
    "path": "/path/to/binary",
    "function_address": "0x140001000",
    "file_offset": "0x600",
    "max_instructions": 1000
  }
}
```

## 🚀 キャッシュシステム

### ハッシュ戦略

デフォルトで**Metadata戦略**を使用。ハッシュ計算を~1msで完了（247MBバイナリでも）。

| 戦略 | 計算時間 | 用途 | 特徴 |
|------|---------|------|------|
| **Metadata** (デフォルト) | ~1ms | 内部キャッシュ・信頼できるバイナリ | ファイルサイズ + 更新日時 + パス |
| **Sampling** | ~450µs | 大規模バイナリの高速ハッシュ | 先頭4KB + 末尾4KB + サイズ |
| **Full** | ~1200ms | 外部バイナリの完全性検証 | ファイル全体をハッシュ化 |

### キャッシュパフォーマンス（247MB Discovery-d.exe）

```
📋 Strategy 1: Metadata (デフォルト)
   🔄 1回目: 1.0ms
   🔄 2回目: 89µs
   🚀 11倍高速化！

📋 Strategy 2: Sampling
   🔄 1回目: 453µs
   🔄 2回目: 47µs
   🚀 10倍高速化！

📋 Strategy 3: Full Hash
   🔄 1回目: 1,219ms
   🔄 2回目: 1,203ms
   効果なし（ハッシュ計算がボトルネック）
```

### カスタマイズ

コードで戦略を変更可能：

```rust
use kensho_mcp::decompiler_prototype::{ParallelDecompiler, HashStrategy};

// Metadata戦略（デフォルト）
let decompiler = ParallelDecompiler::new(&cache_dir)?;

// Sampling戦略
let decompiler = ParallelDecompiler::with_strategy(&cache_dir, HashStrategy::Sampling)?;

// Full戦略（セキュリティ重視）
let decompiler = ParallelDecompiler::with_strategy(&cache_dir, HashStrategy::Full)?;
```

## 🎯 動的解析ツール: memscan
> [!WARNING]
> Windowsのファイルロック問題により、現在ビルドから一時的に除外されています。
> 利用する場合は `Cargo.toml` の `[[bin]]` セクションのコメントアウトを解除してください。

**汎用メモリスキャナー** - あらゆるゲーム・プロセスに対応

### 特徴
- **プロセス名/PIDで自動アタッチ**
- **整数・浮動小数点・文字列・パターンスキャン**
- **インタラクティブモード**対応
- **クロスゲーム対応**（War Thunder, The Finals, 任意のゲーム）

### 使用例

```bash
# プロセス情報を表示
memscan -p aces.exe

# メモリリージョンを列挙
memscan -p aces.exe regions

# 整数値をスキャン（体力値など）
memscan -p aces.exe int 100

# 浮動小数点をスキャン（座標など）
memscan -p aces.exe float 1.5

# 文字列をスキャン
memscan -p aces.exe string "Player"

# バイトパターンスキャン（AOB - Array of Bytes）
memscan -p aces.exe pattern "48 8B 5C 24 ?? 48 83 C4"
# ?? はワイルドカード

# インタラクティブモード
memscan -p aces.exe interactive
```

### SDK開発ワークフロー

1. **値の特定**: ゲーム内で変化する値（体力、弾数など）をスキャン
2. **複数回スキャン**: 値を変化させて絞り込み
3. **ポインタ特定**: 基底アドレス + オフセットを逆算
4. **構造体解析**: 連続するメモリレイアウトを推定
5. **SDK化**: Rust/C++でラッパーを作成

## 🔬 デコンパイラの実装レベル

### Phase 1-6: 完全実装 ✅

**Phase 1: P-code生成**
- ✅ x86-64命令からP-code変換
- ✅ 74種類のP-code opcode実装
- ✅ 文字列操作命令（lods, stos, movs系）対応

**Phase 2: Capstone統合**
- ✅ Capstoneからの自動P-code生成
- ✅ 100以上のx86-64命令対応

**Phase 3: SSA変換**
- ✅ Static Single Assignment形式変換
- ✅ Phi関数自動挿入
- ✅ Dominance frontier計算

**Phase 4: 型推論**
- ✅ 基本的な型推論エンジン
- ✅ ポインタ型推論
- ✅ 演算からの型推定

**Phase 5: 制御構造認識**
- ✅ if/if-else/while/do-while検出
- ✅ 構造化制御フロー復元
- ✅ ネストした制御構造対応

**Phase 6: 関数解析とキャッシュ**
- ✅ エクスポート関数検出
- ✅ コールグラフ構築
- ✅ 並列デコンパイル対応
- ✅ xxHash3キャッシュシステム

**Phase 7: P-code最適化とSSA高度化** ✅
- ✅ NZMask（Non-Zero Mask）解析システム
- ✅ 基本最適化ルール（RuleAndMask, RuleOrMask, RuleTermOrder等）
- ✅ VariableStackインフラ
- ✅ renameRecurseアルゴリズム（Ghidra heritage.cc方式）
- ✅ 最適化パスの統合

**Phase 8: 変数名復元** ✅
- ✅ PEエクスポートテーブル解析
- ✅ シンボルテーブル構築
- ✅ 関数名マッピング（アドレス⇔名前双方向）

**Phase 9: 高度な最適化とC疑似コード生成** ✅
- ✅ 定数畳み込み（RuleConstantFold: const op const => const）
- ✅ ゼロ演算簡略化（RuleZeroOp: V + 0 => V, V * 0 => 0）
- ✅ V < 1 最適化（RuleLessOne: V < 1 => V == 0）
- ✅ C疑似コード生成エンジン（PrintC相当）
- ✅ 変数名マッピング（レジスタ、メモリ、一時変数）
- ✅ 型推論統合（uint8_t, uint32_t, uint64_t等）

**Phase 10: Def-Use Chain & Switch文復元** ✅
- ✅ Def-Use Chain構築（定義-使用連鎖追跡）
- ✅ データフロー解析（到達可能性、単一使用検出）
- ✅ Copy Propagation（V1=V0; V2=V1; => V2=V0;）
- ✅ Dead Code Elimination基盤（未使用定義検出）
- ✅ ジャンプテーブル検出（間接ジャンプ解析）
- ✅ Switch-Case構造復元
- ✅ Switch文C疑似コード生成

### 未実装（将来拡張）

- ❌ DWARF/PDB完全対応（デバッグシンボル）
- ❌ Common Subexpression Elimination完全版
- ❌ クロスアーキテクチャ対応（ARM/MIPS等）

## 🎨 アーキテクチャ

```
MCP/
├── src/
│   ├── main.rs                    # MCPサーバーエントリポイント
│   ├── analyzer.rs                # バイナリ解析コア
│   ├── disassembler.rs            # Capstone逆アセンブラ
│   ├── decompiler.rs              # 簡易デコンパイラ
│   ├── hierarchical_analyzer.rs   # 階層的解析（ページネーション）
│   └── decompiler_prototype/
│       ├── pcode.rs               # P-code定義
│       ├── x86_64.rs              # x86-64デコーダ
│       ├── capstone_translator.rs # Capstone→P-code変換
│       ├── cfg.rs                 # 制御フローグラフ
│       ├── ssa.rs                 # SSA変換
│       ├── ssa_advanced.rs        # SSA高度化（VariableStack, renameRecurse）
│       ├── nzmask.rs              # NZMask解析システム
│       ├── optimizer.rs           # P-code最適化ルールエンジン（12ルール）
│       ├── c_printer.rs           # C疑似コード生成エンジン
│       ├── symbol_recovery.rs     # シンボル名復元（PE解析）
│       ├── dataflow.rs            # Def-Use Chain & データフロー解析
│       ├── jumptable.rs           # ジャンプテーブル検出 & Switch文復元
│       ├── type_inference.rs      # 型推論
│       ├── control_flow.rs        # 制御構造認識
│       ├── function_analyzer.rs   # 関数解析
│       └── parallel_analyzer.rs   # 並列処理&キャッシュ
├── examples/
│   ├── decompile_demo.rs          # デコンパイルデモ
│   ├── pe_analyzer.rs             # PE解析デモ
│   └── advanced_demo.rs           # 拡張機能デモ
└── Cargo.toml
```

## 🎯 Ghidra vs Kensho MCP Native

| 項目 | Ghidra Headless | Kensho MCP |
|------|----------------|-------------------|
| 起動時間 | 5-10秒 | <100ms |
| メモリ使用 | 500MB-2GB | 10-50MB |
| デコンパイラ品質 | 最高 | 実用的（Phase 1-6完了） |
| AI統合 | Python wrapper経由 | ネイティブMCP |
| 依存関係 | JVM必須 | なし（単一バイナリ） |
| キャッシュ | なし | xxHash3（最大1000倍） |

## 🚧 今後の拡張案

### Phase 11: 高度な最適化拡張
- [ ] Common Subexpression Elimination完全版
- [ ] Loop-invariant code motion（ループ不変式の移動）
- [ ] Strength reduction（演算強度削減）
- [ ] Induction variable analysis（帰納変数解析）
- [x] Z3ソルバー統合プロトタイプ (`src/decompiler_prototype/z3_solver`)

### Phase 12: デバッグ情報対応
- [ ] DWARF完全対応（関数名、変数名、型情報）
- [ ] PDB完全対応（Windows Debug Symbols）
- [ ] ソースレベルマッピング

### Phase 13: マルチアーキテクチャ
- [ ] ARM/ARM64対応
- [ ] MIPS対応
- [ ] RISC-V対応

## 🤝 貢献

Issue・PRお待ちしております！

特に以下の領域に興味がある方：
- デコンパイラアルゴリズム
- 制御フロー解析
- 型推論
- ARM/MIPS/RISC-V対応

## 📄 ライセンス

MIT License

## 🙏 謝辞

- NSA Ghidra Project
- Capstone Disassembly Framework
- goblin
- xxHash
