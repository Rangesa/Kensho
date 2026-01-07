# Kensho MCP - Project Instructions

## Project Overview

Kensho MCPは、RustネイティブのP-codeベース・バイナリ解析フレームワーク。
GhidraのP-codeアーキテクチャを参考に、難読化解除（MBA簡約化）とシンボリック実行に特化した解析エンジンを提供する。

## Architecture

```
kensho-mcp/
├── src/
│   ├── main.rs                    # MCPサーバーエントリーポイント（stdin/stdout JSON-RPC）
│   ├── lib.rs                     # ライブラリルート（モジュール宣言）
│   ├── mcp/                       # MCP (Model Context Protocol) インターフェース
│   │   ├── mod.rs                 # モジュールルート
│   │   ├── tools.rs               # ツール定義（JSONスキーマ）
│   │   └── handlers.rs            # ツールハンドラー実装
│   ├── hierarchical_analyzer.rs   # 階層的解析（ページネーション、キャッシュ）
│   ├── decompiler_prototype/      # デコンパイラコア
│   │   ├── lifter/                # x86-64 → P-code変換（iced-x86ベース）
│   │   ├── ssa/                   # SSA変換（Dominance Frontier、Phi挿入）
│   │   ├── optimizer/             # 最適化パス（NZMask、定数畳み込み、DCE）
│   │   ├── mba/                   # MBA検出・簡約化
│   │   ├── flattening/            # 制御フロー平坦化解析
│   │   ├── vm_detection/          # VM保護検出
│   │   ├── smt/                   # SMT式変換（Kensho SMT用）
│   │   └── symbolic_execution/    # シンボリック実行エンジン
│   ├── kensho_smt/                # 自作SMTソルバー（Z3依存なし）
│   │   ├── solver.rs              # SAT/SMTソルバー本体
│   │   ├── bitblast.rs            # ビットブラスティング
│   │   ├── simplify.rs            # 式簡約化
│   │   └── mba_patterns.rs        # MBA難読化パターン
│   ├── memory_scanner.rs          # メモリスキャナー
│   └── dynamic_analysis/          # 動的解析（Windows専用）
│       ├── mod.rs                 # FunctionTracer, SandboxedProcess等
│       └── ...
├── examples/                      # デモ・テストコード
└── tests/                         # 統合テスト
```

## Key Modules

### MCP Interface (`src/mcp/`)
- `tools.rs`: 全MCPツールのJSON Schema定義
- `handlers.rs`: ツール呼び出しのディスパッチと実行ロジック
- プロトコルバージョン: `2024-11-05`

### P-code Engine (`src/decompiler_prototype/`)
- `lifter/iced_lifter.rs`: iced-x86を使用したP-code生成
- `pcode.rs`: P-code IR定義（PcodeOp, Varnode）
- `cfg.rs`: 制御フローグラフ
- `ssa/transform.rs`: SSA変換（Phi関数挿入）

### Kensho SMT (`src/kensho_smt/`)
- 外部依存なしの純Rust SMTソルバー
- MBA式の等価性検証に使用
- ビットブラスティングによるSAT変換

## Build Commands

```bash
# リリースビルド
cargo build --release

# テスト実行
cargo test

# 特定のexample実行
cargo run --example decompile_demo
cargo run --example vulnerability_detection_demo
```

## MCP Tools (10 tools)

### Basic Analysis (5)
1. `get_binary_summary` - バイナリ概要（必ず最初に呼ぶ）
2. `list_sections` - セクション一覧（ページネーション対応）
3. `list_functions` - 関数一覧（name_filterでフィルタ可能）
4. `list_strings` - 文字列抽出
5. `list_imports` - インポートテーブル

### Decompiler (1)
6. `decompile_function` - 統合デコンパイラ
   - `detail_level`: "basic" | "full"
   - `cache`: true/false
   - `include_disassembly`: true/false

### Obfuscation Analysis (4)
7. `detect_obfuscation` - 総合難読化検出
8. `detect_vm_protection` - VM保護検出
9. `analyze_control_flow_flattening` - 制御フロー平坦化解析
10. `simplify_mba_expression` - MBA簡約化

### Dynamic Analysis (Windows only, 4 tools)
- `trace_function` - 関数トレース
- `dump_memory_region` - メモリダンプ
- `run_in_sandbox` - サンドボックス実行
- `sandbox_trace` - サンドボックス内トレース

## Development Guidelines

### Code Style
- 日本語コメント許可（ドキュメントは日本語/英語混在可）
- エラー処理: `anyhow::Result` を使用
- 非同期: `tokio` ランタイム

### Adding New MCP Tool
1. `src/mcp/tools.rs` にJSON Schema定義を追加
2. `get_tool_definitions()` に追加
3. `src/mcp/handlers.rs` にハンドラー実装
4. `dispatch_tool()` にマッチアーム追加

### Testing
- 単体テスト: 各モジュール内 `#[cfg(test)]`
- 統合テスト: `tests/` ディレクトリ
- デモ: `examples/` でrealバイナリ解析

## Dependencies

### Core
- `tokio`: 非同期ランタイム
- `serde/serde_json`: シリアライゼーション
- `goblin`: PE/ELF/Mach-Oパーサー
- `iced-x86`: x86-64デコーダ
- `petgraph`: グラフアルゴリズム

### Optional
- `capstone`: 逆アセンブラ（Phase 2で削除予定）
- `rayon`: 並列処理（feature flag）

### Windows-only
- `windows`: Windows API（動的解析用）

## Notes

- Capstoneは将来的に削除予定、iced-x86に完全移行
- Z3依存は完全削除済み、kensho_smtで代替
- 大規模バイナリ解析時はページネーション必須
