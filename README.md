# Kensho (kensho-mcp)

RustネイティブのP-codeベース・バイナリ解析フレームワーク。
GhidraのP-codeアーキテクチャを参考に、難読化解除（MBA簡約化）とシンボリック実行に特化した解析エンジンを提供します。

## 🛠 技術仕様

### 1. P-code エンジン
- **Lifter**: `iced-x86` を使用したx86-64命令からP-codeへの変換。
- **SSA Transform**: Dominance Frontierに基づくPhi関数挿入を含むSSA形式への変換。
- **Optimization**: NZMask解析、定数畳み込み、デッドコード削除、Copy Propagation等の最適化パス。

### 2. Kensho SMT Solver (Internal)
- **Native Implementation**: Z3等の外部依存を排除した、RustネイティブのBit-blasting SMTソルバー。
- **MBA Simplification**: 複雑なビット演算（Mixed Boolean-Arithmetic）をSATベースの等価性検証により簡約化。
- **Verification**: 最適化前後のP-codeが論理的に等価であることを証明。

### 3. 解析機能
- **Data Flow**: Def-Use Chainの構築と到達可能性解析。
- **Control Flow**: 制御フロー平坦化の解除、ループ・条件分岐の構造復元。
- **Indirect Jumps**: ジャンプテーブル解析によるSwitch-Case構造の復元。
- **Symbolic Execution**: シンボリックメモリモデルによるパス探索と脆弱性検知。

## 📦 プロジェクト構造

- `src/kensho_smt/`: 自作SATソルバー、ビットブラスティング、式簡約化。
- `src/decompiler_prototype/`: P-code生成、SSA変換、最適化エンジン。
- `src/hierarchical_analyzer.rs`: 大規模バイナリ向けのページネーション付き解析。
- `examples/`: War Thunder（PE64）等の実バイナリを用いた解析デモ。

## 🚀 利用方法

### ビルド
```bash
cargo build --release
```

### MCP (Model Context Protocol) 連携
このサーバーはMCPプロトコルを介して、静的解析結果を構造化データ（JSON）として提供します。

#### Claude Code 設定
`.mcp.json`:
```json
{
  "mcpServers": {
    "kensho-mcp": {
      "type": "stdio",
      "command": "D:\\Programming\\MCP\\target\\release\\kensho-mcp.exe",
      "args": [],
      "env": {}
    }
  }
}
```

#### Gemini CLI 設定
`.gemini/settings.json`:
```json
{
  "mcpServers": {
    "kensho-mcp": {
      "command": "D:\\Programming\\MCP\\target\\release\\kensho-mcp.exe",
      "args": [],
      "env": {},
      "timeout": 60000,
      "trust": true
    }
  }
}
```

または、グローバル設定（`~/.gemini/settings.json`）に追加することで、全プロジェクトから利用可能になります。

#### 利用可能なMCPツール (10個)

**基本解析ツール (5個):**
- `get_binary_summary`: バイナリの基本情報（PE/ELF情報、エントロピー、インポート統計）
- `list_sections`: セクション情報とエントロピー分析（ページネーション対応）
- `list_functions`: 関数一覧（エクスポート/シンボルテーブルから検出、ページネーション対応）
- `list_strings`: 抽出された文字列リスト（ページネーション対応）
- `list_imports`: インポートテーブル（DLL別グループ化）

**デコンパイルツール (1個):**
- `decompile_function`: 統合デコンパイラ（P-code変換、SSA、型推論、制御構造解析）
  - キャッシュ制御: `cache` パラメータで有効/無効を選択
  - 詳細レベル: `detail_level` で basic（統計のみ）/ full（型推論含む）を選択
  - ファイルオフセット自動計算: PE/ELF対応、仮想アドレスから自動変換

**難読化解析ツール (4個):**
- `detect_obfuscation`: 総合的な難読化パターン検出（MBA、制御フロー平坦化、VM保護、opaque predicates等）
- `detect_vm_protection`: VM-based obfuscation（VMProtect等）の検出
- `analyze_control_flow_flattening`: 制御フロー平坦化の詳細解析（ディスパッチャー、状態変数、遷移）
- `simplify_mba_expression`: MBA式の簡約化と等価性検証（Kensho SMT solver使用）

## 🔬 実装ステータス (Phases)

- [x] Phase 1-6: 基本P-code生成、SSA変換、型推論、制御構造認識。
- [x] Phase 7-9: NZMask最適化、シンボル復元、C疑似コード生成。
- [x] Phase 10: Def-Use Chain、ジャンプテーブル解析、Switch文復元。
- [x] Phase 11: 難読化解析（MBA検出・簡約化、VM保護検出、制御フロー平坦化解析、SMT検証）。
- [x] SMT Migration: 外部Z3依存の完全削除と自作ソルバーへの移行。
- [x] MCP Integration: Claude Code / Gemini CLI対応、難読化解析ツールのMCP公開。

## 📜 ライセンス

MIT License
