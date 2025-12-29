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

`mcp.json` 設定例:
```json
{
  "mcpServers": {
    "kensho": {
      "command": "target/release/kensho-mcp.exe"
    }
  }
}
```

## 🔬 実装ステータス (Phases)

- [x] Phase 1-6: 基本P-code生成、SSA変換、型推論、制御構造認識。
- [x] Phase 7-9: NZMask最適化、シンボル復元、C疑似コード生成。
- [x] Phase 10: Def-Use Chain、ジャンプテーブル解析、Switch文復元。
- [x] SMT Migration: 外部Z3依存の完全削除と自作ソルバーへの移行。

## 📜 ライセンス

MIT License
