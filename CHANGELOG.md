# Changelog

All notable changes to Kensho MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed - MCP Module Refactoring (2026-01-05)

#### ファイル構造のリファクタリング

**main.rs の軽量化（755行 → 170行）**:
- MCPサーバーのエントリーポイントとプロトコル処理のみに特化
- ツール定義とハンドラーを新規 `src/mcp/` モジュールに分離

**新規モジュール `src/mcp/`**:
- `mod.rs`: モジュールエントリーポイント
- `tools.rs`: 全ツールのJSONスキーマ定義（270行）
- `handlers.rs`: 全ツールの実行ロジック（350行）

**メリット**:
- 責務分離（ツール定義 vs 実行ロジック）
- 新ツール追加時の変更箇所が明確
- テスト容易性の向上
- コードの可読性向上

**ドキュメント追加**:
- `docs/MCP_MODULE_ARCHITECTURE.md`: MCPモジュールの設計・拡張ガイド

### Changed - MCP Tool Consolidation (2026-01-05)

#### ツール統合（16個→10個）

MCPツールを重複削除と統合により16個から10個に削減しました。

**削除されたツール（6個）:**
- `detect_export_functions` - `get_binary_summary`で機能カバー可能
- `decompile_with_ghidra` - Ghidra外部依存を削除
- `dump_process_memory` - 動的解析機能を削除（静的解析のみに特化）
- `decompile_memory_dump` - `dump_process_memory`削除により不要
- `analyze_function_detail` - 統合デコンパイラに置き換え
- `decompile_function_cached` - 統合デコンパイラに吸収

**新規ツール（1個）:**
- `decompile_function` - 統合デコンパイラ
  - ParallelDecompilerベースの完全なパイプライン（P-code、SSA、型推論、制御構造解析）
  - `cache`パラメータ: キャッシュ有効/無効を選択（デフォルト: true）
  - `detail_level`パラメータ: basic（統計のみ）/ full（型推論含む）を選択
  - `include_disassembly`パラメータ: 逆アセンブル含有（fullモード時のみ有効）
  - ファイルオフセット自動計算: PE/ELF対応、仮想アドレスから自動変換

**最終構成（10個）:**
- 基本解析: 5個（summary, sections, functions, strings, imports）
- デコンパイル: 1個（decompile_function）
- 難読化解析: 4個（detect_obfuscation, detect_vm_protection, analyze_control_flow_flattening, simplify_mba_expression）

#### アーキテクチャ改善

**UnifiedDecompiler実装**:
- 新規ファイル: `src/decompiler_prototype/unified_decompiler.rs`
- `ParallelDecompiler`をラップし、統合インターフェースを提供
- `DetailLevel` enum導入: Basic（軽量）/ Full（詳細）
- PE/ELFバイナリからの自動ファイルオフセット計算機能
- goblinライブラリを使用したVA→RVA→File Offset変換

**ParallelDecompilerの公開API化**:
- `decompile_function_uncached()`をpublicに変更
- UnifiedDecompilerからキャッシュなし実行が可能に

**HierarchicalAnalyzerのクリーンアップ**:
- `analyze_function_detail()`メソッドを削除
- `FunctionDetail`および`InstructionInfo`構造体を削除
- Disassembler/Decompilerへの古い依存関係を削除

**Ghidra外部依存の完全削除**:
- `src/ghidra_headless.rs`の使用を停止（ファイルは残存）
- main.rsからGhidraHeadless初期化コードを削除
- 設定なしで即座に利用可能な状態に

**未使用コードの削除**:
- Windows専用`memory_scanner`モジュールのインポートを削除
- 未使用の`Context`トレイトインポートを削除
- `mut tools`を`tools`に修正（不変化）

#### ドキュメント更新

**README.md**:
- MCPツールリストを16個→10個に更新
- 各カテゴリの個数を明記
- `decompile_function`の詳細説明を追加

**docs/MCP_USAGE_GUIDE.md**:
- `decompile_function`の使用例を追加
  - 基本使用（軽量・高速）
  - 詳細解析（型推論含む）
- パラメータ説明を詳細化
- `dump_process_memory`セクションを削除
- `list_functions`セクションを追加

### Added - Phase 1 Obfuscation Analysis Tools (2026-01-04)

#### 新規MCPツール（難読化解析）

- **detect_obfuscation**: 総合的な難読化パターン検出
  - MBA式、制御フロー平坦化、VM保護、opaque predicates等を検出
  - overall_scoreで難読化度を0.0〜1.0のスコアで評価
  - パターンごとの信頼度とロケーション情報を提供

- **detect_vm_protection**: VM-based obfuscation検出
  - VMProtect等のVM保護パターンを検出
  - VMディスパッチャー、ハンドラー、バイトコード命令を分析
  - 信頼度スコア付きで検出結果を返却

- **analyze_control_flow_flattening**: 制御フロー平坦化の詳細解析
  - ディスパッチャーブロックの特定
  - 状態変数の追跡
  - 状態遷移の解析
  - カバレッジと信頼度スコアの計算

- **simplify_mba_expression**: MBA式の簡約化
  - Kensho SMT solverによる等価性検証
  - ビットブラスティングベースのSAT求解
  - 簡約化された式と検証結果を返却

#### Gemini CLI対応

- `.gemini/settings.json` 設定ファイルを追加
  - Gemini CLIからKensho MCPサーバーを利用可能に
  - timeout、trustパラメータを設定
  - グローバル設定とプロジェクト設定の両方をサポート

#### ドキュメント

- `docs/MCP_USAGE_GUIDE.md`: 包括的な使用ガイドを追加
  - Claude CodeとGemini CLIの両方のセットアップ手順
  - 全MCPツールの使用例
  - トラブルシューティングガイド
  - 具体的な出力例

- `README.md`: MCP統合セクションを大幅拡充
  - Claude Code設定例
  - Gemini CLI設定例
  - 利用可能な全MCPツールのリスト
  - Phase 11（難読化解析）とMCP統合の実装完了をマーク

### Changed

#### アーキテクチャ改善

- Go実装を`archive/go_prototype/`に移動
  - Rust一本化による保守性向上
  - `.mcp.json`をRust実装を参照するよう更新

- Phase 11難読化解析モジュールとの統合
  - ObfuscationDetector、MBADetector、VMDetector、FlatteningAnalyzerを活用
  - Kensho SMT solverによる等価性検証を実装
  - 全ての難読化検出機能をMCPツールとして公開

### Fixed

- src/main.rsのモジュールインポートエラーを修正
  - `mod`宣言から`use kensho_mcp::`インポートに変更
  - バイナリとライブラリの分離を明確化

- 未使用インポート・フィールドの警告を削除
  - `cargo fix`と選択的な`#[allow(dead_code)]`アノテーションで103件の警告をゼロに

- ObfuscationPattern APIミスマッチを修正
  - `locations`フィールドを適切にJSONシリアライズ
  - 各難読化検出ツールのAPIを正しく統合

### Technical Details

#### Phase 11実装詳細

**ObfuscationDetector統合**:
- `ObfuscationDetector::analyze()`で総合的な難読化解析
- Phase 10（基本パターン検出）+ Phase 11（高度解析）の統合
- overall_scoreの計算ロジック: 基本パターン(0.5) + MBA(0.15) + 平坦化(0.15) + VM(0.2)

**MBADetector統合**:
- `MBADetector::detect()`でMBA式を検出
- 複雑度、チェーン長、ビット演算/算術演算カウントを分析
- `KenshoMBASimplifier::simplify_expression()`でSMT検証ベースの簡約化

**FlatteningAnalyzer統合**:
- `FlatteningAnalyzer::analyze()`で制御フロー平坦化を検出
- ディスパッチャー検出: 出力次数≥5 + 高入力次数
- 状態変数追跡: CBranch/BranchIndの条件変数を分析
- 遷移追跡: 各ブロックからディスパッチャーへの状態値更新を追跡

**VMDetector統合**:
- `VMDetector::detect()`でVM-based obfuscationを検出
- Option<VMPattern>を返却（検出されない場合はNone）
- ディスパッチャー、ハンドラー、バイトコード命令を特定

#### ビルド結果

```
Finished `release` profile [optimized] target(s) in 16.57s
```

全ての難読化解析ツールが正常にビルドされ、MCPプロトコル経由で利用可能になりました。

## [0.1.0] - 2025-12-27

### Added

- 初期リリース
- P-codeエンジン（x86-64 Lifter、SSA変換、最適化）
- Kensho SMT Solver（ネイティブSATソルバー、MBA簡約化）
- 基本解析機能（データフロー、制御フロー、シンボリック実行）
- MCP基本ツール（get_binary_summary、list_sections、list_strings、list_imports、decompile_function_native、dump_process_memory）
- Phase 1-10実装完了
