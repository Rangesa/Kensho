# Changelog

All notable changes to Kensho MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
