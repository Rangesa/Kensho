/// Kensho MCP ライブラリ
///
/// バイナリ解析とデコンパイラ機能を提供。
pub mod hierarchical_analyzer;
pub mod disassembler;
pub mod decompiler;
pub mod ghidra_headless;

// Ghidraデコンパイラコアのプロトタイプ実装
pub mod decompiler_prototype;

// 動的解析（メモリ走査）
pub mod memory_scanner;

// 動的解析（プロセストレース、デバッグAPI）
#[cfg(windows)]
pub mod dynamic_analysis;

// kensho専用SMTソルバー（軽量、外部依存なし）
pub mod kensho_smt;

// MCP (Model Context Protocol) ツール定義・ハンドラー
pub mod mcp;
