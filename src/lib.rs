/// Ghidra-MCP ライブラリ
///
/// バイナリ解析とデコンパイラ機能を提供

pub mod hierarchical_analyzer;
pub mod disassembler;
pub mod decompiler;
pub mod ghidra_headless;

// Ghidraデコンパイラコアのプロトタイプ実装
pub mod decompiler_prototype;

// 動的解析（メモリスキャン）
pub mod memory_scanner;
