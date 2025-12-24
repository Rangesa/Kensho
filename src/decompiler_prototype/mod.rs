/// Ghidraデコンパイラコアのプロトタイプ実装
///
/// フェーズ1: P-code生成とシンプルなデコンパイル
/// フェーズ2: Capstoneからの自動変換
/// フェーズ3: SSA変換とデータフロー解析
/// フェーズ7: P-code最適化とSSA高度化

pub mod pcode;
pub mod x86_64;
pub mod cfg;
pub mod printer;
pub mod capstone_translator;
pub mod ssa;
pub mod ssa_advanced;
pub mod nzmask;
pub mod optimizer;
pub mod control_flow;
pub mod type_inference;
pub mod function_analyzer;
pub mod parallel_analyzer;
pub mod c_printer;
pub mod symbol_recovery;
pub mod dataflow;
pub mod jumptable;

pub use pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
pub use x86_64::{X86Register, X86Decoder};
pub use cfg::ControlFlowGraph;
pub use printer::SimplePrinter;
pub use capstone_translator::CapstoneTranslator;
pub use ssa::SSATransform;
pub use ssa_advanced::{VariableStack, AdvancedSSATransform};
pub use nzmask::{NZMaskAnalyzer, NZMaskStats};
pub use optimizer::{Optimizer, OptimizationStats, OptimizationRule};
pub use control_flow::{ControlFlowAnalyzer, ControlStructure, ControlStructurePrinter};
pub use type_inference::{TypeInference, Type, IntType, FloatType};
pub use function_analyzer::{FunctionDetector, FunctionInfo, FunctionStatistics};
pub use parallel_analyzer::{ParallelDecompiler, CachedFunctionResult, CacheStatistics, HashStrategy};
pub use c_printer::CPrinter;
pub use symbol_recovery::{SymbolTable, Symbol, SymbolKind};
pub use dataflow::{DefUseChain, CopyPropagation, DeadCodeElimination, DataFlowStats};
pub use jumptable::{JumpTable, JumpTableDetector, SwitchStatement, SwitchPrinter};
