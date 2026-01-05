







pub mod pcode;
pub mod x86_64;
pub mod cfg;
pub mod printer;
pub mod capstone_translator;  // Phase 2縺ｧ蜑企勁莠亥ｮ・pub mod lifter;  // Phase 1: iced-x86繝吶・繧ｹ縺ｮ繝ｪ繝輔ち繝ｼ
pub mod ssa;
pub mod ssa_advanced;
pub mod nzmask;
pub mod optimizer;
pub mod control_flow;
pub mod type_inference;
pub mod function_analyzer;
pub mod parallel_analyzer;
pub mod unified_decompiler;  // MCP tool consolidation
pub mod c_printer;
pub mod symbol_recovery;
pub mod dataflow;
pub mod jumptable;
pub mod test_utils;
pub mod debug_symbols;
pub mod json_printer;
pub mod memory_dump;
pub mod obfuscation_detector;

// Phase 11: Advanced obfuscation analysis
pub mod mba;
pub mod smt;
pub mod flattening;
pub mod vm_detection;

// Phase 13-14: Robust binary loading and symbolic execution
pub mod binary_loader;
pub mod symbolic_execution;

// Phase 15: Advanced type inference
pub mod struct_analyzer;
pub mod vtable_detector;
pub mod signature_inference;

pub use pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
pub use x86_64::{X86Register, X86Decoder};
pub use cfg::ControlFlowGraph;
pub use printer::SimplePrinter;
pub use capstone_translator::CapstoneTranslator;  // Phase 2縺ｧ蜑企勁莠亥ｮ・pub use lifter::IcedLifter;  // Phase 1: iced-x86繝吶・繧ｹ縺ｮ繝ｪ繝輔ち繝ｼ
pub use ssa::SSATransform;
pub use ssa_advanced::{VariableStack, AdvancedSSATransform};
pub use nzmask::{NZMaskAnalyzer, NZMaskStats};
pub use optimizer::{Optimizer, OptimizationStats, OptimizationRule};
pub use control_flow::{ControlFlowAnalyzer, ControlStructure, ControlStructurePrinter};
pub use type_inference::{TypeInference, Type, IntType, FloatType};
pub use function_analyzer::{FunctionDetector, FunctionInfo, FunctionStatistics};
pub use parallel_analyzer::{ParallelDecompiler, CachedFunctionResult, CacheStatistics, HashStrategy};
pub use unified_decompiler::{UnifiedDecompiler, UnifiedDecompileResult, DetailLevel, DisassemblyLine, TypeBinding};
pub use c_printer::CPrinter;
pub use symbol_recovery::{SymbolTable, Symbol, SymbolKind};
pub use dataflow::{DefUseChain, CopyPropagation, DeadCodeElimination, DataFlowStats};
pub use jumptable::{JumpTable, JumpTableDetector, SwitchStatement, SwitchPrinter};
pub use json_printer::{JsonPrinter, AnalysisResult, ConfidenceScores};
pub use memory_dump::MemoryDumpFile;
pub use obfuscation_detector::{ObfuscationDetector, ObfuscationData, ObfuscationPattern, ObfuscationPatternType};

// Phase 11 public API
pub use mba::{MBADetector, MBAPattern, MBASimplifier, SimplifiedExpression};
pub use mba::{KenshoMBASimplifier, KenshoSimplificationStats};
pub use smt::{SMTVerifier, OpaquenessResult, EquivalenceResult};
pub use flattening::{FlatteningAnalyzer, StateVariableInfo, StateTransition};
pub use vm_detection::{VMDetector, VMPattern, VMHandlerInfo};

// Phase 13-14 public API (kensho SMT only)
pub use binary_loader::{RobustBinaryLoader, BinaryInfo, BinaryType, ParseStatus};
pub use symbolic_execution::{
    SymbolicExecutor, SymbolicState, SymbolicMemory, SymbolicValue, ExplorationStrategy,
    SymbolicAddress, AddressOverlap, AddressRange,
    SymbolicMemoryV2, VulnerabilityDetector, Vulnerability, VulnerabilityType
};

// Phase 15 public API: Advanced type inference
pub use struct_analyzer::{StructAnalyzer, StructLayout, InferredField, FieldAccessType, InferredType as InferredStructType};
pub use vtable_detector::{VTableDetector, VTableInfo, VirtualFunction};
pub use signature_inference::{SignatureInferenceEngine, FunctionSignature, Parameter, ParameterLocation, CallingConvention, Architecture};
