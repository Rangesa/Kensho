//! Symbolic Execution and Analysis Modules
//!
//! シンボリック実行、メモリモデリング、脆弱性検出などの機能を提供。
//! 全てkensho SMTソルバーを使用しています。

pub mod symbolic_executor;
pub mod expression_simplifier;
pub mod memory_model;
pub mod symbolic_address;
pub mod memory_model_v2;
pub mod vulnerability_detector;

pub use symbolic_executor::{SymbolicExecutor, SymbolicState, ExplorationStrategy, ExecutionStatistics};
pub use expression_simplifier::{ExpressionSimplifier, SimplificationPattern};
pub use memory_model::{SymbolicMemory, SymbolicValue, MemoryRegion, MemoryStatistics};
pub use symbolic_address::{SymbolicAddress, AddressOverlap, AddressRange};
pub use memory_model_v2::{SymbolicMemoryV2, SymbolicValue as SymbolicValueV2, MemoryRegionInfo, MemoryStatistics as MemoryStatisticsV2};
pub use vulnerability_detector::{VulnerabilityDetector, Vulnerability, VulnerabilityType};
