/// Control flow flattening analysis
///
/// Phase 11.3: Detect and analyze control flow flattening patterns
///
/// Control flow flattening transforms structured control flow (if/while/switch)
/// into a dispatcher-based pattern where all basic blocks branch to a central
/// dispatcher that decides the next block based on a state variable.
///
/// References:
/// - Udupa & Debray (2005): "Deobfuscation: Reverse Engineering Obfuscated Code"
/// - Wang et al. (1998): "Software Tamper Resistance"

pub mod analyzer;

pub use analyzer::{
    FlatteningAnalyzer, StateVariableInfo, StateTransition, FlatteningStatistics,
};
