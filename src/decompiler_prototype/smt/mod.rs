/// SMT solver integration for obfuscation analysis
///
/// Phase 11.2: Z3 theorem prover integration for:
/// - Opaque predicate verification
/// - MBA expression equivalence checking
/// - Dead code detection
///
/// References:
/// - Z3: https://github.com/Z3Prover/z3
/// - SMT-LIB: https://smtlib.cs.uiowa.edu/

pub mod verifier;
pub mod converter;

pub use verifier::{SMTVerifier, OpaquenessResult, EquivalenceResult, SMTStatistics};
pub use converter::PcodeToZ3Converter;
