/// Mixed Boolean-Arithmetic (MBA) obfuscation detection and simplification
///
/// Phase 11.1: MBA pattern detection and algebraic simplification
///
/// MBA obfuscation transforms simple arithmetic operations into complex expressions
/// mixing bitwise and arithmetic operations, making the code difficult to understand.
///
/// Example: x + y can be transformed to (x ⊕ y) + 2(x ∧ y)
///
/// References:
/// - Liu et al. (2021): "MBA-Blast: Unveiling and Simplifying Mixed Boolean-Arithmetic Obfuscation"

pub mod detector;
pub mod simplifier;
pub mod kensho_simplifier;

pub use detector::{MBADetector, MBAPattern, MBALocation, MBAStatistics};
pub use simplifier::{MBASimplifier, SimplifiedExpression, VerificationMethod, SimplificationRule};
pub use kensho_simplifier::{KenshoMBASimplifier, KenshoSimplificationStats};
