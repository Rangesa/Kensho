/// VM-based obfuscation detection
///
/// Phase 11.4: Detect virtualization-based obfuscation patterns
///
/// VM-based obfuscation wraps code in a custom bytecode interpreter:
/// - Fetch: Read next bytecode instruction
/// - Decode: Map bytecode to handler
/// - Dispatch: Jump to handler function
///
/// References:
/// - Yadegari & Debray (2015): "A Generic Approach to Automatic Deobfuscation of Executable Code"
/// - Coogan et al. (2011): "Automatic Static Unpacking of Malware Binaries"
/// - VMProtect, Themida, Code Virtualizer

pub mod detector;

pub use detector::{
    VMDetector, VMPattern, VMHandlerInfo, VMStatistics, DispatcherInfo, VPCInfo,
};
