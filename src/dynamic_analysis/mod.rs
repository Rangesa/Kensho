// 動的解析モジュール（Windows専用、外部依存なし）

#![cfg(windows)]

pub mod ffi;
pub mod debugger;
pub mod tracer;
pub mod sandbox;

pub use debugger::ProcessDebugger;
pub use tracer::{FunctionTracer, InstructionTrace, RegisterSnapshot, TraceResult};
pub use sandbox::{SandboxConfig, SandboxedProcess, SandboxResult};
