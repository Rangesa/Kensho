//! MCP (Model Context Protocol) モジュール
//! 
//! ツール定義とハンドラーを分離して管理

pub mod tools;
pub mod handlers;

pub use tools::get_tool_definitions;
pub use handlers::dispatch_tool;
