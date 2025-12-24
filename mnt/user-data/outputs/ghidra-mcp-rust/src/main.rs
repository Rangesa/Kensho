use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, error};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

mod analyzer;
mod binary_loader;
mod disassembler;
mod decompiler;
mod mcp_protocol;

use analyzer::BinaryAnalyzer;

#[derive(Debug, Deserialize)]
struct McpRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct McpResponse {
    jsonrpc: String,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<McpError>,
}

#[derive(Debug, Serialize)]
struct McpError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// Ghidra風ネイティブMCPサーバー
/// Rust実装で超高速・軽量なバイナリ解析をAIエージェントに提供
#[tokio::main]
async fn main() -> Result<()> {
    // ログ初期化
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    info!("🦀 Ghidra-MCP Native Server starting...");

    // 解析器を初期化
    let analyzer = Arc::new(BinaryAnalyzer::new());

    // 標準入出力でMCP通信
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    info!("✅ Server ready, waiting for MCP requests...");

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                let response = match process_request(&line, Arc::clone(&analyzer)).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!("Request processing error: {}", e);
                        McpResponse {
                            jsonrpc: "2.0".to_string(),
                            id: None,
                            result: None,
                            error: Some(McpError {
                                code: -32603,
                                message: e.to_string(),
                                data: None,
                            }),
                        }
                    }
                };

                let response_str = serde_json::to_string(&response)?;
                stdout.write_all(response_str.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
            Err(e) => {
                error!("Read error: {}", e);
                break;
            }
        }
    }

    info!("Server shutting down");
    Ok(())
}

async fn process_request(
    request_str: &str,
    analyzer: Arc<BinaryAnalyzer>,
) -> Result<McpResponse> {
    let request: McpRequest = serde_json::from_str(request_str)?;
    
    info!("Processing method: {}", request.method);

    let result = match request.method.as_str() {
        "initialize" => handle_initialize().await?,
        "tools/list" => handle_list_tools().await?,
        "tools/call" => handle_tool_call(request.params, analyzer).await?,
        _ => {
            return Ok(McpResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(McpError {
                    code: -32601,
                    message: format!("Method not found: {}", request.method),
                    data: None,
                }),
            });
        }
    };

    Ok(McpResponse {
        jsonrpc: "2.0".to_string(),
        id: request.id,
        result: Some(result),
        error: None,
    })
}

async fn handle_initialize() -> Result<Value> {
    Ok(json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "ghidra-mcp-native",
            "version": "0.1.0"
        }
    }))
}

async fn handle_list_tools() -> Result<Value> {
    Ok(json!({
        "tools": [
            {
                "name": "analyze_binary",
                "description": "バイナリファイルの基本情報を解析（形式、アーキテクチャ、エントリポイント等）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "解析対象のバイナリファイルパス"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "disassemble",
                "description": "指定アドレスから逆アセンブル実行",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "バイナリファイルパス"
                        },
                        "address": {
                            "type": "string",
                            "description": "開始アドレス（16進数: 0x1000）"
                        },
                        "count": {
                            "type": "integer",
                            "description": "逆アセンブルする命令数（デフォルト: 20）",
                            "default": 20
                        }
                    },
                    "required": ["path", "address"]
                }
            },
            {
                "name": "find_functions",
                "description": "バイナリ内の関数を検出・リスト化",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "バイナリファイルパス"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "decompile_function",
                "description": "関数を疑似Cコードにデコンパイル（簡易実装）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "バイナリファイルパス"
                        },
                        "function_name": {
                            "type": "string",
                            "description": "関数名またはアドレス"
                        }
                    },
                    "required": ["path", "function_name"]
                }
            },
            {
                "name": "find_strings",
                "description": "バイナリ内の文字列を抽出",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "バイナリファイルパス"
                        },
                        "min_length": {
                            "type": "integer",
                            "description": "最小文字列長（デフォルト: 4）",
                            "default": 4
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "analyze_imports",
                "description": "インポートされた関数・ライブラリを解析",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "バイナリファイルパス"
                        }
                    },
                    "required": ["path"]
                }
            }
        ]
    }))
}

async fn handle_tool_call(
    params: Option<Value>,
    analyzer: Arc<BinaryAnalyzer>,
) -> Result<Value> {
    let params = params.ok_or_else(|| anyhow::anyhow!("Missing params"))?;
    let tool_name = params["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing tool name"))?;
    let arguments = &params["arguments"];

    let result = match tool_name {
        "analyze_binary" => {
            let path = arguments["path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing path"))?;
            analyzer.analyze_binary(path).await?
        }
        "disassemble" => {
            let path = arguments["path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing path"))?;
            let address = arguments["address"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing address"))?;
            let count = arguments["count"].as_u64().unwrap_or(20) as usize;
            analyzer.disassemble(path, address, count).await?
        }
        "find_functions" => {
            let path = arguments["path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing path"))?;
            analyzer.find_functions(path).await?
        }
        "decompile_function" => {
            let path = arguments["path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing path"))?;
            let function_name = arguments["function_name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing function_name"))?;
            analyzer.decompile_function(path, function_name).await?
        }
        "find_strings" => {
            let path = arguments["path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing path"))?;
            let min_length = arguments["min_length"].as_u64().unwrap_or(4) as usize;
            analyzer.find_strings(path, min_length).await?
        }
        "analyze_imports" => {
            let path = arguments["path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing path"))?;
            analyzer.analyze_imports(path).await?
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown tool: {}", tool_name));
        }
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": result
        }]
    }))
}
