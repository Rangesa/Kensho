//! Kensho MCP サーバー
//! 
//! バイナリ解析機能をMCP (Model Context Protocol) 経由で提供

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, error};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

use kensho_mcp::hierarchical_analyzer::HierarchicalAnalyzer;
use kensho_mcp::mcp::{get_tool_definitions, dispatch_tool};

// =============================================================================
// MCP プロトコル構造体
// =============================================================================

#[derive(Debug, Deserialize)]
struct McpRequest {
    #[allow(dead_code)]
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
}

// =============================================================================
// エントリーポイント
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stderr).init();

    info!("Kensho MCP Hierarchical Server starting...");

    // 階層的解析器を初期化（キャッシュ機能付き）
    let analyzer = Arc::new(Mutex::new(HierarchicalAnalyzer::new()));

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    info!("Server ready (Hierarchical Analysis Mode)");

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
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

// =============================================================================
// リクエスト処理
// =============================================================================

async fn process_request(
    request_str: &str,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
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

// =============================================================================
// プロトコルハンドラー
// =============================================================================

async fn handle_initialize() -> Result<Value> {
    Ok(json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "kensho-mcp-hierarchical",
            "version": "2.0.0",
            "description": "Hierarchical binary analysis - prevents context overflow"
        }
    }))
}

async fn handle_list_tools() -> Result<Value> {
    let tools = get_tool_definitions();
    Ok(json!({ "tools": tools }))
}

async fn handle_tool_call(
    params: Option<Value>,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
) -> Result<Value> {
    let params = params.ok_or_else(|| anyhow::anyhow!("Missing params"))?;
    let tool_name = params["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing tool name"))?;
    let arguments = &params["arguments"];

    dispatch_tool(tool_name, arguments, analyzer).await
}

