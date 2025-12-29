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

/// Ghidra鬚ｨ繝阪う繝・ぅ繝邦CP繧ｵ繝ｼ繝舌・
/// Rust螳溯｣・〒雜・ｫ倬溘・霆ｽ驥上↑繝舌う繝翫Μ隗｣譫舌ｒAI繧ｨ繝ｼ繧ｸ繧ｧ繝ｳ繝医↓謠蝉ｾ・#[tokio::main]
async fn main() -> Result<()> {
    // 繝ｭ繧ｰ蛻晄悄蛹・    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    info!("ｦ Ghidra-MCP Native Server starting...");

    // 隗｣譫仙勣繧貞・譛溷喧
    let analyzer = Arc::new(BinaryAnalyzer::new());

    // 讓呎ｺ門・蜃ｺ蜉帙〒MCP騾壻ｿ｡
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    info!("笨・Server ready, waiting for MCP requests...");

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
                "description": "繝舌う繝翫Μ繝輔ぃ繧､繝ｫ縺ｮ蝓ｺ譛ｬ諠・ｱ繧定ｧ｣譫撰ｼ亥ｽ｢蠑上√い繝ｼ繧ｭ繝・け繝√Ε縲√お繝ｳ繝医Μ繝昴う繝ｳ繝育ｭ会ｼ・,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "隗｣譫仙ｯｾ雎｡縺ｮ繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繝代せ"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "disassemble",
                "description": "謖・ｮ壹い繝峨Ξ繧ｹ縺九ｉ騾・い繧ｻ繝ｳ繝悶Ν螳溯｡・,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繝代せ"
                        },
                        "address": {
                            "type": "string",
                            "description": "髢句ｧ九い繝峨Ξ繧ｹ・・6騾ｲ謨ｰ: 0x1000・・
                        },
                        "count": {
                            "type": "integer",
                            "description": "騾・い繧ｻ繝ｳ繝悶Ν縺吶ｋ蜻ｽ莉､謨ｰ・医ョ繝輔か繝ｫ繝・ 20・・,
                            "default": 20
                        }
                    },
                    "required": ["path", "address"]
                }
            },
            {
                "name": "find_functions",
                "description": "繝舌う繝翫Μ蜀・・髢｢謨ｰ繧呈､懷・繝ｻ繝ｪ繧ｹ繝亥喧",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繝代せ"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "decompile_function",
                "description": "髢｢謨ｰ繧堤桝莨ｼC繧ｳ繝ｼ繝峨↓繝・さ繝ｳ繝代う繝ｫ・育ｰ｡譏灘ｮ溯｣・ｼ・,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繝代せ"
                        },
                        "function_name": {
                            "type": "string",
                            "description": "髢｢謨ｰ蜷阪∪縺溘・繧｢繝峨Ξ繧ｹ"
                        }
                    },
                    "required": ["path", "function_name"]
                }
            },
            {
                "name": "find_strings",
                "description": "繝舌う繝翫Μ蜀・・譁・ｭ怜・繧呈歓蜃ｺ",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繝代せ"
                        },
                        "min_length": {
                            "type": "integer",
                            "description": "譛蟆乗枚蟄怜・髟ｷ・医ョ繝輔か繝ｫ繝・ 4・・,
                            "default": 4
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "analyze_imports",
                "description": "繧､繝ｳ繝昴・繝医＆繧後◆髢｢謨ｰ繝ｻ繝ｩ繧､繝悶Λ繝ｪ繧定ｧ｣譫・,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繝代せ"
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
