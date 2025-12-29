use anyhow::{Result, Context};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, error};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

mod hierarchical_analyzer;
mod disassembler;
mod decompiler;
mod ghidra_headless;

// Ghidraデコンパイラコアのプロトタイプ実装（新規追加）
mod decompiler_prototype;

// メモリスキャナ（Windows専用）
#[cfg(windows)]
mod memory_scanner;

use hierarchical_analyzer::HierarchicalAnalyzer;
use ghidra_headless::GhidraHeadless;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    info!("🦀 Kensho MCP Hierarchical Server starting...");

    // 階層的解析器を初期化（キャッシュ機能付き）
    let analyzer = Arc::new(Mutex::new(HierarchicalAnalyzer::new()));

    // Ghidra Headless初期化（オプショナル）
    let ghidra = if let Ok(ghidra_path) = std::env::var("GHIDRA_PATH") {
        match GhidraHeadless::new(&ghidra_path) {
            Ok(gh) => {
                info!("✅ Ghidra Headless enabled at: {}", ghidra_path);
                // ディスクキャッシュをロード
                if let Err(e) = gh.load_cache_from_disk() {
                    error!("Failed to load Ghidra cache: {}", e);
                }
                Some(Arc::new(Mutex::new(gh)))
            }
            Err(e) => {
                error!("Failed to initialize Ghidra Headless: {}", e);
                None
            }
        }
    } else {
        info!("💡 Ghidra Headless disabled (GHIDRA_PATH not set)");
        None
    };

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    info!("🚀 Server ready (Hierarchical Analysis Mode)");

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let response = match process_request(&line, Arc::clone(&analyzer), ghidra.clone()).await {
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

async fn process_request(
    request_str: &str,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
    ghidra: Option<Arc<Mutex<GhidraHeadless>>>,
) -> Result<McpResponse> {
    let request: McpRequest = serde_json::from_str(request_str)?;
    
    info!("Processing method: {}", request.method);

    let result = match request.method.as_str() {
        "initialize" => handle_initialize().await?,
        "tools/list" => handle_list_tools(ghidra.is_some()).await?,
        "tools/call" => handle_tool_call(request.params, analyzer, ghidra).await?,
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

async fn handle_list_tools(ghidra_enabled: bool) -> Result<Value> {
    let mut tools = vec![
            // 階層1: サマリー（必ず最初に呼ぶ）
            json!({
                "name": "get_binary_summary",
                "description": "バイナリの概要情報を取得（超軽量、統計のみ）。最初に必ずこれを呼んで全体像を把握する",
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
            }),

            // 階層2: セクション一覧
            json!({
                "name": "list_sections",
                "description": "セクション一覧を取得（ページネーション対応）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "page": {
                            "type": "integer",
                            "description": "ページ番号（0開始）",
                            "default": 0
                        },
                        "page_size": {
                            "type": "integer",
                            "description": "1ページあたりの件数",
                            "default": 20
                        }
                    },
                    "required": ["path"]
                }
            }),

            // 階層2: 関数一覧（ページネーション + フィルタリング対応）
            json!({
                "name": "list_functions",
                "description": "関数一覧を取得（ページネーション対応、名前フィルタ可能）。大規模バイナリでは必ずフィルタ使用を推奨",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "page": {
                            "type": "integer",
                            "description": "ページ番号",
                            "default": 0
                        },
                        "page_size": {
                            "type": "integer",
                            "description": "1ページあたりの件数（推奨: 20-100）",
                            "default": 50
                        },
                        "name_filter": {
                            "type": "string",
                            "description": "関数名フィルタ（部分一致）。例: 'update', 'render', 'network'",
                        }
                    },
                    "required": ["path"]
                }
            }),

            // 階層2: 文字列一覧
            json!({
                "name": "list_strings",
                "description": "バイナリ内の文字列を取得（ページネーション対応）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "page": {"type": "integer", "default": 0},
                        "page_size": {"type": "integer", "default": 100},
                        "min_length": {
                            "type": "integer",
                            "description": "最小文字列長",
                            "default": 4
                        }
                    },
                    "required": ["path"]
                }
            }),

            // 階層3: 関数詳細解析（重い操作、必要な関数のみ）
            json!({
                "name": "analyze_function_detail",
                "description": "特定の関数を詳細解析（逆アセンブル + デコンパイル）。コンテキスト消費大なので、本当に必要な関数のみ実行",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "function_address": {
                            "type": "string",
                            "description": "関数のアドレス（16進数: 0x140001000）"
                        }
                    },
                    "required": ["path", "function_address"]
                }
            }),

            // 便利ツール: インポート（小規模なので全件OK）
            json!({
                "name": "list_imports",
                "description": "インポート関数一覧（通常は数百〜数千件なので全件返す）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"}
                    },
                    "required": ["path"]
                }
            }),

            // ネイティブデコンパイラ（P-code + SSA + 型推論 + 制御構造）
            json!({
                "name": "decompile_function_native",
                "description": "ネイティブデコンパイラで関数を解析（P-code生成、SSA変換、型推論、制御構造検出）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "バイナリファイルパス"
                        },
                        "function_address": {
                            "type": "string",
                            "description": "関数のアドレス（16進数: 0x140001000）"
                        },
                        "max_instructions": {
                            "type": "integer",
                            "description": "最大命令数",
                            "default": 1000
                        }
                    },
                    "required": ["path", "function_address"]
                }
            }),

            // エクスポート関数検出
            json!({
                "name": "detect_export_functions",
                "description": "PEファイルからエクスポート関数を検出",
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
            }),

            // 並列デコンパイル（キャッシュ付き）
            json!({
                "name": "decompile_function_cached",
                "description": "キャッシュ機能付き高速デコンパイル（2回目以降は即座に結果を返す）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "バイナリファイルパス"
                        },
                        "function_address": {
                            "type": "string",
                            "description": "関数のアドレス（16進数: 0x140001000）"
                        },
                        "file_offset": {
                            "type": "string",
                            "description": "ファイルオフセット（16進数: 0x600）"
                        },
                        "max_instructions": {
                            "type": "integer",
                            "description": "最大命令数",
                            "default": 1000
                        }
                    },
                    "required": ["path", "function_address", "file_offset"]
                }
            }),

            // Phase 1: メモリダンプからのデコンパイル（パッキング対策）
            json!({
                "name": "decompile_memory_dump",
                "description": "メモリダンプから関数をデコンパイル（キャッシュ対応、パッキング対策）",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dump_path": {
                            "type": "string",
                            "description": "ダンプファイルパス（拡張子なし、.dump.json/.dump.binが自動追加）"
                        },
                        "function_offset": {
                            "type": "string",
                            "description": "関数のオフセット（16進数: 0x1000）"
                        },
                        "max_instructions": {
                            "type": "integer",
                            "description": "最大命令数",
                            "default": 1000
                        }
                    },
                    "required": ["dump_path", "function_offset"]
                }
            })
    ];

    // Ghidra連携ツールを追加（有効な場合のみ）
    if ghidra_enabled {
        tools.push(json!({
            "name": "decompile_with_ghidra",
            "description": "Ghidra Headlessで高品質デコンパイル（初回は遅いがキャッシュ有効）",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "バイナリファイルパス"
                    },
                    "function_address": {
                        "type": "string",
                        "description": "関数のアドレス（16進数: 0x140001000）"
                    }
                },
                "required": ["path", "function_address"]
            }
        }));
    }

    // Windows専用: プロセスメモリダンプツール（パッキング対策）
    #[cfg(windows)]
    {
        tools.push(json!({
            "name": "dump_process_memory",
            "description": "プロセスメモリをダンプしてファイルに保存（パッキング対策、Windows専用）",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "process_name": {
                        "type": "string",
                        "description": "プロセス名またはPID"
                    },
                    "address": {
                        "type": "string",
                        "description": "ダンプ開始アドレス（16進数: 0x140000000）"
                    },
                    "size": {
                        "type": "integer",
                        "description": "ダンプサイズ（バイト）",
                        "default": 1048576
                    },
                    "output_path": {
                        "type": "string",
                        "description": "出力パス（拡張子なし、.dump.json/.dump.binが自動追加）"
                    }
                },
                "required": ["process_name", "address", "output_path"]
            }
        }));
    }

    Ok(json!({
        "tools": tools
    }))
}

async fn handle_tool_call(
    params: Option<Value>,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
    ghidra: Option<Arc<Mutex<GhidraHeadless>>>,
) -> Result<Value> {
    let params = params.ok_or_else(|| anyhow::anyhow!("Missing params"))?;
    let tool_name = params["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing tool name"))?;
    let arguments = &params["arguments"];

    info!("Calling tool: {}", tool_name);

    let result = match tool_name {
        "get_binary_summary" => {
            let path = arguments["path"].as_str().unwrap();
            let mut analyzer = analyzer.lock().await;
            let summary = analyzer.get_summary(path)?;
            serde_json::to_value(summary)?
        }
        
        "list_sections" => {
            let path = arguments["path"].as_str().unwrap();
            let page = arguments["page"].as_u64().unwrap_or(0) as usize;
            let page_size = arguments["page_size"].as_u64().unwrap_or(20) as usize;
            
            let mut analyzer = analyzer.lock().await;
            let sections = analyzer.list_sections(path, page, page_size)?;
            serde_json::to_value(sections)?
        }
        
        "list_functions" => {
            let path = arguments["path"].as_str().unwrap();
            let page = arguments["page"].as_u64().unwrap_or(0) as usize;
            let page_size = arguments["page_size"].as_u64().unwrap_or(50) as usize;
            let name_filter = arguments["name_filter"].as_str();
            
            let mut analyzer = analyzer.lock().await;
            let functions = analyzer.list_functions(path, page, page_size, name_filter)?;
            serde_json::to_value(functions)?
        }
        
        "list_strings" => {
            let path = arguments["path"].as_str().unwrap();
            let page = arguments["page"].as_u64().unwrap_or(0) as usize;
            let page_size = arguments["page_size"].as_u64().unwrap_or(100) as usize;
            let min_length = arguments["min_length"].as_u64().unwrap_or(4) as usize;
            
            let mut analyzer = analyzer.lock().await;
            let strings = analyzer.list_strings(path, page, page_size, min_length)?;
            serde_json::to_value(strings)?
        }
        
        "analyze_function_detail" => {
            let path = arguments["path"].as_str().unwrap();
            let addr_str = arguments["function_address"].as_str().unwrap();
            
            let address = if addr_str.starts_with("0x") {
                u64::from_str_radix(&addr_str[2..], 16)?
            } else {
                addr_str.parse()?
            };
            
            let mut analyzer = analyzer.lock().await;
            let detail = analyzer.analyze_function_detail(path, address)?;
            serde_json::to_value(detail)?
        }
        
        "list_imports" => {
            let path = arguments["path"].as_str().unwrap();
            let mut analyzer = analyzer.lock().await;
            let imports = analyzer.list_imports(path)?;
            serde_json::to_value(imports)?
        }

        "decompile_function_native" => {
            let path = arguments["path"].as_str().unwrap();
            let addr_str = arguments["function_address"].as_str().unwrap();
            let max_instructions = arguments["max_instructions"].as_u64().unwrap_or(1000) as usize;

            let address = if addr_str.starts_with("0x") {
                u64::from_str_radix(&addr_str[2..], 16)?
            } else {
                addr_str.parse()?
            };

            // バイナリファイルを読み込み
            let binary_data = std::fs::read(path)?;

            // Capstone Translatorを使用してP-codeに変換
            use decompiler_prototype::{
                CapstoneTranslator, SSATransform, TypeInference,
                ControlFlowAnalyzer, ControlStructurePrinter, ControlFlowGraph
            };

            let mut translator = CapstoneTranslator::new()?;

            // 関数のコードを抽出（簡易版: addressから最大max_instructions分）
            let offset = address as usize;
            let code_slice = if offset < binary_data.len() {
                let end = std::cmp::min(offset + max_instructions * 15, binary_data.len());
                &binary_data[offset..end]
            } else {
                &[]
            };

            // P-codeに変換
            let pcodes = translator.translate(code_slice, address, max_instructions)?;

            // CFGを構築
            let mut cfg = ControlFlowGraph::from_pcodes(pcodes.clone());

            // SSA変換
            let mut ssa = SSATransform::new();
            ssa.transform(&mut cfg);

            // 型推論
            let mut type_inference = TypeInference::new();
            type_inference.run(&pcodes);

            // 制御構造解析
            let mut analyzer = ControlFlowAnalyzer::new();
            let structure = analyzer.analyze(&cfg);

            // 結果を整形
            let mut printer = ControlStructurePrinter::new();
            let structure_str = printer.print(&structure);

            // 型情報を整形
            let type_info: Vec<String> = type_inference.get_all_types()
                .iter()
                .map(|(varnode, ty)| {
                    format!("{:?} :: {}", varnode, ty.to_c_string())
                })
                .collect();

            json!({
                "function_address": format!("0x{:x}", address),
                "instruction_count": pcodes.len(),
                "control_structure": structure_str,
                "type_inference": type_info,
                "loops_detected": analyzer.get_loops().len(),
                "backend": "Native Decompiler (P-code + SSA + Type Inference)"
            })
        }

        "detect_export_functions" => {
            use decompiler_prototype::{FunctionDetector};
            use goblin::pe::PE;

            let path = arguments["path"].as_str().unwrap();
            let binary_data = std::fs::read(path)?;
            let pe = PE::parse(&binary_data)?;

            let mut detector = FunctionDetector::new();
            let image_base = pe.image_base as u64;
            detector.detect_exports(&pe, image_base)?;

            let export_functions: Vec<_> = detector.get_export_functions()
                .iter()
                .map(|f| {
                    json!({
                        "name": f.name.as_ref().unwrap_or(&"<unnamed>".to_string()),
                        "address": format!("0x{:X}", f.start_address),
                        "is_export": f.is_export
                    })
                })
                .collect();

            let stats = detector.get_statistics();

            json!({
                "export_functions": export_functions,
                "statistics": {
                    "total_functions": stats.total_functions,
                    "export_functions": stats.export_functions
                }
            })
        }

        "decompile_function_cached" => {
            use decompiler_prototype::ParallelDecompiler;
            use std::env;
            use std::path::Path;

            let path = arguments["path"].as_str().unwrap();
            let addr_str = arguments["function_address"].as_str().unwrap();
            let offset_str = arguments["file_offset"].as_str().unwrap();
            let max_instructions = arguments["max_instructions"].as_u64().unwrap_or(1000) as usize;

            let address = if addr_str.starts_with("0x") {
                u64::from_str_radix(&addr_str[2..], 16)?
            } else {
                addr_str.parse()?
            };

            let file_offset = if offset_str.starts_with("0x") {
                usize::from_str_radix(&offset_str[2..], 16)?
            } else {
                offset_str.parse()?
            };

            // キャッシュディレクトリを設定
            let cache_dir = env::temp_dir().join("kensho_mcp_cache");
            let decompiler = ParallelDecompiler::new(&cache_dir)?;

            // バイナリをロード
            let binary_data = std::fs::read(path)?;
            let binary_path = Path::new(path);

            // デコンパイル（キャッシュ付き）
            let result = decompiler.decompile_function_cached(
                Some(binary_path),
                &binary_data,
                address,
                file_offset,
                max_instructions,
            )?;

            let cache_stats = decompiler.get_cache_stats();

            json!({
                "function_address": format!("0x{:X}", result.address),
                "pcode_count": result.pcode_count,
                "block_count": result.block_count,
                "type_count": result.type_count,
                "loop_count": result.loop_count,
                "control_structure": result.control_structure,
                "cached_at": result.cached_at,
                "cache_stats": {
                    "memory_cached_binaries": cache_stats.memory_cached_binaries,
                    "disk_cached_binaries": cache_stats.disk_cached_binaries,
                    "cache_directory": cache_stats.cache_directory
                },
                "backend": "Native Decompiler with Cache"
            })
        }

        "decompile_with_ghidra" => {
            if let Some(ref ghidra) = ghidra {
                let path = arguments["path"].as_str().unwrap();
                let addr_str = arguments["function_address"].as_str().unwrap();

                let address = if addr_str.starts_with("0x") {
                    u64::from_str_radix(&addr_str[2..], 16)?
                } else {
                    addr_str.parse()?
                };

                let ghidra = ghidra.lock().await;
                let decompiled = ghidra.decompile(path, address)?;

                json!({
                    "function_address": format!("0x{:x}", address),
                    "decompiled_code": decompiled,
                    "backend": "Ghidra Headless"
                })
            } else {
                json!({
                    "error": "Ghidra Headless not enabled. Set GHIDRA_PATH environment variable."
                })
            }
        }

        "decompile_memory_dump" => {
            use decompiler_prototype::{MemoryDumpFile, ParallelDecompiler};
            use std::env;

            let dump_path = arguments["dump_path"].as_str().unwrap();
            let offset_str = arguments["function_offset"].as_str().unwrap();
            let max_instructions = arguments["max_instructions"].as_u64().unwrap_or(1000) as usize;

            // Parse offset
            let offset = if offset_str.starts_with("0x") {
                u64::from_str_radix(&offset_str[2..], 16)?
            } else {
                offset_str.parse()?
            };

            // Load dump
            let dump_file = MemoryDumpFile::new(dump_path);
            let (metadata, data) = dump_file.load()
                .context("Failed to load memory dump")?;

            // Decompile from dump
            let cache_dir = env::temp_dir().join("kensho_mcp_cache");
            let decompiler = ParallelDecompiler::new(&cache_dir)?;

            // Calculate function address as base_address + offset
            let function_address = metadata.base_address + offset;

            let result = decompiler.decompile_function_cached(
                None,  // No file path - using in-memory data
                &data,
                function_address,
                offset as usize,  // file_offset = offset in dump
                max_instructions
            )?;

            let cache_stats = decompiler.get_cache_stats();

            json!({
                "process_name": metadata.process_name,
                "pid": metadata.pid,
                "base_address": format!("0x{:x}", metadata.base_address),
                "function_address": format!("0x{:X}", result.address),
                "pcode_count": result.pcode_count,
                "block_count": result.block_count,
                "type_count": result.type_count,
                "loop_count": result.loop_count,
                "control_structure": result.control_structure,
                "cached_at": result.cached_at,
                "cache_stats": {
                    "memory_cached_binaries": cache_stats.memory_cached_binaries,
                    "disk_cached_binaries": cache_stats.disk_cached_binaries,
                    "cache_directory": cache_stats.cache_directory
                },
                "backend": "Memory Dump Decompiler"
            })
        }

        #[cfg(windows)]
        "dump_process_memory" => {
            use decompiler_prototype::{MemoryDumpFile, memory_dump::create_dump_from_scanner};

            let process_name = arguments["process_name"].as_str().unwrap();
            let address_str = arguments["address"].as_str().unwrap();
            let size = arguments["size"].as_u64().unwrap_or(1048576) as usize;
            let output_path = arguments["output_path"].as_str().unwrap();

            // Parse address
            let address = if address_str.starts_with("0x") {
                u64::from_str_radix(&address_str[2..], 16)?
            } else {
                address_str.parse()?
            };

            // Connect to process
            let scanner = memory_scanner::MemoryScanner::from_process_name(process_name)?;

            // Create dump
            let (metadata, data) = create_dump_from_scanner(&scanner, address, size)?;

            // Save to disk
            let dump_file = MemoryDumpFile::new(output_path);
            dump_file.save(&metadata, &data)
                .context("Failed to save memory dump")?;

            json!({
                "success": true,
                "process_name": metadata.process_name,
                "pid": metadata.pid,
                "base_address": format!("0x{:x}", metadata.base_address),
                "size": metadata.size,
                "output_metadata": dump_file.metadata_path().display().to_string(),
                "output_data": dump_file.data_path().display().to_string()
            })
        }

        _ => {
            return Err(anyhow::anyhow!("Unknown tool: {}", tool_name));
        }
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&result)?
        }]
    }))
}
