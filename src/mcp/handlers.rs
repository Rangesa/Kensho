//! MCP ツールハンドラー
//!
//! 各ツールの実行ロジックを実装

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::hierarchical_analyzer::HierarchicalAnalyzer;

/// ツール呼び出しをディスパッチ
pub async fn dispatch_tool(
    tool_name: &str,
    arguments: &Value,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
) -> Result<Value> {
    info!("Dispatching tool: {}", tool_name);

    let result = match tool_name {
        // === 階層1: サマリー ===
        "get_binary_summary" => handle_get_binary_summary(arguments, analyzer).await?,
        
        // === 階層2: 一覧系 ===
        "list_sections" => handle_list_sections(arguments, analyzer).await?,
        "list_functions" => handle_list_functions(arguments, analyzer).await?,
        "list_strings" => handle_list_strings(arguments, analyzer).await?,
        "list_imports" => handle_list_imports(arguments, analyzer).await?,
        
        // === デコンパイラ ===
        "decompile_function" => handle_decompile_function(arguments).await?,
        
        // === 難読化解析 ===
        "detect_obfuscation" => handle_detect_obfuscation(arguments).await?,
        "detect_vm_protection" => handle_detect_vm_protection(arguments).await?,
        "analyze_control_flow_flattening" => handle_analyze_control_flow_flattening(arguments).await?,
        "simplify_mba_expression" => handle_simplify_mba_expression(arguments).await?,

        // === 動的解析（Windows専用） ===
        #[cfg(windows)]
        "trace_function" => handle_trace_function(arguments.as_object().unwrap())?,
        #[cfg(windows)]
        "dump_memory_region" => handle_dump_memory_region(arguments.as_object().unwrap())?,
        #[cfg(windows)]
        "run_in_sandbox" => handle_run_in_sandbox(arguments.as_object().unwrap())?,
        #[cfg(windows)]
        "sandbox_trace" => handle_sandbox_trace(arguments.as_object().unwrap())?,
        #[cfg(windows)]
        "analyze_with_trace" => handle_analyze_with_trace(arguments.as_object().unwrap())?,

        _ => return Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&result)?
        }]
    }))
}

// =============================================================================
// 階層1: サマリー
// =============================================================================

async fn handle_get_binary_summary(
    arguments: &Value,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
) -> Result<Value> {
    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let mut analyzer = analyzer.lock().await;
    let summary = analyzer.get_summary(path)?;
    Ok(serde_json::to_value(summary)?)
}

// =============================================================================
// 階層2: 一覧系
// =============================================================================

async fn handle_list_sections(
    arguments: &Value,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
) -> Result<Value> {
    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let page = arguments["page"].as_u64().unwrap_or(0) as usize;
    let page_size = arguments["page_size"].as_u64().unwrap_or(20) as usize;
    
    let mut analyzer = analyzer.lock().await;
    let sections = analyzer.list_sections(path, page, page_size)?;
    Ok(serde_json::to_value(sections)?)
}

async fn handle_list_functions(
    arguments: &Value,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
) -> Result<Value> {
    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let page = arguments["page"].as_u64().unwrap_or(0) as usize;
    let page_size = arguments["page_size"].as_u64().unwrap_or(50) as usize;
    let name_filter = arguments["name_filter"].as_str();
    
    let mut analyzer = analyzer.lock().await;
    let functions = analyzer.list_functions(path, page, page_size, name_filter)?;
    Ok(serde_json::to_value(functions)?)
}

async fn handle_list_strings(
    arguments: &Value,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
) -> Result<Value> {
    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let page = arguments["page"].as_u64().unwrap_or(0) as usize;
    let page_size = arguments["page_size"].as_u64().unwrap_or(100) as usize;
    let min_length = arguments["min_length"].as_u64().unwrap_or(4) as usize;
    
    let mut analyzer = analyzer.lock().await;
    let strings = analyzer.list_strings(path, page, page_size, min_length)?;
    Ok(serde_json::to_value(strings)?)
}

async fn handle_list_imports(
    arguments: &Value,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
) -> Result<Value> {
    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let mut analyzer = analyzer.lock().await;
    let imports = analyzer.list_imports(path)?;
    Ok(serde_json::to_value(imports)?)
}

// =============================================================================
// デコンパイラ
// =============================================================================

async fn handle_decompile_function(arguments: &Value) -> Result<Value> {
    use crate::decompiler_prototype::{UnifiedDecompiler, DetailLevel};
    use std::env;

    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let addr_str = arguments["function_address"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing function_address"))?;
    let file_offset_str = arguments.get("file_offset").and_then(|v| v.as_str());
    let max_instructions = arguments.get("max_instructions")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000) as usize;
    let cache = arguments.get("cache")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let detail_level_str = arguments.get("detail_level")
        .and_then(|v| v.as_str())
        .unwrap_or("basic");
    let include_disassembly = arguments.get("include_disassembly")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // アドレス解析
    let address = parse_hex_address(addr_str)?;

    // ファイルオフセット解析
    let file_offset = if let Some(offset_str) = file_offset_str {
        Some(parse_hex_offset(offset_str)?)
    } else {
        None
    };

    // 詳細レベル解析
    let detail_level = match detail_level_str {
        "full" => DetailLevel::Full,
        _ => DetailLevel::Basic,
    };

    // 統合デコンパイラ初期化
    let cache_dir = env::temp_dir().join("kensho_mcp_cache");
    let decompiler = UnifiedDecompiler::new(&cache_dir)?;

    // デコンパイル実行
    let result = decompiler.decompile(
        Path::new(path),
        address,
        file_offset,
        max_instructions,
        cache,
        detail_level,
        include_disassembly,
    )?;

    Ok(json!({
        "function_address": format!("0x{:X}", result.function_address),
        "pcode_count": result.pcode_count,
        "block_count": result.block_count,
        "loop_count": result.loop_count,
        "control_structure": result.control_structure,
        "disassembly": result.disassembly,
        "type_inference": result.type_inference,
        "cached_at": result.cached_at
    }))
}

// =============================================================================
// 難読化解析
// =============================================================================

async fn handle_detect_obfuscation(arguments: &Value) -> Result<Value> {
    use crate::decompiler_prototype::{
        ObfuscationDetector, ObfuscationPatternType
    };

    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let addr_str = arguments["function_address"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing function_address"))?;
    let max_instructions = arguments["max_instructions"].as_u64().unwrap_or(1000) as usize;

    let address = parse_hex_address(addr_str)?;
    let (cfg, _) = load_cfg_from_binary(path, address, max_instructions)?;

    // 難読化検出
    let obfuscation_data = ObfuscationDetector::analyze(&cfg);

    Ok(json!({
        "function_address": format!("0x{:x}", address),
        "is_obfuscated": obfuscation_data.overall_score > 0.5,
        "overall_score": obfuscation_data.overall_score,
        "patterns_detected": obfuscation_data.patterns.iter().map(|p| {
            json!({
                "type": format!("{:?}", p.pattern_type),
                "confidence": p.confidence,
                "locations": p.locations.iter().map(|loc| {
                    json!({
                        "block_id": loc.block_id,
                        "op_index": loc.op_index,
                        "address": loc.address.as_ref()
                    })
                }).collect::<Vec<_>>(),
                "description": p.description
            })
        }).collect::<Vec<_>>(),
        "statistics": {
            "total_patterns": obfuscation_data.patterns.len(),
            "mba_count": obfuscation_data.patterns.iter()
                .filter(|p| matches!(p.pattern_type, ObfuscationPatternType::MBAExpression))
                .count(),
            "vm_count": obfuscation_data.patterns.iter()
                .filter(|p| matches!(p.pattern_type, ObfuscationPatternType::VMBasedObfuscation))
                .count(),
            "flattening_count": obfuscation_data.patterns.iter()
                .filter(|p| matches!(p.pattern_type, ObfuscationPatternType::ControlFlowFlattening))
                .count()
        }
    }))
}

async fn handle_detect_vm_protection(arguments: &Value) -> Result<Value> {
    use crate::decompiler_prototype::VMDetector;

    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let addr_str = arguments["function_address"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing function_address"))?;
    let max_instructions = arguments["max_instructions"].as_u64().unwrap_or(1000) as usize;

    let address = parse_hex_address(addr_str)?;
    let (cfg, _) = load_cfg_from_binary(path, address, max_instructions)?;

    // VM保護検出
    let vm_pattern = VMDetector::detect(&cfg);

    Ok(json!({
        "function_address": format!("0x{:x}", address),
        "vm_detected": vm_pattern.is_some(),
        "pattern": vm_pattern.as_ref().map(|p| {
            json!({
                "type": format!("{:?}", p),
                "confidence": 0.8,
                "description": "VM-based obfuscation pattern detected"
            })
        })
    }))
}

async fn handle_analyze_control_flow_flattening(arguments: &Value) -> Result<Value> {
    use crate::decompiler_prototype::FlatteningAnalyzer;

    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let addr_str = arguments["function_address"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing function_address"))?;
    let max_instructions = arguments["max_instructions"].as_u64().unwrap_or(1000) as usize;

    let address = parse_hex_address(addr_str)?;
    let (cfg, _) = load_cfg_from_binary(path, address, max_instructions)?;

    // 制御フロー平坦化解析
    let state_var_opt = FlatteningAnalyzer::analyze(&cfg);
    let is_flattened = state_var_opt.is_some();

    Ok(json!({
        "function_address": format!("0x{:x}", address),
        "is_flattened": is_flattened,
        "state_variable": state_var_opt.as_ref().map(|sv| {
            json!({
                "varnode": format!("{:?}", sv.state_variable),
                "dispatcher_block": sv.dispatcher_block,
                "transitions_count": sv.transitions.len(),
                "confidence": sv.confidence
            })
        }),
        "confidence": if is_flattened { 0.9 } else { 0.0 }
    }))
}

async fn handle_simplify_mba_expression(arguments: &Value) -> Result<Value> {
    use crate::decompiler_prototype::{MBADetector, KenshoMBASimplifier, CapstoneTranslator};

    let path = arguments["path"].as_str().ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let addr_str = arguments["function_address"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing function_address"))?;
    let max_instructions = arguments["max_instructions"].as_u64().unwrap_or(1000) as usize;

    let address = parse_hex_address(addr_str)?;

    // バイナリロード & P-code変換
    let binary_data = std::fs::read(path)?;
    let code_slice = get_code_slice(&binary_data, address, max_instructions);

    let mut translator = CapstoneTranslator::new()?;
    let pcodes = translator.translate(code_slice, address, max_instructions)?;

    // MBA検出
    let mba_patterns = MBADetector::detect(&pcodes);

    // MBA簡約化
    let mut simplifier = KenshoMBASimplifier::new();
    let simplified_result = simplifier.simplify_with_kensho(&pcodes);
    let stats = simplifier.stats();

    Ok(json!({
        "function_address": format!("0x{:x}", address),
        "mba_patterns_detected": mba_patterns.len(),
        "simplification_found": simplified_result.is_some(),
        "patterns": mba_patterns.iter().map(|p| {
            json!({
                "type": format!("{:?}", p),
                "description": "MBA obfuscation pattern"
            })
        }).collect::<Vec<_>>(),
        "simplified_expression": simplified_result.as_ref().map(|s| {
            json!({
                "expression": &s.expression,
                "verification": format!("{:?}", s.verification),
                "rules_applied": s.rules_applied.iter().map(|r| format!("{:?}", r)).collect::<Vec<_>>()
            })
        }),
        "statistics": {
            "verifications": stats.verifications,
            "successful_simplifications": stats.successful_simplifications,
            "cache_hits": stats.cache_hits,
            "total_verification_time_ms": stats.total_verification_time_ms
        }
    }))
}

// =============================================================================
// ヘルパー関数
// =============================================================================

/// 16進数アドレス文字列をパース
fn parse_hex_address(addr_str: &str) -> Result<u64> {
    if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
        Ok(u64::from_str_radix(&addr_str[2..], 16)?)
    } else {
        Ok(addr_str.parse()?)
    }
}

/// 16進数オフセット文字列をパース
fn parse_hex_offset(offset_str: &str) -> Result<usize> {
    if offset_str.starts_with("0x") || offset_str.starts_with("0X") {
        Ok(usize::from_str_radix(&offset_str[2..], 16)?)
    } else {
        Ok(offset_str.parse()?)
    }
}

/// バイナリからCFGをロード
fn load_cfg_from_binary(
    path: &str,
    address: u64,
    max_instructions: usize,
) -> Result<(crate::decompiler_prototype::ControlFlowGraph, Vec<crate::decompiler_prototype::PcodeOp>)> {
    use crate::decompiler_prototype::{CapstoneTranslator, ControlFlowGraph};

    let binary_data = std::fs::read(path)?;
    let code_slice = get_code_slice(&binary_data, address, max_instructions);

    let mut translator = CapstoneTranslator::new()?;
    let pcodes = translator.translate(code_slice, address, max_instructions)?;
    let cfg = ControlFlowGraph::from_pcodes(pcodes.clone());

    Ok((cfg, pcodes))
}

/// バイナリデータからコードスライスを取得
fn get_code_slice(binary_data: &[u8], address: u64, max_instructions: usize) -> &[u8] {
    let offset = address as usize;
    if offset < binary_data.len() {
        let end = std::cmp::min(offset + max_instructions * 15, binary_data.len());
        &binary_data[offset..end]
    } else {
        &[]
    }
}

// =============================================================================
// 動的解析ハンドラー（Windows専用）
// =============================================================================

#[cfg(windows)]
pub fn handle_trace_function(arguments: &serde_json::Map<String, serde_json::Value>) -> Result<Value> {
    use crate::dynamic_analysis::{FunctionTracer, TraceResult};

    let pid = arguments["pid"].as_u64().ok_or_else(|| anyhow!("Invalid PID"))? as u32;
    let addr_str = arguments["function_address"].as_str().unwrap();
    let max_instructions = arguments
        .get("max_instructions")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000) as usize;

    // アドレス解析
    let address = if addr_str.starts_with("0x") {
        u64::from_str_radix(&addr_str[2..], 16)?
    } else {
        addr_str.parse()?
    };

    // トレース実行
    let mut tracer = FunctionTracer::new(pid)?;
    let traces = tracer.trace_function(address, max_instructions)?;

    let result = TraceResult::new(address, traces);

    Ok(serde_json::to_value(&result)?)
}

#[cfg(windows)]
pub fn handle_dump_memory_region(arguments: &serde_json::Map<String, serde_json::Value>) -> Result<Value> {
    use crate::dynamic_analysis::ProcessDebugger;

    let pid = arguments["pid"].as_u64().ok_or_else(|| anyhow!("Invalid PID"))? as u32;
    let addr_str = arguments["address"].as_str().unwrap();
    let size = arguments
        .get("size")
        .and_then(|v| v.as_u64())
        .unwrap_or(4096) as usize;

    // アドレス解析
    let address = if addr_str.starts_with("0x") {
        u64::from_str_radix(&addr_str[2..], 16)?
    } else {
        addr_str.parse()?
    };

    // メモリダンプ
    let debugger = ProcessDebugger::attach(pid)?;
    let memory = debugger.read_memory(address, size)?;

    // Base64エンコード
    let encoded = base64_encode(&memory);

    Ok(json!({
        "address": format!("0x{:X}", address),
        "size": memory.len(),
        "data_base64": encoded,
        "data_hex": hex_encode(&memory[..std::cmp::min(256, memory.len())]) // 最初の256バイトのみhex表示
    }))
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(windows)]
pub fn handle_run_in_sandbox(arguments: &serde_json::Map<String, serde_json::Value>) -> Result<Value> {
    use crate::dynamic_analysis::{SandboxConfig, SandboxedProcess};

    let exe_path = arguments["exe_path"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing exe_path"))?;
    let args = arguments.get("args").and_then(|v| v.as_str());
    let memory_limit_mb = arguments
        .get("memory_limit_mb")
        .and_then(|v| v.as_u64())
        .unwrap_or(512) as usize;
    let timeout_ms = arguments
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30000) as u32;

    // サンドボックス設定
    let config = SandboxConfig {
        memory_limit: memory_limit_mb * 1024 * 1024,
        cpu_time_limit: 0,
        process_limit: 1,
        restrict_ui: true,
        restrict_network: false,
        low_integrity: true,
        kill_on_close: true,
    };

    // サンドボックス内でプロセス起動
    let process = SandboxedProcess::spawn(exe_path, args, config)?;
    let pid = process.process_id();

    // 完了待機
    let result = process.wait(timeout_ms)?;

    Ok(json!({
        "success": true,
        "process_id": pid,
        "exit_code": result.exit_code,
        "memory_peak": result.memory_peak,
        "terminated_by_limit": result.terminated_by_limit,
        "sandbox_config": {
            "memory_limit_mb": memory_limit_mb,
            "timeout_ms": timeout_ms,
            "restricted_privileges": true,
            "ui_restricted": true
        }
    }))
}

#[cfg(windows)]
pub fn handle_sandbox_trace(arguments: &serde_json::Map<String, serde_json::Value>) -> Result<Value> {
    use crate::dynamic_analysis::{SandboxConfig, SandboxedProcess, FunctionTracer, TraceResult};

    let exe_path = arguments["exe_path"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing exe_path"))?;
    let addr_str = arguments["function_address"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing function_address"))?;
    let args = arguments.get("args").and_then(|v| v.as_str());
    let max_instructions = arguments
        .get("max_instructions")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000) as usize;
    let memory_limit_mb = arguments
        .get("memory_limit_mb")
        .and_then(|v| v.as_u64())
        .unwrap_or(512) as usize;

    // アドレス解析
    let address = if addr_str.starts_with("0x") {
        u64::from_str_radix(&addr_str[2..], 16)?
    } else {
        addr_str.parse()?
    };

    // サンドボックス設定（トレース用に調整）
    let config = SandboxConfig {
        memory_limit: memory_limit_mb * 1024 * 1024,
        cpu_time_limit: 0,
        process_limit: 1,
        restrict_ui: true,
        restrict_network: false,
        low_integrity: true,
        kill_on_close: true,
    };

    // サンドボックス内でプロセス起動
    let process = SandboxedProcess::spawn(exe_path, args, config)?;
    let pid = process.process_id();

    // トレース実行
    let mut tracer = FunctionTracer::new(pid)?;
    let traces = tracer.trace_function(address, max_instructions)?;
    let trace_result = TraceResult::new(address, traces);

    // プロセス終了待機（短いタイムアウト）
    let _ = process.wait(5000);

    Ok(json!({
        "success": true,
        "sandbox": {
            "process_id": pid,
            "memory_limit_mb": memory_limit_mb,
            "restricted": true
        },
        "trace": trace_result
    }))
}

#[cfg(windows)]
pub fn handle_analyze_with_trace(arguments: &serde_json::Map<String, serde_json::Value>) -> Result<Value> {
    use crate::dynamic_analysis::{SandboxConfig, SandboxedProcess, FunctionTracer, TraceResult};
    use crate::decompiler_prototype::{
        CapstoneTranslator, ControlFlowGraph, ObfuscationDetector, ObfuscationPatternType
    };
    use std::collections::HashSet;

    let exe_path = arguments["exe_path"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing exe_path"))?;
    let addr_str = arguments["function_address"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing function_address"))?;
    let args = arguments.get("args").and_then(|v| v.as_str());
    let max_instructions = arguments
        .get("max_instructions")
        .and_then(|v| v.as_u64())
        .unwrap_or(500) as usize;
    let memory_limit_mb = arguments
        .get("memory_limit_mb")
        .and_then(|v| v.as_u64())
        .unwrap_or(256) as usize;
    let detect_obfuscation = arguments
        .get("detect_obfuscation")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // アドレス解析
    let address = if addr_str.starts_with("0x") {
        u64::from_str_radix(&addr_str[2..], 16)?
    } else {
        addr_str.parse()?
    };

    // ===========================================
    // Phase 1: 動的解析（サンドボックス + トレース）
    // ===========================================
    let config = SandboxConfig {
        memory_limit: memory_limit_mb * 1024 * 1024,
        cpu_time_limit: 0,
        process_limit: 1,
        restrict_ui: true,
        restrict_network: false,
        low_integrity: true,
        kill_on_close: true,
    };

    let process = SandboxedProcess::spawn(exe_path, args, config)?;
    let pid = process.process_id();

    // プロセス初期化待機（100ms）
    std::thread::sleep(std::time::Duration::from_millis(100));

    // トレース実行（エラーをグレースフルに処理）
    let (traces, trace_error) = match FunctionTracer::new(pid) {
        Ok(mut tracer) => {
            match tracer.trace_function(address, max_instructions) {
                Ok(t) => (t, None),
                Err(e) => (Vec::new(), Some(e.to_string()))
            }
        }
        Err(e) => (Vec::new(), Some(e.to_string()))
    };

    // プロセス終了待機
    let sandbox_result = process.wait(5000);

    // 実行されたアドレスを収集
    let executed_addresses: Vec<u64> = traces.iter().map(|t| t.address).collect();
    let unique_addresses: HashSet<u64> = executed_addresses.iter().cloned().collect();
    let execution_path: Vec<String> = executed_addresses
        .iter()
        .take(50)  // 最初の50命令のみ表示
        .map(|a| format!("0x{:X}", a))
        .collect();

    // ===========================================
    // Phase 2: 静的解析（デコンパイル + 難読化検出）
    // ===========================================
    let binary_data = std::fs::read(exe_path)?;

    // 静的解析結果
    let mut static_analysis = json!({
        "success": false,
        "error": null,
        "pcode_count": 0,
        "block_count": 0,
        "obfuscation": null
    });

    // バイナリからコードを抽出して解析
    if let Some(code_offset) = find_code_offset_for_address(&binary_data, address) {
        let code_slice = &binary_data[code_offset..std::cmp::min(code_offset + max_instructions * 15, binary_data.len())];

        if let Ok(mut translator) = CapstoneTranslator::new() {
            if let Ok(pcodes) = translator.translate(code_slice, address, max_instructions) {
                let cfg = ControlFlowGraph::from_pcodes(pcodes.clone());

                static_analysis["success"] = json!(true);
                static_analysis["pcode_count"] = json!(pcodes.len());
                static_analysis["block_count"] = json!(cfg.blocks.len());

                // 難読化検出
                if detect_obfuscation {
                    let obf_data = ObfuscationDetector::analyze(&cfg);
                    static_analysis["obfuscation"] = json!({
                        "detected": obf_data.overall_score > 0.3,
                        "score": obf_data.overall_score,
                        "patterns": obf_data.patterns.iter().map(|p| {
                            json!({
                                "type": format!("{:?}", p.pattern_type),
                                "confidence": p.confidence,
                                "description": &p.description
                            })
                        }).collect::<Vec<_>>(),
                        "mba_count": obf_data.patterns.iter()
                            .filter(|p| matches!(p.pattern_type, ObfuscationPatternType::MBAExpression))
                            .count(),
                        "vm_count": obf_data.patterns.iter()
                            .filter(|p| matches!(p.pattern_type, ObfuscationPatternType::VMBasedObfuscation))
                            .count()
                    });
                }
            }
        }
    }

    // ===========================================
    // Phase 3: 統合分析（動的値 + 静的構造）
    // ===========================================
    let mut insights: Vec<String> = Vec::new();

    // 実行パス分析
    insights.push(format!(
        "実行された命令数: {} (ユニーク: {})",
        executed_addresses.len(),
        unique_addresses.len()
    ));

    // 分岐パターン分析
    if executed_addresses.len() > 1 {
        let mut branch_count = 0;
        for i in 1..executed_addresses.len() {
            let diff = executed_addresses[i] as i64 - executed_addresses[i-1] as i64;
            if diff.abs() > 20 {
                branch_count += 1;
            }
        }
        if branch_count > 0 {
            insights.push(format!("検出された分岐: {} 回", branch_count));
        }
    }

    // 動的値サンプル（最初の5命令のレジスタ値）
    let dynamic_samples: Vec<Value> = traces
        .iter()
        .take(5)
        .map(|t| {
            json!({
                "address": format!("0x{:X}", t.address),
                "rax": format!("0x{:X}", t.registers.rax),
                "rcx": format!("0x{:X}", t.registers.rcx),
                "rdx": format!("0x{:X}", t.registers.rdx),
                "rsp": format!("0x{:X}", t.registers.rsp)
            })
        })
        .collect();

    // 難読化と動的値の組み合わせ分析
    if let Some(obf) = static_analysis["obfuscation"].as_object() {
        if obf.get("detected").and_then(|v| v.as_bool()).unwrap_or(false) {
            insights.push("難読化が検出されました - 動的値と比較して実際の挙動を確認推奨".to_string());
        }
    }

    Ok(json!({
        "success": true,
        "function_address": format!("0x{:X}", address),

        "dynamic_analysis": {
            "sandbox": {
                "process_id": pid,
                "memory_limit_mb": memory_limit_mb,
                "exit_code": sandbox_result.as_ref().map(|r| r.exit_code).ok()
            },
            "trace": {
                "success": trace_error.is_none(),
                "error": trace_error,
                "total_instructions": executed_addresses.len(),
                "unique_addresses": unique_addresses.len(),
                "execution_path": execution_path,
                "register_samples": dynamic_samples
            }
        },

        "static_analysis": static_analysis,

        "combined_insights": {
            "summary": insights,
            "recommendation": if trace_error.is_some() {
                "トレース失敗 - 静的解析結果のみ参照可能"
            } else if unique_addresses.len() < 10 {
                "トレース命令数が少ない - 開始アドレスまたはタイミングの調整を推奨"
            } else if static_analysis["obfuscation"]["detected"].as_bool().unwrap_or(false) {
                "難読化検出 - 動的値を参考に手動解析を推奨"
            } else {
                "正常に解析完了"
            }
        }
    }))
}

/// バイナリ内のアドレスに対応するファイルオフセットを推定
#[cfg(windows)]
fn find_code_offset_for_address(binary_data: &[u8], address: u64) -> Option<usize> {
    // PE形式の場合、セクションヘッダーから計算
    // 簡易実装: アドレスの下位ビットをオフセットとして使用
    let offset = (address & 0xFFFF) as usize;
    if offset < binary_data.len() {
        Some(offset)
    } else if address < binary_data.len() as u64 {
        Some(address as usize)
    } else {
        // .textセクションの典型的なオフセット
        Some(0x400.min(binary_data.len().saturating_sub(1)))
    }
}
