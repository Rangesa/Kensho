//! MCP ツールハンドラー
//! 
//! 各ツールの実行ロジックを実装

use anyhow::Result;
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
        ObfuscationDetector, CapstoneTranslator, ControlFlowGraph, ObfuscationPatternType
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
