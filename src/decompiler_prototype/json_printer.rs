/// JSON output printer for decompilation results
/// Outputs structured JSON format for machine consumption

use serde::{Serialize, Deserialize};
use super::cfg::{ControlFlowGraph, BasicBlock};
use super::pcode::{PcodeOp, Varnode, AddressSpace, OpCode};
use super::dataflow::DefUseChain;
use super::obfuscation_detector::{ObfuscationDetector, ObfuscationData};
use anyhow::{Result, Context};
use chrono::Utc;

// Top-level structure

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalysisResult {
    pub format_version: String,
    pub analysis_timestamp: String,
    pub binary: BinaryInfo,
    pub function: FunctionInfo,
    pub cfg: CfgData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataflow: Option<DataflowData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_inference: Option<TypeInferenceData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols: Option<SymbolsData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<ObfuscationData>,
    pub confidence: ConfidenceScores,
    pub metadata: AnalysisMetadata,
}

// Binary information

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BinaryInfo {
    pub path: String,
    pub architecture: String,
    pub format: String,  // "PE", "ELF", "Mach-O"
}

// Function information

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionInfo {
    pub address: String,
    pub size: usize,
    pub entry_point: String,
    pub exit_points: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<FunctionName>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionName {
    pub known: bool,
    pub value: String,
    pub source: NameSource,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum NameSource {
    Dwarf,
    Pdb,
    Export,
    Inferred,
}

// CFG data

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CfgData {
    pub entry_block: usize,
    pub blocks: Vec<BlockData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockData {
    pub id: usize,
    pub address: String,
    pub size: usize,
    pub ops: Vec<PcodeOpData>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PcodeOpData {
    pub opcode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<VarnodeData>,
    pub inputs: Vec<VarnodeData>,
    pub address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VarnodeData {
    pub space: String,  // "register", "const", "unique", "ram", "stack"
    pub offset: u64,
    pub size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

// Dataflow analysis

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataflowData {
    pub def_use_chains: Vec<DefUseChainData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DefUseChainData {
    pub definition: OpLocation,
    pub uses: Vec<OpLocation>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpLocation {
    pub block: usize,
    pub op: usize,
}

// Type inference data

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TypeInferenceData {
    pub varnodes: Vec<VarnodeTypeInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VarnodeTypeInfo {
    pub varnode: VarnodeData,
    pub inferred_type: String,
    pub confidence: f64,
}

// Symbol information

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SymbolsData {
    pub functions: Vec<FunctionSymbol>,
    pub variables: Vec<VariableSymbol>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionSymbol {
    pub address: String,
    pub name: String,
    pub source: NameSource,
    pub confidence: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VariableSymbol {
    pub address: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    pub source: NameSource,
}

// Confidence scores

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfidenceScores {
    pub control_flow: f64,     // CFG construction confidence
    pub data_types: f64,       // Type inference confidence
    pub variable_names: f64,   // Variable naming confidence
    pub function_purpose: f64, // Function purpose estimation confidence
}

// Metadata

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalysisMetadata {
    pub optimizations_applied: Vec<String>,
    pub analysis_time_ms: f64,
    pub cache_hit: bool,
}

// JSON Printer

pub struct JsonPrinter;

impl JsonPrinter {
    /// Print analysis results as JSON
    pub fn print_analysis(
        cfg: &ControlFlowGraph,
        dataflow: Option<&DefUseChain>,
        binary_path: Option<&str>,
    ) -> Result<String> {
        let start_time = std::time::Instant::now();

        // Analyze obfuscation patterns
        let obfuscation = Some(ObfuscationDetector::analyze(cfg));

        let result = AnalysisResult {
            format_version: "1.0".to_string(),
            analysis_timestamp: Utc::now().to_rfc3339(),
            binary: Self::build_binary_info(binary_path),
            function: Self::build_function_info(cfg)?,
            cfg: Self::build_cfg_data(cfg)?,
            dataflow: dataflow.map(|df| Self::build_dataflow_data(df)),
            type_inference: None,  // TODO: Implement in Task 4
            symbols: None,         // TODO: Implement in Task 6,7
            obfuscation,           // Phase 2: Obfuscation detection
            confidence: Self::calculate_confidence(cfg),
            metadata: Self::build_metadata(start_time),
        };

        serde_json::to_string_pretty(&result)
            .context("JSON serialization failed")
    }

    fn build_binary_info(binary_path: Option<&str>) -> BinaryInfo {
        BinaryInfo {
            path: binary_path.unwrap_or("unknown").to_string(),
            architecture: "x86-64".to_string(),
            format: "unknown".to_string(),  // TODO: Detect actual format
        }
    }

    fn build_function_info(cfg: &ControlFlowGraph) -> Result<FunctionInfo> {
        let entry = cfg.entry().context("No entry block")?;
        let start_address = entry.start_address;

        // Calculate function size and exit points
        let mut size = 0;
        let mut exit_points = Vec::new();

        for block in cfg.blocks.values() {
            size += block.end_address.saturating_sub(block.start_address) as usize;
            if block.is_return() {
                if let Some(last_op) = block.ops.last() {
                    exit_points.push(format!("0x{:x}", last_op.address));
                }
            }
        }

        Ok(FunctionInfo {
            address: format!("0x{:x}", start_address),
            size,
            entry_point: format!("0x{:x}", start_address),
            exit_points,
            name: None,  // TODO: Symbol resolution in Task 6,7
        })
    }

    fn build_cfg_data(cfg: &ControlFlowGraph) -> Result<CfgData> {
        let blocks: Vec<BlockData> = cfg.blocks_in_order()
            .into_iter()
            .map(|block| Self::convert_block(block))
            .collect();

        Ok(CfgData {
            entry_block: cfg.entry_block,
            blocks,
        })
    }

    fn convert_block(block: &BasicBlock) -> BlockData {
        BlockData {
            id: block.id,
            address: format!("0x{:x}", block.start_address),
            size: block.end_address.saturating_sub(block.start_address) as usize,
            ops: block.ops.iter().map(Self::convert_pcode_op).collect(),
            successors: block.successors.clone(),
            predecessors: block.predecessors.clone(),
        }
    }

    fn convert_pcode_op(op: &PcodeOp) -> PcodeOpData {
        PcodeOpData {
            opcode: format!("{:?}", op.opcode),
            output: op.output.as_ref().map(Self::convert_varnode),
            inputs: op.inputs.iter().map(Self::convert_varnode).collect(),
            address: format!("0x{:x}", op.address),
        }
    }

    fn convert_varnode(vn: &Varnode) -> VarnodeData {
        let (space, name) = match vn.space {
            AddressSpace::Register => {
                let register_name = Self::get_register_name(vn.offset, vn.size);
                ("register", register_name)
            }
            AddressSpace::Const => ("const", None),
            AddressSpace::Unique => ("unique", None),
            AddressSpace::Ram => ("ram", None),
            AddressSpace::Stack => ("stack", None),
        };

        VarnodeData {
            space: space.to_string(),
            offset: vn.offset,
            size: vn.size,
            name,
        }
    }

    fn get_register_name(offset: u64, size: usize) -> Option<String> {
        // x86-64 register mapping
        match (offset, size) {
            (0, 8) => Some("rax".to_string()),
            (0, 4) => Some("eax".to_string()),
            (0, 2) => Some("ax".to_string()),
            (0, 1) => Some("al".to_string()),
            (8, 8) => Some("rcx".to_string()),
            (8, 4) => Some("ecx".to_string()),
            (16, 8) => Some("rdx".to_string()),
            (16, 4) => Some("edx".to_string()),
            (24, 8) => Some("rbx".to_string()),
            (24, 4) => Some("ebx".to_string()),
            (32, 8) => Some("rsp".to_string()),
            (32, 4) => Some("esp".to_string()),
            (40, 8) => Some("rbp".to_string()),
            (40, 4) => Some("ebp".to_string()),
            (48, 8) => Some("rsi".to_string()),
            (48, 4) => Some("esi".to_string()),
            (56, 8) => Some("rdi".to_string()),
            (56, 4) => Some("edi".to_string()),
            (64, 8) => Some("r8".to_string()),
            (72, 8) => Some("r9".to_string()),
            (80, 8) => Some("r10".to_string()),
            (88, 8) => Some("r11".to_string()),
            (96, 8) => Some("r12".to_string()),
            (104, 8) => Some("r13".to_string()),
            (112, 8) => Some("r14".to_string()),
            (120, 8) => Some("r15".to_string()),
            _ => None,
        }
    }

    fn build_dataflow_data(_dataflow: &DefUseChain) -> DataflowData {
        // TODO: Extract actual def-use chains from DefUseChain
        // Currently returns empty implementation
        DataflowData {
            def_use_chains: Vec::new(),
        }
    }

    fn calculate_confidence(cfg: &ControlFlowGraph) -> ConfidenceScores {
        // Calculate CFG construction confidence
        let control_flow = Self::calculate_control_flow_confidence(cfg);
        let data_types = Self::calculate_data_type_confidence(cfg);
        let variable_names = 0.0;   // TODO: Calculate after symbol resolution in Task 6,7
        let function_purpose = Self::calculate_function_purpose_confidence(cfg);

        ConfidenceScores {
            control_flow,
            data_types,
            variable_names,
            function_purpose,
        }
    }

    /// Calculate control flow confidence
    /// Considers indirect branches and unreachable blocks
    fn calculate_control_flow_confidence(cfg: &ControlFlowGraph) -> f64 {
        if cfg.blocks.is_empty() {
            return 0.0;
        }

        let mut confidence = 1.0;
        let mut has_indirect_branch = false;
        let mut unreachable_blocks = 0;

        // Check for indirect jumps
        for block in cfg.blocks.values() {
            for op in &block.ops {
                if matches!(op.opcode, OpCode::BranchInd | OpCode::CallInd) {
                    has_indirect_branch = true;
                    break;
                }
            }
        }

        // Check for unreachable blocks (empty predecessors except entry)
        for block in cfg.blocks.values() {
            if block.id != cfg.entry_block && block.predecessors.is_empty() {
                unreachable_blocks += 1;
            }
        }

        // Reduce confidence by 0.1 for indirect jumps
        if has_indirect_branch {
            confidence -= 0.1;
        }

        // Reduce confidence by 0.05 per unreachable block (max 0.3)
        confidence -= (unreachable_blocks as f64 * 0.05).min(0.3);

        confidence.max(0.0)
    }

    /// Calculate data type inference confidence
    /// Based on proportion of typable varnodes
    fn calculate_data_type_confidence(cfg: &ControlFlowGraph) -> f64 {
        let mut total_varnodes = 0;
        let mut typed_varnodes = 0;

        for block in cfg.blocks.values() {
            for op in &block.ops {
                // Count output varnodes
                if let Some(output) = &op.output {
                    total_varnodes += 1;
                    // Register or standard size (1,2,4,8 bytes) are typable
                    if matches!(output.space, AddressSpace::Register)
                        || matches!(output.size, 1 | 2 | 4 | 8)
                    {
                        typed_varnodes += 1;
                    }
                }

                // Count input varnodes
                for input in &op.inputs {
                    total_varnodes += 1;
                    if matches!(input.space, AddressSpace::Register | AddressSpace::Const)
                        || matches!(input.size, 1 | 2 | 4 | 8)
                    {
                        typed_varnodes += 1;
                    }
                }
            }
        }

        if total_varnodes == 0 {
            return 0.0;
        }

        // Return ratio of typable varnodes (0.0-1.0)
        (typed_varnodes as f64 / total_varnodes as f64).min(1.0)
    }

    /// Calculate function purpose confidence
    /// Based on function complexity
    fn calculate_function_purpose_confidence(cfg: &ControlFlowGraph) -> f64 {
        if cfg.blocks.is_empty() {
            return 0.0;
        }

        let block_count = cfg.blocks.len();
        let mut branch_count = 0;
        let mut has_loop = false;

        for block in cfg.blocks.values() {
            for op in &block.ops {
                if matches!(op.opcode, OpCode::CBranch | OpCode::Branch) {
                    branch_count += 1;
                }
            }

            // Loop detection: self-loop or back edge
            for &succ_id in &block.successors {
                if succ_id <= block.id {
                    has_loop = true;
                }
            }
        }

        // Simple function (<=3 blocks, <=1 branch): high confidence
        if block_count <= 3 && branch_count <= 1 {
            return 0.8;
        }

        // Medium complexity with loop: medium confidence
        if has_loop && block_count <= 10 {
            return 0.5;
        }

        // Complex function: low confidence
        if block_count > 10 || branch_count > 5 {
            return 0.2;
        }

        // Default
        0.4
    }

    fn build_metadata(start_time: std::time::Instant) -> AnalysisMetadata {
        let elapsed = start_time.elapsed();

        AnalysisMetadata {
            optimizations_applied: Vec::new(),  // TODO: Track after optimizer integration
            analysis_time_ms: elapsed.as_secs_f64() * 1000.0,
            cache_hit: false,  // TODO: Track after cache implementation
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::test_utils::example_translation;

    #[test]
    fn test_json_basic_output() {
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        let json = JsonPrinter::print_analysis(&cfg, None, Some("/test/binary.exe"))
            .expect("JSON generation failed");

        // Verify JSON is parseable
        let result: AnalysisResult = serde_json::from_str(&json)
            .expect("JSON parsing failed");

        assert_eq!(result.format_version, "1.0");
        assert_eq!(result.binary.architecture, "x86-64");
        assert!(!result.cfg.blocks.is_empty());
        assert_eq!(result.confidence.control_flow, 1.0);
    }

    #[test]
    fn test_varnode_conversion() {
        use crate::decompiler_prototype::pcode::Varnode;

        let rax = Varnode::register(0, 8);
        let vn_data = JsonPrinter::convert_varnode(&rax);

        assert_eq!(vn_data.space, "register");
        assert_eq!(vn_data.offset, 0);
        assert_eq!(vn_data.size, 8);
        assert_eq!(vn_data.name, Some("rax".to_string()));
    }

    #[test]
    fn test_confidence_scores() {
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        let confidence = JsonPrinter::calculate_confidence(&cfg);

        assert_eq!(confidence.control_flow, 1.0);
        assert!(confidence.data_types >= 0.0 && confidence.data_types <= 1.0);
    }
}
