/// Obfuscation pattern detection for P-code CFGs
///
/// This module detects common obfuscation patterns without attempting to deobfuscate.
/// Philosophy: "Truth Over Beauty" - expose obfuscation as-is for LLM inference.
///
/// Phase 10: Basic obfuscation detection
/// Phase 11: Advanced obfuscation analysis (MBA, SMT, Flattening, VM)

use super::cfg::*;
use super::pcode::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

// Phase 11 imports
use super::mba::{MBADetector, MBAPattern, MBAStatistics};
use super::smt::{SMTVerifier, OpaquenessResult};
use super::flattening::{FlatteningAnalyzer, StateVariableInfo};
use super::vm_detection::{VMDetector, VMPattern};

/// Obfuscation pattern detector
pub struct ObfuscationDetector;

/// Complete obfuscation analysis result (Phase 10 + 11)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationData {
    /// Overall obfuscation score (0.0 = clean, 1.0 = heavily obfuscated)
    pub overall_score: f64,

    /// Detected obfuscation patterns (Phase 10)
    pub patterns: Vec<ObfuscationPattern>,

    /// Control flow metrics
    pub control_flow_metrics: ControlFlowMetrics,

    /// Phase 11.1: MBA patterns
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mba_patterns: Option<Vec<MBAPattern>>,

    /// Phase 11.1: MBA statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mba_statistics: Option<MBAStatistics>,

    /// Phase 11.2: SMT verification results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smt_verification: Option<SMTVerificationResults>,

    /// Phase 11.3: Advanced control flow flattening analysis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advanced_flattening: Option<StateVariableInfo>,

    /// Phase 11.4: VM-based obfuscation patterns
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_patterns: Option<Vec<VMPattern>>,
}

/// SMT solver verification results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SMTVerificationResults {
    /// Total predicates verified
    pub total_verified: usize,
    /// Always true predicates
    pub always_true: usize,
    /// Always false predicates
    pub always_false: usize,
    /// Dynamic predicates
    pub dynamic: usize,
    /// Unknown/timeout
    pub unknown: usize,
}

/// Individual obfuscation pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationPattern {
    /// Type of obfuscation pattern
    pub pattern_type: ObfuscationPatternType,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Locations where pattern was found
    pub locations: Vec<ObfuscationLocation>,
    /// Human-readable description
    pub description: String,
}

/// Types of obfuscation patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObfuscationPatternType {
    /// Opaque predicates (always true/false conditions) - Phase 10
    OpaquePredicate,
    /// Control flow flattening (dispatcher pattern) - Phase 10
    ControlFlowFlattening,
    /// Bogus control flow (unreachable blocks) - Phase 10
    BogusControlFlow,
    /// Excessive indirect branches - Phase 10
    ExcessiveJumps,
    /// Instruction substitution patterns - Phase 10
    InstructionSubstitution,
    /// Anti-disassembly tricks - Phase 10
    AntiDisassembly,
    /// MBA expressions (Mixed Boolean-Arithmetic) - Phase 11.1
    MBAExpression,
    /// VM-based obfuscation - Phase 11.4
    VMBasedObfuscation,
}

/// Location of obfuscation pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationLocation {
    /// Block ID in CFG
    pub block_id: usize,
    /// Operation index within block (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_index: Option<usize>,
    /// Address (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// Control flow complexity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowMetrics {
    /// Total number of basic blocks
    pub total_blocks: usize,
    /// Total number of edges
    pub total_edges: usize,
    /// Cyclomatic complexity
    pub cyclomatic_complexity: usize,
    /// Average number of successors per block
    pub avg_successors: f64,
    /// Number of indirect branches
    pub indirect_branches: usize,
    /// Maximum depth of control flow
    pub max_depth: usize,
}

impl ObfuscationDetector {
    /// Analyze CFG for obfuscation patterns (Phase 10 + 11)
    pub fn analyze(cfg: &ControlFlowGraph) -> ObfuscationData {
        let mut patterns = Vec::new();

        // Phase 10: Basic obfuscation detection
        patterns.extend(Self::detect_opaque_predicates(cfg));
        patterns.extend(Self::detect_control_flow_flattening(cfg));
        patterns.extend(Self::detect_bogus_control_flow(cfg));
        patterns.extend(Self::detect_excessive_jumps(cfg));

        // Calculate metrics
        let metrics = Self::calculate_metrics(cfg);

        // Phase 11.1: MBA detection
        let (mba_patterns, mba_statistics) = Self::detect_mba_patterns(cfg);

        // Phase 11.2: SMT verification
        let smt_verification = Self::verify_with_smt(cfg, &patterns);

        // Phase 11.3: Advanced control flow flattening
        let advanced_flattening = Self::analyze_advanced_flattening(cfg);

        // Phase 11.4: VM detection
        let vm_patterns = Self::detect_vm_patterns(cfg);

        // Add MBA and VM patterns to overall patterns list
        if let Some(ref mba_list) = mba_patterns {
            for mba in mba_list {
                patterns.push(ObfuscationPattern {
                    pattern_type: ObfuscationPatternType::MBAExpression,
                    confidence: mba.confidence,
                    locations: vec![ObfuscationLocation {
                        block_id: mba.location.block_id,
                        op_index: Some(mba.location.op_range.0),
                        address: Some(format!("0x{:x}", mba.location.address_range.0)),
                    }],
                    description: format!(
                        "MBA expression: complexity {}, {} ops ({} bitwise, {} arithmetic)",
                        mba.complexity, mba.chain_length, mba.bitop_count, mba.arith_count
                    ),
                });
            }
        }

        if let Some(ref vm_list) = vm_patterns {
            for vm in vm_list {
                patterns.push(ObfuscationPattern {
                    pattern_type: ObfuscationPatternType::VMBasedObfuscation,
                    confidence: vm.confidence,
                    locations: vec![ObfuscationLocation {
                        block_id: vm.dispatcher.block_id,
                        op_index: None,
                        address: None,
                    }],
                    description: format!(
                        "VM-based obfuscation: {} handlers, dispatcher with {} indirect jumps",
                        vm.handlers.len(), vm.dispatcher.indirect_jumps
                    ),
                });
            }
        }

        // Calculate overall score (Phase 10 + 11)
        let overall_score = Self::calculate_overall_score_v2(
            &patterns,
            &metrics,
            &mba_patterns,
            &advanced_flattening,
            &vm_patterns,
        );

        ObfuscationData {
            overall_score,
            patterns,
            control_flow_metrics: metrics,
            mba_patterns,
            mba_statistics,
            smt_verification,
            advanced_flattening,
            vm_patterns,
        }
    }

    /// Detect opaque predicates (conditions that are always true/false)
    ///
    /// Examples:
    /// - x XOR x = 0
    /// - x - x = 0
    /// - x AND 0 = 0
    /// - x OR -1 = -1
    fn detect_opaque_predicates(cfg: &ControlFlowGraph) -> Vec<ObfuscationPattern> {
        let mut patterns = Vec::new();

        for (&block_id, block) in cfg.blocks.iter() {
            for (op_index, op) in block.ops.iter().enumerate() {
                // Check for X XOR X pattern
                if let OpCode::IntXor = op.opcode {
                    if op.inputs.len() == 2 {
                        if Self::are_varnodes_equal(&op.inputs[0], &op.inputs[1]) {
                            patterns.push(ObfuscationPattern {
                                pattern_type: ObfuscationPatternType::OpaquePredicate,
                                confidence: 0.9,
                                locations: vec![ObfuscationLocation {
                                    block_id,
                                    op_index: Some(op_index),
                                    address: Some(format!("0x{:x}", op.address)),
                                }],
                                description: "Opaque predicate: IntXor with identical operands (always 0)".to_string(),
                            });
                        }
                    }
                }

                // Check for X - X pattern
                if let OpCode::IntSub = op.opcode {
                    if op.inputs.len() == 2 {
                        if Self::are_varnodes_equal(&op.inputs[0], &op.inputs[1]) {
                            patterns.push(ObfuscationPattern {
                                pattern_type: ObfuscationPatternType::OpaquePredicate,
                                confidence: 0.9,
                                locations: vec![ObfuscationLocation {
                                    block_id,
                                    op_index: Some(op_index),
                                    address: Some(format!("0x{:x}", op.address)),
                                }],
                                description: "Opaque predicate: IntSub with identical operands (always 0)".to_string(),
                            });
                        }
                    }
                }

                // Check for X AND 0 pattern
                if let OpCode::IntAnd = op.opcode {
                    if op.inputs.len() == 2 {
                        if Self::is_zero_constant(&op.inputs[1]) || Self::is_zero_constant(&op.inputs[0]) {
                            patterns.push(ObfuscationPattern {
                                pattern_type: ObfuscationPatternType::OpaquePredicate,
                                confidence: 0.7,
                                locations: vec![ObfuscationLocation {
                                    block_id,
                                    op_index: Some(op_index),
                                    address: Some(format!("0x{:x}", op.address)),
                                }],
                                description: "Opaque predicate: IntAnd with zero constant (always 0)".to_string(),
                            });
                        }
                    }
                }
            }
        }

        patterns
    }

    /// Detect control flow flattening (dispatcher pattern)
    ///
    /// Characteristics:
    /// - Large switch statement (5+ successors)
    /// - All paths go through the same dispatcher block
    fn detect_control_flow_flattening(cfg: &ControlFlowGraph) -> Vec<ObfuscationPattern> {
        let mut patterns = Vec::new();

        for (&block_id, block) in cfg.blocks.iter() {
            let successor_count = block.successors.len();

            // Detect dispatcher blocks (5+ successors is suspicious)
            if successor_count >= 5 {
                patterns.push(ObfuscationPattern {
                    pattern_type: ObfuscationPatternType::ControlFlowFlattening,
                    confidence: if successor_count >= 10 { 0.9 } else { 0.7 },
                    locations: vec![ObfuscationLocation {
                        block_id,
                        op_index: None,
                        address: if let Some(first_op) = block.ops.first() {
                            Some(format!("0x{:x}", first_op.address))
                        } else {
                            None
                        },
                    }],
                    description: format!(
                        "Suspected dispatcher block with {} successors (control flow flattening)",
                        successor_count
                    ),
                });
            }
        }

        patterns
    }

    /// Detect bogus control flow (unreachable blocks)
    ///
    /// Uses BFS from entry block to find unreachable blocks
    fn detect_bogus_control_flow(cfg: &ControlFlowGraph) -> Vec<ObfuscationPattern> {
        let mut patterns = Vec::new();

        if cfg.blocks.is_empty() {
            return patterns;
        }

        // BFS from entry block (block 0)
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(0);
        visited.insert(0);

        while let Some(block_id) = queue.pop_front() {
            if block_id >= cfg.blocks.len() {
                continue;
            }

            for &successor in &cfg.blocks[&block_id].successors {
                if !visited.contains(&successor) && successor < cfg.blocks.len() {
                    visited.insert(successor);
                    queue.push_back(successor);
                }
            }
        }

        // Find unreachable blocks
        let unreachable: Vec<usize> = (0..cfg.blocks.len())
            .filter(|id| !visited.contains(id))
            .collect();

        if !unreachable.is_empty() {
            let locations: Vec<ObfuscationLocation> = unreachable
                .iter()
                .map(|&block_id| ObfuscationLocation {
                    block_id,
                    op_index: None,
                    address: if let Some(first_op) = cfg.blocks.get(&block_id).and_then(|b| b.ops.first()) {
                        Some(format!("0x{:x}", first_op.address))
                    } else {
                        None
                    },
                })
                .collect();

            patterns.push(ObfuscationPattern {
                pattern_type: ObfuscationPatternType::BogusControlFlow,
                confidence: 0.8,
                locations,
                description: format!("{} unreachable blocks detected (bogus control flow)", unreachable.len()),
            });
        }

        patterns
    }

    /// Detect excessive indirect jumps
    fn detect_excessive_jumps(cfg: &ControlFlowGraph) -> Vec<ObfuscationPattern> {
        let mut patterns = Vec::new();
        let mut indirect_count = 0;
        let mut indirect_locations = Vec::new();

        for (&block_id, block) in cfg.blocks.iter() {
            for (op_index, op) in block.ops.iter().enumerate() {
                if let OpCode::CallInd | OpCode::BranchInd = op.opcode {
                    indirect_count += 1;
                    indirect_locations.push(ObfuscationLocation {
                        block_id,
                        op_index: Some(op_index),
                        address: Some(format!("0x{:x}", op.address)),
                    });
                }
            }
        }

        // If indirect branches exceed 10% of total blocks, it's suspicious
        if !cfg.blocks.is_empty() && (indirect_count as f64 / cfg.blocks.len() as f64) > 0.1 {
            patterns.push(ObfuscationPattern {
                pattern_type: ObfuscationPatternType::ExcessiveJumps,
                confidence: 0.7,
                locations: indirect_locations,
                description: format!(
                    "{} indirect branches in {} blocks ({}%)",
                    indirect_count,
                    cfg.blocks.len(),
                    (indirect_count as f64 / cfg.blocks.len() as f64 * 100.0) as usize
                ),
            });
        }

        patterns
    }

    /// Calculate control flow metrics
    fn calculate_metrics(cfg: &ControlFlowGraph) -> ControlFlowMetrics {
        let total_blocks = cfg.blocks.len();
        let total_edges: usize = cfg.blocks.iter().map(|(_, b)| b.successors.len()).sum();
        let cyclomatic_complexity = if total_blocks > 0 {
            total_edges - total_blocks + 2
        } else {
            0
        };

        let avg_successors = if total_blocks > 0 {
            total_edges as f64 / total_blocks as f64
        } else {
            0.0
        };

        let mut indirect_branches = 0;
        for (_, block) in &cfg.blocks {
            for op in &block.ops {
                if let OpCode::CallInd | OpCode::BranchInd = op.opcode {
                    indirect_branches += 1;
                }
            }
        }

        // Calculate max depth using BFS
        let max_depth = if !cfg.blocks.is_empty() {
            Self::calculate_max_depth(cfg)
        } else {
            0
        };

        ControlFlowMetrics {
            total_blocks,
            total_edges,
            cyclomatic_complexity,
            avg_successors,
            indirect_branches,
            max_depth,
        }
    }

    /// Calculate maximum depth of CFG using BFS
    fn calculate_max_depth(cfg: &ControlFlowGraph) -> usize {
        let mut max_depth = 0;
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((0, 0)); // (block_id, depth)
        visited.insert(0);

        while let Some((block_id, depth)) = queue.pop_front() {
            max_depth = max_depth.max(depth);

            if block_id >= cfg.blocks.len() {
                continue;
            }

            for &successor in &cfg.blocks[&block_id].successors {
                if !visited.contains(&successor) && successor < cfg.blocks.len() {
                    visited.insert(successor);
                    queue.push_back((successor, depth + 1));
                }
            }
        }

        max_depth
    }

    /// Calculate overall obfuscation score (Phase 10)
    #[allow(dead_code)]
    fn calculate_overall_score(patterns: &[ObfuscationPattern], metrics: &ControlFlowMetrics) -> f64 {
        let mut score = 0.0;

        // Pattern-based scoring (0.0 - 0.7)
        let pattern_score: f64 = patterns.iter().map(|p| p.confidence * 0.1).sum();
        score += pattern_score.min(0.7);

        // Complexity-based scoring (0.0 - 0.3)
        if metrics.total_blocks > 0 {
            // High cyclomatic complexity
            let complexity_ratio = metrics.cyclomatic_complexity as f64 / metrics.total_blocks as f64;
            if complexity_ratio > 2.0 {
                score += 0.1;
            }

            // High average successors
            if metrics.avg_successors > 2.0 {
                score += 0.1;
            }

            // Many indirect branches
            let indirect_ratio = metrics.indirect_branches as f64 / metrics.total_blocks as f64;
            if indirect_ratio > 0.1 {
                score += 0.1;
            }
        }

        score.min(1.0)
    }

    /// Calculate overall obfuscation score (Phase 10 + 11)
    fn calculate_overall_score_v2(
        patterns: &[ObfuscationPattern],
        metrics: &ControlFlowMetrics,
        mba_patterns: &Option<Vec<MBAPattern>>,
        advanced_flattening: &Option<StateVariableInfo>,
        vm_patterns: &Option<Vec<VMPattern>>,
    ) -> f64 {
        let mut score = 0.0;

        // Base score from Phase 10 patterns (0.0 - 0.5)
        let pattern_score: f64 = patterns.iter().map(|p| p.confidence * 0.08).sum();
        score += pattern_score.min(0.5);

        // Complexity metrics (0.0 - 0.1)
        if metrics.total_blocks > 0 {
            let complexity_ratio = metrics.cyclomatic_complexity as f64 / metrics.total_blocks as f64;
            if complexity_ratio > 2.0 {
                score += 0.05;
            }
            let indirect_ratio = metrics.indirect_branches as f64 / metrics.total_blocks as f64;
            if indirect_ratio > 0.1 {
                score += 0.05;
            }
        }

        // MBA patterns contribution (0.0 - 0.15)
        if let Some(mba_list) = mba_patterns {
            if !mba_list.is_empty() {
                let mba_score = mba_list.iter().map(|m| m.confidence * 0.03).sum::<f64>();
                score += mba_score.min(0.15);
            }
        }

        // Advanced flattening contribution (0.0 - 0.15)
        if let Some(flattening) = advanced_flattening {
            score += flattening.confidence * 0.15;
        }

        // VM patterns contribution (0.0 - 0.2)
        if let Some(vm_list) = vm_patterns {
            if !vm_list.is_empty() {
                let vm_score = vm_list.iter().map(|v| v.confidence * 0.1).sum::<f64>();
                score += vm_score.min(0.2);
            }
        }

        score.min(1.0)
    }

    /// Phase 11.1: Detect MBA patterns
    fn detect_mba_patterns(cfg: &ControlFlowGraph) -> (Option<Vec<MBAPattern>>, Option<MBAStatistics>) {
        // Collect all P-code operations from all blocks
        let mut all_ops = Vec::new();
        for (_, block) in cfg.blocks.iter() {
            all_ops.extend(block.ops.iter().cloned());
        }

        if all_ops.is_empty() {
            return (None, None);
        }

        let patterns = MBADetector::detect(&all_ops);
        let statistics = MBADetector::calculate_statistics(&patterns);

        if patterns.is_empty() {
            (None, None)
        } else {
            (Some(patterns), Some(statistics))
        }
    }

    /// Phase 11.2: Verify predicates with SMT solver
    fn verify_with_smt(
        cfg: &ControlFlowGraph,
        patterns: &[ObfuscationPattern],
    ) -> Option<SMTVerificationResults> {
        let mut verifier = SMTVerifier::new();

        let mut total_verified = 0;
        let mut always_true = 0;
        let mut always_false = 0;
        let mut dynamic = 0;
        let mut unknown = 0;

        // Verify opaque predicates found in Phase 10
        for pattern in patterns {
            if matches!(pattern.pattern_type, ObfuscationPatternType::OpaquePredicate) {
                for location in &pattern.locations {
                    if let Some(block) = cfg.blocks.get(&location.block_id) {
                        if let Some(op_index) = location.op_index {
                            if let Some(op) = block.ops.get(op_index) {
                                total_verified += 1;
                                match verifier.verify_opaque_predicate(op) {
                                    OpaquenessResult::AlwaysTrue { .. } => always_true += 1,
                                    OpaquenessResult::AlwaysFalse { .. } => always_false += 1,
                                    OpaquenessResult::Dynamic => dynamic += 1,
                                    _ => unknown += 1,
                                }
                            }
                        }
                    }
                }
            }
        }

        if total_verified > 0 {
            Some(SMTVerificationResults {
                total_verified,
                always_true,
                always_false,
                dynamic,
                unknown,
            })
        } else {
            None
        }
    }

    /// Phase 11.3: Advanced control flow flattening analysis
    fn analyze_advanced_flattening(cfg: &ControlFlowGraph) -> Option<StateVariableInfo> {
        FlatteningAnalyzer::analyze(cfg)
    }

    /// Phase 11.4: Detect VM-based obfuscation
    fn detect_vm_patterns(cfg: &ControlFlowGraph) -> Option<Vec<VMPattern>> {
        if let Some(vm_pattern) = VMDetector::detect(cfg) {
            Some(vec![vm_pattern])
        } else {
            None
        }
    }

    /// Check if two varnodes are equal
    fn are_varnodes_equal(v1: &Varnode, v2: &Varnode) -> bool {
        v1.space == v2.space && v1.offset == v2.offset && v1.size == v2.size
    }

    /// Check if varnode is a zero constant
    fn is_zero_constant(v: &Varnode) -> bool {
        v.space == AddressSpace::Const && v.offset == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cfg() {
        let cfg = ControlFlowGraph::new();
        let data = ObfuscationDetector::analyze(&cfg);
        assert_eq!(data.overall_score, 0.0);
        assert!(data.patterns.is_empty());
    }

    #[test]
    fn test_simple_cfg() {
        let mut cfg = ControlFlowGraph::new();

        // Simple linear flow: block 0 -> block 1
        let mut block0 = BasicBlock::new();
        block0.ops.push(PcodeOp {
            opcode: OpCode::IntAdd,
            output: Some(Varnode::register(0, 8)),
            inputs: vec![
                Varnode::register(1, 8),
                Varnode::register(2, 8),
            ],
            address: 0x1000,
        });
        block0.successors = vec![1];

        let mut block1 = BasicBlock::new();
        block1.ops.push(PcodeOp {
            opcode: OpCode::Return,
            output: None,
            inputs: vec![],
            address: 0x1010,
        });

        cfg.blocks.push(block0);
        cfg.blocks.push(block1);

        let data = ObfuscationDetector::analyze(&cfg);

        // Should have low obfuscation score for simple CFG
        assert!(data.overall_score < 0.3);
        assert_eq!(data.control_flow_metrics.total_blocks, 2);
        assert_eq!(data.control_flow_metrics.total_edges, 1);
    }

    #[test]
    fn test_opaque_predicate_detection() {
        let mut cfg = ControlFlowGraph::new();

        let mut block = BasicBlock::new();

        // x XOR x - opaque predicate
        let reg_x = Varnode::register(10, 8);
        block.ops.push(PcodeOp {
            opcode: OpCode::IntXor,
            output: Some(Varnode::register(20, 8)),
            inputs: vec![reg_x.clone(), reg_x.clone()],
            address: 0x2000,
        });

        cfg.blocks.push(block);

        let data = ObfuscationDetector::analyze(&cfg);

        assert!(!data.patterns.is_empty());
        let has_opaque = data.patterns.iter().any(|p| {
            matches!(p.pattern_type, ObfuscationPatternType::OpaquePredicate)
        });
        assert!(has_opaque);
    }

    #[test]
    fn test_control_flow_flattening_detection() {
        let mut cfg = ControlFlowGraph::new();

        // Dispatcher block with 7 successors
        let mut dispatcher = BasicBlock::new();
        dispatcher.ops.push(PcodeOp {
            opcode: OpCode::BranchIndirect,
            output: None,
            inputs: vec![Varnode::register(0, 8)],
            address: 0x3000,
        });
        dispatcher.successors = vec![1, 2, 3, 4, 5, 6, 7];

        cfg.blocks.push(dispatcher);
        for _ in 0..7 {
            cfg.blocks.push(BasicBlock::new());
        }

        let data = ObfuscationDetector::analyze(&cfg);

        let has_flattening = data.patterns.iter().any(|p| {
            matches!(p.pattern_type, ObfuscationPatternType::ControlFlowFlattening)
        });
        assert!(has_flattening);
    }
}
