use super::super::cfg::{ControlFlowGraph, BasicBlock};
use super::super::pcode::{OpCode, Varnode, AddressSpace};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVariableInfo {
    pub state_variable: Varnode,
    pub dispatcher_block: usize,
    pub transitions: Vec<StateTransition>,
    pub confidence: f64,
    pub analysis: FlatteningAnalysis,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from_block: usize,
    pub state_value: Option<u64>,
    pub to_block: usize,
    pub confidence: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatteningAnalysis {
    pub total_blocks: usize,
    pub blocks_through_dispatcher: usize,
    pub coverage: f64,
    pub dispatcher_successors: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatteningStatistics {
    pub total_dispatchers: usize,
    pub total_transitions: usize,
    pub avg_dispatcher_successors: f64,
    pub coverage: f64,
}

pub struct FlatteningAnalyzer;

impl FlatteningAnalyzer {
    pub fn analyze(cfg: &ControlFlowGraph) -> Option<StateVariableInfo> {
        if cfg.blocks.is_empty() {
            return None;
        }

        // Step 1: Find dispatcher block (high out-degree)
        let dispatcher = Self::find_dispatcher(cfg)?;

        // Step 2: Identify state variable
        let state_var = Self::identify_state_variable(cfg, dispatcher)?;

        // Step 3: Trace state transitions
        let transitions = Self::trace_state_transitions(cfg, &state_var, dispatcher);

        // Step 4: Analyze coverage and characteristics
        let analysis = Self::analyze_characteristics(cfg, dispatcher, &transitions);

        // Step 5: Calculate confidence
        let confidence = Self::calculate_confidence(&transitions, &analysis);

        Some(StateVariableInfo {
            state_variable: state_var,
            dispatcher_block: dispatcher,
            transitions,
            confidence,
            analysis,
        })
    }

    /// Find dispatcher block (high out-degree, central position)
    fn find_dispatcher(cfg: &ControlFlowGraph) -> Option<usize> {
        let mut candidates = Vec::new();

        for (id, block) in cfg.blocks.iter() {
            let successor_count = block.successors.len();

            // Dispatcher characteristics:
            // 1. High out-degree (>= 5)
            // 2. Receives edges from many blocks (high in-degree)

            if successor_count >= 5 {
                // Calculate in-degree
                let in_degree = cfg
                    .blocks
                    .iter()
                    .filter(|(_, b)| b.successors.contains(id))
                    .count();

                // Score: out-degree + in-degree
                let score = successor_count + in_degree;
                candidates.push((*id, score));
            }
        }

        // Return the highest scoring candidate
        candidates.sort_by_key(|(_, score)| std::cmp::Reverse(*score));
        candidates.first().map(|(id, _)| *id)
    }

    /// Identify the state variable used for dispatching
    fn identify_state_variable(
        cfg: &ControlFlowGraph,
        dispatcher: usize,
    ) -> Option<Varnode> {
        let block = cfg.blocks.get(&dispatcher)?;

        // Look for the variable used in the dispatcher's branch condition
        // Typically: switch(state_var) or if(state_var == X)

        // Find the last conditional or indirect branch
        for op in block.ops.iter().rev() {
            match op.opcode {
                OpCode::CBranch | OpCode::BranchInd => {
                    // The condition or target is likely based on the state variable
                    if !op.inputs.is_empty() {
                        return Some(op.inputs[0].clone());
                    }
                }

                // Look for comparisons
                OpCode::IntEqual | OpCode::IntNotEqual | OpCode::IntLess => {
                    // First input is likely the state variable
                    if !op.inputs.is_empty() {
                        return Some(op.inputs[0].clone());
                    }
                }

                _ => {}
            }
        }

        None
    }

    /// Trace state variable transitions
    fn trace_state_transitions(
        cfg: &ControlFlowGraph,
        state_var: &Varnode,
        dispatcher: usize,
    ) -> Vec<StateTransition> {
        let mut transitions = Vec::new();

        // For each block that jumps to dispatcher
        for (block_id, block) in cfg.blocks.iter() {
            if !block.successors.contains(&dispatcher) {
                continue;
            }

            // Find state variable update (e.g., mov state_var, constant)
            if let Some((state_value, confidence)) = Self::find_state_update(block, state_var) {
                transitions.push(StateTransition {
                    from_block: *block_id,
                    state_value: Some(state_value),
                    to_block: dispatcher,
                    confidence,
                });
            } else {
                // Unknown state value
                transitions.push(StateTransition {
                    from_block: *block_id,
                    state_value: None,
                    to_block: dispatcher,
                    confidence: 0.3,
                });
            }
        }

        transitions
    }

    /// Find state variable update in a block
    fn find_state_update(block: &BasicBlock, state_var: &Varnode) -> Option<(u64, f64)> {
        // Look for: state_var = constant
        for op in &block.ops {
            if let Some(output) = &op.output {
                if Self::varnodes_equal(output, state_var) {
                    // Check if it's assigned a constant
                    if let OpCode::Copy = op.opcode {
                        if !op.inputs.is_empty() {
                            if let Some(value) = Self::get_constant_value(&op.inputs[0]) {
                                return Some((value, 0.9));
                            }
                        }
                    }

                    // Check for other assignments
                    if !op.inputs.is_empty() {
                        if let Some(value) = Self::get_constant_value(&op.inputs[0]) {
                            return Some((value, 0.7));
                        }
                    }
                }
            }
        }

        None
    }

    /// Analyze flattening characteristics
    fn analyze_characteristics(
        cfg: &ControlFlowGraph,
        dispatcher: usize,
        transitions: &[StateTransition],
    ) -> FlatteningAnalysis {
        let total_blocks = cfg.blocks.len();
        let blocks_through_dispatcher = transitions.len();
        let coverage = if total_blocks > 0 {
            blocks_through_dispatcher as f64 / total_blocks as f64
        } else {
            0.0
        };

        let dispatcher_successors = cfg
            .blocks
            .get(&dispatcher)
            .map(|b| b.successors.len())
            .unwrap_or(0);

        FlatteningAnalysis {
            total_blocks,
            blocks_through_dispatcher,
            coverage,
            dispatcher_successors,
        }
    }

    /// Calculate confidence score
    fn calculate_confidence(
        transitions: &[StateTransition],
        analysis: &FlatteningAnalysis,
    ) -> f64 {
        // Confidence factors:
        // 1. Coverage (more blocks through dispatcher = higher confidence)
        // 2. Dispatcher size (more successors = higher confidence)
        // 3. Transition confidence

        let coverage_score = analysis.coverage;

        let dispatcher_score = if analysis.dispatcher_successors >= 10 {
            1.0
        } else if analysis.dispatcher_successors >= 5 {
            0.7
        } else {
            0.4
        };

        let transition_confidence = if !transitions.is_empty() {
            transitions.iter().map(|t| t.confidence).sum::<f64>() / transitions.len() as f64
        } else {
            0.0
        };

        let confidence =
            (coverage_score * 0.4 + dispatcher_score * 0.4 + transition_confidence * 0.2)
                .clamp(0.0, 1.0);

        // Round to 2 decimal places
        (confidence * 100.0).round() / 100.0
    }

    /// Calculate statistics for flattening patterns
    pub fn calculate_statistics(
        patterns: &[StateVariableInfo],
    ) -> FlatteningStatistics {
        if patterns.is_empty() {
            return FlatteningStatistics {
                total_dispatchers: 0,
                total_transitions: 0,
                avg_dispatcher_successors: 0.0,
                coverage: 0.0,
            };
        }

        let total_dispatchers = patterns.len();
        let total_transitions = patterns.iter().map(|p| p.transitions.len()).sum();
        let avg_dispatcher_successors = patterns
            .iter()
            .map(|p| p.analysis.dispatcher_successors as f64)
            .sum::<f64>()
            / total_dispatchers as f64;
        let coverage = patterns.iter().map(|p| p.analysis.coverage).sum::<f64>()
            / total_dispatchers as f64;

        FlatteningStatistics {
            total_dispatchers,
            total_transitions,
            avg_dispatcher_successors,
            coverage,
        }
    }

    // Utility functions

    fn varnodes_equal(v1: &Varnode, v2: &Varnode) -> bool {
        v1.space == v2.space && v1.offset == v2.offset && v1.size == v2.size
    }

    fn get_constant_value(v: &Varnode) -> Option<u64> {
        if v.space == AddressSpace::Const {
            Some(v.offset)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_dispatcher_detection() {
        let mut cfg = ControlFlowGraph {
            blocks: HashMap::new(),
        };

        // Create dispatcher block (block 0) with 7 successors
        let mut dispatcher = BasicBlock::new();
        dispatcher.ops.push(PcodeOp {
            opcode: OpCode::BranchInd,
            output: None,
            inputs: vec![Varnode::register(0, 8)],
            address: 0x1000,
        });
        dispatcher.successors = vec![1, 2, 3, 4, 5, 6, 7];

        cfg.blocks.insert(0, dispatcher);

        // Create other blocks that jump back to dispatcher
        for i in 1..=7 {
            let mut block = BasicBlock::new();
            block.ops.push(PcodeOp {
                opcode: OpCode::Copy,
                output: Some(Varnode::register(0, 8)),
                inputs: vec![Varnode::constant(i as u64, 8)],
                address: 0x2000 + (i * 0x10),
            });
            block.successors = vec![0]; // Jump back to dispatcher
            cfg.blocks.insert(i, block);
        }

        let result = FlatteningAnalyzer::analyze(&cfg);
        assert!(result.is_some());

        let info = result.unwrap();
        assert_eq!(info.dispatcher_block, 0);
        assert!(info.confidence > 0.5);
    }

    #[test]
    fn test_no_flattening() {
        let mut cfg = ControlFlowGraph {
            blocks: HashMap::new(),
        };

        // Simple linear flow: 0 -> 1 -> 2
        for i in 0..3 {
            let mut block = BasicBlock::new();
            if i < 2 {
                block.successors = vec![i + 1];
            }
            cfg.blocks.insert(i, block);
        }

        let result = FlatteningAnalyzer::analyze(&cfg);

        // Should not detect flattening (no high out-degree blocks)
        assert!(result.is_none());
    }
}
