/// VM-based obfuscation detector
///
/// Detects virtualization patterns: fetch-decode-dispatch loops

use super::super::cfg::{ControlFlowGraph, BasicBlock};
use super::super::pcode::{OpCode, PcodeOp, Varnode, AddressSpace};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// VM pattern detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMPattern {
    /// Dispatcher information
    pub dispatcher: DispatcherInfo,

    /// Virtual Program Counter (VPC) information
    pub vpc: Option<VPCInfo>,

    /// Handler functions
    pub handlers: Vec<VMHandlerInfo>,

    /// Confidence score (0.0-1.0)
    pub confidence: f64,

    /// Detection characteristics
    pub characteristics: VMCharacteristics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatcherInfo {
    /// Dispatcher loop block ID
    pub block_id: usize,

    /// Loop characteristics
    pub loop_size: usize,

    /// Indirect jump count in dispatcher
    pub indirect_jumps: usize,

    /// Dispatch table address (if found)
    pub dispatch_table: Option<u64>,

    /// Dispatch method
    pub dispatch_method: DispatchMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DispatchMethod {
    /// Jump table based dispatch
    JumpTable,

    /// Switch-case based dispatch
    SwitchCase,

    /// Computed goto
    ComputedGoto,

    /// Unknown method
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VPCInfo {
    /// VPC register/variable
    pub vpc_variable: Varnode,

    /// VPC update frequency
    pub update_frequency: usize,

    /// VPC increment pattern
    pub increment_pattern: VPCPattern,

    /// Bytecode base address (if constant)
    pub bytecode_base: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VPCPattern {
    /// VPC++ (increment by 1)
    IncrementOne,

    /// VPC += N (variable increment)
    VariableIncrement,

    /// VPC = bytecode[VPC] (computed)
    Computed,

    /// Unknown pattern
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMHandlerInfo {
    /// Handler block ID
    pub block_id: usize,

    /// Handler entry address
    pub address: u64,

    /// Handler opcode (if identified)
    pub opcode: Option<u8>,

    /// Handler complexity
    pub complexity: usize,

    /// Returns to dispatcher
    pub returns_to_dispatcher: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMCharacteristics {
    /// Total handlers found
    pub total_handlers: usize,

    /// Average handler complexity
    pub avg_handler_complexity: f64,

    /// Dispatcher loop iterations
    pub dispatcher_iterations: usize,

    /// Bytecode fetch operations
    pub bytecode_fetches: usize,

    /// Indirect jumps in dispatcher
    pub indirect_jumps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMStatistics {
    pub total_vm_patterns: usize,
    pub total_handlers: usize,
    pub avg_handlers_per_vm: f64,
    pub avg_confidence: f64,
}

pub struct VMDetector;

impl VMDetector {
    /// Detect VM-based obfuscation in CFG
    pub fn detect(cfg: &ControlFlowGraph) -> Option<VMPattern> {
        if cfg.blocks.is_empty() {
            return None;
        }

        // Step 1: Find dispatcher loop
        let dispatcher = Self::find_dispatcher_loop(cfg)?;

        // Step 2: Identify VPC (Virtual Program Counter)
        let vpc = Self::identify_vpc(cfg, &dispatcher);

        // Step 3: Enumerate handlers
        let handlers = Self::enumerate_handlers(cfg, &dispatcher);

        // Step 4: Analyze characteristics
        let characteristics = Self::analyze_characteristics(&dispatcher, &handlers);

        // Step 5: Calculate confidence
        let confidence = Self::calculate_confidence(&dispatcher, &vpc, &handlers, &characteristics);

        Some(VMPattern {
            dispatcher,
            vpc,
            handlers,
            confidence,
            characteristics,
        })
    }

    /// Find dispatcher loop (fetch-decode-dispatch pattern)
    fn find_dispatcher_loop(cfg: &ControlFlowGraph) -> Option<DispatcherInfo> {
        let mut candidates = Vec::new();

        for (id, block) in cfg.blocks.iter() {
            // Dispatcher characteristics:
            // 1. Small loop (back-edge to self or nearby block)
            // 2. High frequency of indirect jumps
            // 3. Table/memory access pattern

            // Check for loop (has back-edge)
            let has_backedge = block.successors.contains(id) ||
                Self::has_nearby_backedge(cfg, *id);

            if !has_backedge {
                continue;
            }

            // Count indirect jumps and branches
            let indirect_jumps = block.ops.iter()
                .filter(|op| matches!(op.opcode, OpCode::BranchInd))
                .count();

            // Look for table access (load from array/table)
            let has_table_access = Self::has_table_access_pattern(block);

            // Check for fetch pattern (memory read + indirect jump)
            let has_fetch_pattern = Self::has_fetch_decode_pattern(block);

            if indirect_jumps > 0 && (has_table_access || has_fetch_pattern) {
                let loop_size = Self::calculate_loop_size(cfg, *id);
                let dispatch_table = Self::find_dispatch_table(block);
                let dispatch_method = Self::identify_dispatch_method(block);

                let score = indirect_jumps * 10 +
                           (if has_table_access { 5 } else { 0 }) +
                           (if has_fetch_pattern { 5 } else { 0 }) +
                           (if loop_size <= 20 { 5 } else { 0 });

                candidates.push((
                    *id,
                    score,
                    DispatcherInfo {
                        block_id: *id,
                        loop_size,
                        indirect_jumps,
                        dispatch_table,
                        dispatch_method,
                    },
                ));
            }
        }

        // Return highest scoring candidate
        candidates.sort_by_key(|(_, score, _)| std::cmp::Reverse(*score));
        candidates.first().map(|(_, _, info)| info.clone())
    }

    /// Identify Virtual Program Counter (VPC)
    fn identify_vpc(cfg: &ControlFlowGraph, dispatcher: &DispatcherInfo) -> Option<VPCInfo> {
        let block = cfg.blocks.get(&dispatcher.block_id)?;

        // VPC characteristics:
        // 1. Register/variable that is frequently read and incremented
        // 2. Used for memory access (bytecode fetch)
        // 3. Updated in dispatcher loop

        let mut variable_usage: HashMap<String, (usize, bool, bool)> = HashMap::new();

        for op in &block.ops {
            // Track variable usage: (read_count, is_incremented, is_used_for_load)
            for input in &op.inputs {
                let key = Self::varnode_key(input);
                let entry = variable_usage.entry(key.clone()).or_insert((0, false, false));
                entry.0 += 1;

                // Check if used for memory load
                if matches!(op.opcode, OpCode::Load) {
                    entry.2 = true;
                }
            }

            // Check for increment pattern
            if let Some(output) = &op.output {
                if matches!(op.opcode, OpCode::IntAdd) {
                    if op.inputs.len() == 2 {
                        let key = Self::varnode_key(output);
                        if let Some(entry) = variable_usage.get_mut(&key) {
                            entry.1 = true;
                        }
                    }
                }
            }
        }

        // Find most likely VPC: high read count, incremented, used for loads
        let mut vpc_candidates: Vec<_> = variable_usage
            .into_iter()
            .filter(|(_, (count, is_inc, is_load))| *count > 2 && *is_inc && *is_load)
            .collect();

        vpc_candidates.sort_by_key(|(_, (count, _, _))| std::cmp::Reverse(*count));

        if let Some((key, (update_frequency, _, _))) = vpc_candidates.first() {
            // Try to reconstruct the varnode from the key
            let vpc_variable = Self::parse_varnode_key(key)?;
            let increment_pattern = Self::identify_increment_pattern(block, &vpc_variable);
            let bytecode_base = Self::find_bytecode_base(block, &vpc_variable);

            Some(VPCInfo {
                vpc_variable,
                update_frequency: *update_frequency,
                increment_pattern,
                bytecode_base,
            })
        } else {
            None
        }
    }

    /// Enumerate handler functions
    fn enumerate_handlers(
        cfg: &ControlFlowGraph,
        dispatcher: &DispatcherInfo,
    ) -> Vec<VMHandlerInfo> {
        let mut handlers = Vec::new();

        // Handlers are blocks reachable from dispatcher
        let dispatcher_block = match cfg.blocks.get(&dispatcher.block_id) {
            Some(b) => b,
            None => return handlers,
        };

        // Get all successors from dispatcher
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        for &succ in &dispatcher_block.successors {
            queue.push_back(succ);
        }

        while let Some(block_id) = queue.pop_front() {
            if visited.contains(&block_id) || block_id == dispatcher.block_id {
                continue;
            }
            visited.insert(block_id);

            let block = match cfg.blocks.get(&block_id) {
                Some(b) => b,
                None => continue,
            };

            // Check if this block returns to dispatcher
            let returns_to_dispatcher = block.successors.contains(&dispatcher.block_id);

            // Calculate handler complexity (number of operations)
            let complexity = block.ops.len();

            // Try to identify handler opcode (if there's a constant comparison)
            let opcode = Self::identify_handler_opcode(block);

            handlers.push(VMHandlerInfo {
                block_id,
                address: block.ops.first().map(|op| op.address).unwrap_or(0),
                opcode,
                complexity,
                returns_to_dispatcher,
            });

            // Don't explore beyond handler (only direct successors of dispatcher)
        }

        handlers
    }

    /// Analyze VM characteristics
    fn analyze_characteristics(
        dispatcher: &DispatcherInfo,
        handlers: &[VMHandlerInfo],
    ) -> VMCharacteristics {
        let total_handlers = handlers.len();

        let avg_handler_complexity = if !handlers.is_empty() {
            handlers.iter().map(|h| h.complexity).sum::<usize>() as f64 / total_handlers as f64
        } else {
            0.0
        };

        let dispatcher_iterations = handlers
            .iter()
            .filter(|h| h.returns_to_dispatcher)
            .count();

        let bytecode_fetches = dispatcher.indirect_jumps;
        let indirect_jumps = dispatcher.indirect_jumps;

        VMCharacteristics {
            total_handlers,
            avg_handler_complexity,
            dispatcher_iterations,
            bytecode_fetches,
            indirect_jumps,
        }
    }

    /// Calculate confidence score
    fn calculate_confidence(
        dispatcher: &DispatcherInfo,
        vpc: &Option<VPCInfo>,
        handlers: &[VMHandlerInfo],
        characteristics: &VMCharacteristics,
    ) -> f64 {
        // Confidence factors:
        // 1. Dispatcher has loop + indirect jumps (required)
        // 2. VPC identified (high confidence)
        // 3. Multiple handlers found
        // 4. Handlers return to dispatcher

        let mut confidence = 0.0;

        // Base: dispatcher loop with indirect jumps
        if dispatcher.indirect_jumps > 0 {
            confidence += 0.3;
        }

        // VPC identified
        if vpc.is_some() {
            confidence += 0.3;
        }

        // Handler count
        let handler_score = match characteristics.total_handlers {
            0..=2 => 0.0,
            3..=5 => 0.1,
            6..=10 => 0.2,
            _ => 0.3,
        };
        confidence += handler_score;

        // Handlers return to dispatcher
        let return_ratio = if !handlers.is_empty() {
            handlers.iter().filter(|h| h.returns_to_dispatcher).count() as f64 / handlers.len() as f64
        } else {
            0.0
        };
        confidence += return_ratio * 0.1;

        confidence.clamp(0.0, 1.0)
    }

    /// Calculate statistics
    pub fn calculate_statistics(patterns: &[VMPattern]) -> VMStatistics {
        if patterns.is_empty() {
            return VMStatistics {
                total_vm_patterns: 0,
                total_handlers: 0,
                avg_handlers_per_vm: 0.0,
                avg_confidence: 0.0,
            };
        }

        let total_vm_patterns = patterns.len();
        let total_handlers = patterns.iter().map(|p| p.handlers.len()).sum();
        let avg_handlers_per_vm = total_handlers as f64 / total_vm_patterns as f64;
        let avg_confidence = patterns.iter().map(|p| p.confidence).sum::<f64>() / total_vm_patterns as f64;

        VMStatistics {
            total_vm_patterns,
            total_handlers,
            avg_handlers_per_vm,
            avg_confidence,
        }
    }

    // Utility functions

    fn has_nearby_backedge(cfg: &ControlFlowGraph, block_id: usize) -> bool {
        // Check if any successor has a back-edge to this block or nearby blocks
        if let Some(block) = cfg.blocks.get(&block_id) {
            for &succ in &block.successors {
                if succ <= block_id {
                    return true;
                }
                // Check 2 levels deep
                if let Some(succ_block) = cfg.blocks.get(&succ) {
                    for &succ_succ in &succ_block.successors {
                        if succ_succ <= block_id {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_table_access_pattern(block: &BasicBlock) -> bool {
        // Look for: load from (base + index * scale)
        for op in &block.ops {
            if matches!(op.opcode, OpCode::Load) {
                // Check if address is computed (not constant)
                if !op.inputs.is_empty() {
                    if op.inputs[0].space != AddressSpace::Const {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_fetch_decode_pattern(block: &BasicBlock) -> bool {
        // Pattern: Load (fetch) -> comparison/switch (decode) -> indirect branch (dispatch)
        let has_load = block.ops.iter().any(|op| matches!(op.opcode, OpCode::Load));
        let has_compare = block.ops.iter().any(|op| {
            matches!(
                op.opcode,
                OpCode::IntEqual | OpCode::IntNotEqual | OpCode::IntLess
            )
        });
        let has_indirect_branch = block.ops.iter().any(|op| matches!(op.opcode, OpCode::BranchInd));

        has_load && has_compare && has_indirect_branch
    }

    fn calculate_loop_size(cfg: &ControlFlowGraph, start_id: usize) -> usize {
        // BFS to find loop body size
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_id);

        while let Some(block_id) = queue.pop_front() {
            if visited.contains(&block_id) {
                continue;
            }
            visited.insert(block_id);

            if let Some(block) = cfg.blocks.get(&block_id) {
                for &succ in &block.successors {
                    if succ >= start_id && !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }

            if visited.len() > 50 {
                break;
            }
        }

        visited.len()
    }

    fn find_dispatch_table(block: &BasicBlock) -> Option<u64> {
        // Look for constant base address used in computed loads
        for op in &block.ops {
            if matches!(op.opcode, OpCode::Load | OpCode::IntAdd) {
                for input in &op.inputs {
                    if input.space == AddressSpace::Const && input.offset > 0x10000 {
                        return Some(input.offset);
                    }
                }
            }
        }
        None
    }

    fn identify_dispatch_method(block: &BasicBlock) -> DispatchMethod {
        let has_load = block.ops.iter().any(|op| matches!(op.opcode, OpCode::Load));
        let has_comparison = block.ops.iter().any(|op| {
            matches!(op.opcode, OpCode::IntEqual | OpCode::IntNotEqual)
        });

        if has_load && !has_comparison {
            DispatchMethod::JumpTable
        } else if has_comparison {
            DispatchMethod::SwitchCase
        } else {
            DispatchMethod::ComputedGoto
        }
    }

    fn varnode_key(v: &Varnode) -> String {
        format!("{:?}_{}_{}",  v.space, v.offset, v.size)
    }

    fn parse_varnode_key(key: &str) -> Option<Varnode> {
        // Simplified parsing - in production, use proper parsing
        // For now, return a dummy register varnode
        Some(Varnode::register(0, 8))
    }

    fn identify_increment_pattern(block: &BasicBlock, vpc: &Varnode) -> VPCPattern {
        for op in &block.ops {
            if matches!(op.opcode, OpCode::IntAdd) {
                if op.inputs.len() == 2 {
                    // Check if incrementing by 1
                    if let Some(const_val) = Self::get_constant_value(&op.inputs[1]) {
                        if const_val == 1 {
                            return VPCPattern::IncrementOne;
                        } else {
                            return VPCPattern::VariableIncrement;
                        }
                    }
                }
            }
        }
        VPCPattern::Unknown
    }

    fn find_bytecode_base(block: &BasicBlock, vpc: &Varnode) -> Option<u64> {
        // Look for base address used with VPC
        for op in &block.ops {
            if matches!(op.opcode, OpCode::Load | OpCode::IntAdd) {
                for input in &op.inputs {
                    if input.space == AddressSpace::Const && input.offset > 0x10000 {
                        return Some(input.offset);
                    }
                }
            }
        }
        None
    }

    fn identify_handler_opcode(block: &BasicBlock) -> Option<u8> {
        // Look for constant comparisons that might indicate opcode
        for op in &block.ops {
            if matches!(op.opcode, OpCode::IntEqual | OpCode::IntNotEqual) {
                if op.inputs.len() == 2 {
                    if let Some(const_val) = Self::get_constant_value(&op.inputs[1]) {
                        if const_val <= 255 {
                            return Some(const_val as u8);
                        }
                    }
                }
            }
        }
        None
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
    fn test_vm_dispatcher_detection() {
        let mut cfg = ControlFlowGraph {
            blocks: HashMap::new(),
        };

        // Create dispatcher loop (block 0)
        let mut dispatcher = BasicBlock::new();

        // Fetch: load bytecode
        dispatcher.ops.push(PcodeOp {
            opcode: OpCode::Load,
            output: Some(Varnode::register(0, 1)),
            inputs: vec![Varnode::register(1, 8)], // VPC
            address: 0x1000,
        });

        // Decode: compare
        dispatcher.ops.push(PcodeOp {
            opcode: OpCode::IntEqual,
            output: Some(Varnode::unique(100, 1)),
            inputs: vec![Varnode::register(0, 1), Varnode::constant(1, 1)],
            address: 0x1004,
        });

        // Dispatch: indirect jump
        dispatcher.ops.push(PcodeOp {
            opcode: OpCode::BranchInd,
            output: None,
            inputs: vec![Varnode::register(2, 8)],
            address: 0x1008,
        });

        // VPC increment
        dispatcher.ops.push(PcodeOp {
            opcode: OpCode::IntAdd,
            output: Some(Varnode::register(1, 8)),
            inputs: vec![Varnode::register(1, 8), Varnode::constant(1, 8)],
            address: 0x100c,
        });

        dispatcher.successors = vec![0, 1, 2, 3]; // Loop + handlers

        cfg.blocks.insert(0, dispatcher);

        // Create handlers
        for i in 1..=3 {
            let mut handler = BasicBlock::new();
            handler.ops.push(PcodeOp {
                opcode: OpCode::IntAdd,
                output: Some(Varnode::register(3, 8)),
                inputs: vec![Varnode::register(3, 8), Varnode::constant(1, 8)],
                address: 0x2000 + (i * 0x100),
            });
            handler.successors = vec![0]; // Return to dispatcher
            cfg.blocks.insert(i, handler);
        }

        let result = VMDetector::detect(&cfg);
        assert!(result.is_some());

        let pattern = result.unwrap();
        assert_eq!(pattern.dispatcher.block_id, 0);
        assert!(pattern.handlers.len() >= 3);
        assert!(pattern.confidence > 0.5);
    }

    #[test]
    fn test_no_vm_pattern() {
        let mut cfg = ControlFlowGraph {
            blocks: HashMap::new(),
        };

        // Simple linear flow: no VM pattern
        for i in 0..3 {
            let mut block = BasicBlock::new();
            block.ops.push(PcodeOp {
                opcode: OpCode::IntAdd,
                output: Some(Varnode::register(i, 8)),
                inputs: vec![Varnode::register(i, 8), Varnode::constant(1, 8)],
                address: 0x1000 + (i * 0x10),
            });
            if i < 2 {
                block.successors = vec![i + 1];
            }
            cfg.blocks.insert(i, block);
        }

        let result = VMDetector::detect(&cfg);
        assert!(result.is_none());
    }
}
