/// MBA pattern detector
///
/// Detects Mixed Boolean-Arithmetic patterns in P-code sequences

use super::super::pcode::{OpCode, PcodeOp, Varnode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MBA pattern detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MBAPattern {
    /// Complexity score (1-10)
    pub complexity: u8,

    /// Number of bitwise operations (AND, OR, XOR, NOT)
    pub bitop_count: usize,

    /// Number of arithmetic operations (ADD, SUB, MUL, DIV)
    pub arith_count: usize,

    /// Total operation chain length
    pub chain_length: usize,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,

    /// Location in CFG
    pub location: MBALocation,

    /// Variables involved
    pub variables: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MBALocation {
    pub block_id: usize,
    pub op_range: (usize, usize), // (start, end)
    pub address_range: (u64, u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MBAStatistics {
    pub total_patterns: usize,
    pub avg_complexity: f64,
    pub max_complexity: u8,
    pub total_operations_hidden: usize,
}

pub struct MBADetector;

impl MBADetector {
    /// Detect MBA patterns in a sequence of P-code operations
    pub fn detect(ops: &[PcodeOp]) -> Vec<MBAPattern> {
        let mut patterns = Vec::new();

        // Sliding window approach (window size: 3-15 operations)
        for window_size in 3..=15 {
            if window_size > ops.len() {
                break;
            }

            for window_start in 0..=ops.len().saturating_sub(window_size) {
                let window = &ops[window_start..window_start + window_size];

                if let Some(pattern) = Self::analyze_window(window, window_start) {
                    patterns.push(pattern);
                }
            }
        }

        // Merge overlapping patterns (keep the most complex one)
        Self::merge_patterns(patterns)
    }

    /// Detect MBA patterns in a CFG block
    pub fn detect_in_block(block_id: usize, ops: &[PcodeOp]) -> Vec<MBAPattern> {
        let mut patterns = Self::detect(ops);

        // Update block_id
        for pattern in &mut patterns {
            pattern.location.block_id = block_id;
        }

        patterns
    }

    /// Calculate statistics for detected patterns
    pub fn calculate_statistics(patterns: &[MBAPattern]) -> MBAStatistics {
        if patterns.is_empty() {
            return MBAStatistics {
                total_patterns: 0,
                avg_complexity: 0.0,
                max_complexity: 0,
                total_operations_hidden: 0,
            };
        }

        let total_patterns = patterns.len();
        let avg_complexity = patterns.iter().map(|p| p.complexity as f64).sum::<f64>()
            / total_patterns as f64;
        let max_complexity = patterns.iter().map(|p| p.complexity).max().unwrap_or(0);
        let total_operations_hidden = patterns.iter().map(|p| p.chain_length).sum();

        MBAStatistics {
            total_patterns,
            avg_complexity,
            max_complexity,
            total_operations_hidden,
        }
    }

    fn analyze_window(ops: &[PcodeOp], window_start: usize) -> Option<MBAPattern> {
        let bitop_count = Self::count_bitwise_ops(ops);
        let arith_count = Self::count_arithmetic_ops(ops);

        // MBA heuristic: both bitwise and arithmetic ops present
        if bitop_count > 0 && arith_count > 0 {
            // Calculate complexity score
            let complexity = Self::calculate_complexity(ops, bitop_count, arith_count);

            // Only report if complexity is significant (>= 3)
            if complexity >= 3 {
                let variables = Self::extract_variables(ops);
                let location = Self::extract_location(ops, window_start);

                return Some(MBAPattern {
                    complexity,
                    bitop_count,
                    arith_count,
                    chain_length: ops.len(),
                    confidence: Self::calculate_confidence(bitop_count, arith_count, ops.len()),
                    location,
                    variables,
                });
            }
        }

        None
    }

    fn count_bitwise_ops(ops: &[PcodeOp]) -> usize {
        ops.iter()
            .filter(|op| {
                matches!(
                    op.opcode,
                    OpCode::IntAnd
                        | OpCode::IntOr
                        | OpCode::IntXor
                        | OpCode::IntNegate
                        | OpCode::IntLeft
                        | OpCode::IntRight
                        | OpCode::IntSRight
                )
            })
            .count()
    }

    fn count_arithmetic_ops(ops: &[PcodeOp]) -> usize {
        ops.iter()
            .filter(|op| {
                matches!(
                    op.opcode,
                    OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult | OpCode::IntDiv
                )
            })
            .count()
    }

    fn calculate_complexity(ops: &[PcodeOp], bitop_count: usize, arith_count: usize) -> u8 {
        // Complexity factors:
        // 1. Number of operations
        // 2. Mix ratio (bitwise vs arithmetic)
        // 3. Chain depth

        let base_complexity = (bitop_count + arith_count).min(10);
        let mix_factor = if bitop_count == arith_count {
            1.2 // Perfect mix is more suspicious
        } else {
            1.0
        };

        let chain_depth = Self::calculate_chain_depth(ops);
        let depth_factor = (chain_depth as f64 / 5.0).min(1.5);

        let complexity = (base_complexity as f64 * mix_factor * depth_factor) as u8;
        complexity.clamp(1, 10)
    }

    fn calculate_chain_depth(ops: &[PcodeOp]) -> usize {
        // Count how many operations depend on previous results
        let mut depth = 0;
        let mut defined_vars = HashMap::new();

        for (_idx, op) in ops.iter().enumerate() {
            if let Some(output) = &op.output {
                // Check if inputs are defined in this chain
                let max_input_depth = op
                    .inputs
                    .iter()
                    .filter_map(|input| defined_vars.get(input))
                    .max()
                    .unwrap_or(&0);

                let current_depth = max_input_depth + 1;
                defined_vars.insert(output.clone(), current_depth);
                depth = depth.max(current_depth);
            }
        }

        depth
    }

    fn calculate_confidence(bitop_count: usize, arith_count: usize, chain_len: usize) -> f64 {
        // Confidence increases with:
        // 1. More operations
        // 2. Better balance between bitwise and arithmetic
        // 3. Longer chains

        let count_score = ((bitop_count + arith_count) as f64 / 10.0).min(1.0);

        let balance = bitop_count.min(arith_count) as f64
            / bitop_count.max(arith_count).max(1) as f64;

        let chain_score = (chain_len as f64 / 15.0).min(1.0);

        let confidence = (count_score * 0.4 + balance * 0.4 + chain_score * 0.2).clamp(0.3, 0.95);

        // Round to 2 decimal places
        (confidence * 100.0).round() / 100.0
    }

    fn extract_variables(ops: &[PcodeOp]) -> Vec<String> {
        let mut vars = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for op in ops {
            for input in &op.inputs {
                let var_name = Self::varnode_to_name(input);
                if seen.insert(var_name.clone()) {
                    vars.push(var_name);
                }
            }

            if let Some(output) = &op.output {
                let var_name = Self::varnode_to_name(output);
                if seen.insert(var_name.clone()) {
                    vars.push(var_name);
                }
            }
        }

        vars
    }

    fn varnode_to_name(varnode: &Varnode) -> String {
        use super::super::pcode::AddressSpace;

        match varnode.space {
            AddressSpace::Register => format!("reg_{}", varnode.offset),
            AddressSpace::Const => format!("const_{}", varnode.offset),
            AddressSpace::Unique => format!("unique_{}", varnode.offset),
            AddressSpace::Ram => format!("mem_0x{:x}", varnode.offset),
            AddressSpace::Stack => format!("stack_0x{:x}", varnode.offset),
        }
    }

    fn extract_location(ops: &[PcodeOp], window_start: usize) -> MBALocation {
        let first_addr = ops.first().map(|op| op.address).unwrap_or(0);
        let last_addr = ops.last().map(|op| op.address).unwrap_or(0);

        MBALocation {
            block_id: 0, // Will be updated by caller
            op_range: (window_start, window_start + ops.len()),
            address_range: (first_addr, last_addr),
        }
    }

    fn merge_patterns(mut patterns: Vec<MBAPattern>) -> Vec<MBAPattern> {
        if patterns.is_empty() {
            return patterns;
        }

        // Sort by start position
        patterns.sort_by_key(|p| p.location.op_range.0);

        let mut merged = Vec::new();
        let mut current = patterns[0].clone();

        for pattern in patterns.into_iter().skip(1) {
            // Check if overlapping
            if pattern.location.op_range.0 <= current.location.op_range.1 {
                // Keep the more complex pattern
                if pattern.complexity > current.complexity {
                    current = pattern;
                }
            } else {
                merged.push(current);
                current = pattern;
            }
        }

        merged.push(current);
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::pcode::Varnode;

    #[test]
    fn test_basic_mba_detection() {
        // (x XOR y) + 2(x AND y) pattern
        let ops = vec![
            PcodeOp {
                opcode: OpCode::IntXor,
                output: Some(Varnode::unique(100, 8)),
                inputs: vec![Varnode::register(0, 8), Varnode::register(1, 8)],
                address: 0x1000,
            },
            PcodeOp {
                opcode: OpCode::IntAnd,
                output: Some(Varnode::unique(101, 8)),
                inputs: vec![Varnode::register(0, 8), Varnode::register(1, 8)],
                address: 0x1004,
            },
            PcodeOp {
                opcode: OpCode::IntMult,
                output: Some(Varnode::unique(102, 8)),
                inputs: vec![Varnode::unique(101, 8), Varnode::constant(2, 8)],
                address: 0x1008,
            },
            PcodeOp {
                opcode: OpCode::IntAdd,
                output: Some(Varnode::unique(103, 8)),
                inputs: vec![Varnode::unique(100, 8), Varnode::unique(102, 8)],
                address: 0x100C,
            },
        ];

        let patterns = MBADetector::detect(&ops);

        assert!(!patterns.is_empty());
        assert!(patterns[0].complexity >= 3);
        assert!(patterns[0].bitop_count >= 2);
        assert!(patterns[0].arith_count >= 2);
    }

    #[test]
    fn test_no_mba_detection() {
        // Simple arithmetic only (no MBA)
        let ops = vec![
            PcodeOp {
                opcode: OpCode::IntAdd,
                output: Some(Varnode::unique(100, 8)),
                inputs: vec![Varnode::register(0, 8), Varnode::register(1, 8)],
                address: 0x1000,
            },
            PcodeOp {
                opcode: OpCode::IntSub,
                output: Some(Varnode::unique(101, 8)),
                inputs: vec![Varnode::unique(100, 8), Varnode::constant(5, 8)],
                address: 0x1004,
            },
        ];

        let patterns = MBADetector::detect(&ops);

        // Should not detect MBA (no bitwise operations)
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_statistics() {
        let patterns = vec![
            MBAPattern {
                complexity: 5,
                bitop_count: 3,
                arith_count: 2,
                chain_length: 5,
                confidence: 0.8,
                location: MBALocation {
                    block_id: 0,
                    op_range: (0, 5),
                    address_range: (0x1000, 0x1014),
                },
                variables: vec!["x".to_string(), "y".to_string()],
            },
            MBAPattern {
                complexity: 7,
                bitop_count: 4,
                arith_count: 3,
                chain_length: 7,
                confidence: 0.9,
                location: MBALocation {
                    block_id: 0,
                    op_range: (10, 17),
                    address_range: (0x1020, 0x103C),
                },
                variables: vec!["a".to_string(), "b".to_string()],
            },
        ];

        let stats = MBADetector::calculate_statistics(&patterns);

        assert_eq!(stats.total_patterns, 2);
        assert_eq!(stats.avg_complexity, 6.0);
        assert_eq!(stats.max_complexity, 7);
        assert_eq!(stats.total_operations_hidden, 12);
    }
}
