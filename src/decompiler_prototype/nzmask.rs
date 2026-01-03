/// Non-zero mask analysis for P-code optimization
///
/// NZMask tracks which bits in a Varnode can potentially be non-zero.
/// This enables optimizations like:
/// - V & 0xFF: NZMask = min(nzmask(V), 0xFF)
/// - V | W: NZMask = nzmask(V) | nzmask(W)

use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
use std::collections::HashMap;

/// Analyzer for non-zero mask computation
#[derive(Debug, Clone)]
pub struct NZMaskAnalyzer {
    /// Stores computed masks for each varnode
    masks: HashMap<VarnodeKey, u64>,
}

/// Key for identifying varnodes in the mask map
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VarnodeKey {
    space: AddressSpace,
    offset: u64,
    size: usize,
}

impl From<&Varnode> for VarnodeKey {
    fn from(vn: &Varnode) -> Self {
        VarnodeKey {
            space: vn.space,
            offset: vn.offset,
            size: vn.size,
        }
    }
}

impl NZMaskAnalyzer {
    /// Create a new NZMask analyzer
    pub fn new() -> Self {
        Self {
            masks: HashMap::new(),
        }
    }

    /// Calculate the full mask for a given size (all 1s for size bytes)
    fn calc_mask(size: usize) -> u64 {
        if size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        }
    }

    /// Get the non-zero mask for a varnode
    pub fn get_nzmask(&self, vn: &Varnode) -> u64 {
        let key = VarnodeKey::from(vn);
        self.masks.get(&key).copied().unwrap_or_else(|| {
            if vn.space == AddressSpace::Const {
                vn.offset & Self::calc_mask(vn.size)
            } else {
                Self::calc_mask(vn.size)
            }
        })
    }

    /// Set the non-zero mask for a varnode
    pub fn set_nzmask(&mut self, vn: &Varnode, mask: u64) {
        let key = VarnodeKey::from(vn);
        let bounded_mask = mask & Self::calc_mask(vn.size);
        self.masks.insert(key, bounded_mask);
    }

    /// Compute the NZMask for a P-code operation's output
    pub fn compute_op_nzmask(&mut self, op: &PcodeOp) -> Option<u64> {
        use OpCode::*;

        match op.opcode {
            Copy => {
                let input_mask = self.get_nzmask(&op.inputs[0]);
                Some(input_mask)
            }

            IntAnd => {
                let mask1 = self.get_nzmask(&op.inputs[0]);
                let mask2 = self.get_nzmask(&op.inputs[1]);
                Some(mask1 & mask2)
            }
            IntOr => {
                let mask1 = self.get_nzmask(&op.inputs[0]);
                let mask2 = self.get_nzmask(&op.inputs[1]);
                Some(mask1 | mask2)
            }
            IntXor => {
                let mask1 = self.get_nzmask(&op.inputs[0]);
                let mask2 = self.get_nzmask(&op.inputs[1]);
                Some(mask1 | mask2)
            }
            IntNegate => {
                let _mask = self.get_nzmask(&op.inputs[0]);
                let size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
                Some(Self::calc_mask(size))
            }

            IntLeft => {
                if op.inputs[1].space == AddressSpace::Const {
                    let mask = self.get_nzmask(&op.inputs[0]);
                    let shift = op.inputs[1].offset;
                    let size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
                    Some((mask << shift) & Self::calc_mask(size))
                } else {
                    None
                }
            }
            IntRight | IntSRight => {
                if op.inputs[1].space == AddressSpace::Const {
                    let mask = self.get_nzmask(&op.inputs[0]);
                    let shift = op.inputs[1].offset;
                    Some(mask >> shift)
                } else {
                    None
                }
            }

            IntZExt => {
                let mask = self.get_nzmask(&op.inputs[0]);
                Some(mask)
            }
            IntSExt => {
                let input_mask = self.get_nzmask(&op.inputs[0]);
                let input_size = op.inputs[0].size;
                let output_size = op.output.as_ref().map(|v| v.size).unwrap_or(8);

                let sign_bit = 1u64 << (input_size * 8 - 1);
                if (input_mask & sign_bit) != 0 {
                    Some(Self::calc_mask(output_size))
                } else {
                    Some(input_mask)
                }
            }

            SubPiece => {
                if op.inputs.len() >= 2 && op.inputs[1].space == AddressSpace::Const {
                    let mask = self.get_nzmask(&op.inputs[0]);
                    let offset_bytes = op.inputs[1].offset as usize;
                    let output_size = op.output.as_ref().map(|v| v.size).unwrap_or(4);

                    let shifted_mask = mask >> (offset_bytes * 8);
                    Some(shifted_mask & Self::calc_mask(output_size))
                } else {
                    None
                }
            }

            IntAdd | IntSub => {
                let size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
                Some(Self::calc_mask(size))
            }

            IntMult => {
                let size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
                Some(Self::calc_mask(size))
            }

            IntEqual | IntNotEqual | IntLess | IntLessEqual | IntSLess | IntSLessEqual => {
                Some(1)
            }

            BoolNegate | BoolAnd | BoolOr | BoolXor => {
                Some(1)
            }

            _ => None,
        }
    }

    /// Analyze all operations and compute their NZMasks
    pub fn analyze_ops(&mut self, ops: &[PcodeOp]) {
        let mut changed = true;

        while changed {
            changed = false;

            for op in ops {
                if let Some(output) = &op.output {
                    if let Some(new_mask) = self.compute_op_nzmask(op) {
                        let old_mask = self.get_nzmask(output);
                        if old_mask != new_mask {
                            self.set_nzmask(output, new_mask);
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    /// Compute which bits of a varnode are consumed by operations
    ///
    /// This is used for dead code elimination
    pub fn compute_consume_mask(&self, vn: &Varnode, ops: &[PcodeOp]) -> u64 {
        let mut consume = 0u64;

        for op in ops {
            for (idx, input) in op.inputs.iter().enumerate() {
                if input == vn {
                    match op.opcode {
                        OpCode::IntAnd if idx == 0 && op.inputs.len() > 1 => {
                            if op.inputs[1].space == AddressSpace::Const {
                                consume |= op.inputs[1].offset;
                            } else {
                                consume = Self::calc_mask(vn.size);
                            }
                        }
                        OpCode::IntOr if idx == 0 && op.inputs.len() > 1 => {
                            if op.inputs[1].space == AddressSpace::Const {
                                consume |= !op.inputs[1].offset & Self::calc_mask(vn.size);
                            } else {
                                consume = Self::calc_mask(vn.size);
                            }
                        }
                        OpCode::SubPiece if idx == 0 => {
                            if op.inputs.len() >= 2 && op.inputs[1].space == AddressSpace::Const {
                                let offset = op.inputs[1].offset as usize;
                                let size = op.output.as_ref().map(|v| v.size).unwrap_or(4);
                                let mask = Self::calc_mask(size) << (offset * 8);
                                consume |= mask;
                            } else {
                                consume = Self::calc_mask(vn.size);
                            }
                        }
                        _ => {
                            consume = Self::calc_mask(vn.size);
                        }
                    }
                }
            }
        }

        consume
    }

    /// Get statistics about the computed masks
    pub fn stats(&self) -> NZMaskStats {
        let mut zero_count = 0;
        let mut partial_count = 0;
        let mut full_count = 0;

        for (key, &mask) in &self.masks {
            let full_mask = Self::calc_mask(key.size);
            if mask == 0 {
                zero_count += 1;
            } else if mask == full_mask {
                full_count += 1;
            } else {
                partial_count += 1;
            }
        }

        NZMaskStats {
            total: self.masks.len(),
            zero_count,
            partial_count,
            full_count,
        }
    }
}

impl Default for NZMaskAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about NZMask analysis results
#[derive(Debug, Clone)]
pub struct NZMaskStats {
    pub total: usize,
    pub zero_count: usize,
    pub partial_count: usize,
    pub full_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_mask() {
        assert_eq!(NZMaskAnalyzer::calc_mask(1), 0xFF);
        assert_eq!(NZMaskAnalyzer::calc_mask(2), 0xFFFF);
        assert_eq!(NZMaskAnalyzer::calc_mask(4), 0xFFFF_FFFF);
        assert_eq!(NZMaskAnalyzer::calc_mask(8), 0xFFFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn test_constant_nzmask() {
        let analyzer = NZMaskAnalyzer::new();
        let vn = Varnode::constant(0x0F, 1);
        assert_eq!(analyzer.get_nzmask(&vn), 0x0F);
    }

    #[test]
    fn test_and_nzmask() {
        let mut analyzer = NZMaskAnalyzer::new();

        let v1 = Varnode::register(0, 4);
        let v2 = Varnode::constant(0xFF, 4);
        let output = Varnode::unique(100, 4);

        analyzer.set_nzmask(&v1, 0xFFFF_FFFF);

        let op = PcodeOp::binary(OpCode::IntAnd, output.clone(), v1, v2, 0x1000);
        let mask = analyzer.compute_op_nzmask(&op).unwrap();

        assert_eq!(mask, 0xFF);
    }

    #[test]
    fn test_or_nzmask() {
        let mut analyzer = NZMaskAnalyzer::new();

        let v1 = Varnode::register(0, 4);
        let v2 = Varnode::constant(0xF0, 4);
        let output = Varnode::unique(100, 4);

        analyzer.set_nzmask(&v1, 0x0F);

        let op = PcodeOp::binary(OpCode::IntOr, output.clone(), v1, v2, 0x1000);
        let mask = analyzer.compute_op_nzmask(&op).unwrap();

        assert_eq!(mask, 0xFF);
    }
}
