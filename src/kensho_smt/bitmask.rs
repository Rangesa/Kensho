//! Bit-level analysis: bitmask propagation and constant bit detection
//!
//! This module implements bit-level analysis for MBA simplification.
//! It tracks which bits are known to be 0 or 1 through operations,
//! enabling more aggressive simplification and constant propagation.
//!
//! Key concepts:
//! - **BitMask**: Tracks known_zeros and known_ones for each bit position
//! - **NZMask**: Non-zero mask - bits that may be non-zero
//! - **Constant bits**: Bits that are known to be 0 or 1
//!
//! References:
//! - "Hacker's Delight" by Henry S. Warren Jr.
//! - LLVM's KnownBits analysis

use crate::kensho_smt::expr::Expr;

/// Represents knowledge about which bits are known to be 0 or 1
///
/// Invariant: known_zeros & known_ones == 0
/// (a bit cannot be both known-zero and known-one)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitMask {
    /// Bits that are known to be 0
    pub known_zeros: u64,

    /// Bits that are known to be 1
    pub known_ones: u64,

    /// Bit width
    pub width: u32,
}

impl BitMask {
    /// Create a new bitmask with no known bits
    pub fn unknown(width: u32) -> Self {
        Self {
            known_zeros: 0,
            known_ones: 0,
            width,
        }
    }

    /// Create a bitmask from a constant value
    pub fn constant(value: u64, width: u32) -> Self {
        let mask = Expr::width_mask(width);
        let value = value & mask;
        Self {
            known_zeros: !value & mask,
            known_ones: value & mask,
            width,
        }
    }

    /// Get the width mask for this bitmask
    pub fn width_mask(&self) -> u64 {
        Expr::width_mask(self.width)
    }

    /// Check if all bits are known (fully determined constant)
    pub fn is_constant(&self) -> bool {
        let mask = self.width_mask();
        (self.known_zeros | self.known_ones) == mask
    }

    /// Get the constant value if all bits are known
    pub fn constant_value(&self) -> Option<u64> {
        if self.is_constant() {
            Some(self.known_ones)
        } else {
            None
        }
    }

    /// Get unknown bits (bits that could be either 0 or 1)
    pub fn unknown_bits(&self) -> u64 {
        let mask = self.width_mask();
        !self.known_zeros & !self.known_ones & mask
    }

    /// Get non-zero mask (bits that may be non-zero)
    pub fn nzmask(&self) -> u64 {
        let mask = self.width_mask();
        !self.known_zeros & mask
    }

    /// Compute the minimum possible value
    pub fn min_value(&self) -> u64 {
        self.known_ones
    }

    /// Compute the maximum possible value
    pub fn max_value(&self) -> u64 {
        let mask = self.width_mask();
        self.known_ones | (!self.known_zeros & mask)
    }

    /// Union of two bitmasks (conservative approximation)
    pub fn union(&self, other: &BitMask) -> BitMask {
        assert_eq!(self.width, other.width);
        BitMask {
            known_zeros: self.known_zeros & other.known_zeros,
            known_ones: self.known_ones & other.known_ones,
            width: self.width,
        }
    }

    /// Intersection of two bitmasks (more precise)
    pub fn intersect(&self, other: &BitMask) -> BitMask {
        assert_eq!(self.width, other.width);
        BitMask {
            known_zeros: self.known_zeros | other.known_zeros,
            known_ones: self.known_ones | other.known_ones,
            width: self.width,
        }
    }
}

/// Compute bitmask for an expression
pub fn compute_bitmask(expr: &Expr) -> BitMask {
    match expr {
        Expr::BV { value, width } => BitMask::constant(*value, *width),

        Expr::Var { width, .. } => BitMask::unknown(*width),

        Expr::Add(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_add(&left_bm, &right_bm)
        }

        Expr::Sub(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_sub(&left_bm, &right_bm)
        }

        Expr::Mul(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_mul(&left_bm, &right_bm)
        }

        Expr::And(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_and(&left_bm, &right_bm)
        }

        Expr::Or(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_or(&left_bm, &right_bm)
        }

        Expr::Xor(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_xor(&left_bm, &right_bm)
        }

        Expr::Shl(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_shl(&left_bm, &right_bm)
        }

        Expr::Lshr(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_lshr(&left_bm, &right_bm)
        }

        Expr::Ashr(left, right) => {
            let left_bm = compute_bitmask(left);
            let right_bm = compute_bitmask(right);
            propagate_ashr(&left_bm, &right_bm)
        }

        Expr::Not(inner) => {
            let inner_bm = compute_bitmask(inner);
            propagate_not(&inner_bm)
        }

        Expr::Neg(inner) => {
            let inner_bm = compute_bitmask(inner);
            propagate_neg(&inner_bm)
        }

        Expr::Eq(_, _) => {
            // Boolean result: 0 or 1
            BitMask::unknown(1)
        }
    }
}

/// Propagate bitmask through AND operation
fn propagate_and(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);
    // x & y:
    // - If either bit is known 0, result is 0
    // - If both bits are known 1, result is 1
    BitMask {
        known_zeros: left.known_zeros | right.known_zeros,
        known_ones: left.known_ones & right.known_ones,
        width: left.width,
    }
}

/// Propagate bitmask through OR operation
fn propagate_or(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);
    // x | y:
    // - If either bit is known 1, result is 1
    // - If both bits are known 0, result is 0
    BitMask {
        known_zeros: left.known_zeros & right.known_zeros,
        known_ones: left.known_ones | right.known_ones,
        width: left.width,
    }
}

/// Propagate bitmask through XOR operation
fn propagate_xor(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);
    // x ^ y:
    // - If both bits are known, result is known (xor of the known bits)
    // - If either bit is unknown, result is unknown
    let left_known = left.known_zeros | left.known_ones;
    let right_known = right.known_zeros | right.known_ones;
    let both_known = left_known & right_known;

    let result_value = (left.known_ones ^ right.known_ones) & both_known;
    let mask = left.width_mask();

    BitMask {
        known_zeros: (!result_value & both_known) & mask,
        known_ones: result_value & mask,
        width: left.width,
    }
}

/// Propagate bitmask through NOT operation
fn propagate_not(inner: &BitMask) -> BitMask {
    // ~x: swap known_zeros and known_ones
    let mask = inner.width_mask();
    BitMask {
        known_zeros: inner.known_ones & mask,
        known_ones: inner.known_zeros & mask,
        width: inner.width,
    }
}

/// Propagate bitmask through NEG operation (two's complement)
fn propagate_neg(inner: &BitMask) -> BitMask {
    // -x = ~x + 1
    // This is complex because of carry propagation
    // Conservative: only preserve knowledge if fully known
    if let Some(value) = inner.constant_value() {
        let mask = inner.width_mask();
        BitMask::constant(value.wrapping_neg() & mask, inner.width)
    } else {
        // Conservative: unknown
        BitMask::unknown(inner.width)
    }
}

/// Propagate bitmask through ADD operation
fn propagate_add(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);

    // If both are fully known, compute exact result
    if let (Some(lval), Some(rval)) = (left.constant_value(), right.constant_value()) {
        let mask = left.width_mask();
        return BitMask::constant(lval.wrapping_add(rval) & mask, left.width);
    }

    // Conservative analysis: track low bits that are unaffected by carry
    // For simplicity, only preserve knowledge for low bits where no carry can occur
    let mut known_zeros = 0u64;
    let known_ones = 0u64;

    for i in 0..left.width {
        let bit_mask = 1u64 << i;

        // Check if this bit is known in both operands
        let left_is_zero = (left.known_zeros & bit_mask) != 0;
        let _left_is_one = (left.known_ones & bit_mask) != 0;
        let right_is_zero = (right.known_zeros & bit_mask) != 0;
        let _right_is_one = (right.known_ones & bit_mask) != 0;

        if left_is_zero && right_is_zero {
            // 0 + 0 = 0 (assuming no carry from lower bits)
            // Conservative: only if we can prove no carry
            if i == 0 || (known_zeros & ((1u64 << i) - 1)) == ((1u64 << i) - 1) {
                known_zeros |= bit_mask;
            }
        }
    }

    BitMask {
        known_zeros,
        known_ones,
        width: left.width,
    }
}

/// Propagate bitmask through SUB operation
fn propagate_sub(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);

    // If both are fully known, compute exact result
    if let (Some(lval), Some(rval)) = (left.constant_value(), right.constant_value()) {
        let mask = left.width_mask();
        return BitMask::constant(lval.wrapping_sub(rval) & mask, left.width);
    }

    // Conservative: unknown (carry propagation is complex)
    BitMask::unknown(left.width)
}

/// Propagate bitmask through MUL operation
fn propagate_mul(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);

    // If both are fully known, compute exact result
    if let (Some(lval), Some(rval)) = (left.constant_value(), right.constant_value()) {
        let mask = left.width_mask();
        return BitMask::constant(lval.wrapping_mul(rval) & mask, left.width);
    }

    // Special cases:
    // - x * 0 = 0
    // - x * 1 = x
    if right.constant_value() == Some(0) {
        return BitMask::constant(0, left.width);
    }
    if right.constant_value() == Some(1) {
        return left.clone();
    }
    if left.constant_value() == Some(0) {
        return BitMask::constant(0, left.width);
    }
    if left.constant_value() == Some(1) {
        return right.clone();
    }

    // Conservative: unknown
    BitMask::unknown(left.width)
}

/// Propagate bitmask through SHL operation (logical left shift)
fn propagate_shl(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);

    // If shift amount is constant
    if let Some(shift) = right.constant_value() {
        if shift >= left.width as u64 {
            // Shift by >= width: result is 0
            return BitMask::constant(0, left.width);
        }

        let shift = shift as u32;
        let mask = left.width_mask();

        BitMask {
            known_zeros: ((left.known_zeros << shift) | ((1u64 << shift) - 1)) & mask,
            known_ones: (left.known_ones << shift) & mask,
            width: left.width,
        }
    } else {
        // Unknown shift: conservative
        BitMask::unknown(left.width)
    }
}

/// Propagate bitmask through LSHR operation (logical right shift)
fn propagate_lshr(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);

    // If shift amount is constant
    if let Some(shift) = right.constant_value() {
        if shift >= left.width as u64 {
            // Shift by >= width: result is 0
            return BitMask::constant(0, left.width);
        }

        let shift = shift as u32;
        let mask = left.width_mask();
        let high_bits = mask << (left.width - shift);

        BitMask {
            known_zeros: ((left.known_zeros >> shift) | high_bits) & mask,
            known_ones: (left.known_ones >> shift) & mask,
            width: left.width,
        }
    } else {
        // Unknown shift: conservative
        BitMask::unknown(left.width)
    }
}

/// Propagate bitmask through ASHR operation (arithmetic right shift - sign extend)
fn propagate_ashr(left: &BitMask, right: &BitMask) -> BitMask {
    assert_eq!(left.width, right.width);

    // If shift amount is constant
    if let Some(shift) = right.constant_value() {
        if shift >= left.width as u64 {
            // Shift by >= width: result is all sign bit
            let sign_bit = 1u64 << (left.width - 1);
            if (left.known_ones & sign_bit) != 0 {
                // Sign bit is 1: result is all 1s
                return BitMask::constant(left.width_mask(), left.width);
            } else if (left.known_zeros & sign_bit) != 0 {
                // Sign bit is 0: result is all 0s
                return BitMask::constant(0, left.width);
            } else {
                // Sign bit unknown: result unknown
                return BitMask::unknown(left.width);
            }
        }

        let shift = shift as u32;
        let mask = left.width_mask();
        let sign_bit = 1u64 << (left.width - 1);

        // Determine sign extension
        if (left.known_ones & sign_bit) != 0 {
            // Sign bit is 1: fill with 1s
            let high_bits = mask << (left.width - shift);
            BitMask {
                known_zeros: (left.known_zeros >> shift) & mask,
                known_ones: ((left.known_ones >> shift) | high_bits) & mask,
                width: left.width,
            }
        } else if (left.known_zeros & sign_bit) != 0 {
            // Sign bit is 0: fill with 0s
            let high_bits = mask << (left.width - shift);
            BitMask {
                known_zeros: ((left.known_zeros >> shift) | high_bits) & mask,
                known_ones: (left.known_ones >> shift) & mask,
                width: left.width,
            }
        } else {
            // Sign bit unknown: conservative
            BitMask::unknown(left.width)
        }
    } else {
        // Unknown shift: conservative
        BitMask::unknown(left.width)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmask_constant() {
        let bm = BitMask::constant(0b1010, 4);
        assert_eq!(bm.known_zeros, 0b0101);
        assert_eq!(bm.known_ones, 0b1010);
        assert!(bm.is_constant());
        assert_eq!(bm.constant_value(), Some(0b1010));
    }

    #[test]
    fn test_bitmask_unknown() {
        let bm = BitMask::unknown(8);
        assert_eq!(bm.known_zeros, 0);
        assert_eq!(bm.known_ones, 0);
        assert!(!bm.is_constant());
        assert_eq!(bm.constant_value(), None);
    }

    #[test]
    fn test_propagate_and() {
        let left = BitMask::constant(0b1100, 4);
        let right = BitMask::constant(0b1010, 4);
        let result = propagate_and(&left, &right);
        assert_eq!(result.constant_value(), Some(0b1000));
    }

    #[test]
    fn test_propagate_or() {
        let left = BitMask::constant(0b1100, 4);
        let right = BitMask::constant(0b1010, 4);
        let result = propagate_or(&left, &right);
        assert_eq!(result.constant_value(), Some(0b1110));
    }

    #[test]
    fn test_propagate_xor() {
        let left = BitMask::constant(0b1100, 4);
        let right = BitMask::constant(0b1010, 4);
        let result = propagate_xor(&left, &right);
        assert_eq!(result.constant_value(), Some(0b0110));
    }

    #[test]
    fn test_propagate_not() {
        let inner = BitMask::constant(0b1010, 4);
        let result = propagate_not(&inner);
        assert_eq!(result.constant_value(), Some(0b0101));
    }

    #[test]
    fn test_propagate_shl() {
        let left = BitMask::constant(0b0011, 8);
        let right = BitMask::constant(2, 8);
        let result = propagate_shl(&left, &right);
        assert_eq!(result.constant_value(), Some(0b1100));
    }

    #[test]
    fn test_propagate_lshr() {
        let left = BitMask::constant(0b1100, 8);
        let right = BitMask::constant(2, 8);
        let result = propagate_lshr(&left, &right);
        assert_eq!(result.constant_value(), Some(0b0011));
    }

    #[test]
    fn test_nzmask() {
        let bm = BitMask {
            known_zeros: 0b1010,
            known_ones: 0b0100,
            width: 4,
        };
        // Non-zero mask = bits that may be non-zero = !known_zeros & mask
        assert_eq!(bm.nzmask(), 0b0101);
    }

    #[test]
    fn test_compute_bitmask_expr() {
        let x = Expr::const_bv(0b1100, 4);
        let y = Expr::const_bv(0b1010, 4);
        let and_expr = Expr::and(x, y);

        let result = compute_bitmask(&and_expr);
        assert_eq!(result.constant_value(), Some(0b1000));
    }
}
