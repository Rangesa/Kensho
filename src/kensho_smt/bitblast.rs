//! Bit-blasting: Convert bit-vector expressions to Boolean formulas
//!
//! Bit-blasting transforms bit-vector operations into Boolean logic,
//! enabling the use of Boolean SAT solvers for bit-vector problems.
//!
//! Example:
//! - BV expr `x + y` (8-bit) → 8 Boolean expressions (one per bit)
//! - BV expr `x & y` → bit-wise AND: `x[i] ∧ y[i]` for each bit i
//!
//! References:
//! - "Bit-Vector Logic" in Handbook of Satisfiability
//! - "A Decision Procedure for Bit-Vectors and Arrays" (Ganesh & Dill)

use crate::kensho_smt::expr::Expr;
use std::collections::HashMap;

/// Boolean expression for SAT solving
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoolExpr {
    /// Constant true
    True,
    /// Constant false
    False,
    /// Boolean variable (name, bit_index)
    Var(String, usize),
    /// Logical AND
    And(Box<BoolExpr>, Box<BoolExpr>),
    /// Logical OR
    Or(Box<BoolExpr>, Box<BoolExpr>),
    /// Logical NOT
    Not(Box<BoolExpr>),
    /// Logical XOR
    Xor(Box<BoolExpr>, Box<BoolExpr>),
    /// Logical IMPLIES (a → b = ¬a ∨ b)
    Implies(Box<BoolExpr>, Box<BoolExpr>),
    /// Logical IFF (a ↔ b = (a ∧ b) ∨ (¬a ∧ ¬b))
    Iff(Box<BoolExpr>, Box<BoolExpr>),
}

impl BoolExpr {
    /// Create AND expression
    pub fn and(left: BoolExpr, right: BoolExpr) -> Self {
        BoolExpr::And(Box::new(left), Box::new(right))
    }

    /// Create OR expression
    pub fn or(left: BoolExpr, right: BoolExpr) -> Self {
        BoolExpr::Or(Box::new(left), Box::new(right))
    }

    /// Create NOT expression
    pub fn not(expr: BoolExpr) -> Self {
        BoolExpr::Not(Box::new(expr))
    }

    /// Create XOR expression
    pub fn xor(left: BoolExpr, right: BoolExpr) -> Self {
        BoolExpr::Xor(Box::new(left), Box::new(right))
    }

    /// Create IMPLIES expression
    pub fn implies(left: BoolExpr, right: BoolExpr) -> Self {
        BoolExpr::Implies(Box::new(left), Box::new(right))
    }

    /// Create IFF (if-and-only-if) expression
    pub fn iff(left: BoolExpr, right: BoolExpr) -> Self {
        BoolExpr::Iff(Box::new(left), Box::new(right))
    }

    /// Simplify Boolean expression
    pub fn simplify(&self) -> BoolExpr {
        match self {
            BoolExpr::True | BoolExpr::False | BoolExpr::Var(_, _) => self.clone(),

            BoolExpr::Not(inner) => match &**inner {
                BoolExpr::True => BoolExpr::False,
                BoolExpr::False => BoolExpr::True,
                BoolExpr::Not(inner2) => inner2.simplify(),
                _ => BoolExpr::not(inner.simplify()),
            },

            BoolExpr::And(left, right) => {
                let l = left.simplify();
                let r = right.simplify();
                match (&l, &r) {
                    (BoolExpr::False, _) | (_, BoolExpr::False) => BoolExpr::False,
                    (BoolExpr::True, x) | (x, BoolExpr::True) => x.clone(),
                    _ => BoolExpr::and(l, r),
                }
            }

            BoolExpr::Or(left, right) => {
                let l = left.simplify();
                let r = right.simplify();
                match (&l, &r) {
                    (BoolExpr::True, _) | (_, BoolExpr::True) => BoolExpr::True,
                    (BoolExpr::False, x) | (x, BoolExpr::False) => x.clone(),
                    _ => BoolExpr::or(l, r),
                }
            }

            BoolExpr::Xor(left, right) => {
                let l = left.simplify();
                let r = right.simplify();
                match (&l, &r) {
                    (BoolExpr::False, x) | (x, BoolExpr::False) => x.clone(),
                    (BoolExpr::True, x) => BoolExpr::not(x.clone()).simplify(),
                    (x, BoolExpr::True) => BoolExpr::not(x.clone()).simplify(),
                    // x ⊕ x = False
                    _ if l == r => BoolExpr::False,
                    // ¬x ⊕ x = True (or x ⊕ ¬x = True)
                    (BoolExpr::Not(inner_l), inner_r) if inner_l.as_ref() == inner_r => BoolExpr::True,
                    (inner_l, BoolExpr::Not(inner_r)) if inner_l == inner_r.as_ref() => BoolExpr::True,
                    _ => BoolExpr::xor(l, r),
                }
            }

            BoolExpr::Implies(left, right) => {
                // a → b = ¬a ∨ b
                let l = left.simplify();
                let r = right.simplify();
                BoolExpr::or(BoolExpr::not(l), r).simplify()
            }

            BoolExpr::Iff(left, right) => {
                // a ↔ b = (a ∧ b) ∨ (¬a ∧ ¬b)
                let l = left.simplify();
                let r = right.simplify();
                let both_true = BoolExpr::and(l.clone(), r.clone());
                let both_false = BoolExpr::and(BoolExpr::not(l), BoolExpr::not(r));
                BoolExpr::or(both_true, both_false).simplify()
            }
        }
    }
}

/// Bit-blaster: Converts bit-vector expressions to Boolean formulas
pub struct BitBlaster {
    /// Cache of blasted expressions: (expr, bit_index) -> BoolExpr
    cache: HashMap<(Expr, usize), BoolExpr>,
}

impl BitBlaster {
    /// Create a new bit-blaster
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Bit-blast a bit-vector expression to Boolean formulas (one per bit)
    ///
    /// # Arguments
    /// * `expr` - The bit-vector expression to blast
    ///
    /// # Returns
    /// Vector of Boolean expressions, one for each bit (LSB first)
    pub fn blast(&mut self, expr: &Expr) -> Vec<BoolExpr> {
        let width = expr.width() as usize;
        (0..width).map(|i| self.blast_bit(expr, i)).collect()
    }

    /// Bit-blast a single bit of a bit-vector expression
    ///
    /// # Arguments
    /// * `expr` - The bit-vector expression
    /// * `bit_index` - The bit position to extract (0 = LSB)
    ///
    /// # Returns
    /// Boolean expression for the specified bit
    pub fn blast_bit(&mut self, expr: &Expr, bit_index: usize) -> BoolExpr {
        let key = (expr.clone(), bit_index);

        // Check cache
        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }

        let result = match expr {
            Expr::BV { value, .. } => {
                // Extract bit from constant
                if (value >> bit_index) & 1 == 1 {
                    BoolExpr::True
                } else {
                    BoolExpr::False
                }
            }

            Expr::Var { name, .. } => BoolExpr::Var(name.clone(), bit_index),

            Expr::And(left, right) => {
                let l = self.blast_bit(left, bit_index);
                let r = self.blast_bit(right, bit_index);
                BoolExpr::and(l, r)
            }

            Expr::Or(left, right) => {
                let l = self.blast_bit(left, bit_index);
                let r = self.blast_bit(right, bit_index);
                BoolExpr::or(l, r)
            }

            Expr::Xor(left, right) => {
                let l = self.blast_bit(left, bit_index);
                let r = self.blast_bit(right, bit_index);
                BoolExpr::xor(l, r)
            }

            Expr::Not(inner) => {
                let inner_bit = self.blast_bit(inner, bit_index);
                BoolExpr::not(inner_bit)
            }

            Expr::Add(left, right) => self.blast_add_bit(left, right, bit_index),

            Expr::Sub(left, right) => {
                // a - b = a + (-b) = a + (~b + 1)
                let neg_right = Expr::add(Expr::not((**right).clone()), Expr::const_bv(1, right.width()));
                self.blast_add_bit(left, &neg_right, bit_index)
            }

            Expr::Mul(left, right) => self.blast_mul_bit(left, right, bit_index),

            Expr::Neg(inner) => {
                // -x = ~x + 1
                let not_inner = Expr::not((**inner).clone());
                let one = Expr::const_bv(1, inner.width());
                let neg_expr = Expr::add(not_inner, one);
                self.blast_bit(&neg_expr, bit_index)
            }

            Expr::Shl(left, right) => self.blast_shl_bit(left, right, bit_index),

            Expr::Lshr(left, right) => self.blast_lshr_bit(left, right, bit_index),

            Expr::Ashr(left, right) => self.blast_ashr_bit(left, right, bit_index),

            Expr::Eq(left, right) => {
                // Equality: all bits must be equal
                // result[0] = (left[0] ↔ right[0]) ∧ ... ∧ (left[n-1] ↔ right[n-1])
                // Other bits are False
                if bit_index == 0 {
                    let width = left.width() as usize;
                    let mut eq = BoolExpr::True;
                    for i in 0..width {
                        let l = self.blast_bit(left, i);
                        let r = self.blast_bit(right, i);
                        eq = BoolExpr::and(eq, BoolExpr::iff(l, r));
                    }
                    eq
                } else {
                    BoolExpr::False
                }
            }
        };

        self.cache.insert(key, result.clone());
        result
    }

    /// Bit-blast addition at a specific bit (with carry propagation)
    fn blast_add_bit(&mut self, left: &Expr, right: &Expr, bit_index: usize) -> BoolExpr {
        if bit_index == 0 {
            // LSB: no carry-in
            let l = self.blast_bit(left, 0);
            let r = self.blast_bit(right, 0);
            BoolExpr::xor(l, r)
        } else {
            // Bit i: sum = left[i] ⊕ right[i] ⊕ carry[i-1]
            let l = self.blast_bit(left, bit_index);
            let r = self.blast_bit(right, bit_index);
            let carry_in = self.compute_carry(left, right, bit_index - 1);
            BoolExpr::xor(BoolExpr::xor(l, r), carry_in)
        }
    }

    /// Compute carry bit for addition
    fn compute_carry(&mut self, left: &Expr, right: &Expr, bit_index: usize) -> BoolExpr {
        if bit_index == 0 {
            // carry[0] = left[0] ∧ right[0]
            let l = self.blast_bit(left, 0);
            let r = self.blast_bit(right, 0);
            BoolExpr::and(l, r)
        } else {
            // carry[i] = (left[i] ∧ right[i]) ∨ (left[i] ∧ carry[i-1]) ∨ (right[i] ∧ carry[i-1])
            let l = self.blast_bit(left, bit_index);
            let r = self.blast_bit(right, bit_index);
            let carry_prev = self.compute_carry(left, right, bit_index - 1);

            let lr = BoolExpr::and(l.clone(), r.clone());
            let lc = BoolExpr::and(l, carry_prev.clone());
            let rc = BoolExpr::and(r, carry_prev);

            BoolExpr::or(lr, BoolExpr::or(lc, rc))
        }
    }

    /// Bit-blast multiplication at a specific bit (simplified - quadratic complexity)
    fn blast_mul_bit(&mut self, left: &Expr, right: &Expr, bit_index: usize) -> BoolExpr {
        let width = left.width() as usize;

        // Multiplication: result[k] = Σ(i+j=k) left[i] ∧ right[j]
        let mut sum = BoolExpr::False;

        for i in 0..=bit_index.min(width - 1) {
            let j = bit_index - i;
            if j < width {
                let l = self.blast_bit(left, i);
                let r = self.blast_bit(right, j);
                let product = BoolExpr::and(l, r);
                sum = BoolExpr::xor(sum, product);
            }
        }

        sum
    }

    /// Bit-blast left shift at a specific bit
    fn blast_shl_bit(&mut self, left: &Expr, right: &Expr, bit_index: usize) -> BoolExpr {
        // If shift amount is constant, handle directly
        if let Some(shift_val) = right.const_value() {
            let shift = shift_val as usize;
            if bit_index < shift {
                return BoolExpr::False;
            }
            return self.blast_bit(left, bit_index - shift);
        }

        // Dynamic shift: use multiplexer
        let width = left.width() as usize;
        let mut result = BoolExpr::False;

        for shift_val in 0..width {
            if bit_index >= shift_val {
                let shifted_bit = if bit_index - shift_val < width {
                    self.blast_bit(left, bit_index - shift_val)
                } else {
                    BoolExpr::False
                };

                // Check if shift amount equals shift_val
                let shift_eq = self.blast_equals_constant(right, shift_val as u64);
                result = BoolExpr::or(result, BoolExpr::and(shift_eq, shifted_bit));
            }
        }

        result
    }

    /// Bit-blast logical right shift at a specific bit
    fn blast_lshr_bit(&mut self, left: &Expr, right: &Expr, bit_index: usize) -> BoolExpr {
        if let Some(shift_val) = right.const_value() {
            let shift = shift_val as usize;
            let new_index = bit_index + shift;
            let width = left.width() as usize;

            if new_index >= width {
                return BoolExpr::False;
            }
            return self.blast_bit(left, new_index);
        }

        // Dynamic shift
        let width = left.width() as usize;
        let mut result = BoolExpr::False;

        for shift_val in 0..width {
            let new_index = bit_index + shift_val;
            let shifted_bit = if new_index < width {
                self.blast_bit(left, new_index)
            } else {
                BoolExpr::False
            };

            let shift_eq = self.blast_equals_constant(right, shift_val as u64);
            result = BoolExpr::or(result, BoolExpr::and(shift_eq, shifted_bit));
        }

        result
    }

    /// Bit-blast arithmetic right shift at a specific bit
    fn blast_ashr_bit(&mut self, left: &Expr, right: &Expr, bit_index: usize) -> BoolExpr {
        let width = left.width() as usize;
        let sign_bit_index = width - 1;

        if let Some(shift_val) = right.const_value() {
            let shift = shift_val as usize;
            let new_index = bit_index + shift;

            if new_index >= width {
                // Fill with sign bit
                return self.blast_bit(left, sign_bit_index);
            }
            return self.blast_bit(left, new_index);
        }

        // Dynamic shift
        let mut result = BoolExpr::False;

        for shift_val in 0..width {
            let new_index = bit_index + shift_val;
            let shifted_bit = if new_index < width {
                self.blast_bit(left, new_index)
            } else {
                // Sign extension
                self.blast_bit(left, sign_bit_index)
            };

            let shift_eq = self.blast_equals_constant(right, shift_val as u64);
            result = BoolExpr::or(result, BoolExpr::and(shift_eq, shifted_bit));
        }

        result
    }

    /// Create Boolean expression: expr == constant
    fn blast_equals_constant(&mut self, expr: &Expr, constant: u64) -> BoolExpr {
        let width = expr.width() as usize;
        let mut eq = BoolExpr::True;

        for i in 0..width {
            let bit_val = (constant >> i) & 1;
            let bit_expr = self.blast_bit(expr, i);

            let eq_bit = if bit_val == 1 {
                bit_expr
            } else {
                BoolExpr::not(bit_expr)
            };

            eq = BoolExpr::and(eq, eq_bit);
        }

        eq
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for BitBlaster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blast_constant() {
        let mut blaster = BitBlaster::new();
        let expr = Expr::const_bv(0b1010, 4);
        let bits = blaster.blast(&expr);

        assert_eq!(bits.len(), 4);
        assert_eq!(bits[0], BoolExpr::False); // LSB
        assert_eq!(bits[1], BoolExpr::True);
        assert_eq!(bits[2], BoolExpr::False);
        assert_eq!(bits[3], BoolExpr::True);  // MSB
    }

    #[test]
    fn test_blast_and() {
        let mut blaster = BitBlaster::new();
        let x = Expr::var("x", 4);
        let y = Expr::var("y", 4);
        let expr = Expr::and(x, y);

        let bit0 = blaster.blast_bit(&expr, 0);
        match bit0 {
            BoolExpr::And(l, r) => {
                assert_eq!(*l, BoolExpr::Var("x".to_string(), 0));
                assert_eq!(*r, BoolExpr::Var("y".to_string(), 0));
            }
            _ => panic!("Expected And expression"),
        }
    }

    #[test]
    fn test_blast_or() {
        let mut blaster = BitBlaster::new();
        let x = Expr::var("x", 4);
        let y = Expr::var("y", 4);
        let expr = Expr::or(x, y);

        let bit0 = blaster.blast_bit(&expr, 0);
        match bit0 {
            BoolExpr::Or(l, r) => {
                assert_eq!(*l, BoolExpr::Var("x".to_string(), 0));
                assert_eq!(*r, BoolExpr::Var("y".to_string(), 0));
            }
            _ => panic!("Expected Or expression"),
        }
    }

    #[test]
    fn test_bool_expr_simplify() {
        let expr = BoolExpr::and(BoolExpr::True, BoolExpr::Var("x".to_string(), 0));
        let simplified = expr.simplify();
        assert_eq!(simplified, BoolExpr::Var("x".to_string(), 0));
    }

    #[test]
    fn test_bool_expr_not_not() {
        let expr = BoolExpr::not(BoolExpr::not(BoolExpr::Var("x".to_string(), 0)));
        let simplified = expr.simplify();
        assert_eq!(simplified, BoolExpr::Var("x".to_string(), 0));
    }
}
