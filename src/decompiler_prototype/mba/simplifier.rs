/// MBA expression simplifier
///
/// Applies algebraic rewrite rules to simplify MBA expressions

use super::super::pcode::{OpCode, PcodeOp, Varnode, AddressSpace};
use super::detector::MBAPattern;
use serde::{Deserialize, Serialize};

/// Simplified expression result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplifiedExpression {
    /// Human-readable form (e.g., "x + y")
    pub expression: String,

    /// P-code representation (simplified)
    pub pcode_ops: Vec<PcodeOp>,

    /// Verification method used
    pub verification: VerificationMethod,

    /// Rules applied
    pub rules_applied: Vec<SimplificationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// Algebraic rewrite rules only
    AlgebraicRules,

    /// Verified by SMT solver (Z3)
    SmtProven { solving_time_ms: f64 },

    /// Candidate only (not verified)
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimplificationRule {
    /// (x ⊕ y) + 2(x ∧ y) → x + y
    XorAndAdd,

    /// (x ∧ y) + (x ∨ y) → x + y
    AndOrAdd,

    /// (x ∨ y) + (x ∧ y) → x | y (bitwise)
    OrAndBitwise,

    /// x ⊕ (x ∧ y) → x ∧ ¬y
    XorAndMask,

    /// (x | y) - (x & y) → x ^ y
    OrMinusAnd,

    /// 2(x & y) + (x ^ y) → x + y
    TwoAndPlusXor,

    /// (x & ~y) + (y & ~x) → x ^ y
    MaskedXor,

    /// (x | y) - (x ^ y) → x & y
    OrMinusXor,

    /// ~(x ^ y) + 2(x | y) → ~x + ~y - 1
    NotXorPlusOr,

    /// (x + y) ^ (x & y) → x | y
    AddXorAnd,
}

pub struct MBASimplifier;

impl MBASimplifier {
    /// Apply algebraic simplification rules
    pub fn simplify_basic(pattern: &MBAPattern, ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        // Try each rule in order
        let rules = [
            Self::apply_rule_xor_and_add,
            Self::apply_rule_and_or_add,
            Self::apply_rule_or_minus_and,
            Self::apply_rule_two_and_plus_xor,
            Self::apply_rule_masked_xor,
            Self::apply_rule_or_minus_xor,
            Self::apply_rule_add_xor_and,
        ];

        for rule in &rules {
            if let Some(simplified) = rule(ops) {
                return Some(simplified);
            }
        }

        None
    }

    /// Rule 1: (x ⊕ y) + 2(x ∧ y) → x + y
    fn apply_rule_xor_and_add(ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        // Pattern: XOR, AND, MULT(2), ADD
        if ops.len() < 4 {
            return None;
        }

        // Find XOR operation
        let xor_op = ops.iter().find(|op| matches!(op.opcode, OpCode::IntXor))?;
        let xor_out = xor_op.output.as_ref()?;
        let x = xor_op.inputs.get(0)?;
        let y = xor_op.inputs.get(1)?;

        // Find AND operation with same inputs
        let and_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntAnd)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], x) && Self::varnodes_equal(&op.inputs[1], y))
                    || (Self::varnodes_equal(&op.inputs[0], y) && Self::varnodes_equal(&op.inputs[1], x)))
        })?;
        let and_out = and_op.output.as_ref()?;

        // Find MULT by 2
        let mult_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntMult)
                && op.inputs.len() == 2
                && (Self::varnodes_equal(&op.inputs[0], and_out) || Self::varnodes_equal(&op.inputs[1], and_out))
                && op.inputs.iter().any(|v| v.space == AddressSpace::Const && v.offset == 2)
        })?;
        let mult_out = mult_op.output.as_ref()?;

        // Find ADD operation
        let add_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntAdd)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], xor_out) && Self::varnodes_equal(&op.inputs[1], mult_out))
                    || (Self::varnodes_equal(&op.inputs[0], mult_out) && Self::varnodes_equal(&op.inputs[1], xor_out)))
        })?;

        // Simplified: just x + y
        let simplified_op = PcodeOp {
            opcode: OpCode::IntAdd,
            output: add_op.output.clone(),
            inputs: vec![x.clone(), y.clone()],
            address: add_op.address,
        };

        Some(SimplifiedExpression {
            expression: format!("{} + {}", Self::varnode_to_name(x), Self::varnode_to_name(y)),
            pcode_ops: vec![simplified_op],
            verification: VerificationMethod::AlgebraicRules,
            rules_applied: vec![SimplificationRule::XorAndAdd],
        })
    }

    /// Rule 2: (x ∧ y) + (x ∨ y) → x + y
    fn apply_rule_and_or_add(ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        if ops.len() < 3 {
            return None;
        }

        // Find AND operation
        let and_op = ops.iter().find(|op| matches!(op.opcode, OpCode::IntAnd))?;
        let and_out = and_op.output.as_ref()?;
        let x = and_op.inputs.get(0)?;
        let y = and_op.inputs.get(1)?;

        // Find OR operation with same inputs
        let or_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntOr)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], x) && Self::varnodes_equal(&op.inputs[1], y))
                    || (Self::varnodes_equal(&op.inputs[0], y) && Self::varnodes_equal(&op.inputs[1], x)))
        })?;
        let or_out = or_op.output.as_ref()?;

        // Find ADD operation
        let add_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntAdd)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], and_out) && Self::varnodes_equal(&op.inputs[1], or_out))
                    || (Self::varnodes_equal(&op.inputs[0], or_out) && Self::varnodes_equal(&op.inputs[1], and_out)))
        })?;

        // Simplified: x + y
        let simplified_op = PcodeOp {
            opcode: OpCode::IntAdd,
            output: add_op.output.clone(),
            inputs: vec![x.clone(), y.clone()],
            address: add_op.address,
        };

        Some(SimplifiedExpression {
            expression: format!("{} + {}", Self::varnode_to_name(x), Self::varnode_to_name(y)),
            pcode_ops: vec![simplified_op],
            verification: VerificationMethod::AlgebraicRules,
            rules_applied: vec![SimplificationRule::AndOrAdd],
        })
    }

    /// Rule 3: (x | y) - (x & y) → x ^ y
    fn apply_rule_or_minus_and(ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        if ops.len() < 3 {
            return None;
        }

        // Find OR operation
        let or_op = ops.iter().find(|op| matches!(op.opcode, OpCode::IntOr))?;
        let or_out = or_op.output.as_ref()?;
        let x = or_op.inputs.get(0)?;
        let y = or_op.inputs.get(1)?;

        // Find AND operation with same inputs
        let and_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntAnd)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], x) && Self::varnodes_equal(&op.inputs[1], y))
                    || (Self::varnodes_equal(&op.inputs[0], y) && Self::varnodes_equal(&op.inputs[1], x)))
        })?;
        let and_out = and_op.output.as_ref()?;

        // Find SUB operation
        let sub_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntSub)
                && op.inputs.len() == 2
                && Self::varnodes_equal(&op.inputs[0], or_out)
                && Self::varnodes_equal(&op.inputs[1], and_out)
        })?;

        // Simplified: x ^ y
        let simplified_op = PcodeOp {
            opcode: OpCode::IntXor,
            output: sub_op.output.clone(),
            inputs: vec![x.clone(), y.clone()],
            address: sub_op.address,
        };

        Some(SimplifiedExpression {
            expression: format!("{} ^ {}", Self::varnode_to_name(x), Self::varnode_to_name(y)),
            pcode_ops: vec![simplified_op],
            verification: VerificationMethod::AlgebraicRules,
            rules_applied: vec![SimplificationRule::OrMinusAnd],
        })
    }

    /// Rule 4: 2(x & y) + (x ^ y) → x + y
    fn apply_rule_two_and_plus_xor(ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        if ops.len() < 4 {
            return None;
        }

        // Find XOR operation
        let xor_op = ops.iter().find(|op| matches!(op.opcode, OpCode::IntXor))?;
        let xor_out = xor_op.output.as_ref()?;
        let x = xor_op.inputs.get(0)?;
        let y = xor_op.inputs.get(1)?;

        // Find AND operation with same inputs
        let and_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntAnd)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], x) && Self::varnodes_equal(&op.inputs[1], y))
                    || (Self::varnodes_equal(&op.inputs[0], y) && Self::varnodes_equal(&op.inputs[1], x)))
        })?;
        let and_out = and_op.output.as_ref()?;

        // Find MULT by 2
        let mult_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntMult)
                && op.inputs.len() == 2
                && (Self::varnodes_equal(&op.inputs[0], and_out) || Self::varnodes_equal(&op.inputs[1], and_out))
                && op.inputs.iter().any(|v| v.space == AddressSpace::Const && v.offset == 2)
        })?;
        let mult_out = mult_op.output.as_ref()?;

        // Find ADD operation
        let add_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntAdd)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], xor_out) && Self::varnodes_equal(&op.inputs[1], mult_out))
                    || (Self::varnodes_equal(&op.inputs[0], mult_out) && Self::varnodes_equal(&op.inputs[1], xor_out)))
        })?;

        // Simplified: x + y
        let simplified_op = PcodeOp {
            opcode: OpCode::IntAdd,
            output: add_op.output.clone(),
            inputs: vec![x.clone(), y.clone()],
            address: add_op.address,
        };

        Some(SimplifiedExpression {
            expression: format!("{} + {}", Self::varnode_to_name(x), Self::varnode_to_name(y)),
            pcode_ops: vec![simplified_op],
            verification: VerificationMethod::AlgebraicRules,
            rules_applied: vec![SimplificationRule::TwoAndPlusXor],
        })
    }

    /// Rule 5: (x & ~y) + (y & ~x) → x ^ y
    fn apply_rule_masked_xor(ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        // This is a more complex pattern, placeholder for now
        None
    }

    /// Rule 6: (x | y) - (x ^ y) → x & y
    fn apply_rule_or_minus_xor(ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        if ops.len() < 3 {
            return None;
        }

        // Find OR operation
        let or_op = ops.iter().find(|op| matches!(op.opcode, OpCode::IntOr))?;
        let or_out = or_op.output.as_ref()?;
        let x = or_op.inputs.get(0)?;
        let y = or_op.inputs.get(1)?;

        // Find XOR operation with same inputs
        let xor_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntXor)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], x) && Self::varnodes_equal(&op.inputs[1], y))
                    || (Self::varnodes_equal(&op.inputs[0], y) && Self::varnodes_equal(&op.inputs[1], x)))
        })?;
        let xor_out = xor_op.output.as_ref()?;

        // Find SUB operation
        let sub_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntSub)
                && op.inputs.len() == 2
                && Self::varnodes_equal(&op.inputs[0], or_out)
                && Self::varnodes_equal(&op.inputs[1], xor_out)
        })?;

        // Simplified: x & y
        let simplified_op = PcodeOp {
            opcode: OpCode::IntAnd,
            output: sub_op.output.clone(),
            inputs: vec![x.clone(), y.clone()],
            address: sub_op.address,
        };

        Some(SimplifiedExpression {
            expression: format!("{} & {}", Self::varnode_to_name(x), Self::varnode_to_name(y)),
            pcode_ops: vec![simplified_op],
            verification: VerificationMethod::AlgebraicRules,
            rules_applied: vec![SimplificationRule::OrMinusXor],
        })
    }

    /// Rule 7: (x + y) ^ (x & y) → x | y
    fn apply_rule_add_xor_and(ops: &[PcodeOp]) -> Option<SimplifiedExpression> {
        if ops.len() < 3 {
            return None;
        }

        // Find ADD operation
        let add_op = ops.iter().find(|op| matches!(op.opcode, OpCode::IntAdd))?;
        let add_out = add_op.output.as_ref()?;
        let x = add_op.inputs.get(0)?;
        let y = add_op.inputs.get(1)?;

        // Find AND operation with same inputs
        let and_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntAnd)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], x) && Self::varnodes_equal(&op.inputs[1], y))
                    || (Self::varnodes_equal(&op.inputs[0], y) && Self::varnodes_equal(&op.inputs[1], x)))
        })?;
        let and_out = and_op.output.as_ref()?;

        // Find XOR operation
        let xor_op = ops.iter().find(|op| {
            matches!(op.opcode, OpCode::IntXor)
                && op.inputs.len() == 2
                && ((Self::varnodes_equal(&op.inputs[0], add_out) && Self::varnodes_equal(&op.inputs[1], and_out))
                    || (Self::varnodes_equal(&op.inputs[0], and_out) && Self::varnodes_equal(&op.inputs[1], add_out)))
        })?;

        // Simplified: x | y
        let simplified_op = PcodeOp {
            opcode: OpCode::IntOr,
            output: xor_op.output.clone(),
            inputs: vec![x.clone(), y.clone()],
            address: xor_op.address,
        };

        Some(SimplifiedExpression {
            expression: format!("{} | {}", Self::varnode_to_name(x), Self::varnode_to_name(y)),
            pcode_ops: vec![simplified_op],
            verification: VerificationMethod::AlgebraicRules,
            rules_applied: vec![SimplificationRule::AddXorAnd],
        })
    }

    fn varnodes_equal(v1: &Varnode, v2: &Varnode) -> bool {
        v1.space == v2.space && v1.offset == v2.offset && v1.size == v2.size
    }

    fn varnode_to_name(varnode: &Varnode) -> String {
        match varnode.space {
            AddressSpace::Register => format!("reg_{}", varnode.offset),
            AddressSpace::Const => format!("{}", varnode.offset),
            AddressSpace::Unique => format!("tmp_{}", varnode.offset),
            AddressSpace::Ram => format!("mem[0x{:x}]", varnode.offset),
            AddressSpace::Stack => format!("stack[0x{:x}]", varnode.offset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_and_add_rule() {
        // (x ⊕ y) + 2(x ∧ y)
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

        let simplified = MBASimplifier::apply_rule_xor_and_add(&ops).unwrap();

        assert_eq!(simplified.pcode_ops.len(), 1);
        assert!(matches!(simplified.pcode_ops[0].opcode, OpCode::IntAdd));
        assert!(simplified.expression.contains("+"));
    }

    #[test]
    fn test_and_or_add_rule() {
        // (x ∧ y) + (x ∨ y) → x + y
        let ops = vec![
            PcodeOp {
                opcode: OpCode::IntAnd,
                output: Some(Varnode::unique(100, 8)),
                inputs: vec![Varnode::register(0, 8), Varnode::register(1, 8)],
                address: 0x1000,
            },
            PcodeOp {
                opcode: OpCode::IntOr,
                output: Some(Varnode::unique(101, 8)),
                inputs: vec![Varnode::register(0, 8), Varnode::register(1, 8)],
                address: 0x1004,
            },
            PcodeOp {
                opcode: OpCode::IntAdd,
                output: Some(Varnode::unique(102, 8)),
                inputs: vec![Varnode::unique(100, 8), Varnode::unique(101, 8)],
                address: 0x1008,
            },
        ];

        let simplified = MBASimplifier::apply_rule_and_or_add(&ops).unwrap();

        assert_eq!(simplified.pcode_ops.len(), 1);
        assert!(matches!(simplified.pcode_ops[0].opcode, OpCode::IntAdd));
    }
}
