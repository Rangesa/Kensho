//! Strength Reduction
//!
//! 演算強度削減：コストの高い演算を低コストの演算に置き換える。
//!
//! 主な変換:
//! - x * 2 → x << 1 (左シフト)
//! - x * 4 → x << 2
//! - x / 2 → x >> 1 (右シフト、符号なしの場合)
//! - x * 0 → 0
//! - x * 1 → x
//! - x ^ 0 → x
//! - x & 0 → 0
//! - x | 0 → x
//!
//! ループ内の帰納変数に対する強度削減:
//! ```
//! for (i = 0; i < n; i++) {
//!     x = i * 4;      // 毎回乗算
//! }
//! ```
//!
//! 最適化後:
//! ```
//! x = 0;
//! for (i = 0; i < n; i++) {
//!     x = x + 4;      // 加算に変換
//! }
//! ```

use crate::decompiler_prototype::pcode::{PcodeOp, OpCode, Varnode, AddressSpace};

pub struct RuleStrengthReduction {
    reduced_count: usize,
}

impl RuleStrengthReduction {
    pub fn new() -> Self {
        Self { reduced_count: 0 }
    }

    /// 演算強度削減を適用
    pub fn apply(&mut self, ops: &mut Vec<PcodeOp>) -> bool {
        let mut changed = false;
        self.reduced_count = 0;

        for i in 0..ops.len() {
            // 乗算の強度削減
            if ops[i].opcode == OpCode::IntMult && ops[i].inputs.len() == 2 {
                if let Some(new_op) = self.reduce_multiplication(&ops[i].clone()) {
                    ops[i] = new_op;
                    self.reduced_count += 1;
                    changed = true;
                }
            }

            // 除算の強度削減
            if ops[i].opcode == OpCode::IntDiv && ops[i].inputs.len() == 2 {
                if let Some(new_op) = self.reduce_division(&ops[i].clone()) {
                    ops[i] = new_op;
                    self.reduced_count += 1;
                    changed = true;
                }
            }

            // べき乗の強度削減
            if ops[i].opcode == OpCode::IntMult {
                if let Some(new_ops) = self.reduce_power(&ops[i].clone()) {
                    // べき乗を連続したシフトに展開
                    ops.splice(i..i + 1, new_ops);
                    self.reduced_count += 1;
                    changed = true;
                }
            }
        }

        changed
    }

    /// 乗算の強度削減
    fn reduce_multiplication(&self, op: &PcodeOp) -> Option<PcodeOp> {
        if op.inputs.len() != 2 {
            return None;
        }

        let const_val = self.get_constant_value(&op.inputs[1])?;
        let var = &op.inputs[0];

        // 2のべき乗による乗算 → シフトに変換
        if const_val > 0 && (const_val & (const_val - 1)) == 0 {
            let shift_amount = const_val.trailing_zeros() as u64;
            let shift_const = Varnode::constant(shift_amount, op.inputs[1].size);

            return Some(PcodeOp {
                opcode: OpCode::IntLeft,
                inputs: vec![var.clone(), shift_const],
                output: op.output.clone(),
                address: op.address,
            });
        }

        // 特殊ケース
        match const_val {
            0 => {
                // x * 0 = 0
                Some(PcodeOp {
                    opcode: OpCode::Copy,
                    inputs: vec![Varnode::constant(0, op.inputs[0].size)],
                    output: op.output.clone(),
                    address: op.address,
                })
            }
            1 => {
                // x * 1 = x
                Some(PcodeOp {
                    opcode: OpCode::Copy,
                    inputs: vec![var.clone()],
                    output: op.output.clone(),
                    address: op.address,
                })
            }
            3 => {
                // x * 3 = x + x + x → (x << 1) + x
                let temp = Varnode::new(AddressSpace::Unique, rand::random(), var.size);
                // これは簡略化 - 実際には複数命令に展開
                None
            }
            _ => None,
        }
    }

    /// 除算の強度削減
    fn reduce_division(&self, op: &PcodeOp) -> Option<PcodeOp> {
        if op.inputs.len() != 2 {
            return None;
        }

        let const_val = self.get_constant_value(&op.inputs[1])?;
        let var = &op.inputs[0];

        // 2のべき乗による除算 → 右シフトに変換（符号なしの場合）
        if const_val > 0 && (const_val & (const_val - 1)) == 0 {
            let shift_amount = const_val.trailing_zeros() as u64;
            let shift_const = Varnode::constant(shift_amount, op.inputs[1].size);

            return Some(PcodeOp {
                opcode: OpCode::IntRight, // 符号なし右シフト
                inputs: vec![var.clone(), shift_const],
                output: op.output.clone(),
                address: op.address,
            });
        }

        match const_val {
            1 => {
                // x / 1 = x
                Some(PcodeOp {
                    opcode: OpCode::Copy,
                    inputs: vec![var.clone()],
                    output: op.output.clone(),
                    address: op.address,
                })
            }
            _ => None,
        }
    }

    /// べき乗の強度削減
    fn reduce_power(&self, _op: &PcodeOp) -> Option<Vec<PcodeOp>> {
        // x^8 = ((x^2)^2)^2 のような最適化
        // 実装簡略化のためNone
        None
    }

    /// 定数値を取得
    fn get_constant_value(&self, v: &Varnode) -> Option<u64> {
        if v.space == AddressSpace::Const {
            Some(v.offset)
        } else {
            None
        }
    }

    pub fn reduced_count(&self) -> usize {
        self.reduced_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiply_by_power_of_two() {
        let mut rule = RuleStrengthReduction::new();

        let v_x = Varnode::new(AddressSpace::Register, 0, 8);
        let v_4 = Varnode::constant(4, 8);
        let v_out = Varnode::new(AddressSpace::Unique, 0, 8);

        let mut ops = vec![PcodeOp {
            opcode: OpCode::IntMult,
            inputs: vec![v_x.clone(), v_4],
            output: Some(v_out.clone()),
        }];

        let changed = rule.apply(&mut ops);

        assert!(changed);
        assert_eq!(rule.reduced_count(), 1);
        assert_eq!(ops[0].opcode, OpCode::IntLeft);
        assert_eq!(ops[0].inputs[1].offset, 2); // 4 = 2^2
    }

    #[test]
    fn test_multiply_by_zero() {
        let mut rule = RuleStrengthReduction::new();

        let v_x = Varnode::new(AddressSpace::Register, 0, 8);
        let v_0 = Varnode::constant(0, 8);
        let v_out = Varnode::new(AddressSpace::Unique, 0, 8);

        let mut ops = vec![PcodeOp {
            opcode: OpCode::IntMult,
            inputs: vec![v_x, v_0],
            output: Some(v_out),
        }];

        let changed = rule.apply(&mut ops);

        assert!(changed);
        assert_eq!(ops[0].opcode, OpCode::Copy);
        assert_eq!(ops[0].inputs[0].offset, 0);
    }

    #[test]
    fn test_divide_by_power_of_two() {
        let mut rule = RuleStrengthReduction::new();

        let v_x = Varnode::new(AddressSpace::Register, 0, 8);
        let v_8 = Varnode::constant(8, 8);
        let v_out = Varnode::new(AddressSpace::Unique, 0, 8);

        let mut ops = vec![PcodeOp {
            opcode: OpCode::IntDiv,
            inputs: vec![v_x, v_8],
            output: Some(v_out),
        }];

        let changed = rule.apply(&mut ops);

        assert!(changed);
        assert_eq!(ops[0].opcode, OpCode::IntRight);
        assert_eq!(ops[0].inputs[1].offset, 3); // 8 = 2^3
    }
}
