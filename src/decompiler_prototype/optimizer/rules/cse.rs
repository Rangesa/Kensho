//! Common Subexpression Elimination (CSE)
//!
//! 共通部分式の削除により、同じ計算を複数回行うことを避ける。
//!
//! 例:
//! ```
//! v1 = a + b
//! v2 = c * d
//! v3 = a + b    // v1と同じ計算
//! v4 = v3 + v2
//! ```
//!
//! 最適化後:
//! ```
//! v1 = a + b
//! v2 = c * d
//! v3 = v1       // コピーに置き換え
//! v4 = v3 + v2
//! ```

use crate::decompiler_prototype::pcode::{PcodeOp, OpCode, Varnode};
use std::collections::HashMap;

/// CSE最適化ルール
pub struct RuleCSE {
    /// 式のハッシュ -> 結果Varnode のマップ
    expression_map: HashMap<String, Varnode>,
    /// 削除された命令数
    eliminated_count: usize,
}

impl RuleCSE {
    pub fn new() -> Self {
        Self {
            expression_map: HashMap::new(),
            eliminated_count: 0,
        }
    }

    /// CSE最適化を適用
    pub fn apply(&mut self, ops: &mut Vec<PcodeOp>) -> bool {
        let mut changed = false;
        self.expression_map.clear();
        self.eliminated_count = 0;

        let mut i = 0;
        while i < ops.len() {
            let op = &ops[i];

            // 純粋関数的な演算のみ対象（副作用なし）
            if self.is_pure_operation(&op.opcode) {
                let expr_hash = self.hash_expression(op);

                if let Some(existing_result) = self.expression_map.get(&expr_hash) {
                    // 既に同じ計算が存在 -> Copy命令に置き換え
                    if let Some(output) = &op.output {
                        ops[i] = PcodeOp {
                            opcode: OpCode::Copy,
                            inputs: vec![existing_result.clone()],
                            output: Some(output.clone()),
                            address: ops[i].address,
                        };
                        self.eliminated_count += 1;
                        changed = true;
                    }
                } else {
                    // 新しい式を記録
                    if let Some(output) = &op.output {
                        self.expression_map.insert(expr_hash, output.clone());
                    }
                }
            } else if self.has_side_effects(&op.opcode) {
                // 副作用のある命令の後はマップをクリア（保守的）
                self.expression_map.clear();
            }

            i += 1;
        }

        changed
    }

    /// 式のハッシュ値を計算
    fn hash_expression(&self, op: &PcodeOp) -> String {
        let mut hash = format!("{:?}", op.opcode);

        for input in &op.inputs {
            hash.push('_');
            hash.push_str(&self.varnode_to_string(input));
        }

        hash
    }

    /// Varnodeを文字列に変換
    fn varnode_to_string(&self, v: &Varnode) -> String {
        format!("{:?}_{:x}_{}", v.space, v.offset, v.size)
    }

    /// 純粋関数的な演算か判定
    fn is_pure_operation(&self, opcode: &OpCode) -> bool {
        matches!(
            opcode,
            OpCode::IntAdd
                | OpCode::IntSub
                | OpCode::IntMult
                | OpCode::IntDiv
                | OpCode::IntSDiv
                | OpCode::IntRem
                | OpCode::IntSRem
                | OpCode::IntAnd
                | OpCode::IntOr
                | OpCode::IntXor
                | OpCode::IntNegate
                | OpCode::IntLeft
                | OpCode::IntRight
                | OpCode::IntSRight
                | OpCode::IntZExt
                | OpCode::IntSExt
                | OpCode::IntEqual
                | OpCode::IntNotEqual
                | OpCode::IntLess
                | OpCode::IntSLess
                | OpCode::IntLessEqual
                | OpCode::IntSLessEqual
                | OpCode::FloatAdd
                | OpCode::FloatSub
                | OpCode::FloatMult
                | OpCode::FloatDiv
                | OpCode::FloatNeg
                | OpCode::FloatAbs
                | OpCode::FloatSqrt
                | OpCode::FloatEqual
                | OpCode::FloatNotEqual
                | OpCode::FloatLess
                | OpCode::FloatLessEqual
        )
    }

    /// 副作用のある命令か判定
    fn has_side_effects(&self, opcode: &OpCode) -> bool {
        matches!(
            opcode,
            OpCode::Store
                | OpCode::Call
                | OpCode::CallInd
                | OpCode::Return
                | OpCode::Branch
                | OpCode::CBranch
                | OpCode::BranchInd
        )
    }

    /// 削除された式の数を取得
    pub fn eliminated_count(&self) -> usize {
        self.eliminated_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::pcode::AddressSpace;

    #[test]
    fn test_cse_basic() {
        let mut rule = RuleCSE::new();

        let v_a = Varnode::new(AddressSpace::Register, 0, 8);
        let v_b = Varnode::new(AddressSpace::Register, 8, 8);
        let v_1 = Varnode::new(AddressSpace::Unique, 0, 8);
        let v_2 = Varnode::new(AddressSpace::Unique, 1, 8);

        let mut ops = vec![
            // v1 = a + b
            PcodeOp {
                opcode: OpCode::IntAdd,
                inputs: vec![v_a.clone(), v_b.clone()],
                output: Some(v_1.clone()),
            },
            // v2 = a + b  (同じ計算)
            PcodeOp {
                opcode: OpCode::IntAdd,
                inputs: vec![v_a.clone(), v_b.clone()],
                output: Some(v_2.clone()),
            },
        ];

        let changed = rule.apply(&mut ops);

        assert!(changed);
        assert_eq!(rule.eliminated_count(), 1);

        // 2番目の命令がCopyに変換されているはず
        assert_eq!(ops[1].opcode, OpCode::Copy);
        assert_eq!(ops[1].inputs.len(), 1);
        assert_eq!(ops[1].inputs[0], v_1);
    }

    #[test]
    fn test_cse_with_side_effects() {
        let mut rule = RuleCSE::new();

        let v_a = Varnode::new(AddressSpace::Register, 0, 8);
        let v_b = Varnode::new(AddressSpace::Register, 8, 8);
        let v_mem = Varnode::new(AddressSpace::Ram, 0x1000, 8);
        let v_1 = Varnode::new(AddressSpace::Unique, 0, 8);
        let v_2 = Varnode::new(AddressSpace::Unique, 1, 8);

        let mut ops = vec![
            // v1 = a + b
            PcodeOp {
                opcode: OpCode::IntAdd,
                inputs: vec![v_a.clone(), v_b.clone()],
                output: Some(v_1.clone()),
            },
            // store to memory (副作用あり)
            PcodeOp {
                opcode: OpCode::Store,
                inputs: vec![v_mem.clone(), v_1.clone()],
                output: None,
            },
            // v2 = a + b  (副作用の後なので最適化されない)
            PcodeOp {
                opcode: OpCode::IntAdd,
                inputs: vec![v_a.clone(), v_b.clone()],
                output: Some(v_2.clone()),
            },
        ];

        let changed = rule.apply(&mut ops);

        // 副作用の後なので最適化されない
        assert!(!changed);
        assert_eq!(rule.eliminated_count(), 0);
    }
}
