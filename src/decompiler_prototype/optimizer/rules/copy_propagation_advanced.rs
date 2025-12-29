//! Advanced Copy Propagation
//!
//! 拡張版コピー伝播：複数のコピー連鎖を解決し、最終的な値まで伝播。
//!
//! 基本版:
//! ```
//! v1 = v0
//! v2 = v1  →  v2 = v0
//! ```
//!
//! 拡張版:
//! ```
//! v1 = v0
//! v2 = v1
//! v3 = v2
//! v4 = v3  →  全てv0に置き換え
//!
//! // 条件付きコピー伝播
//! if (cond) v1 = v0
//! else      v1 = v2
//! v3 = v1  →  両方のパスで解析
//! ```

use crate::decompiler_prototype::pcode::{PcodeOp, OpCode, Varnode};
use std::collections::HashMap;

pub struct RuleCopyPropagationAdvanced {
    /// コピー関係のマップ: 変数 → 最終的なコピー元
    copy_map: HashMap<Varnode, Varnode>,
    propagated_count: usize,
}

impl RuleCopyPropagationAdvanced {
    pub fn new() -> Self {
        Self {
            copy_map: HashMap::new(),
            propagated_count: 0,
        }
    }

    /// 高度なコピー伝播を適用
    pub fn apply(&mut self, ops: &mut Vec<PcodeOp>) -> bool {
        self.copy_map.clear();
        self.propagated_count = 0;

        // Pass 1: コピー関係を構築
        self.build_copy_chains(ops);

        // Pass 2: 連鎖を解決
        self.resolve_copy_chains();

        // Pass 3: コピー伝播を適用
        let mut changed = false;
        for op in ops.iter_mut() {
            // 入力を置き換え
            for input in &mut op.inputs {
                if let Some(replacement) = self.copy_map.get(input) {
                    if replacement != input {
                        *input = replacement.clone();
                        self.propagated_count += 1;
                        changed = true;
                    }
                }
            }
        }

        // Pass 4: 不要なコピー命令を削除
        ops.retain(|op| {
            if op.opcode == OpCode::Copy && op.inputs.len() == 1 {
                if let Some(output) = &op.output {
                    // 入力と出力が同じならコピー不要
                    if &op.inputs[0] == output {
                        return false;
                    }
                }
            }
            true
        });

        changed
    }

    /// コピー関係を構築
    fn build_copy_chains(&mut self, ops: &[PcodeOp]) {
        for op in ops {
            if op.opcode == OpCode::Copy && op.inputs.len() == 1 {
                if let Some(output) = &op.output {
                    self.copy_map.insert(output.clone(), op.inputs[0].clone());
                }
            }
        }
    }

    /// コピー連鎖を解決
    /// v1 -> v2 -> v3 を v1 -> v3, v2 -> v3 に解決
    fn resolve_copy_chains(&mut self) {
        let mut resolved = HashMap::new();

        for (dest, src) in &self.copy_map {
            let final_src = self.find_final_source(src);
            resolved.insert(dest.clone(), final_src);
        }

        self.copy_map = resolved;
    }

    /// 最終的なコピー元を再帰的に探索
    fn find_final_source(&self, var: &Varnode) -> Varnode {
        let mut current = var.clone();
        let mut visited = std::collections::HashSet::new();

        while let Some(next) = self.copy_map.get(&current) {
            // 循環検出
            if !visited.insert(current.clone()) {
                break;
            }
            current = next.clone();
        }

        current
    }

    /// 拡張機能: 条件付きコピー伝播
    pub fn apply_conditional(&mut self, _ops: &mut Vec<PcodeOp>) -> bool {
        // PHI関数を考慮したコピー伝播
        // SSA形式でのマージポイントを処理
        // 実装簡略化のため、基本版のみ
        false
    }

    pub fn propagated_count(&self) -> usize {
        self.propagated_count
    }

    pub fn copy_chains(&self) -> &HashMap<Varnode, Varnode> {
        &self.copy_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::pcode::AddressSpace;

    #[test]
    fn test_copy_chain_resolution() {
        let mut rule = RuleCopyPropagationAdvanced::new();

        let v0 = Varnode::new(AddressSpace::Register, 0, 8);
        let v1 = Varnode::new(AddressSpace::Unique, 0, 8);
        let v2 = Varnode::new(AddressSpace::Unique, 1, 8);
        let v3 = Varnode::new(AddressSpace::Unique, 2, 8);

        let mut ops = vec![
            // v1 = v0
            PcodeOp {
                opcode: OpCode::Copy,
                inputs: vec![v0.clone()],
                output: Some(v1.clone()),
            },
            // v2 = v1
            PcodeOp {
                opcode: OpCode::Copy,
                inputs: vec![v1.clone()],
                output: Some(v2.clone()),
            },
            // v3 = v2
            PcodeOp {
                opcode: OpCode::Copy,
                inputs: vec![v2.clone()],
                output: Some(v3.clone()),
            },
            // result = v3 + 1
            PcodeOp {
                opcode: OpCode::IntAdd,
                inputs: vec![v3.clone(), Varnode::constant(1, 8)],
                output: Some(Varnode::new(AddressSpace::Unique, 3, 8)),
            },
        ];

        let changed = rule.apply(&mut ops);

        assert!(changed);
        assert!(rule.propagated_count() > 0);

        // 最後の命令の入力がv0に置き換わっているはず
        assert_eq!(ops.last().unwrap().inputs[0], v0);
    }

    #[test]
    fn test_remove_redundant_copy() {
        let mut rule = RuleCopyPropagationAdvanced::new();

        let v0 = Varnode::new(AddressSpace::Register, 0, 8);

        let mut ops = vec![
            // v0 = v0 (冗長なコピー)
            PcodeOp {
                opcode: OpCode::Copy,
                inputs: vec![v0.clone()],
                output: Some(v0.clone()),
            },
        ];

        rule.apply(&mut ops);

        // 冗長なコピーが削除されるはず
        assert!(ops.is_empty());
    }

    #[test]
    fn test_circular_copy_detection() {
        let mut rule = RuleCopyPropagationAdvanced::new();

        let v1 = Varnode::new(AddressSpace::Unique, 0, 8);
        let v2 = Varnode::new(AddressSpace::Unique, 1, 8);

        // 循環参照を手動で作成
        rule.copy_map.insert(v1.clone(), v2.clone());
        rule.copy_map.insert(v2.clone(), v1.clone());

        // 循環を検出して無限ループを回避
        let final_src = rule.find_final_source(&v1);

        // どちらかで停止するはず
        assert!(final_src == v1 || final_src == v2);
    }
}
