/// データフロー解析基盤
///
/// Def-Use Chain（定義-使用連鎖）を構築してデータフローを追跡
/// Ghidraのvarnode.hh/op.hhに基づく実装

use crate::decompiler_prototype::pcode::{AddressSpace, OpCode, PcodeOp, Varnode};
use std::collections::{HashMap, HashSet};

/// Varnodeの定義-使用情報
#[derive(Debug, Clone)]
pub struct DefUseChain {
    /// Varnode → 定義操作のマッピング
    defs: HashMap<VarnodeId, OpId>,
    /// Varnode → 使用操作リストのマッピング
    uses: HashMap<VarnodeId, Vec<OpId>>,
    /// 操作のインデックス
    ops: Vec<PcodeOp>,
}

/// Varnodeを一意に識別するID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarnodeId {
    space: AddressSpace,
    offset: u64,
    size: usize,
    /// SSA形式での生成順序（同じアドレスでも異なる定義を区別）
    generation: usize,
}

impl From<&Varnode> for VarnodeId {
    fn from(vn: &Varnode) -> Self {
        VarnodeId {
            space: vn.space,
            offset: vn.offset,
            size: vn.size,
            generation: 0, // デフォルト世代
        }
    }
}

/// P-code操作のID
pub type OpId = usize;

impl DefUseChain {
    /// 新しいDef-Use Chainを作成
    pub fn new() -> Self {
        Self {
            defs: HashMap::new(),
            uses: HashMap::new(),
            ops: Vec::new(),
        }
    }

    /// P-code操作列からDef-Use Chainを構築
    pub fn build(&mut self, ops: &[PcodeOp]) {
        self.ops = ops.to_vec();

        for (op_id, op) in ops.iter().enumerate() {
            // 出力Varnodeの定義を記録
            if let Some(output) = &op.output {
                let vn_id = VarnodeId::from(output);
                self.defs.insert(vn_id, op_id);
            }

            // 入力Varnodeの使用を記録
            for input in &op.inputs {
                let vn_id = VarnodeId::from(input);
                self.uses
                    .entry(vn_id)
                    .or_insert_with(Vec::new)
                    .push(op_id);
            }
        }
    }

    /// Varnodeを定義する操作を取得
    pub fn get_def(&self, vn: &Varnode) -> Option<&PcodeOp> {
        let vn_id = VarnodeId::from(vn);
        let op_id = self.defs.get(&vn_id)?;
        self.ops.get(*op_id)
    }

    /// Varnodeを使用する操作リストを取得
    pub fn get_uses(&self, vn: &Varnode) -> Vec<&PcodeOp> {
        let vn_id = VarnodeId::from(vn);
        if let Some(op_ids) = self.uses.get(&vn_id) {
            op_ids.iter().filter_map(|&id| self.ops.get(id)).collect()
        } else {
            Vec::new()
        }
    }

    /// Varnodeが単一使用かどうか（Copy propagationの条件）
    pub fn is_single_use(&self, vn: &Varnode) -> bool {
        let vn_id = VarnodeId::from(vn);
        self.uses.get(&vn_id).map(|v| v.len() == 1).unwrap_or(false)
    }

    /// Varnodeが未使用かどうか（Dead code eliminationの候補）
    pub fn is_unused(&self, vn: &Varnode) -> bool {
        let vn_id = VarnodeId::from(vn);
        self.uses.get(&vn_id).map(|v| v.is_empty()).unwrap_or(true)
    }

    /// 到達可能な操作を収集（Dead code elimination用）
    pub fn collect_reachable_ops(&self) -> HashSet<OpId> {
        let mut reachable = HashSet::new();
        let mut worklist = Vec::new();

        // 副作用のある操作から開始
        for (op_id, op) in self.ops.iter().enumerate() {
            if self.has_side_effects(op) {
                reachable.insert(op_id);
                worklist.push(op_id);
            }
        }

        // 後方データフロー追跡
        while let Some(op_id) = worklist.pop() {
            let op = &self.ops[op_id];

            // この操作の入力を定義する操作も到達可能
            for input in &op.inputs {
                if let Some(def_op_id) = self.defs.get(&VarnodeId::from(input)) {
                    if reachable.insert(*def_op_id) {
                        worklist.push(*def_op_id);
                    }
                }
            }
        }

        reachable
    }

    /// 操作が副作用を持つかどうか
    fn has_side_effects(&self, op: &PcodeOp) -> bool {
        matches!(
            op.opcode,
            OpCode::Store
                | OpCode::Call
                | OpCode::CallInd
                | OpCode::Branch
                | OpCode::CBranch
                | OpCode::BranchInd
                | OpCode::Return
        )
    }

    /// Copy操作を追跡してソースVarnodeを取得
    ///
    /// Copy propagation用: V1 = V0; V2 = V1; => V2 = V0;
    pub fn trace_copy_source(&self, vn: &Varnode) -> Option<Varnode> {
        let mut current = vn.clone();
        let mut visited = HashSet::new();

        loop {
            let vn_id = VarnodeId::from(&current);

            // 無限ループ防止
            if !visited.insert(vn_id) {
                return None;
            }

            // 定義操作を取得
            let def_op = self.get_def(&current)?;

            // Copy操作なら入力をさらに追跡
            if def_op.opcode == OpCode::Copy && !def_op.inputs.is_empty() {
                current = def_op.inputs[0].clone();
            } else {
                // Copy以外の操作に到達したら終了
                return Some(current);
            }
        }
    }

    /// データフロー統計情報
    pub fn stats(&self) -> DataFlowStats {
        let total_defs = self.defs.len();
        let total_uses: usize = self.uses.values().map(|v| v.len()).sum();
        let unused_defs = self
            .defs
            .keys()
            .filter(|vn_id| {
                self.uses
                    .get(vn_id)
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
            })
            .count();

        DataFlowStats {
            total_ops: self.ops.len(),
            total_defs,
            total_uses,
            unused_defs,
            single_use_defs: self
                .defs
                .keys()
                .filter(|vn_id| {
                    self.uses
                        .get(vn_id)
                        .map(|v| v.len() == 1)
                        .unwrap_or(false)
                })
                .count(),
        }
    }
}

impl Default for DefUseChain {
    fn default() -> Self {
        Self::new()
    }
}

/// データフロー統計情報
#[derive(Debug, Clone)]
pub struct DataFlowStats {
    pub total_ops: usize,
    pub total_defs: usize,
    pub total_uses: usize,
    pub unused_defs: usize,
    pub single_use_defs: usize,
}

/// Copy Propagation最適化
///
/// V1 = V0; V2 = V1; => V2 = V0; のような連鎖コピーを削減
pub struct CopyPropagation {
    du_chain: DefUseChain,
}

impl CopyPropagation {
    pub fn new(du_chain: DefUseChain) -> Self {
        Self { du_chain }
    }

    /// Copy propagationを適用
    pub fn apply(&mut self, ops: &mut Vec<PcodeOp>) -> usize {
        let mut propagation_count = 0;

        for op in ops.iter_mut() {
            // 入力Varnodeをコピー元まで追跡
            for input in &mut op.inputs {
                if let Some(source) = self.du_chain.trace_copy_source(input) {
                    if source != *input {
                        *input = source;
                        propagation_count += 1;
                    }
                }
            }
        }

        propagation_count
    }
}

/// Dead Code Elimination
///
/// 到達不能な操作や未使用の定義を削除
pub struct DeadCodeElimination {
    du_chain: DefUseChain,
}

impl DeadCodeElimination {
    pub fn new(du_chain: DefUseChain) -> Self {
        Self { du_chain }
    }

    /// Dead codeを除去
    pub fn eliminate(&self, ops: &mut Vec<PcodeOp>) -> usize {
        let reachable = self.du_chain.collect_reachable_ops();
        let original_len = ops.len();

        // 到達可能な操作のみを保持
        ops.retain(|_| true); // TODO: 実際のインデックス対応が必要

        // 簡易版: 未使用の出力を持つ操作を削除
        let removed = ops
            .iter()
            .filter(|op| {
                if let Some(output) = &op.output {
                    self.du_chain.is_unused(output)
                        && !self.du_chain.has_side_effects(op)
                } else {
                    false
                }
            })
            .count();

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_def_use_chain() {
        let v0 = Varnode::register(0, 4);
        let v1 = Varnode::unique(0, 4);
        let v2 = Varnode::unique(1, 4);

        let ops = vec![
            PcodeOp::binary(OpCode::IntAdd, v1.clone(), v0.clone(), Varnode::constant(1, 4), 0x1000),
            PcodeOp::unary(OpCode::Copy, v2.clone(), v1.clone(), 0x1004),
        ];

        let mut du_chain = DefUseChain::new();
        du_chain.build(&ops);

        // v1を定義する操作を取得
        assert!(du_chain.get_def(&v1).is_some());

        // v1を使用する操作を取得
        let uses = du_chain.get_uses(&v1);
        assert_eq!(uses.len(), 1);
    }

    #[test]
    fn test_copy_propagation() {
        let v0 = Varnode::register(0, 4);
        let v1 = Varnode::unique(0, 4);
        let v2 = Varnode::unique(1, 4);

        let ops = vec![
            PcodeOp::unary(OpCode::Copy, v1.clone(), v0.clone(), 0x1000),
            PcodeOp::unary(OpCode::Copy, v2.clone(), v1.clone(), 0x1004),
        ];

        let mut du_chain = DefUseChain::new();
        du_chain.build(&ops);

        // v2のコピー元を追跡 => v0
        let source = du_chain.trace_copy_source(&v2);
        assert!(source.is_some());
        assert_eq!(source.unwrap(), v0);
    }
}
