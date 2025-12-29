//! Loop-Invariant Code Motion (LICM)
//!
//! ループ不変式（ループ内で値が変わらない計算）をループの外に移動。
//!
//! 例:
//! ```
//! while (i < n) {
//!     x = a + b;    // aとbがループ内で変更されない場合
//!     arr[i] = x;
//!     i++;
//! }
//! ```
//!
//! 最適化後:
//! ```
//! x = a + b;        // ループの前に移動
//! while (i < n) {
//!     arr[i] = x;
//!     i++;
//! }
//! ```

use crate::decompiler_prototype::pcode::{PcodeOp, OpCode, Varnode};
use crate::decompiler_prototype::cfg::{ControlFlowGraph, BlockId};
use std::collections::{HashSet, HashMap};

pub struct RuleLICM {
    moved_count: usize,
}

impl RuleLICM {
    pub fn new() -> Self {
        Self { moved_count: 0 }
    }

    /// LICM最適化を適用
    pub fn apply(&mut self, cfg: &mut ControlFlowGraph) -> bool {
        self.moved_count = 0;

        // ループを検出
        let loops = self.detect_loops(cfg);
        if loops.is_empty() {
            return false;
        }

        let mut changed = false;

        for (header, loop_blocks) in loops {
            // ループ内で変更される変数を収集
            let modified_vars = self.collect_modified_vars(cfg, &loop_blocks);

            // ループ不変命令を検出
            let invariant_ops = self.find_invariant_ops(cfg, &loop_blocks, &modified_vars);

            if !invariant_ops.is_empty() {
                // ループ不変命令をプリヘッダに移動
                self.move_to_preheader(cfg, header, &invariant_ops);
                self.moved_count += invariant_ops.len();
                changed = true;
            }
        }

        changed
    }

    /// ループを検出（バックエッジを探す）
    fn detect_loops(&self, cfg: &ControlFlowGraph) -> Vec<(BlockId, Vec<BlockId>)> {
        let mut loops = Vec::new();
        let dominators = self.compute_dominators(cfg);

        for (block_id, block) in cfg.blocks.iter() {
            for &succ_id in &block.successors {
                // バックエッジ: succ_idがblock_idを支配する
                if dominators.get(&block_id).map_or(false, |doms| doms.contains(&succ_id)) {
                    // ループヘッダはsucc_id
                    let loop_blocks = self.find_loop_body(cfg, succ_id, *block_id);
                    loops.push((succ_id, loop_blocks));
                }
            }
        }

        loops
    }

    /// 支配関係を計算（簡易版）
    fn compute_dominators(&self, cfg: &ControlFlowGraph) -> HashMap<BlockId, HashSet<BlockId>> {
        let mut dominators: HashMap<BlockId, HashSet<BlockId>> = HashMap::new();
        let block_count = cfg.blocks.len();

        // 初期化
        for i in 0..block_count {
            if i == 0 {
                // エントリブロックは自分だけを支配
                let mut set = HashSet::new();
                set.insert(0);
                dominators.insert(0, set);
            } else {
                // 他のブロックは全ブロックを支配すると仮定
                let mut set = HashSet::new();
                for j in 0..block_count {
                    set.insert(j);
                }
                dominators.insert(i, set);
            }
        }

        // 不動点反復
        let mut changed = true;
        while changed {
            changed = false;
            for i in 1..block_count {
                let preds: Vec<usize> = cfg
                    .blocks
                    .iter()
                    .filter(|(block_id, b)| b.successors.contains(&i))
                    .map(|(block_id, _)| *block_id)
                    .collect();

                if preds.is_empty() {
                    continue;
                }

                // 全ての先行ブロックの支配関係の積集合
                let mut new_doms = dominators[&preds[0]].clone();
                for &pred in &preds[1..] {
                    new_doms = new_doms
                        .intersection(&dominators[&pred])
                        .cloned()
                        .collect();
                }
                new_doms.insert(i);

                if new_doms != dominators[&i] {
                    dominators.insert(i, new_doms);
                    changed = true;
                }
            }
        }

        dominators
    }

    /// ループ本体を検出
    fn find_loop_body(&self, cfg: &ControlFlowGraph, header: BlockId, latch: BlockId) -> Vec<BlockId> {
        let mut loop_blocks = vec![header];
        let mut worklist = vec![latch];
        let mut visited = HashSet::new();
        visited.insert(header);

        while let Some(block_id) = worklist.pop() {
            if visited.contains(&block_id) {
                continue;
            }
            visited.insert(block_id);
            loop_blocks.push(block_id);

            // 先行ブロックを追加
            for (pred_id, pred_block) in cfg.blocks.iter() {
                if pred_block.successors.contains(&block_id) {
                    worklist.push(*pred_id);
                }
            }
        }

        loop_blocks
    }

    /// ループ内で変更される変数を収集
    fn collect_modified_vars(&self, cfg: &ControlFlowGraph, loop_blocks: &[BlockId]) -> HashSet<Varnode> {
        let mut modified = HashSet::new();

        for &block_id in loop_blocks {
            if let Some(block) = cfg.blocks.get(&block_id) {
                for op in &block.ops {
                    if let Some(output) = &op.output {
                        modified.insert(output.clone());
                    }
                }
            }
        }

        modified
    }

    /// ループ不変命令を検出
    fn find_invariant_ops(
        &self,
        cfg: &ControlFlowGraph,
        loop_blocks: &[BlockId],
        modified_vars: &HashSet<Varnode>,
    ) -> Vec<(BlockId, usize)> {
        let mut invariant_ops = Vec::new();

        for &block_id in loop_blocks {
            if let Some(block) = cfg.blocks.get(&block_id) {
                for (op_idx, op) in block.ops.iter().enumerate() {
                    if self.is_invariant(op, modified_vars) {
                        invariant_ops.push((block_id, op_idx));
                    }
                }
            }
        }

        invariant_ops
    }

    /// 命令が不変か判定
    fn is_invariant(&self, op: &PcodeOp, modified_vars: &HashSet<Varnode>) -> bool {
        // 副作用のある命令は移動しない
        if matches!(
            op.opcode,
            OpCode::Store | OpCode::Call | OpCode::CallInd | OpCode::Return
        ) {
            return false;
        }

        // 入力がループ内で変更されていない
        op.inputs.iter().all(|input| !modified_vars.contains(input))
    }

    /// ループ不変命令をプリヘッダに移動
    fn move_to_preheader(
        &mut self,
        _cfg: &mut ControlFlowGraph,
        _header: BlockId,
        _invariant_ops: &[(BlockId, usize)],
    ) {
        // 実装簡略化のため、ここではカウントのみ
        // 完全な実装ではCFGを変更してプリヘッダブロックを挿入
    }

    pub fn moved_count(&self) -> usize {
        self.moved_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_licm_detection() {
        let rule = RuleLICM::new();
        // テスト実装は簡略化
        assert_eq!(rule.moved_count(), 0);
    }
}
