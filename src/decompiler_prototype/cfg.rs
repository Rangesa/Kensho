/// 制御フロー解析
/// 基本ブロックの構築と制御フローグラフ

use super::pcode::{OpCode, PcodeOp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 基本ブロックID
pub type BlockId = usize;

/// 基本ブロック
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub start_address: u64,
    pub end_address: u64,
    pub ops: Vec<PcodeOp>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
}

impl BasicBlock {
    pub fn new(id: BlockId, start_address: u64) -> Self {
        Self {
            id,
            start_address,
            end_address: start_address,
            ops: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    /// ブロックに命令を追加
    pub fn add_op(&mut self, op: PcodeOp) {
        self.end_address = op.address;
        self.ops.push(op);
    }

    /// このブロックが分岐命令で終わるか
    pub fn is_branch(&self) -> bool {
        if let Some(last) = self.ops.last() {
            matches!(
                last.opcode,
                OpCode::Branch | OpCode::CBranch | OpCode::BranchInd | OpCode::Return
            )
        } else {
            false
        }
    }

    /// このブロックが関数終端か
    pub fn is_return(&self) -> bool {
        if let Some(last) = self.ops.last() {
            matches!(last.opcode, OpCode::Return)
        } else {
            false
        }
    }
}

/// 制御フローグラフ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<BlockId, BasicBlock>,
    pub entry_block: BlockId,
    pub next_block_id: BlockId,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            entry_block: 0,
            next_block_id: 0,
        }
    }

    /// P-code列から制御フローグラフを構築
    pub fn from_pcodes(pcodes: Vec<PcodeOp>) -> Self {
        let mut cfg = ControlFlowGraph::new();

        if pcodes.is_empty() {
            return cfg;
        }

        // 1つ目のブロックを作成
        let mut current_block = BasicBlock::new(0, pcodes[0].address);
        cfg.entry_block = 0;
        cfg.next_block_id = 1;

        for op in pcodes {
            let should_split = matches!(
                op.opcode,
                OpCode::Branch | OpCode::CBranch | OpCode::BranchInd | OpCode::Return
            );

            current_block.add_op(op);

            if should_split {
                // ブロックを確定して次のブロックを開始
                let block_id = current_block.id;
                cfg.blocks.insert(block_id, current_block);

                current_block = BasicBlock::new(cfg.next_block_id, 0);
                cfg.next_block_id += 1;
            }
        }

        // 最後のブロックを追加
        if !current_block.ops.is_empty() {
            cfg.blocks.insert(current_block.id, current_block);
        }

        cfg
    }

    /// エントリブロックを取得
    pub fn entry(&self) -> Option<&BasicBlock> {
        self.blocks.get(&self.entry_block)
    }

    /// ブロック数を取得
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// すべてのブロックを順番に取得
    pub fn blocks_in_order(&self) -> Vec<&BasicBlock> {
        let mut blocks: Vec<_> = self.blocks.values().collect();
        blocks.sort_by_key(|b| b.id);
        blocks
    }
}

impl std::fmt::Display for ControlFlowGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Control Flow Graph:")?;
        writeln!(f, "  Entry Block: {}", self.entry_block)?;
        writeln!(f, "  Block Count: {}", self.block_count())?;
        writeln!(f)?;

        for block in self.blocks_in_order() {
            writeln!(f, "Block {} (0x{:x} - 0x{:x}):", block.id, block.start_address, block.end_address)?;
            for op in &block.ops {
                writeln!(f, "  0x{:x}: {}", op.address, op)?;
            }
            if !block.successors.is_empty() {
                writeln!(f, "  Successors: {:?}", block.successors)?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::x86_64::example_translation;

    #[test]
    fn test_cfg_construction() {
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        // ret命令で分割されるので2ブロック
        assert!(cfg.block_count() >= 1);
        assert!(cfg.entry().is_some());
    }

    #[test]
    fn test_block_properties() {
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        let entry = cfg.entry().unwrap();
        assert!(!entry.ops.is_empty());
    }
}
