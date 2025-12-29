use super::super::cfg::*;
use std::collections::{HashMap, HashSet};
pub struct DominanceTree {
    pub idom: HashMap<BlockId, BlockId>,
    pub dominates: HashMap<BlockId, HashSet<BlockId>>,
    pub children: HashMap<BlockId, Vec<BlockId>>,
}

impl DominanceTree {
    pub fn new() -> Self {
        Self {
            idom: HashMap::new(),
            dominates: HashMap::new(),
            children: HashMap::new(),
        }
    }
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let mut tree = Self::new();
        let entry = cfg.entry_block;
        let blocks: Vec<BlockId> = cfg.blocks.keys().copied().collect();
        let mut idom: HashMap<BlockId, Option<BlockId>> = HashMap::new();
        for &block_id in &blocks {
            if block_id == entry {
                idom.insert(block_id, None);
            } else {
                idom.insert(block_id, None);
            }
        }
        let rpo = Self::reverse_postorder(cfg, entry);
        let mut changed = true;
        while changed {
            changed = false;
            for &block_id in &rpo {
                if block_id == entry {
                    continue;
                }
                let block = &cfg.blocks[&block_id];
                let predecessors: Vec<BlockId> = block.predecessors.clone();
                if predecessors.is_empty() {
                    continue;
                }
                let mut new_idom: Option<BlockId> = None;
                for &pred in &predecessors {
                    if idom.get(&pred).and_then(|x| *x).is_some() || pred == entry {
                        if new_idom.is_none() {
                            new_idom = Some(pred);
                        } else {
                            new_idom = Some(Self::intersect(&idom, new_idom.unwrap(), pred, &rpo));
                        }
                    }
                }
                if new_idom != idom[&block_id] {
                    idom.insert(block_id, new_idom);
                    changed = true;
                }
            }
        }
        for (block_id, dom) in idom {
            if let Some(dominator) = dom {
                tree.idom.insert(block_id, dominator);
                tree.children.entry(dominator).or_insert_with(Vec::new).push(block_id);
            }
        }
        tree.compute_dominates(entry);

        tree
    }
    fn intersect(
        idom: &HashMap<BlockId, Option<BlockId>>,
        mut b1: BlockId,
        mut b2: BlockId,
        rpo: &[BlockId],
    ) -> BlockId {
        let rpo_pos: HashMap<BlockId, usize> = rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

        while b1 != b2 {
            while rpo_pos.get(&b1).copied().unwrap_or(999) < rpo_pos.get(&b2).copied().unwrap_or(999) {
                if let Some(Some(next)) = idom.get(&b1) {
                    b1 = *next;
                } else {
                    break;
                }
            }
            while rpo_pos.get(&b2).copied().unwrap_or(999) < rpo_pos.get(&b1).copied().unwrap_or(999) {
                if let Some(Some(next)) = idom.get(&b2) {
                    b2 = *next;
                } else {
                    break;
                }
            }
        }

        b1
    }
    fn reverse_postorder(cfg: &ControlFlowGraph, entry: BlockId) -> Vec<BlockId> {
        let mut visited = HashSet::new();
        let mut postorder = Vec::new();

        fn dfs(
            cfg: &ControlFlowGraph,
            block_id: BlockId,
            visited: &mut HashSet<BlockId>,
            postorder: &mut Vec<BlockId>,
        ) {
            if visited.contains(&block_id) {
                return;
            }
            visited.insert(block_id);

            if let Some(block) = cfg.blocks.get(&block_id) {
                for &successor in &block.successors {
                    dfs(cfg, successor, visited, postorder);
                }
            }

            postorder.push(block_id);
        }

        dfs(cfg, entry, &mut visited, &mut postorder);
        postorder.reverse();
        postorder
    }
    fn compute_dominates(&mut self, block_id: BlockId) {
        let mut dominated = HashSet::new();
        dominated.insert(block_id);
        let children_copy = self.children.get(&block_id).cloned();
        if let Some(children) = children_copy {
            for child in children {
                self.compute_dominates(child);
                if let Some(child_dominated) = self.dominates.get(&child) {
                    dominated.extend(child_dominated.iter());
                }
                dominated.insert(child);
            }
        }
        self.dominates.insert(block_id, dominated);
    }
    pub fn dominates(&self, dominator: BlockId, block: BlockId) -> bool {
        self.dominates
            .get(&dominator)
            .map(|set| set.contains(&block))
            .unwrap_or(false)
    }
    pub fn immediate_dominator(&self, block: BlockId) -> Option<BlockId> {
        self.idom.get(&block).copied()
    }
}
impl Default for DominanceTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dominance_tree() {
        let mut cfg = ControlFlowGraph::new();
        cfg.entry_block = 0;
        let mut block0 = BasicBlock::new(0, 0);
        let mut block1 = BasicBlock::new(1, 10);
        let mut block2 = BasicBlock::new(2, 20);
        let mut block3 = BasicBlock::new(3, 30);
        let mut block4 = BasicBlock::new(4, 40);
        block0.successors.push(1);
        block1.successors.push(2);
        block1.successors.push(3);
        block2.successors.push(4);
        block3.successors.push(4);
        block1.predecessors.push(0);
        block2.predecessors.push(1);
        block3.predecessors.push(1);
        block4.predecessors.push(2);
        block4.predecessors.push(3);
        cfg.blocks.insert(0, block0);
        cfg.blocks.insert(1, block1);
        cfg.blocks.insert(2, block2);
        cfg.blocks.insert(3, block3);
        cfg.blocks.insert(4, block4);
        let dom_tree = DominanceTree::compute(&cfg);
        assert!(dom_tree.dominates(0, 0));
        assert!(dom_tree.dominates(0, 1));
        assert!(dom_tree.dominates(0, 4));
        assert!(dom_tree.dominates(1, 4));
        println!("Dominance tree test passed!");
    }
}