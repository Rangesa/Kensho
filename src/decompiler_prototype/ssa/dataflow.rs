use super::super::cfg::*;
use super::super::pcode::{Varnode, AddressSpace};
use std::collections::{HashMap, HashSet};



pub struct DataFlowAnalysis {


    reaching_defs: HashMap<BlockId, HashSet<(Varnode, BlockId)>>,


    live_vars: HashMap<BlockId, HashSet<Varnode>>,
}

impl DataFlowAnalysis {


    pub fn new() -> Self {
        Self {
            reaching_defs: HashMap::new(),
            live_vars: HashMap::new(),
        }
    }



    pub fn compute_reaching_definitions(&mut self, cfg: &ControlFlowGraph) {
        let mut changed = true;


        for &block_id in cfg.blocks.keys() {
            self.reaching_defs.insert(block_id, HashSet::new());
        }


        while changed {
            changed = false;

            for (&block_id, block) in &cfg.blocks {
                let mut new_defs = HashSet::new();


                for &pred in &block.predecessors {
                    if let Some(pred_defs) = self.reaching_defs.get(&pred) {
                        new_defs.extend(pred_defs.iter().cloned());
                    }
                }


                for op in &block.ops {
                    if let Some(ref output) = op.output {
                        new_defs.insert((output.clone(), block_id));
                    }
                }


                if new_defs != self.reaching_defs[&block_id] {
                    self.reaching_defs.insert(block_id, new_defs);
                    changed = true;
                }
            }
        }
    }



    pub fn compute_live_variables(&mut self, cfg: &ControlFlowGraph) {
        let mut changed = true;


        for &block_id in cfg.blocks.keys() {
            self.live_vars.insert(block_id, HashSet::new());
        }


        while changed {
            changed = false;

            for (&block_id, block) in &cfg.blocks {
                let mut new_live = HashSet::new();


                for &succ in &block.successors {
                    if let Some(succ_live) = self.live_vars.get(&succ) {
                        new_live.extend(succ_live.iter().cloned());
                    }
                }

                for op in block.ops.iter().rev() {

                    if let Some(ref output) = op.output {
                        new_live.remove(output);
                    }


                    for input in &op.inputs {
                        if input.space != AddressSpace::Const {
                            new_live.insert(input.clone());
                        }
                    }
                }


                if new_live != self.live_vars[&block_id] {
                    self.live_vars.insert(block_id, new_live);
                    changed = true;
                }
            }
        }
    }



    pub fn live_at_block_start(&self, block_id: BlockId) -> Option<&HashSet<Varnode>> {
        self.live_vars.get(&block_id)
    }
}

impl Default for DataFlowAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataflow() {
        let mut cfg = ControlFlowGraph::new();
        cfg.entry_block = 0;
        let mut block = BasicBlock::new(0, 0);


        let rax = Varnode::register(0, 8);
        let rbx = Varnode::register(8, 8);

        block.ops.push(PcodeOp::unary(OpCode::Copy, rax.clone(), Varnode::constant(10, 8), 0));
        block.ops.push(PcodeOp::binary(OpCode::IntAdd, rbx.clone(), rax.clone(), Varnode::constant(5, 8), 10));

        cfg.blocks.insert(0, block);

        let mut df = DataFlowAnalysis::new();
        df.compute_reaching_definitions(&cfg);
        df.compute_live_variables(&cfg);

        println!("Dataflow analysis test passed!");
    }
}
