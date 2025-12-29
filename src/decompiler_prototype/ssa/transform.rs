use super::super::cfg::*;
use super::super::pcode::{Varnode, OpCode, PcodeOp, AddressSpace};
use std::collections::{HashMap, HashSet, VecDeque};
use super::dominance::DominanceTree;



pub struct SSATransform {


    def_counters: HashMap<Varnode, usize>,


    var_stacks: HashMap<Varnode, Vec<usize>>,


    dominance_tree: DominanceTree,


    dominance_frontier: HashMap<BlockId, HashSet<BlockId>>,
}

impl SSATransform {


    pub fn new() -> Self {
        Self {
            def_counters: HashMap::new(),
            var_stacks: HashMap::new(),
            dominance_tree: DominanceTree::new(),
            dominance_frontier: HashMap::new(),
        }
    }



    pub fn transform(&mut self, cfg: &mut ControlFlowGraph) {

        self.dominance_tree = DominanceTree::compute(cfg);


        self.compute_dominance_frontier(cfg);


        self.insert_phi_nodes(cfg);


        self.rename_variables(cfg, cfg.entry_block);
    }



    fn compute_dominance_frontier(&mut self, cfg: &ControlFlowGraph) {
        for (&block_id, block) in &cfg.blocks {

            if block.predecessors.len() >= 2 {
                for &pred in &block.predecessors {
                    let mut runner = pred;


                    loop {

                        self.dominance_frontier
                            .entry(runner)
                            .or_insert_with(HashSet::new)
                            .insert(block_id);


                        if let Some(idom) = self.dominance_tree.immediate_dominator(block_id) {
                            if runner == idom {
                                break;
                            }
                        }


                        if let Some(next) = self.dominance_tree.immediate_dominator(runner) {
                            runner = next;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }



    fn insert_phi_nodes(&mut self, cfg: &mut ControlFlowGraph) {

        let all_vars = self.collect_all_variables(cfg);

        for var in all_vars {

            let mut def_blocks = HashSet::new();
            for (&block_id, block) in &cfg.blocks {
                for op in &block.ops {
                    if let Some(ref output) = op.output {
                        if Self::same_variable(output, &var) {
                            def_blocks.insert(block_id);
                        }
                    }
                }
            }

            //
            let mut phi_blocks = HashSet::new();
            let mut worklist: VecDeque<BlockId> = def_blocks.iter().copied().collect();

            while let Some(block_id) = worklist.pop_front() {

                if let Some(frontier) = self.dominance_frontier.get(&block_id) {
                    for &df_block in frontier {
                        if !phi_blocks.contains(&df_block) {

                            phi_blocks.insert(df_block);
                            worklist.push_back(df_block);


                            if let Some(block) = cfg.blocks.get_mut(&df_block) {
                                let num_preds = block.predecessors.len();
                                let phi_inputs = vec![var.clone(); num_preds];

                                let phi_op = PcodeOp::new(
                                    OpCode::MultiEqual,
                                    Some(var.clone()),
                                    phi_inputs,
                                    block.start_address,
                                );


                                block.ops.insert(0, phi_op);
                            }
                        }
                    }
                }
            }
        }
    }



    fn collect_all_variables(&self, cfg: &ControlFlowGraph) -> Vec<Varnode> {
        let mut vars = HashSet::new();

        for block in cfg.blocks.values() {
            for op in &block.ops {

                if let Some(ref output) = op.output {
                    vars.insert(output.clone());
                }


                for input in &op.inputs {

                    if input.space != AddressSpace::Const {
                        vars.insert(input.clone());
                    }
                }
            }
        }

        vars.into_iter().collect()
    }



    fn rename_variables(&mut self, cfg: &mut ControlFlowGraph, block_id: BlockId) {
        let block = match cfg.blocks.get(&block_id) {
            Some(b) => b,
            None => return,
        };


        let ops_len = block.ops.len();
        for i in 0..ops_len {
            let block = cfg.blocks.get_mut(&block_id).unwrap();
            let op = &mut block.ops[i];


            for input in &mut op.inputs {
                if input.space != AddressSpace::Const {
                    if let Some(stack) = self.var_stacks.get(input) {
                        if let Some(&version) = stack.last() {

                            input.offset = (input.offset & 0xFFFFFFFF) | ((version as u64) << 32);
                        }
                    }
                }
            }


            if let Some(ref mut output) = op.output {
                if output.space != AddressSpace::Const {

                    let counter = self.def_counters.entry(output.clone()).or_insert(0);
                    *counter += 1;
                    let version = *counter;


                    self.var_stacks
                        .entry(output.clone())
                        .or_insert_with(Vec::new)
                        .push(version);


                    output.offset = (output.offset & 0xFFFFFFFF) | ((version as u64) << 32);
                }
            }
        }


        let successors: Vec<BlockId> = cfg.blocks[&block_id].successors.clone();
        for &succ in &successors {
            let succ_block = cfg.blocks.get_mut(&succ).unwrap();

            for op in &mut succ_block.ops {
                if op.opcode == OpCode::MultiEqual {


                    for input in &mut op.inputs {
                        if input.space != AddressSpace::Const {
                            if let Some(stack) = self.var_stacks.get(input) {
                                if let Some(&version) = stack.last() {
                                    input.offset = (input.offset & 0xFFFFFFFF) | ((version as u64) << 32);
                                }
                            }
                        }
                    }
                }
            }
        }


        if let Some(children) = self.dominance_tree.children.get(&block_id) {
            let children_copy = children.clone();
            for child in children_copy {
                self.rename_variables(cfg, child);
            }
        }


    }



    fn same_variable(v1: &Varnode, v2: &Varnode) -> bool {
        v1.space == v2.space && (v1.offset & 0xFFFFFFFF) == (v2.offset & 0xFFFFFFFF) && v1.size == v2.size
    }
}

impl Default for SSATransform {
    fn default() -> Self {
        Self::new()
    }
}
