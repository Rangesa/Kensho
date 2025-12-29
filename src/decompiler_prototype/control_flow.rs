/// Control flow analysis and structure recovery
/// Recovers high-level control structures (if, while, switch) from CFG

use super::cfg::*;
use super::pcode::*;
use std::collections::{HashMap, HashSet, VecDeque};

/// High-level control structure
#[derive(Debug, Clone)]
pub enum ControlStructure {
    /// Sequential execution of multiple structures
    Sequence(Vec<ControlStructure>),
    /// If-then-else conditional
    IfThenElse {
        condition_block: BlockId,
        then_branch: Box<ControlStructure>,
        else_branch: Option<Box<ControlStructure>>,
    },
    /// If-then conditional (no else)
    IfThen {
        condition_block: BlockId,
        then_branch: Box<ControlStructure>,
    },
    /// While loop
    While {
        condition_block: BlockId,
        body: Box<ControlStructure>,
    },
    /// Do-while loop
    DoWhile {
        body: Box<ControlStructure>,
        condition_block: BlockId,
    },
    /// Infinite loop
    InfiniteLoop {
        body: Box<ControlStructure>,
    },
    /// Switch statement
    Switch {
        condition_block: BlockId,
        cases: Vec<(Option<i64>, ControlStructure)>,
    },
    /// Basic block
    BasicBlock(BlockId),
    /// Break statement
    Break,
    /// Continue statement
    Continue,
}

/// Loop information
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// Loop header block
    pub header: BlockId,
    /// Blocks in loop body
    pub body: HashSet<BlockId>,
    /// Back edges (tail -> header)
    pub back_edges: Vec<(BlockId, BlockId)>,
    /// Loop type
    pub loop_type: LoopType,
}

/// Loop type classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopType {
    /// While loop (condition at top)
    While,
    /// Do-while loop (condition at bottom)
    DoWhile,
    /// Infinite loop
    Infinite,
}

/// Control flow analyzer
pub struct ControlFlowAnalyzer {
    /// Dominator mapping
    dominators: HashMap<BlockId, BlockId>,
    /// Detected loops
    loops: Vec<LoopInfo>,
    /// Visited blocks during traversal
    visited: HashSet<BlockId>,
}

impl ControlFlowAnalyzer {
    /// Create new analyzer
    pub fn new() -> Self {
        Self {
            dominators: HashMap::new(),
            loops: Vec::new(),
            visited: HashSet::new(),
        }
    }

    /// Get detected loops
    pub fn get_loops(&self) -> &Vec<LoopInfo> {
        &self.loops
    }

    /// Analyze control flow and build structure
    pub fn analyze(&mut self, cfg: &ControlFlowGraph) -> ControlStructure {
        self.compute_dominators(cfg);
        self.detect_loops(cfg);
        self.build_control_structure(cfg, cfg.entry_block)
    }

    /// Compute dominators using iterative algorithm
    fn compute_dominators(&mut self, cfg: &ControlFlowGraph) {
        let entry = cfg.entry_block;
        let mut idom: HashMap<BlockId, Option<BlockId>> = HashMap::new();

        for &block_id in cfg.blocks.keys() {
            if block_id == entry {
                idom.insert(block_id, None);
            } else {
                idom.insert(block_id, None);
            }
        }

        let rpo = self.reverse_postorder(cfg, entry);

        let mut changed = true;
        while changed {
            changed = false;

            for &block_id in &rpo {
                if block_id == entry {
                    continue;
                }

                let block = &cfg.blocks[&block_id];
                if block.predecessors.is_empty() {
                    continue;
                }

                let mut new_idom: Option<BlockId> = None;
                for &pred in &block.predecessors {
                    if idom.get(&pred).and_then(|x| *x).is_some() || pred == entry {
                        new_idom = Some(pred);
                        break;
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
                self.dominators.insert(block_id, dominator);
            }
        }
    }

    /// Compute reverse postorder traversal
    fn reverse_postorder(&self, cfg: &ControlFlowGraph, entry: BlockId) -> Vec<BlockId> {
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

    /// Detect loops using back edges
    fn detect_loops(&mut self, cfg: &ControlFlowGraph) {
        let mut back_edges = Vec::new();

        for (&block_id, block) in &cfg.blocks {
            for &successor in &block.successors {
                if self.dominates(successor, block_id) {
                    back_edges.push((block_id, successor));
                }
            }
        }

        for (tail, header) in back_edges {
            let body = self.find_loop_body(cfg, header, tail);
            let loop_type = self.determine_loop_type(cfg, header, &body);

            self.loops.push(LoopInfo {
                header,
                body,
                back_edges: vec![(tail, header)],
                loop_type,
            });
        }
    }

    /// Find all blocks in loop body
    fn find_loop_body(&self, cfg: &ControlFlowGraph, header: BlockId, tail: BlockId) -> HashSet<BlockId> {
        let mut body = HashSet::new();
        body.insert(header);

        if tail == header {
            return body;
        }

        let mut worklist = VecDeque::new();
        worklist.push_back(tail);
        body.insert(tail);

        while let Some(block_id) = worklist.pop_front() {
            if let Some(block) = cfg.blocks.get(&block_id) {
                for &pred in &block.predecessors {
                    if !body.contains(&pred) && self.dominates(header, pred) {
                        body.insert(pred);
                        worklist.push_back(pred);
                    }
                }
            }
        }

        body
    }

    /// Determine loop type from structure
    fn determine_loop_type(&self, cfg: &ControlFlowGraph, header: BlockId, _body: &HashSet<BlockId>) -> LoopType {
        if let Some(header_block) = cfg.blocks.get(&header) {
            if let Some(last_op) = header_block.ops.last() {
                match last_op.opcode {
                    OpCode::CBranch => LoopType::While,
                    OpCode::Branch => LoopType::Infinite,
                    _ => LoopType::DoWhile,
                }
            } else {
                LoopType::While
            }
        } else {
            LoopType::While
        }
    }

    /// Check if one block dominates another
    fn dominates(&self, dominator: BlockId, block: BlockId) -> bool {
        if dominator == block {
            return true;
        }

        let mut current = block;
        while let Some(&dom) = self.dominators.get(&current) {
            if dom == dominator {
                return true;
            }
            if dom == current {
                break;
            }
            current = dom;
        }

        false
    }

    /// Build control structure recursively
    fn build_control_structure(&mut self, cfg: &ControlFlowGraph, block_id: BlockId) -> ControlStructure {
        if self.visited.contains(&block_id) {
            return ControlStructure::BasicBlock(block_id);
        }
        self.visited.insert(block_id);

        if let Some(loop_info) = self.find_loop_by_header(block_id) {
            return self.build_loop_structure(cfg, loop_info);
        }

        let block = match cfg.blocks.get(&block_id) {
            Some(b) => b,
            None => return ControlStructure::BasicBlock(block_id),
        };

        match block.successors.len() {
            0 => ControlStructure::BasicBlock(block_id),
            1 => {
                let next = block.successors[0];
                let next_struct = self.build_control_structure(cfg, next);
                ControlStructure::Sequence(vec![
                    ControlStructure::BasicBlock(block_id),
                    next_struct,
                ])
            }
            2 => self.build_if_structure(cfg, block_id, &block.successors),
            _ => self.build_switch_structure(cfg, block_id, &block.successors),
        }
    }

    /// Build if-then-else structure
    fn build_if_structure(&mut self, cfg: &ControlFlowGraph, condition_block: BlockId, successors: &[BlockId]) -> ControlStructure {
        if successors.len() != 2 {
            return ControlStructure::BasicBlock(condition_block);
        }

        let then_block = successors[0];
        let else_block = successors[1];

        let merge_point = self.find_merge_point(cfg, then_block, else_block);

        let then_branch = Box::new(self.build_region(cfg, then_block, merge_point));

        if else_block == merge_point.unwrap_or(else_block) {
            ControlStructure::IfThen {
                condition_block,
                then_branch,
            }
        } else {
            let else_branch = Some(Box::new(self.build_region(cfg, else_block, merge_point)));
            ControlStructure::IfThenElse {
                condition_block,
                then_branch,
                else_branch,
            }
        }
    }

    /// Build switch structure
    fn build_switch_structure(&mut self, cfg: &ControlFlowGraph, condition_block: BlockId, successors: &[BlockId]) -> ControlStructure {
        let mut cases = Vec::new();

        for (i, &succ) in successors.iter().enumerate() {
            let case_value = if i == successors.len() - 1 {
                None
            } else {
                Some(i as i64)
            };

            let case_struct = self.build_control_structure(cfg, succ);
            cases.push((case_value, case_struct));
        }

        ControlStructure::Switch {
            condition_block,
            cases,
        }
    }

    /// Build loop structure
    fn build_loop_structure(&mut self, cfg: &ControlFlowGraph, loop_info: LoopInfo) -> ControlStructure {
        let header = loop_info.header;
        let body_blocks: Vec<BlockId> = loop_info.body.iter().copied().filter(|&b| b != header).collect();

        let mut body_structures = Vec::new();
        for &block_id in &body_blocks {
            if !self.visited.contains(&block_id) {
                let struct_node = self.build_control_structure(cfg, block_id);
                body_structures.push(struct_node);
            }
        }

        let body = if body_structures.is_empty() {
            Box::new(ControlStructure::BasicBlock(header))
        } else if body_structures.len() == 1 {
            Box::new(body_structures.into_iter().next().unwrap())
        } else {
            Box::new(ControlStructure::Sequence(body_structures))
        };

        match loop_info.loop_type {
            LoopType::While => ControlStructure::While {
                condition_block: header,
                body,
            },
            LoopType::DoWhile => ControlStructure::DoWhile {
                body,
                condition_block: header,
            },
            LoopType::Infinite => ControlStructure::InfiniteLoop { body },
        }
    }

    /// Build a region between start and end
    fn build_region(&mut self, cfg: &ControlFlowGraph, start: BlockId, end: Option<BlockId>) -> ControlStructure {
        if Some(start) == end {
            return ControlStructure::BasicBlock(start);
        }

        let mut current = start;
        let mut sequence = Vec::new();

        loop {
            if Some(current) == end {
                break;
            }

            sequence.push(ControlStructure::BasicBlock(current));

            let block = match cfg.blocks.get(&current) {
                Some(b) => b,
                None => break,
            };

            if block.successors.is_empty() {
                break;
            }

            if block.successors.len() == 1 {
                current = block.successors[0];
            } else {
                let branch_struct = self.build_control_structure(cfg, current);
                sequence.push(branch_struct);
                break;
            }
        }

        if sequence.is_empty() {
            ControlStructure::BasicBlock(start)
        } else if sequence.len() == 1 {
            sequence.into_iter().next().unwrap()
        } else {
            ControlStructure::Sequence(sequence)
        }
    }

    /// Find merge point of two branches
    fn find_merge_point(&self, cfg: &ControlFlowGraph, branch1: BlockId, branch2: BlockId) -> Option<BlockId> {
        let mut visited1 = HashSet::new();
        let mut queue1 = VecDeque::new();
        queue1.push_back(branch1);

        while let Some(block_id) = queue1.pop_front() {
            if visited1.contains(&block_id) {
                continue;
            }
            visited1.insert(block_id);

            if let Some(block) = cfg.blocks.get(&block_id) {
                for &succ in &block.successors {
                    queue1.push_back(succ);
                }
            }
        }

        let mut visited2 = HashSet::new();
        let mut queue2 = VecDeque::new();
        queue2.push_back(branch2);

        while let Some(block_id) = queue2.pop_front() {
            if visited2.contains(&block_id) {
                continue;
            }
            visited2.insert(block_id);

            if visited1.contains(&block_id) {
                return Some(block_id);
            }

            if let Some(block) = cfg.blocks.get(&block_id) {
                for &succ in &block.successors {
                    queue2.push_back(succ);
                }
            }
        }

        None
    }

    /// Find loop by header block
    fn find_loop_by_header(&self, header: BlockId) -> Option<LoopInfo> {
        self.loops.iter().find(|l| l.header == header).cloned()
    }
}

impl Default for ControlFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Printer for control structures
pub struct ControlStructurePrinter {
    indent_level: usize,
}

impl ControlStructurePrinter {
    pub fn new() -> Self {
        Self { indent_level: 0 }
    }

    /// Print control structure
    pub fn print(&mut self, structure: &ControlStructure) -> String {
        match structure {
            ControlStructure::Sequence(seq) => {
                let mut result = String::new();
                for item in seq {
                    result.push_str(&self.print(item));
                }
                result
            }
            ControlStructure::IfThenElse {
                condition_block,
                then_branch,
                else_branch,
            } => {
                let indent = "  ".repeat(self.indent_level);
                let mut result = format!("{}if (block_{}) {{\n", indent, condition_block);

                self.indent_level += 1;
                result.push_str(&self.print(then_branch));
                self.indent_level -= 1;

                if let Some(else_br) = else_branch {
                    result.push_str(&format!("{}}} else {{\n", indent));
                    self.indent_level += 1;
                    result.push_str(&self.print(else_br));
                    self.indent_level -= 1;
                }

                result.push_str(&format!("{}}}\n", indent));
                result
            }
            ControlStructure::IfThen {
                condition_block,
                then_branch,
            } => {
                let indent = "  ".repeat(self.indent_level);
                let mut result = format!("{}if (block_{}) {{\n", indent, condition_block);

                self.indent_level += 1;
                result.push_str(&self.print(then_branch));
                self.indent_level -= 1;

                result.push_str(&format!("{}}}\n", indent));
                result
            }
            ControlStructure::While {
                condition_block,
                body,
            } => {
                let indent = "  ".repeat(self.indent_level);
                let mut result = format!("{}while (block_{}) {{\n", indent, condition_block);

                self.indent_level += 1;
                result.push_str(&self.print(body));
                self.indent_level -= 1;

                result.push_str(&format!("{}}}\n", indent));
                result
            }
            ControlStructure::DoWhile {
                body,
                condition_block,
            } => {
                let indent = "  ".repeat(self.indent_level);
                let mut result = format!("{}do {{\n", indent);

                self.indent_level += 1;
                result.push_str(&self.print(body));
                self.indent_level -= 1;

                result.push_str(&format!("{}}} while (block_{});\n", indent, condition_block));
                result
            }
            ControlStructure::InfiniteLoop { body } => {
                let indent = "  ".repeat(self.indent_level);
                let mut result = format!("{}loop {{\n", indent);

                self.indent_level += 1;
                result.push_str(&self.print(body));
                self.indent_level -= 1;

                result.push_str(&format!("{}}}\n", indent));
                result
            }
            ControlStructure::Switch {
                condition_block,
                cases,
            } => {
                let indent = "  ".repeat(self.indent_level);
                let mut result = format!("{}switch (block_{}) {{\n", indent, condition_block);

                self.indent_level += 1;
                for (case_value, case_body) in cases {
                    let case_indent = "  ".repeat(self.indent_level);
                    if let Some(val) = case_value {
                        result.push_str(&format!("{}case {}:\n", case_indent, val));
                    } else {
                        result.push_str(&format!("{}default:\n", case_indent));
                    }

                    self.indent_level += 1;
                    result.push_str(&self.print(case_body));
                    self.indent_level -= 1;
                }
                self.indent_level -= 1;

                result.push_str(&format!("{}}}\n", indent));
                result
            }
            ControlStructure::BasicBlock(id) => {
                let indent = "  ".repeat(self.indent_level);
                format!("{}block_{};\n", indent, id)
            }
            ControlStructure::Break => {
                let indent = "  ".repeat(self.indent_level);
                format!("{}break;\n", indent)
            }
            ControlStructure::Continue => {
                let indent = "  ".repeat(self.indent_level);
                format!("{}continue;\n", indent)
            }
        }
    }
}

impl Default for ControlStructurePrinter {
    fn default() -> Self {
        Self::new()
    }
}
