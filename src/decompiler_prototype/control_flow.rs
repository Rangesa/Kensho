/// 制御構造検出
/// CFGから高レベルの制御構造（if/while/for/switch）を検出する

use super::cfg::*;
use super::pcode::*;
use std::collections::{HashMap, HashSet, VecDeque};

/// 制御構造の種類
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlStructure {
    /// 順次実行
    Sequence(Vec<ControlStructure>),
    /// if文: (条件ブロック, then部, else部)
    IfThenElse {
        condition_block: BlockId,
        then_branch: Box<ControlStructure>,
        else_branch: Option<Box<ControlStructure>>,
    },
    /// if文（else無し）
    IfThen {
        condition_block: BlockId,
        then_branch: Box<ControlStructure>,
    },
    /// whileループ: (条件ブロック, ループ本体)
    While {
        condition_block: BlockId,
        body: Box<ControlStructure>,
    },
    /// do-whileループ: (ループ本体, 条件ブロック)
    DoWhile {
        body: Box<ControlStructure>,
        condition_block: BlockId,
    },
    /// 無限ループ
    InfiniteLoop {
        body: Box<ControlStructure>,
    },
    /// switch文: (条件ブロック, case分岐)
    Switch {
        condition_block: BlockId,
        cases: Vec<(Option<i64>, ControlStructure)>, // (case値, 処理)
    },
    /// 単一のブロック
    BasicBlock(BlockId),
    /// break文
    Break,
    /// continue文
    Continue,
}

/// ループ情報
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// ループヘッダー（条件判定ブロック）
    pub header: BlockId,
    /// ループ本体（ループに含まれるすべてのブロック）
    pub body: HashSet<BlockId>,
    /// バックエッジ（ループに戻る辺）
    pub back_edges: Vec<(BlockId, BlockId)>,
    /// ループの種類
    pub loop_type: LoopType,
}

/// ループの種類
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopType {
    /// whileループ（前判定）
    While,
    /// do-whileループ（後判定）
    DoWhile,
    /// 無限ループ
    Infinite,
}

/// 制御構造解析器
pub struct ControlFlowAnalyzer {
    /// 支配木情報
    dominators: HashMap<BlockId, BlockId>,
    /// ループ情報
    loops: Vec<LoopInfo>,
    /// 訪問済みブロック
    visited: HashSet<BlockId>,
}

impl ControlFlowAnalyzer {
    /// 新しい解析器を作成
    pub fn new() -> Self {
        Self {
            dominators: HashMap::new(),
            loops: Vec::new(),
            visited: HashSet::new(),
        }
    }

    /// 検出されたループ情報を取得
    pub fn get_loops(&self) -> &[LoopInfo] {
        &self.loops
    }

    /// CFGから制御構造を検出
    pub fn analyze(&mut self, cfg: &ControlFlowGraph) -> ControlStructure {
        // 1. 支配木を計算
        self.compute_dominators(cfg);

        // 2. ループを検出
        self.detect_loops(cfg);

        // 3. 制御構造を構築
        self.build_control_structure(cfg, cfg.entry_block)
    }

    /// 支配木を計算（簡易版）
    fn compute_dominators(&mut self, cfg: &ControlFlowGraph) {
        let entry = cfg.entry_block;
        let mut idom: HashMap<BlockId, Option<BlockId>> = HashMap::new();

        // 初期化
        for &block_id in cfg.blocks.keys() {
            if block_id == entry {
                idom.insert(block_id, None);
            } else {
                idom.insert(block_id, None);
            }
        }

        // 逆ポストオーダー
        let rpo = self.reverse_postorder(cfg, entry);

        // 収束まで繰り返し
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

                // 処理済みの先行ブロックから新しい支配者を計算
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

        // 結果を保存
        for (block_id, dom) in idom {
            if let Some(dominator) = dom {
                self.dominators.insert(block_id, dominator);
            }
        }
    }

    /// 逆ポストオーダー
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

    /// ループを検出
    fn detect_loops(&mut self, cfg: &ControlFlowGraph) {
        // バックエッジを検出（後続ブロックが支配者の場合）
        let mut back_edges = Vec::new();

        for (&block_id, block) in &cfg.blocks {
            for &successor in &block.successors {
                // successorがblock_idを支配する場合、これはバックエッジ
                if self.dominates(successor, block_id) {
                    back_edges.push((block_id, successor));
                }
            }
        }

        // 各バックエッジからループを構築
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

    /// ループ本体を検出
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

    /// ループの種類を判定
    fn determine_loop_type(&self, cfg: &ControlFlowGraph, header: BlockId, body: &HashSet<BlockId>) -> LoopType {
        // ヘッダーブロックの終端命令をチェック
        if let Some(header_block) = cfg.blocks.get(&header) {
            if let Some(last_op) = header_block.ops.last() {
                match last_op.opcode {
                    OpCode::CBranch => {
                        // 条件分岐がある場合はwhileループ
                        LoopType::While
                    }
                    OpCode::Branch => {
                        // 無条件分岐の場合は無限ループの可能性
                        LoopType::Infinite
                    }
                    _ => {
                        // その他の場合はdo-whileと判定
                        LoopType::DoWhile
                    }
                }
            } else {
                LoopType::While
            }
        } else {
            LoopType::While
        }
    }

    /// ブロックAがブロックBを支配するか
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

    /// 制御構造を構築
    fn build_control_structure(&mut self, cfg: &ControlFlowGraph, block_id: BlockId) -> ControlStructure {
        if self.visited.contains(&block_id) {
            return ControlStructure::BasicBlock(block_id);
        }
        self.visited.insert(block_id);

        // このブロックがループヘッダーか確認
        if let Some(loop_info) = self.find_loop_by_header(block_id) {
            return self.build_loop_structure(cfg, loop_info);
        }

        let block = match cfg.blocks.get(&block_id) {
            Some(b) => b,
            None => return ControlStructure::BasicBlock(block_id),
        };

        // 後続ブロック数で分岐
        match block.successors.len() {
            0 => {
                // リターンまたは終端
                ControlStructure::BasicBlock(block_id)
            }
            1 => {
                // 順次実行
                let next = block.successors[0];
                let next_struct = self.build_control_structure(cfg, next);
                ControlStructure::Sequence(vec![
                    ControlStructure::BasicBlock(block_id),
                    next_struct,
                ])
            }
            2 => {
                // if文またはループ
                self.build_if_structure(cfg, block_id, &block.successors)
            }
            _ => {
                // switch文の可能性
                self.build_switch_structure(cfg, block_id, &block.successors)
            }
        }
    }

    /// if文の構造を構築
    fn build_if_structure(&mut self, cfg: &ControlFlowGraph, condition_block: BlockId, successors: &[BlockId]) -> ControlStructure {
        if successors.len() != 2 {
            return ControlStructure::BasicBlock(condition_block);
        }

        let then_block = successors[0];
        let else_block = successors[1];

        // 合流点を探す
        let merge_point = self.find_merge_point(cfg, then_block, else_block);

        let then_branch = Box::new(self.build_region(cfg, then_block, merge_point));

        // else分岐が空でないかチェック
        if else_block == merge_point.unwrap_or(else_block) {
            // else分岐なし
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

    /// switch文の構造を構築
    fn build_switch_structure(&mut self, cfg: &ControlFlowGraph, condition_block: BlockId, successors: &[BlockId]) -> ControlStructure {
        let mut cases = Vec::new();

        for (i, &succ) in successors.iter().enumerate() {
            let case_value = if i == successors.len() - 1 {
                None // default case
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

    /// ループ構造を構築
    fn build_loop_structure(&mut self, cfg: &ControlFlowGraph, loop_info: LoopInfo) -> ControlStructure {
        let header = loop_info.header;
        let body_blocks: Vec<BlockId> = loop_info.body.iter().copied().filter(|&b| b != header).collect();

        // ループ本体を構築
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

    /// 領域を構築（開始ブロックから終了ブロックまで）
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
                // 分岐がある場合は再帰的に構築
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

    /// 合流点を見つける
    fn find_merge_point(&self, cfg: &ControlFlowGraph, branch1: BlockId, branch2: BlockId) -> Option<BlockId> {
        let mut visited1 = HashSet::new();
        let mut queue1 = VecDeque::new();
        queue1.push_back(branch1);

        // branch1から到達可能なすべてのブロックを収集
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

        // branch2から到達可能で、branch1からも到達可能な最初のブロックを探す
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

    /// ヘッダーでループを検索
    fn find_loop_by_header(&self, header: BlockId) -> Option<LoopInfo> {
        self.loops.iter().find(|l| l.header == header).cloned()
    }
}

impl Default for ControlFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// 制御構造を人間が読みやすい形式で出力
pub struct ControlStructurePrinter {
    indent_level: usize,
}

impl ControlStructurePrinter {
    pub fn new() -> Self {
        Self { indent_level: 0 }
    }

    /// 制御構造を文字列に変換
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_if_structure() {
        let mut cfg = ControlFlowGraph::new();
        cfg.entry_block = 0;

        // if (cond) { block1 } else { block2 }
        // Block 0 (condition) -> Block 1 (then), Block 2 (else)
        // Block 1, 2 -> Block 3 (merge)
        let mut block0 = BasicBlock::new(0, 0);
        block0.successors = vec![1, 2];
        block0.ops.push(PcodeOp::no_output(OpCode::CBranch, vec![], 0));

        let mut block1 = BasicBlock::new(1, 10);
        block1.predecessors = vec![0];
        block1.successors = vec![3];

        let mut block2 = BasicBlock::new(2, 20);
        block2.predecessors = vec![0];
        block2.successors = vec![3];

        let mut block3 = BasicBlock::new(3, 30);
        block3.predecessors = vec![1, 2];

        cfg.blocks.insert(0, block0);
        cfg.blocks.insert(1, block1);
        cfg.blocks.insert(2, block2);
        cfg.blocks.insert(3, block3);

        let mut analyzer = ControlFlowAnalyzer::new();
        let structure = analyzer.analyze(&cfg);

        println!("=== If Structure ===");
        let mut printer = ControlStructurePrinter::new();
        println!("{}", printer.print(&structure));

        assert!(matches!(structure, ControlStructure::IfThenElse { .. } | ControlStructure::Sequence(_)));
    }

    #[test]
    fn test_loop_detection() {
        let mut cfg = ControlFlowGraph::new();
        cfg.entry_block = 0;

        // while (block0) { block1 }
        // Block 0 (condition) -> Block 1 (body), Block 2 (exit)
        // Block 1 -> Block 0 (back edge)
        let mut block0 = BasicBlock::new(0, 0);
        block0.successors = vec![1, 2];
        block0.ops.push(PcodeOp::no_output(OpCode::CBranch, vec![], 0));

        let mut block1 = BasicBlock::new(1, 10);
        block1.predecessors = vec![0];
        block1.successors = vec![0]; // back edge

        let mut block2 = BasicBlock::new(2, 20);
        block2.predecessors = vec![0];

        cfg.blocks.insert(0, block0);
        cfg.blocks.insert(1, block1);
        cfg.blocks.insert(2, block2);

        let mut analyzer = ControlFlowAnalyzer::new();
        let structure = analyzer.analyze(&cfg);

        println!("=== Loop Structure ===");
        let mut printer = ControlStructurePrinter::new();
        println!("{}", printer.print(&structure));

        assert!(!analyzer.loops.is_empty());
        println!("Detected {} loops", analyzer.loops.len());
    }
}
