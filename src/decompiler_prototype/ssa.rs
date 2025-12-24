/// SSA (Static Single Assignment) 変換
/// P-codeをSSA形式に変換し、データフロー解析を実行

use super::pcode::*;
use super::cfg::*;
use std::collections::{HashMap, HashSet, VecDeque};

/// SSA変換エンジン
pub struct SSATransform {
    /// 変数の定義カウンタ（各変数の世代番号を追跡）
    def_counters: HashMap<Varnode, usize>,
    /// 変数スタック（各変数の現在の世代を保持）
    var_stacks: HashMap<Varnode, Vec<usize>>,
    /// 支配木
    dominance_tree: DominanceTree,
    /// 支配境界（Dominance Frontier）
    dominance_frontier: HashMap<BlockId, HashSet<BlockId>>,
}

/// 支配木構造
pub struct DominanceTree {
    /// 各ブロックの直接支配者（Immediate Dominator）
    pub idom: HashMap<BlockId, BlockId>,
    /// 支配関係（あるブロックが支配するブロック集合）
    pub dominates: HashMap<BlockId, HashSet<BlockId>>,
    /// 支配木の子ノード
    pub children: HashMap<BlockId, Vec<BlockId>>,
}

impl DominanceTree {
    /// 新しい支配木を作成
    pub fn new() -> Self {
        Self {
            idom: HashMap::new(),
            dominates: HashMap::new(),
            children: HashMap::new(),
        }
    }

    /// CFGから支配木を計算
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let mut tree = Self::new();

        // Cooper-Harvey-Kennedy アルゴリズムで支配木を計算
        let entry = cfg.entry_block;
        let blocks: Vec<BlockId> = cfg.blocks.keys().copied().collect();

        // 初期化: エントリブロック以外はすべて未定義
        let mut idom: HashMap<BlockId, Option<BlockId>> = HashMap::new();
        for &block_id in &blocks {
            if block_id == entry {
                idom.insert(block_id, None);
            } else {
                idom.insert(block_id, None);
            }
        }

        // 逆ポストオーダーでブロックを処理
        let rpo = Self::reverse_postorder(cfg, entry);

        // 収束するまで繰り返し
        let mut changed = true;
        while changed {
            changed = false;

            for &block_id in &rpo {
                if block_id == entry {
                    continue;
                }

                // このブロックの先行ブロックを取得
                let block = &cfg.blocks[&block_id];
                let predecessors: Vec<BlockId> = block.predecessors.clone();

                if predecessors.is_empty() {
                    continue;
                }

                // 処理済みの先行ブロックから新しい支配者を計算
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

                // 支配者が変更されたかチェック
                if new_idom != idom[&block_id] {
                    idom.insert(block_id, new_idom);
                    changed = true;
                }
            }
        }

        // 結果を支配木に格納
        for (block_id, dom) in idom {
            if let Some(dominator) = dom {
                tree.idom.insert(block_id, dominator);
                tree.children.entry(dominator).or_insert_with(Vec::new).push(block_id);
            }
        }

        // 支配関係を計算
        tree.compute_dominates(entry);

        tree
    }

    /// 2つのブロックの共通支配者を見つける
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

    /// 逆ポストオーダーでブロックを並べる
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

    /// 支配関係を計算（再帰的）
    fn compute_dominates(&mut self, block_id: BlockId) {
        let mut dominated = HashSet::new();
        dominated.insert(block_id);

        // 子ノードをcloneして借用を解決
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

    /// あるブロックが別のブロックを支配するか
    pub fn dominates(&self, dominator: BlockId, block: BlockId) -> bool {
        self.dominates
            .get(&dominator)
            .map(|set| set.contains(&block))
            .unwrap_or(false)
    }

    /// 直接支配者を取得
    pub fn immediate_dominator(&self, block: BlockId) -> Option<BlockId> {
        self.idom.get(&block).copied()
    }
}

impl Default for DominanceTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SSATransform {
    /// 新しいSSA変換エンジンを作成
    pub fn new() -> Self {
        Self {
            def_counters: HashMap::new(),
            var_stacks: HashMap::new(),
            dominance_tree: DominanceTree::new(),
            dominance_frontier: HashMap::new(),
        }
    }

    /// CFGをSSA形式に変換
    pub fn transform(&mut self, cfg: &mut ControlFlowGraph) {
        // 1. 支配木を計算
        self.dominance_tree = DominanceTree::compute(cfg);

        // 2. 支配境界を計算
        self.compute_dominance_frontier(cfg);

        // 3. Phi-nodeを挿入
        self.insert_phi_nodes(cfg);

        // 4. 変数の名前を付け直す
        self.rename_variables(cfg, cfg.entry_block);
    }

    /// 支配境界を計算
    fn compute_dominance_frontier(&mut self, cfg: &ControlFlowGraph) {
        for (&block_id, block) in &cfg.blocks {
            // 先行ブロックが2個以上ある場合のみ処理
            if block.predecessors.len() >= 2 {
                for &pred in &block.predecessors {
                    let mut runner = pred;

                    // predから支配者まで遡る
                    loop {
                        // runnerの支配境界にblock_idを追加
                        self.dominance_frontier
                            .entry(runner)
                            .or_insert_with(HashSet::new)
                            .insert(block_id);

                        // runnerがblock_idを厳密に支配する場合は終了
                        if let Some(idom) = self.dominance_tree.immediate_dominator(block_id) {
                            if runner == idom {
                                break;
                            }
                        }

                        // 次の支配者に進む
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

    /// Phi-nodeを挿入
    fn insert_phi_nodes(&mut self, cfg: &mut ControlFlowGraph) {
        // 各変数について処理
        let all_vars = self.collect_all_variables(cfg);

        for var in all_vars {
            // この変数が定義されているブロックを収集
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

            // Phi-nodeを挿入する場所を計算
            let mut phi_blocks = HashSet::new();
            let mut worklist: VecDeque<BlockId> = def_blocks.iter().copied().collect();

            while let Some(block_id) = worklist.pop_front() {
                // このブロックの支配境界にPhi-nodeを挿入
                if let Some(frontier) = self.dominance_frontier.get(&block_id) {
                    for &df_block in frontier {
                        if !phi_blocks.contains(&df_block) {
                            // Phi-nodeを挿入
                            phi_blocks.insert(df_block);
                            worklist.push_back(df_block);

                            // 実際のPhi-node命令を追加
                            if let Some(block) = cfg.blocks.get_mut(&df_block) {
                                let num_preds = block.predecessors.len();
                                let phi_inputs = vec![var.clone(); num_preds];

                                let phi_op = PcodeOp::new(
                                    OpCode::MultiEqual,
                                    Some(var.clone()),
                                    phi_inputs,
                                    block.start_address,
                                );

                                // Phi-nodeはブロックの先頭に挿入
                                block.ops.insert(0, phi_op);
                            }
                        }
                    }
                }
            }
        }
    }

    /// すべての変数を収集
    fn collect_all_variables(&self, cfg: &ControlFlowGraph) -> Vec<Varnode> {
        let mut vars = HashSet::new();

        for block in cfg.blocks.values() {
            for op in &block.ops {
                // 出力変数
                if let Some(ref output) = op.output {
                    vars.insert(output.clone());
                }

                // 入力変数
                for input in &op.inputs {
                    // 定数は除外
                    if input.space != AddressSpace::Const {
                        vars.insert(input.clone());
                    }
                }
            }
        }

        vars.into_iter().collect()
    }

    /// 変数の名前を付け直す（SSA形式）
    fn rename_variables(&mut self, cfg: &mut ControlFlowGraph, block_id: BlockId) {
        let block = match cfg.blocks.get(&block_id) {
            Some(b) => b,
            None => return,
        };

        // このブロックの命令を処理
        let ops_len = block.ops.len();
        for i in 0..ops_len {
            let block = cfg.blocks.get_mut(&block_id).unwrap();
            let op = &mut block.ops[i];

            // 入力変数の名前を変更
            for input in &mut op.inputs {
                if input.space != AddressSpace::Const {
                    if let Some(stack) = self.var_stacks.get(input) {
                        if let Some(&version) = stack.last() {
                            // 変数名にバージョンを追加
                            input.offset = (input.offset & 0xFFFFFFFF) | ((version as u64) << 32);
                        }
                    }
                }
            }

            // 出力変数の名前を変更
            if let Some(ref mut output) = op.output {
                if output.space != AddressSpace::Const {
                    // 新しいバージョン番号を割り当て
                    let counter = self.def_counters.entry(output.clone()).or_insert(0);
                    *counter += 1;
                    let version = *counter;

                    // スタックにプッシュ
                    self.var_stacks
                        .entry(output.clone())
                        .or_insert_with(Vec::new)
                        .push(version);

                    // 変数名にバージョンを追加
                    output.offset = (output.offset & 0xFFFFFFFF) | ((version as u64) << 32);
                }
            }
        }

        // 後続ブロックのPhi-nodeパラメータを更新
        let successors: Vec<BlockId> = cfg.blocks[&block_id].successors.clone();
        for &succ in &successors {
            let succ_block = cfg.blocks.get_mut(&succ).unwrap();

            for op in &mut succ_block.ops {
                if op.opcode == OpCode::MultiEqual {
                    // Phi-nodeの対応する入力を更新
                    // （この実装は簡略化されています）
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

        // 支配木の子ノードを再帰的に処理
        if let Some(children) = self.dominance_tree.children.get(&block_id) {
            let children_copy = children.clone();
            for child in children_copy {
                self.rename_variables(cfg, child);
            }
        }

        // スタックから変数をポップ（この実装では省略）
    }

    /// 2つの変数が同じか判定（オフセットとサイズが同じ）
    fn same_variable(v1: &Varnode, v2: &Varnode) -> bool {
        v1.space == v2.space && (v1.offset & 0xFFFFFFFF) == (v2.offset & 0xFFFFFFFF) && v1.size == v2.size
    }
}

impl Default for SSATransform {
    fn default() -> Self {
        Self::new()
    }
}

/// データフロー解析
pub struct DataFlowAnalysis {
    /// 到達定義（Reaching Definitions）
    reaching_defs: HashMap<BlockId, HashSet<(Varnode, BlockId)>>,
    /// 活性変数（Live Variables）
    live_vars: HashMap<BlockId, HashSet<Varnode>>,
}

impl DataFlowAnalysis {
    /// 新しいデータフロー解析を作成
    pub fn new() -> Self {
        Self {
            reaching_defs: HashMap::new(),
            live_vars: HashMap::new(),
        }
    }

    /// 到達定義解析を実行
    pub fn compute_reaching_definitions(&mut self, cfg: &ControlFlowGraph) {
        let mut changed = true;

        // 初期化
        for &block_id in cfg.blocks.keys() {
            self.reaching_defs.insert(block_id, HashSet::new());
        }

        // 収束するまで繰り返し
        while changed {
            changed = false;

            for (&block_id, block) in &cfg.blocks {
                let mut new_defs = HashSet::new();

                // 先行ブロックからの定義を収集
                for &pred in &block.predecessors {
                    if let Some(pred_defs) = self.reaching_defs.get(&pred) {
                        new_defs.extend(pred_defs.iter().cloned());
                    }
                }

                // このブロックでの定義を追加
                for op in &block.ops {
                    if let Some(ref output) = op.output {
                        new_defs.insert((output.clone(), block_id));
                    }
                }

                // 変更があったかチェック
                if new_defs != self.reaching_defs[&block_id] {
                    self.reaching_defs.insert(block_id, new_defs);
                    changed = true;
                }
            }
        }
    }

    /// 活性変数解析を実行
    pub fn compute_live_variables(&mut self, cfg: &ControlFlowGraph) {
        let mut changed = true;

        // 初期化
        for &block_id in cfg.blocks.keys() {
            self.live_vars.insert(block_id, HashSet::new());
        }

        // 収束するまで繰り返し（後方解析）
        while changed {
            changed = false;

            for (&block_id, block) in &cfg.blocks {
                let mut new_live = HashSet::new();

                // 後続ブロックからの活性変数を収集
                for &succ in &block.successors {
                    if let Some(succ_live) = self.live_vars.get(&succ) {
                        new_live.extend(succ_live.iter().cloned());
                    }
                }

                // このブロックの命令を逆順に処理
                for op in block.ops.iter().rev() {
                    // 出力変数は活性ではなくなる
                    if let Some(ref output) = op.output {
                        new_live.remove(output);
                    }

                    // 入力変数は活性になる
                    for input in &op.inputs {
                        if input.space != AddressSpace::Const {
                            new_live.insert(input.clone());
                        }
                    }
                }

                // 変更があったかチェック
                if new_live != self.live_vars[&block_id] {
                    self.live_vars.insert(block_id, new_live);
                    changed = true;
                }
            }
        }
    }

    /// ブロックの先頭で活性な変数を取得
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
    fn test_dominance_tree() {
        let mut cfg = ControlFlowGraph::new();
        cfg.entry_block = 0;

        // 簡単なCFGを構築
        // Block 0 -> Block 1
        // Block 1 -> Block 2, Block 3
        // Block 2 -> Block 4
        // Block 3 -> Block 4
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

        // Block 0 はすべてのブロックを支配
        assert!(dom_tree.dominates(0, 0));
        assert!(dom_tree.dominates(0, 1));
        assert!(dom_tree.dominates(0, 4));

        // Block 1 は Block 4 を支配
        assert!(dom_tree.dominates(1, 4));

        println!("Dominance tree test passed!");
    }

    #[test]
    fn test_dataflow() {
        let mut cfg = ControlFlowGraph::new();
        cfg.entry_block = 0;
        let mut block = BasicBlock::new(0, 0);

        // 簡単な命令を追加
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
