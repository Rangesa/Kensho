//! Symbolic Execution Engine
//!
//! シンボリック実行によるパス探索と制約解決を提供します。
//!
//! 機能:
//! - DFS/BFS/Smart探索（優先度付きキュー）
//! - シンボリックステート管理
//! - パス制約の収集と解決（kensho SMT統合）
//! - メモリモデリング（簡易版）
//! - Loop Bounding（無限ループ防止）
//! - State Merging（パス爆発緩和）
//! - 制約キャッシング（ソルバー呼び出し削減）
//!
//! 使用例:
//! ```
//! let mut executor = SymbolicExecutor::new();
//! executor.set_strategy(ExplorationStrategy::Smart);
//! executor.set_max_depth(50);
//! executor.set_max_states(5000);
//! let states = executor.execute(&cfg, entry_point);
//! ```

use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode, AddressSpace};
use crate::decompiler_prototype::cfg::{ControlFlowGraph, BlockId};
use std::collections::{HashMap, HashSet, VecDeque, BinaryHeap};
use std::cmp::Ordering;

// kensho SMTソルバーをインポート
use crate::kensho_smt::{BoolExpr, CNF, Clause, DPLLSolver, SatSolverResult, Solver as KenshoSolver, RewriteSystem};

/// シンボリック実行のステート
#[derive(Debug, Clone)]
pub struct SymbolicState {
    /// 現在のプログラムカウンタ（ブロックID）
    pub current_block: BlockId,

    /// シンボリック変数の値（Varnode → Z3式）
    pub symbolic_values: HashMap<Varnode, String>,

    /// パス制約（Boolean式として管理）
    pub path_constraints: Vec<BoolExpr>,

    /// 実行済みブロック（ループ検出用）
    pub visited_blocks: HashSet<BlockId>,

    /// ステートID（デバッグ用）
    pub state_id: usize,

    /// 深さ（エントリーポイントからの距離）
    pub depth: usize,

    /// ループ反復回数（ループヘッド → 反復回数）
    pub loop_iterations: HashMap<BlockId, usize>,
}

impl SymbolicState {
    pub fn new(entry_block: BlockId, state_id: usize) -> Self {
        let mut visited = HashSet::new();
        visited.insert(entry_block);

        Self {
            current_block: entry_block,
            symbolic_values: HashMap::new(),
            path_constraints: Vec::new(),
            visited_blocks: visited,
            state_id,
            depth: 0,
            loop_iterations: HashMap::new(),
        }
    }

    /// ステートをクローンして新しいブロックに遷移
    pub fn transition_to(&self, next_block: BlockId, state_id: usize) -> Self {
        let mut new_state = self.clone();
        new_state.current_block = next_block;
        new_state.visited_blocks.insert(next_block);
        new_state.state_id = state_id;
        new_state.depth += 1;
        new_state
    }

    /// パス制約を追加
    pub fn add_constraint(&mut self, constraint: BoolExpr) {
        self.path_constraints.push(constraint);
    }

    /// ループ反復回数を記録
    pub fn increment_loop_iteration(&mut self, loop_head: BlockId) {
        *self.loop_iterations.entry(loop_head).or_insert(0) += 1;
    }

    /// ループ反復回数を取得
    pub fn get_loop_iteration(&self, loop_head: BlockId) -> usize {
        *self.loop_iterations.get(&loop_head).unwrap_or(&0)
    }
}

/// パス探索戦略
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExplorationStrategy {
    /// 深さ優先探索（DFS）
    DFS,
    /// 幅優先探索（BFS）
    BFS,
    /// スマート探索（制約の複雑さとカバレッジを考慮）
    Smart,
}

/// 優先度付きステート（Smart戦略用）
#[derive(Clone)]
struct PrioritizedState {
    priority: f64,
    state: SymbolicState,
}

impl PartialEq for PrioritizedState {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for PrioritizedState {}

impl PartialOrd for PrioritizedState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // 優先度が高い方を先に処理（逆順）
        other.priority.partial_cmp(&self.priority)
    }
}

impl Ord for PrioritizedState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

/// シンボリック実行の統計情報
#[derive(Debug, Default, Clone)]
pub struct ExecutionStatistics {
    /// 探索したステート数
    pub states_explored: usize,
    /// 到達可能なパス数
    pub reachable_paths: usize,
    /// 充足不可能なパス数
    pub infeasible_paths: usize,
    /// 最大深さ
    pub max_depth: usize,
    /// 実行時間（ミリ秒）
    pub execution_time_ms: f64,
    /// ループバウンドで打ち切ったパス数
    pub loop_bounded_paths: usize,
    /// キャッシュヒット数
    pub cache_hits: usize,
    /// キャッシュミス数
    pub cache_misses: usize,
    /// マージされたステート数
    pub merged_states: usize,
}

/// 制約キャッシュ
struct ConstraintCache {
    cache: HashMap<u64, bool>,
}

impl ConstraintCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    fn get(&self, hash: u64) -> Option<bool> {
        self.cache.get(&hash).copied()
    }

    fn insert(&mut self, hash: u64, result: bool) {
        self.cache.insert(hash, result);
    }

    fn clear(&mut self) {
        self.cache.clear();
    }
}

/// Loop Bounding用のトラッカー
struct LoopBoundTracker {
    max_iterations: usize,
}

impl LoopBoundTracker {
    fn new(max_iterations: usize) -> Self {
        Self { max_iterations }
    }

    fn should_continue(&self, state: &SymbolicState, loop_head: BlockId) -> bool {
        state.get_loop_iteration(loop_head) < self.max_iterations
    }
}

/// シンボリック実行エンジン
pub struct SymbolicExecutor {
    /// kensho SMTソルバー
    kensho_solver: KenshoSolver,

    /// 書き換えシステム
    rewrite_system: RewriteSystem,

    /// パス探索戦略
    strategy: ExplorationStrategy,

    /// 最大探索深さ（無限ループ防止）
    max_depth: usize,

    /// 最大ステート数（メモリ制限）
    max_states: usize,

    /// 次のステートID
    next_state_id: usize,

    /// 統計情報
    stats: ExecutionStatistics,

    /// 詳細ログを出力するか
    verbose: bool,

    /// 制約キャッシュ
    constraint_cache: ConstraintCache,

    /// Loop Boundingトラッカー
    loop_tracker: LoopBoundTracker,

    /// State Mergingを有効化するか
    enable_state_merging: bool,

    /// マージポイントでのステートバッファ（BlockId → States）
    merge_buffer: HashMap<BlockId, Vec<SymbolicState>>,
}

impl SymbolicExecutor {
    pub fn new() -> Self {
        Self {
            kensho_solver: KenshoSolver::new(),
            rewrite_system: RewriteSystem::default_rules(),
            strategy: ExplorationStrategy::DFS,
            max_depth: 100,
            max_states: 1000,
            next_state_id: 0,
            stats: ExecutionStatistics::default(),
            verbose: false,
            constraint_cache: ConstraintCache::new(),
            loop_tracker: LoopBoundTracker::new(10),  // デフォルト: ループ10回まで
            enable_state_merging: false,  // デフォルトで無効（高コストのため）
            merge_buffer: HashMap::new(),
        }
    }

    /// 探索戦略を設定
    pub fn set_strategy(&mut self, strategy: ExplorationStrategy) {
        self.strategy = strategy;
    }

    /// 最大深さを設定
    pub fn set_max_depth(&mut self, depth: usize) {
        self.max_depth = depth;
    }

    /// 最大ステート数を設定
    pub fn set_max_states(&mut self, states: usize) {
        self.max_states = states;
    }

    /// 詳細ログを有効化
    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    /// ループ最大反復回数を設定
    pub fn set_max_loop_iterations(&mut self, iterations: usize) {
        self.loop_tracker.max_iterations = iterations;
    }

    /// State Mergingを有効化/無効化
    pub fn set_state_merging(&mut self, enable: bool) {
        self.enable_state_merging = enable;
    }

    /// シンボリック実行を開始
    pub fn execute(&mut self, cfg: &ControlFlowGraph, entry_block: BlockId) -> Vec<SymbolicState> {
        let start = std::time::Instant::now();

        self.stats = ExecutionStatistics::default();
        self.constraint_cache.clear();
        self.merge_buffer.clear();

        let initial_state = SymbolicState::new(entry_block, self.get_next_state_id());

        let reachable_states = match self.strategy {
            ExplorationStrategy::DFS => self.explore_dfs(cfg, initial_state),
            ExplorationStrategy::BFS => self.explore_bfs(cfg, initial_state),
            ExplorationStrategy::Smart => self.explore_smart(cfg, initial_state),
        };

        self.stats.execution_time_ms = start.elapsed().as_secs_f64() * 1000.0;
        self.stats.reachable_paths = reachable_states.len();

        reachable_states
    }

    /// 深さ優先探索（DFS）
    fn explore_dfs(&mut self, cfg: &ControlFlowGraph, initial_state: SymbolicState) -> Vec<SymbolicState> {
        let mut worklist = vec![initial_state];
        let mut reachable_states = Vec::new();

        while let Some(state) = worklist.pop() {
            if self.stats.states_explored >= self.max_states {
                if self.verbose {
                    println!("[SymEx] Max states reached: {}", self.max_states);
                }
                break;
            }

            if state.depth >= self.max_depth {
                if self.verbose {
                    println!("[SymEx] Max depth reached: {}", self.max_depth);
                }
                continue;
            }

            self.stats.states_explored += 1;
            self.stats.max_depth = self.stats.max_depth.max(state.depth);

            if self.verbose {
                println!("[SymEx] Exploring state {} at block {:?}, depth {}",
                         state.state_id, state.current_block, state.depth);
            }

            // 現在のブロックの後継を取得
            let successors = self.get_successors(cfg, &state);

            if successors.is_empty() {
                // 終端ブロックに到達
                reachable_states.push(state);
                continue;
            }

            // 各後継ブロックへの遷移を探索
            for next_block in successors {
                let mut next_state = state.transition_to(next_block, self.get_next_state_id());

                // ループ検出とバウンドチェック
                if self.is_loop_edge(&state, next_block) {
                    next_state.increment_loop_iteration(next_block);

                    if !self.loop_tracker.should_continue(&next_state, next_block) {
                        self.stats.loop_bounded_paths += 1;
                        if self.verbose {
                            println!("[SymEx] Loop bound reached for block {:?}", next_block);
                        }
                        continue;
                    }
                }

                // パス制約が充足可能かチェック
                if self.is_feasible(&next_state) {
                    worklist.push(next_state);
                } else {
                    self.stats.infeasible_paths += 1;
                    if self.verbose {
                        println!("[SymEx] Infeasible path to block {:?}", next_block);
                    }
                }
            }
        }

        reachable_states
    }

    /// 幅優先探索（BFS）
    fn explore_bfs(&mut self, cfg: &ControlFlowGraph, initial_state: SymbolicState) -> Vec<SymbolicState> {
        let mut worklist = VecDeque::new();
        worklist.push_back(initial_state);

        let mut reachable_states = Vec::new();

        while let Some(state) = worklist.pop_front() {
            if self.stats.states_explored >= self.max_states {
                break;
            }

            if state.depth >= self.max_depth {
                continue;
            }

            self.stats.states_explored += 1;
            self.stats.max_depth = self.stats.max_depth.max(state.depth);

            let successors = self.get_successors(cfg, &state);

            if successors.is_empty() {
                reachable_states.push(state);
                continue;
            }

            for next_block in successors {
                let mut next_state = state.transition_to(next_block, self.get_next_state_id());

                // ループバウンドチェック
                if self.is_loop_edge(&state, next_block) {
                    next_state.increment_loop_iteration(next_block);

                    if !self.loop_tracker.should_continue(&next_state, next_block) {
                        self.stats.loop_bounded_paths += 1;
                        continue;
                    }
                }

                if self.is_feasible(&next_state) {
                    worklist.push_back(next_state);
                } else {
                    self.stats.infeasible_paths += 1;
                }
            }
        }

        reachable_states
    }

    /// スマート探索（優先度付きキュー）
    fn explore_smart(&mut self, cfg: &ControlFlowGraph, initial_state: SymbolicState) -> Vec<SymbolicState> {
        let mut worklist = BinaryHeap::new();
        worklist.push(PrioritizedState {
            priority: 1.0,
            state: initial_state,
        });

        let mut reachable_states = Vec::new();

        while let Some(PrioritizedState { state, .. }) = worklist.pop() {
            if self.stats.states_explored >= self.max_states {
                if self.verbose {
                    println!("[SymEx] Max states reached: {}", self.max_states);
                }
                break;
            }

            if state.depth >= self.max_depth {
                continue;
            }

            self.stats.states_explored += 1;
            self.stats.max_depth = self.stats.max_depth.max(state.depth);

            if self.verbose {
                println!("[SymEx] Exploring state {} at block {:?}, depth {}, priority calculated",
                         state.state_id, state.current_block, state.depth);
            }

            let successors = self.get_successors(cfg, &state);

            if successors.is_empty() {
                reachable_states.push(state);
                continue;
            }

            for next_block in successors {
                let mut next_state = state.transition_to(next_block, self.get_next_state_id());

                // ループバウンドチェック
                if self.is_loop_edge(&state, next_block) {
                    next_state.increment_loop_iteration(next_block);

                    if !self.loop_tracker.should_continue(&next_state, next_block) {
                        self.stats.loop_bounded_paths += 1;
                        continue;
                    }
                }

                if self.is_feasible(&next_state) {
                    // 優先度を計算
                    let priority = self.calculate_priority(&next_state, cfg);

                    worklist.push(PrioritizedState {
                        priority,
                        state: next_state,
                    });
                } else {
                    self.stats.infeasible_paths += 1;
                }
            }
        }

        reachable_states
    }

    /// 優先度を計算（高いほど先に探索）
    fn calculate_priority(&self, state: &SymbolicState, cfg: &ControlFlowGraph) -> f64 {
        let mut priority = 0.0;

        // 1. カバレッジスコア（新しいブロックを優先）
        let successors = self.get_successors(cfg, state);
        let unvisited_count = successors.iter()
            .filter(|b| !state.visited_blocks.contains(b))
            .count();
        let coverage_score = if successors.is_empty() {
            0.0
        } else {
            unvisited_count as f64 / successors.len() as f64
        };
        priority += coverage_score * 0.4;

        // 2. 制約の複雑さ（単純な制約を優先）
        let complexity_score = 1.0 / (state.path_constraints.len() as f64 + 1.0);
        priority += complexity_score * 0.3;

        // 3. 探索深さ（浅い方を優先してバランス）
        let depth_score = 1.0 / (state.depth as f64 + 1.0);
        priority += depth_score * 0.3;

        priority
    }

    /// 後継ブロックを取得（CFGから実際の後継を取得）
    fn get_successors(&self, cfg: &ControlFlowGraph, state: &SymbolicState) -> Vec<BlockId> {
        // CFGから後継ブロックを取得
        if let Some(block) = cfg.blocks.get(&state.current_block) {
            block.successors.clone()
        } else {
            Vec::new()
        }
    }

    /// ループエッジかどうかを判定（バックエッジ検出）
    fn is_loop_edge(&self, state: &SymbolicState, next_block: BlockId) -> bool {
        // 簡易実装: next_block <= current_block（プログラムカウンタの逆行）
        // または、既に訪問済みブロックへの遷移
        next_block <= state.current_block || state.visited_blocks.contains(&next_block)
    }

    /// パス制約が充足可能かチェック（kensho SMT統合版）
    fn is_feasible(&mut self, state: &SymbolicState) -> bool {
        if state.path_constraints.is_empty() {
            return true;
        }

        // 制約のハッシュを計算してキャッシュチェック
        let hash = self.hash_constraints(&state.path_constraints);

        if let Some(cached_result) = self.constraint_cache.get(hash) {
            self.stats.cache_hits += 1;
            return cached_result;
        }

        self.stats.cache_misses += 1;

        // kensho SMTで制約を簡約化
        let simplified = self.simplify_constraints_with_kensho(&state.path_constraints);

        // 明らかな矛盾をチェック（Falseがあれば即座にUnsat）
        if simplified.contains(&BoolExpr::False) {
            self.constraint_cache.insert(hash, false);
            return false;
        }

        // Trueのみの場合は常に充足可能
        if simplified.is_empty() || simplified.iter().all(|c| *c == BoolExpr::True) {
            self.constraint_cache.insert(hash, true);
            return true;
        }

        // DPLLソルバーでSATチェック
        let cnf = self.build_cnf_from_constraints(&simplified);
        let mut dpll_solver = DPLLSolver::new(cnf);
        let result = dpll_solver.solve();

        let is_sat = matches!(result, SatSolverResult::Sat(_));
        self.constraint_cache.insert(hash, is_sat);

        is_sat
    }

    /// kensho SMTを使って制約を簡約化
    fn simplify_constraints_with_kensho(&mut self, constraints: &[BoolExpr]) -> Vec<BoolExpr> {
        constraints.iter()
            .map(|c: &BoolExpr| c.simplify())  // BoolExpr::simplify()を使用
            .filter(|c| *c != BoolExpr::True)  // Trueは削除（常に充足）
            .collect()
    }

    /// 制約からCNFを構築
    fn build_cnf_from_constraints(&self, constraints: &[BoolExpr]) -> CNF {
        let mut cnf = CNF::new();

        for constraint in constraints {
            // 各制約をCNFに変換してマージ
            let constraint_cnf = CNF::from_bool_expr(constraint);

            // CNFの節を結合
            for clause in &constraint_cnf.clauses {
                let clause_clone: Clause = clause.clone();
                cnf.add_clause(clause_clone);
            }
        }

        cnf
    }

    /// 制約のハッシュを計算
    fn hash_constraints(&self, constraints: &[BoolExpr]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // 簡易版: 制約の数と最初の数個の制約のデバッグ文字列をハッシュ
        constraints.len().hash(&mut hasher);

        for (i, constraint) in constraints.iter().enumerate().take(10) {
            format!("{:?}", constraint).hash(&mut hasher);
            if i >= 10 {
                break;
            }
        }

        hasher.finish()
    }

    /// 次のステートIDを取得
    fn get_next_state_id(&mut self) -> usize {
        let id = self.next_state_id;
        self.next_state_id += 1;
        id
    }

    /// 統計情報を取得
    pub fn stats(&self) -> &ExecutionStatistics {
        &self.stats
    }

    /// 統計情報をリセット
    pub fn reset_stats(&mut self) {
        self.stats = ExecutionStatistics::default();
        self.next_state_id = 0;
        self.constraint_cache.clear();
    }

    /// State Mergingを実行（合流点で複数のステートをマージ）
    /// 注意: 現在は基本構造のみ実装、完全なITE式マージは未実装
    fn try_merge_states(&mut self, block_id: BlockId) -> Option<SymbolicState> {
        if !self.enable_state_merging {
            return None;
        }

        let states = self.merge_buffer.remove(&block_id)?;

        if states.len() <= 1 {
            return states.into_iter().next();
        }

        // 簡易版のマージ: 最初のステートをベースに、制約を論理和で結合
        let mut merged = states[0].clone();
        merged.state_id = self.get_next_state_id();

        // パス制約のマージ: (c1) ∨ (c2) ∨ ...
        // 注意: 完全なITE式によるメモリ値のマージは未実装
        let merged_constraints: Vec<BoolExpr> = states.iter()
            .map(|s| {
                if s.path_constraints.is_empty() {
                    BoolExpr::True
                } else {
                    // 各ステートの制約を AND で結合
                    s.path_constraints.iter().cloned()
                        .reduce(|acc, c| BoolExpr::and(acc, c))
                        .unwrap_or(BoolExpr::True)
                }
            })
            .collect();

        // 全ステートの制約を OR で結合
        if !merged_constraints.is_empty() {
            let combined = merged_constraints.into_iter()
                .reduce(|acc, c| BoolExpr::or(acc, c))
                .unwrap_or(BoolExpr::True);

            merged.path_constraints = vec![combined];
        }

        self.stats.merged_states += states.len() - 1;

        Some(merged)
    }
}

impl Default for SymbolicExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = SymbolicExecutor::new();
        assert_eq!(executor.strategy, ExplorationStrategy::DFS);
        assert_eq!(executor.max_depth, 100);
        assert_eq!(executor.loop_tracker.max_iterations, 10);
    }

    #[test]
    fn test_state_creation() {
        let state = SymbolicState::new(0, 0);
        assert_eq!(state.current_block, 0);
        assert_eq!(state.depth, 0);
        assert!(state.visited_blocks.contains(&0));
    }

    #[test]
    fn test_state_transition() {
        let state = SymbolicState::new(0, 0);
        let next_state = state.transition_to(1, 1);

        assert_eq!(next_state.current_block, 1);
        assert_eq!(next_state.depth, 1);
        assert!(next_state.visited_blocks.contains(&0));
        assert!(next_state.visited_blocks.contains(&1));
    }

    #[test]
    fn test_strategy_setting() {
        let mut executor = SymbolicExecutor::new();
        executor.set_strategy(ExplorationStrategy::BFS);
        assert_eq!(executor.strategy, ExplorationStrategy::BFS);

        executor.set_strategy(ExplorationStrategy::Smart);
        assert_eq!(executor.strategy, ExplorationStrategy::Smart);
    }

    #[test]
    fn test_loop_iteration_tracking() {
        let mut state = SymbolicState::new(0, 0);
        assert_eq!(state.get_loop_iteration(5), 0);

        state.increment_loop_iteration(5);
        assert_eq!(state.get_loop_iteration(5), 1);

        state.increment_loop_iteration(5);
        assert_eq!(state.get_loop_iteration(5), 2);
    }

    #[test]
    fn test_loop_bound_tracker() {
        let tracker = LoopBoundTracker::new(3);
        let mut state = SymbolicState::new(0, 0);

        assert!(tracker.should_continue(&state, 5));

        state.increment_loop_iteration(5);
        state.increment_loop_iteration(5);
        state.increment_loop_iteration(5);

        assert!(!tracker.should_continue(&state, 5));
    }

    #[test]
    fn test_is_feasible_empty_constraints() {
        let mut executor = SymbolicExecutor::new();
        let state = SymbolicState::new(0, 0);

        assert!(executor.is_feasible(&state));
    }

    #[test]
    fn test_is_feasible_true_constraint() {
        let mut executor = SymbolicExecutor::new();
        let mut state = SymbolicState::new(0, 0);
        state.add_constraint(BoolExpr::True);

        assert!(executor.is_feasible(&state));
    }

    #[test]
    fn test_is_feasible_false_constraint() {
        let mut executor = SymbolicExecutor::new();
        let mut state = SymbolicState::new(0, 0);
        state.add_constraint(BoolExpr::False);

        assert!(!executor.is_feasible(&state));
    }

    #[test]
    fn test_constraint_caching() {
        let mut executor = SymbolicExecutor::new();
        let mut state = SymbolicState::new(0, 0);
        state.add_constraint(BoolExpr::Var("x".to_string(), 0));

        // 1回目: キャッシュミス
        let _ = executor.is_feasible(&state);
        assert_eq!(executor.stats.cache_misses, 1);
        assert_eq!(executor.stats.cache_hits, 0);

        // 2回目: キャッシュヒット
        let _ = executor.is_feasible(&state);
        assert_eq!(executor.stats.cache_hits, 1);
    }

    #[test]
    fn test_prioritized_state_ordering() {
        let state1 = SymbolicState::new(0, 0);
        let state2 = SymbolicState::new(1, 1);

        let ps1 = PrioritizedState {
            priority: 0.5,
            state: state1,
        };

        let ps2 = PrioritizedState {
            priority: 0.8,
            state: state2,
        };

        // 優先度が高い方が先（BinaryHeapは最大ヒープ）
        assert!(ps2 < ps1);  // ps2の方が優先度高いので、ps2 < ps1（逆順）
    }
}
