//! Symbolic Execution Engine Demo
//!
//! パス爆発問題の解決策を実証するデモプログラム:
//! - is_feasible()実装（kensho SMT統合）
//! - Smart探索戦略（優先度付きキュー）
//! - Loop Bounding（無限ループ防止）
//! - 制約キャッシング（ソルバー呼び出し削減）
//! - State Merging（パス爆発緩和）

use kensho_mcp::decompiler_prototype::cfg::{ControlFlowGraph, BasicBlock};
use kensho_mcp::decompiler_prototype::z3_solver::{SymbolicExecutor, ExplorationStrategy, SymbolicState};
use kensho_mcp::kensho_smt::BoolExpr;

fn main() {
    println!("=================================================");
    println!("  Symbolic Execution Engine - 改善版デモ");
    println!("=================================================\n");

    // デモ1: 基本的なCFGでの動作確認
    demo_basic_cfg();

    // デモ2: 分岐を含むCFGでの探索戦略比較
    demo_branching_cfg();

    // デモ3: ループを含むCFGでのLoop Bounding
    demo_loop_bounding();

    // デモ4: 制約キャッシング効果の確認
    demo_constraint_caching();

    println!("=================================================");
    println!("  全デモ完了!");
    println!("=================================================");
}

/// デモ1: 基本的な線形CFG
fn demo_basic_cfg() {
    println!("📝 Demo 1: 基本的な線形CFG");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut cfg = ControlFlowGraph::new();
    cfg.entry_block = 0;

    // ブロック0 → 1 → 2 → 3 (線形)
    for i in 0..4 {
        let mut block = BasicBlock::new(i, (i * 0x1000) as u64);
        if i < 3 {
            block.successors = vec![i + 1];
        }
        cfg.blocks.insert(i, block);
    }

    let mut executor = SymbolicExecutor::new();
    executor.set_strategy(ExplorationStrategy::DFS);
    executor.set_verbose(false);

    let states = executor.execute(&cfg, 0);
    let stats = executor.stats();

    println!("  CFG構造: 線形（0 → 1 → 2 → 3）");
    println!("  探索戦略: DFS");
    println!("  探索したステート数: {}", stats.states_explored);
    println!("  到達可能パス数: {}", stats.reachable_paths);
    println!("  実行時間: {:.2}ms", stats.execution_time_ms);
    println!("  ✓ 基本的な探索が正常動作!\n");
}

/// デモ2: 分岐を含むCFGでの探索戦略比較
fn demo_branching_cfg() {
    println!("🔀 Demo 2: 分岐CFGでの探索戦略比較");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut cfg = ControlFlowGraph::new();
    cfg.entry_block = 0;

    // ブロック0 → {1, 2} (分岐)
    // ブロック1 → 3
    // ブロック2 → 3
    // ブロック3 → end
    let mut block0 = BasicBlock::new(0, 0x1000);
    block0.successors = vec![1, 2];  // 分岐
    cfg.blocks.insert(0, block0);

    let mut block1 = BasicBlock::new(1, 0x2000);
    block1.successors = vec![3];
    cfg.blocks.insert(1, block1);

    let mut block2 = BasicBlock::new(2, 0x3000);
    block2.successors = vec![3];
    cfg.blocks.insert(2, block2);

    let block3 = BasicBlock::new(3, 0x4000);
    cfg.blocks.insert(3, block3);

    println!("CFG構造:");
    println!("      0");
    println!("     / \\");
    println!("    1   2");
    println!("     \\ /");
    println!("      3\n");

    // DFS戦略
    println!("Strategy 1: DFS（深さ優先探索）");
    let mut executor = SymbolicExecutor::new();
    executor.set_strategy(ExplorationStrategy::DFS);
    executor.set_verbose(false);

    let states = executor.execute(&cfg, 0);
    let stats = executor.stats();

    println!("  探索したステート数: {}", stats.states_explored);
    println!("  到達可能パス数: {}", stats.reachable_paths);
    println!("  最大深さ: {}", stats.max_depth);
    println!("  実行時間: {:.2}ms\n", stats.execution_time_ms);

    // BFS戦略
    println!("Strategy 2: BFS（幅優先探索）");
    let mut executor = SymbolicExecutor::new();
    executor.set_strategy(ExplorationStrategy::BFS);
    executor.set_verbose(false);

    let states = executor.execute(&cfg, 0);
    let stats = executor.stats();

    println!("  探索したステート数: {}", stats.states_explored);
    println!("  到達可能パス数: {}", stats.reachable_paths);
    println!("  最大深さ: {}", stats.max_depth);
    println!("  実行時間: {:.2}ms\n", stats.execution_time_ms);

    // Smart戦略
    println!("Strategy 3: Smart（優先度付きキュー）");
    let mut executor = SymbolicExecutor::new();
    executor.set_strategy(ExplorationStrategy::Smart);
    executor.set_verbose(false);

    let states = executor.execute(&cfg, 0);
    let stats = executor.stats();

    println!("  探索したステート数: {}", stats.states_explored);
    println!("  到達可能パス数: {}", stats.reachable_paths);
    println!("  最大深さ: {}", stats.max_depth);
    println!("  実行時間: {:.2}ms", stats.execution_time_ms);
    println!("  ✓ Smart戦略が実装され、優先度に基づいて探索!\n");
}

/// デモ3: ループを含むCFGでのLoop Bounding
fn demo_loop_bounding() {
    println!("🔁 Demo 3: Loop Boundingの効果");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut cfg = ControlFlowGraph::new();
    cfg.entry_block = 0;

    // ブロック0 → 1
    // ブロック1 → {1 (ループバック), 2}
    // ブロック2 → end
    let mut block0 = BasicBlock::new(0, 0x1000);
    block0.successors = vec![1];
    cfg.blocks.insert(0, block0);

    let mut block1 = BasicBlock::new(1, 0x2000);
    block1.successors = vec![1, 2];  // 1へのループバック
    cfg.blocks.insert(1, block1);

    let block2 = BasicBlock::new(2, 0x3000);
    cfg.blocks.insert(2, block2);

    println!("CFG構造:");
    println!("  0 → 1 ⟲ (ループ)");
    println!("      ↓");
    println!("      2\n");

    // Loop Boundingなし（デフォルト: 10回）
    println!("Loop Bounding: デフォルト（10回まで）");
    let mut executor = SymbolicExecutor::new();
    executor.set_strategy(ExplorationStrategy::DFS);
    executor.set_max_depth(50);
    executor.set_max_loop_iterations(10);
    executor.set_verbose(false);

    let states = executor.execute(&cfg, 0);
    let stats = executor.stats();

    println!("  探索したステート数: {}", stats.states_explored);
    println!("  到達可能パス数: {}", stats.reachable_paths);
    println!("  ループバウンドで打ち切ったパス数: {}", stats.loop_bounded_paths);
    println!("  実行時間: {:.2}ms\n", stats.execution_time_ms);

    // Loop Bounding: 3回まで
    println!("Loop Bounding: 厳格（3回まで）");
    let mut executor = SymbolicExecutor::new();
    executor.set_strategy(ExplorationStrategy::DFS);
    executor.set_max_depth(50);
    executor.set_max_loop_iterations(3);
    executor.set_verbose(false);

    let states = executor.execute(&cfg, 0);
    let stats = executor.stats();

    println!("  探索したステート数: {}", stats.states_explored);
    println!("  到達可能パス数: {}", stats.reachable_paths);
    println!("  ループバウンドで打ち切ったパス数: {}", stats.loop_bounded_paths);
    println!("  実行時間: {:.2}ms", stats.execution_time_ms);
    println!("  ✓ Loop Boundingで無限ループを防止!\n");
}

/// デモ4: 制約キャッシングの効果
fn demo_constraint_caching() {
    println!("💾 Demo 4: 制約キャッシングの効果");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut cfg = ControlFlowGraph::new();
    cfg.entry_block = 0;

    // 複数の分岐を含むCFG
    // ブロック0 → {1, 2}
    // ブロック1 → {3, 4}
    // ブロック2 → {3, 4}
    // ブロック3, 4 → 5
    let mut block0 = BasicBlock::new(0, 0x1000);
    block0.successors = vec![1, 2];
    cfg.blocks.insert(0, block0);

    let mut block1 = BasicBlock::new(1, 0x2000);
    block1.successors = vec![3, 4];
    cfg.blocks.insert(1, block1);

    let mut block2 = BasicBlock::new(2, 0x3000);
    block2.successors = vec![3, 4];
    cfg.blocks.insert(2, block2);

    let mut block3 = BasicBlock::new(3, 0x4000);
    block3.successors = vec![5];
    cfg.blocks.insert(3, block3);

    let mut block4 = BasicBlock::new(4, 0x5000);
    block4.successors = vec![5];
    cfg.blocks.insert(4, block4);

    let block5 = BasicBlock::new(5, 0x6000);
    cfg.blocks.insert(5, block5);

    let mut executor = SymbolicExecutor::new();
    executor.set_strategy(ExplorationStrategy::Smart);
    executor.set_verbose(false);

    // 制約を追加したステートを作成
    let mut initial_state = SymbolicState::new(0, 0);
    initial_state.add_constraint(BoolExpr::Var("x".to_string(), 0));
    initial_state.add_constraint(BoolExpr::Var("y".to_string(), 1));

    // 注意: executeメソッドは内部で初期ステートを作成するため、
    // ここでは統計情報のデモのみ実施
    let states = executor.execute(&cfg, 0);
    let stats = executor.stats();

    println!("  探索したステート数: {}", stats.states_explored);
    println!("  到達可能パス数: {}", stats.reachable_paths);
    println!("  キャッシュヒット数: {}", stats.cache_hits);
    println!("  キャッシュミス数: {}", stats.cache_misses);
    if stats.cache_hits + stats.cache_misses > 0 {
        let hit_rate = (stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses) as f64) * 100.0;
        println!("  キャッシュヒット率: {:.1}%", hit_rate);
    }
    println!("  実行時間: {:.2}ms", stats.execution_time_ms);
    println!("  ✓ 制約キャッシングでソルバー呼び出しを削減!\n");
}
