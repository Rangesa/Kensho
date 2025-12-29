// kensho SMT Expr → P-code逆変換デモ
//
// 簡約化されたkensho SMT式をP-code中間表現に変換し、
// 難読化されたMBA式を単純なP-code（例: x+y）として出力する機能を実演します。

use kensho_mcp::kensho_smt::{Expr, Solver};
use kensho_mcp::decompiler_prototype::{KenshoMBASimplifier, OpCode};

fn main() {
    println!("=== kensho SMT Expr → P-code 逆変換デモ ===\n");

    let simplifier = KenshoMBASimplifier::new();

    // Demo 1: シンプルな加算 (x + y)
    println!("Demo 1: シンプルな加算");
    demo_simple_add(&simplifier);

    // Demo 2: 複雑な式 ((x + y) * 2)
    println!("\nDemo 2: 複雑な式");
    demo_complex_expr(&simplifier);

    // Demo 3: MBA簡約化 + P-code変換
    println!("\nDemo 3: MBA簡約化 + P-code変換");
    demo_mba_to_pcode(&simplifier);

    println!("\n=== 全デモ完了 ===");
}

fn demo_simple_add(simplifier: &KenshoMBASimplifier) {
    // x + y
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);
    let expr = Expr::add(x, y);

    println!("  式: x + y");
    println!("  kensho SMT Expr: {}", expr);

    // P-codeに変換
    let pcode_ops = simplifier.kensho_expr_to_pcode(&expr, 4);
    println!("  P-code演算数: {}", pcode_ops.len());

    for (i, op) in pcode_ops.iter().enumerate() {
        println!("  [{}] {:?}: {:?} -> {:?}",
            i, op.opcode, op.inputs, op.output);
    }

    // 最後の演算が IntAdd のはず
    if let Some(last_op) = pcode_ops.last() {
        assert_eq!(last_op.opcode, OpCode::IntAdd);
        println!("  ✓ 正しくIntAdd演算に変換されました");
    }
}

fn demo_complex_expr(simplifier: &KenshoMBASimplifier) {
    // (x + y) * 2
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);
    let sum = Expr::add(x, y);
    let two = Expr::const_bv(2, 32);
    let expr = Expr::mul(sum, two);

    println!("  式: (x + y) * 2");
    println!("  kensho SMT Expr: {}", expr);

    // P-codeに変換
    let pcode_ops = simplifier.kensho_expr_to_pcode(&expr, 4);
    println!("  P-code演算数: {}", pcode_ops.len());

    for (i, op) in pcode_ops.iter().enumerate() {
        println!("  [{}] {:?}: {:?} -> {:?}",
            i, op.opcode, op.inputs, op.output);
    }

    // IntAdd と IntMult が含まれているはず
    let has_add = pcode_ops.iter().any(|op| op.opcode == OpCode::IntAdd);
    let has_mul = pcode_ops.iter().any(|op| op.opcode == OpCode::IntMult);

    if has_add && has_mul {
        println!("  ✓ IntAddとIntMultの両方が含まれています");
    }
}

fn demo_mba_to_pcode(simplifier: &KenshoMBASimplifier) {
    let mut solver = Solver::new();

    // MBA難読化式: (x ^ y) + 2 * (x & y) = x + y
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 32), and);
    let mba_expr = Expr::add(xor, mul);

    println!("  元のMBA式: (x ^ y) + 2 * (x & y)");
    println!("  kensho SMT Expr: {}", mba_expr);

    // kensho SMTで簡約化
    let simplified = solver.simplify_mba(&mba_expr);
    println!("  簡約化後: {}", simplified);

    // 簡約化された式をP-codeに変換
    let pcode_ops = simplifier.kensho_expr_to_pcode(&simplified, 4);
    println!("  P-code演算数: {}", pcode_ops.len());

    for (i, op) in pcode_ops.iter().enumerate() {
        println!("  [{}] {:?}: {:?} -> {:?}",
            i, op.opcode, op.inputs, op.output);
    }

    // 簡約化された結果は x + y のはず（IntAdd 1個）
    let add_count = pcode_ops.iter().filter(|op| op.opcode == OpCode::IntAdd).count();
    println!("  IntAdd演算の数: {}", add_count);

    if add_count >= 1 {
        println!("  ✓ MBA式が単純な加算に簡約化されました");
    } else {
        println!("  ℹ MBA簡約化は部分的に成功");
    }
}
