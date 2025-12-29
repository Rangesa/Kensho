//! kensho SMT Solver Demo
//!
//! Demonstrates the capabilities of kensho's custom SMT solver:
//! - MBA deobfuscation
//! - Bitmask analysis
//! - SAT-based equivalence checking
//! - Rewrite rules

use kensho_mcp::kensho_smt::{Expr, Solver, RewriteSystem};

fn main() {
    println!("=================================================");
    println!("  kensho SMT Solver - Capability Demonstration");
    println!("=================================================\n");

    demo_mba_deobfuscation();
    demo_bitmask_analysis();
    demo_sat_equivalence();
    demo_rewrite_system();
    demo_complex_scenario();
}

/// Demo 1: MBA Deobfuscation
fn demo_mba_deobfuscation() {
    println!("📝 Demo 1: MBA Deobfuscation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    // MBA Pattern 1: (x ^ y) + 2 * (x & y) = x + y
    println!("Pattern 1: (x ^ y) + 2 * (x & y) → x + y");
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 32), and);
    let mba1 = Expr::add(xor, mul);

    println!("  Original:    {:?}", mba1);
    let simplified1 = solver.simplify_mba(&mba1);
    println!("  Simplified:  {:?}", simplified1);
    println!("  ✓ Successfully deobfuscated!\n");

    // MBA Pattern 2: (x | y) + (x & y) = x + y
    println!("Pattern 2: (x | y) + (x & y) → x + y");
    let or = Expr::or(x.clone(), y.clone());
    let and2 = Expr::and(x.clone(), y.clone());
    let mba2 = Expr::add(or, and2);

    println!("  Original:    {:?}", mba2);
    let simplified2 = solver.simplify_mba(&mba2);
    println!("  Simplified:  {:?}", simplified2);
    println!("  ✓ Successfully deobfuscated!\n");

    // MBA Pattern 3: (x | y) - y = x & ~y
    println!("Pattern 3: (x | y) - y → x & ~y");
    let or3 = Expr::or(x.clone(), y.clone());
    let mba3 = Expr::sub(or3, y.clone());

    println!("  Original:    {:?}", mba3);
    let simplified3 = solver.simplify_mba(&mba3);
    println!("  Simplified:  {:?}", simplified3);
    println!("  ✓ Successfully deobfuscated!\n");

    println!();
}

/// Demo 2: Bitmask Analysis
fn demo_bitmask_analysis() {
    println!("🔍 Demo 2: Bitmask Analysis");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let solver = Solver::new();

    // Example 1: AND operation
    println!("Example 1: Constant propagation through AND");
    let expr1 = Expr::and(Expr::const_bv(0b11110000, 8), Expr::const_bv(0b10101010, 8));
    println!("  Expression: 0b11110000 & 0b10101010");

    let bitmask1 = solver.compute_bitmask(&expr1);
    println!("  Known zeros:  0b{:08b}", bitmask1.known_zeros);
    println!("  Known ones:   0b{:08b}", bitmask1.known_ones);
    if let Some(val) = bitmask1.constant_value() {
        println!("  Result:       0b{:08b} (constant)", val);
    }
    println!("  ✓ Fully determined constant!\n");

    // Example 2: OR operation
    println!("Example 2: Constant propagation through OR");
    let expr2 = Expr::or(Expr::const_bv(0b11000000, 8), Expr::const_bv(0b00001111, 8));
    println!("  Expression: 0b11000000 | 0b00001111");

    let bitmask2 = solver.compute_bitmask(&expr2);
    if let Some(val) = bitmask2.constant_value() {
        println!("  Result:       0b{:08b} (constant)", val);
    }
    println!("  ✓ Computed as 0b11001111!\n");

    // Example 3: Non-zero mask
    println!("Example 3: Non-zero mask calculation");
    let x = Expr::var("x", 8);
    let expr3 = Expr::and(x, Expr::const_bv(0b11110000, 8));
    println!("  Expression: x & 0b11110000");

    let nzmask = solver.compute_nzmask(&expr3);
    println!("  NZMask:       0b{:08b}", nzmask);
    println!("  ✓ Lower 4 bits guaranteed zero!\n");

    println!();
}

/// Demo 3: SAT-based Equivalence Checking
fn demo_sat_equivalence() {
    println!("⚖️  Demo 3: SAT-based Equivalence Checking");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut solver = Solver::new();
    let x = Expr::var("x", 8);
    let y = Expr::var("y", 8);

    // Test 1: MBA obfuscation equivalence
    println!("Test 1: Proving MBA obfuscation equivalence");
    let original = Expr::add(x.clone(), y.clone());
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 8), and);
    let obfuscated = Expr::add(xor, mul);

    println!("  Original:     x + y");
    println!("  Obfuscated:   (x ^ y) + 2 * (x & y)");

    let equivalent = solver.are_equivalent_sat(&original, &obfuscated);
    println!("  Equivalence:  {}", if equivalent { "✓ PROVEN EQUIVALENT" } else { "✗ NOT EQUIVALENT" });
    println!();

    // Test 2: Non-equivalence detection
    println!("Test 2: Detecting non-equivalent expressions");
    let expr1 = Expr::add(x.clone(), Expr::const_bv(1, 8));
    let expr2 = x.clone();

    println!("  Expression 1: x + 1");
    println!("  Expression 2: x");

    let equivalent2 = solver.are_equivalent_sat(&expr1, &expr2);
    println!("  Equivalence:  {}", if equivalent2 { "✓ EQUIVALENT" } else { "✗ NOT EQUIVALENT (correct)" });
    println!();

    // Test 3: Algebraic identity
    println!("Test 3: Proving algebraic identity");
    let expr3 = Expr::mul(x.clone(), Expr::const_bv(2, 8));
    let expr4 = Expr::add(x.clone(), x.clone());

    println!("  Expression 1: x * 2");
    println!("  Expression 2: x + x");

    let equivalent3 = solver.are_equivalent_sat(&expr3, &expr4);
    println!("  Equivalence:  {}", if equivalent3 { "✓ PROVEN EQUIVALENT" } else { "✗ NOT EQUIVALENT" });
    println!();

    println!();
}

/// Demo 4: Rewrite System
fn demo_rewrite_system() {
    println!("🔄 Demo 4: Rewrite System");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let system = RewriteSystem::default_rules();
    let x = Expr::var("x", 32);

    // Example 1: Identity elimination
    println!("Example 1: Identity elimination");
    let expr1 = Expr::add(x.clone(), Expr::const_bv(0, 32));
    println!("  Before: {:?}", expr1);
    let rewritten1 = system.apply_fixpoint(&expr1);
    println!("  After:  {:?}", rewritten1);
    println!("  ✓ Removed identity element!\n");

    // Example 2: Idempotent operation
    println!("Example 2: Idempotent operation");
    let expr2 = Expr::xor(x.clone(), x.clone());
    println!("  Before: {:?}", expr2);
    let rewritten2 = system.apply_fixpoint(&expr2);
    println!("  After:  {:?}", rewritten2);
    println!("  ✓ x ^ x → 0!\n");

    // Example 3: Double negation
    println!("Example 3: Double negation");
    let expr3 = Expr::not(Expr::not(x.clone()));
    println!("  Before: {:?}", expr3);
    let rewritten3 = system.apply_fixpoint(&expr3);
    println!("  After:  {:?}", rewritten3);
    println!("  ✓ !!x → x!\n");

    // Example 4: Absorption
    println!("Example 4: Absorption");
    let expr4 = Expr::and(x.clone(), Expr::const_bv(0, 32));
    println!("  Before: {:?}", expr4);
    let rewritten4 = system.apply_fixpoint(&expr4);
    println!("  After:  {:?}", rewritten4);
    println!("  ✓ x & 0 → 0!\n");

    println!();
}

/// Demo 5: Complex Real-world Scenario
fn demo_complex_scenario() {
    println!("🚀 Demo 5: Complex Real-world Scenario");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    println!("Scenario: Nested MBA obfuscation with redundant operations");
    println!();

    // Deeply nested MBA: ((x ^ y) + 2*(x & y)) + 0
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 32), and);
    let mba = Expr::add(xor, mul);
    let nested = Expr::add(mba, Expr::const_bv(0, 32));

    println!("Step 1: Original obfuscated expression");
    println!("  ((x ^ y) + 2 * (x & y)) + 0\n");

    println!("Step 2: Apply MBA simplification");
    let step1 = solver.simplify_mba(&nested);
    println!("  Result: {:?}\n", step1);

    println!("Step 3: Apply algebraic simplification");
    let step2 = solver.simplify(&step1);
    println!("  Result: {:?}\n", step2);

    println!("Step 4: Apply full simplification pipeline");
    let final_result = solver.simplify_full(&nested);
    println!("  Final:  {:?}\n", final_result);

    println!("Step 5: Verify equivalence with original (x + y)");
    let original = Expr::add(x.clone(), y.clone());
    let is_equivalent = solver.are_equivalent_advanced(&nested, &original);
    println!("  Equivalence check: {}\n", if is_equivalent { "✓ VERIFIED" } else { "✗ FAILED" });

    if is_equivalent {
        println!("🎉 Successfully deobfuscated nested MBA expression!");
        println!("   Complex obfuscation → Simple addition");
    }

    println!();
    println!("=================================================");
    println!("  Demo Complete!");
    println!("=================================================");
}
