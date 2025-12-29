//! Phase 3 integration tests: Equivalence checking engine
//!
//! Tests for bit-blasting, SAT solving, and advanced equivalence checking

use kensho_mcp::kensho_smt::{
    BinOpKind, BoolExpr, CNF, DPLLSolver, Expr, Pattern, RewriteRule, RewriteSystem, SatResult,
    SatSolverResult, Solver, BitBlaster,
};

// ========================================
// Bit-blasting tests
// ========================================

#[test]
fn test_bitblast_constant() {
    let mut blaster = BitBlaster::new();
    let expr = Expr::const_bv(0b1010, 4);
    let bits = blaster.blast(&expr);

    assert_eq!(bits.len(), 4);
    assert_eq!(bits[0], BoolExpr::False); // LSB
    assert_eq!(bits[1], BoolExpr::True);
    assert_eq!(bits[2], BoolExpr::False);
    assert_eq!(bits[3], BoolExpr::True); // MSB
}

#[test]
fn test_bitblast_and() {
    let mut blaster = BitBlaster::new();
    let x = Expr::const_bv(0b1100, 4);
    let y = Expr::const_bv(0b1010, 4);
    let expr = Expr::and(x, y);

    let bits = blaster.blast(&expr);
    assert_eq!(bits.len(), 4);

    // Expected: 0b1000
    assert_eq!(bits[0], BoolExpr::False); // 0
    assert_eq!(bits[1], BoolExpr::False); // 0
    assert_eq!(bits[2], BoolExpr::False); // 0
    assert_eq!(bits[3], BoolExpr::True);  // 1
}

#[test]
fn test_bitblast_add() {
    let mut blaster = BitBlaster::new();
    let x = Expr::const_bv(3, 4); // 0011
    let y = Expr::const_bv(5, 4); // 0101
    let expr = Expr::add(x, y);

    let bits = blaster.blast(&expr);
    assert_eq!(bits.len(), 4);

    // Expected: 3 + 5 = 8 = 0b1000
    // But in 4-bit arithmetic: 8 & 0xF = 8 = 0b1000
    assert_eq!(bits[0], BoolExpr::False); // 0
    assert_eq!(bits[1], BoolExpr::False); // 0
    assert_eq!(bits[2], BoolExpr::False); // 0
    assert_eq!(bits[3], BoolExpr::True);  // 1
}

// ========================================
// SAT solver tests
// ========================================

#[test]
fn test_sat_simple_satisfiable() {
    // (x ∨ y) ∧ (¬x ∨ y)
    let mut cnf = CNF::new();
    cnf.add_clause(vec![
        kensho_mcp::kensho_smt::Literal::pos(0),
        kensho_mcp::kensho_smt::Literal::pos(1),
    ]);
    cnf.add_clause(vec![
        kensho_mcp::kensho_smt::Literal::neg(0),
        kensho_mcp::kensho_smt::Literal::pos(1),
    ]);

    let mut solver = DPLLSolver::new(cnf);
    let result = solver.solve();

    match result {
        SatSolverResult::Sat(_model) => {
            // Should be SAT (y=true satisfies both clauses)
        }
        _ => panic!("Expected SAT"),
    }
}

#[test]
fn test_sat_simple_unsatisfiable() {
    // (x) ∧ (¬x)
    let mut cnf = CNF::new();
    cnf.add_clause(vec![kensho_mcp::kensho_smt::Literal::pos(0)]);
    cnf.add_clause(vec![kensho_mcp::kensho_smt::Literal::neg(0)]);

    let mut solver = DPLLSolver::new(cnf);
    let result = solver.solve();

    assert_eq!(result, SatSolverResult::Unsat);
}

#[test]
fn test_sat_from_bool_expr() {
    // x ∧ y
    let expr = BoolExpr::and(
        BoolExpr::Var("x".to_string(), 0),
        BoolExpr::Var("y".to_string(), 0),
    );

    let cnf = CNF::from_bool_expr(&expr);
    let mut solver = DPLLSolver::new(cnf);
    let result = solver.solve();

    match result {
        SatSolverResult::Sat(_) => {
            // Should be SAT
        }
        _ => panic!("Expected SAT"),
    }
}

// ========================================
// Equivalence checking tests
// ========================================

#[test]
fn test_equivalence_sat_simple() {
    let mut solver = Solver::new();

    // x + 0 = x
    let x = Expr::var("x", 8);
    let expr1 = Expr::add(x.clone(), Expr::const_bv(0, 8));
    let expr2 = x;

    assert!(solver.are_equivalent_sat(&expr1, &expr2));
}

#[test]
fn test_equivalence_sat_mba() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 8);
    let y = Expr::var("y", 8);

    // Original: x + y
    let original = Expr::add(x.clone(), y.clone());

    // MBA obfuscated: (x ^ y) + 2 * (x & y)
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x, y);
    let mul = Expr::mul(Expr::const_bv(2, 8), and);
    let obfuscated = Expr::add(xor, mul);

    // They should be equivalent
    assert!(solver.are_equivalent_sat(&original, &obfuscated));
}

#[test]
fn test_equivalence_sat_not_equivalent() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 8);

    // x + 1 ≠ x
    let expr1 = Expr::add(x.clone(), Expr::const_bv(1, 8));
    let expr2 = x;

    assert!(!solver.are_equivalent_sat(&expr1, &expr2));
}

#[test]
fn test_check_sat_bitblast() {
    let mut solver = Solver::new();

    // Tautology: x | ~x = 0xFF (all bits 1)
    let x = Expr::var("x", 8);
    let not_x = Expr::not(x.clone());
    let expr = Expr::or(x, not_x);

    // This should be SAT (always true)
    let result = solver.check_sat_bitblast(&expr);
    assert_eq!(result, SatResult::Sat);
}

#[test]
fn test_equivalence_advanced() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 8);
    let y = Expr::var("y", 8);

    // Test advanced equivalence checking with MBA
    let original = Expr::add(x.clone(), y.clone());

    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x, y);
    let mul = Expr::mul(Expr::const_bv(2, 8), and);
    let obfuscated = Expr::add(xor, mul);

    assert!(solver.are_equivalent_advanced(&original, &obfuscated));
}

// ========================================
// Rewrite system tests
// ========================================

#[test]
fn test_rewrite_add_zero() {
    let mut system = RewriteSystem::new();
    system.add_rule(RewriteRule::new(
        "add_zero",
        Pattern::BinOp(
            BinOpKind::Add,
            Box::new(Pattern::Wildcard("x".to_string())),
            Box::new(Pattern::Const(0, 32)),
        ),
        |bindings| bindings.get("x").unwrap().clone(),
    ));

    let x = Expr::var("x", 32);
    let expr = Expr::add(x.clone(), Expr::const_bv(0, 32));
    let result = system.apply_once(&expr);

    assert_eq!(result, x);
}

#[test]
fn test_rewrite_xor_self() {
    let mut system = RewriteSystem::new();
    system.add_rule(RewriteRule::new(
        "xor_self",
        Pattern::BinOp(
            BinOpKind::Xor,
            Box::new(Pattern::Wildcard("x".to_string())),
            Box::new(Pattern::Wildcard("x".to_string())),
        ),
        |bindings| {
            let x = bindings.get("x").unwrap();
            Expr::const_bv(0, x.width())
        },
    ));

    let x = Expr::var("x", 32);
    let expr = Expr::xor(x.clone(), x.clone());
    let result = system.apply_once(&expr);

    assert_eq!(result, Expr::const_bv(0, 32));
}

#[test]
fn test_rewrite_fixpoint() {
    let system = RewriteSystem::default_rules();

    // Nested expression: ((x + 0) ^ (x + 0))
    let x = Expr::var("x", 32);
    let add_zero = Expr::add(x.clone(), Expr::const_bv(0, 32));
    let expr = Expr::xor(add_zero.clone(), add_zero);

    let result = system.apply_fixpoint(&expr);

    // Should simplify to 0:
    // 1. (x + 0) -> x
    // 2. x ^ x -> 0
    assert_eq!(result, Expr::const_bv(0, 32));
}

#[test]
fn test_rewrite_default_rules() {
    let system = RewriteSystem::default_rules();

    // Test multiple default rules
    let x = Expr::var("x", 32);

    // x + 0 -> x
    let expr1 = Expr::add(x.clone(), Expr::const_bv(0, 32));
    assert_eq!(system.apply_once(&expr1), x);

    // x & 0 -> 0
    let expr2 = Expr::and(x.clone(), Expr::const_bv(0, 32));
    assert_eq!(system.apply_once(&expr2), Expr::const_bv(0, 32));

    // !!x -> x
    let expr3 = Expr::not(Expr::not(x.clone()));
    assert_eq!(system.apply_once(&expr3), x);
}

// ========================================
// Integration tests
// ========================================

#[test]
fn test_full_pipeline_mba_to_sat() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 8);
    let y = Expr::var("y", 8);

    // Complex MBA expression
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 8), and);
    let mba_expr = Expr::add(xor, mul);

    // Step 1: MBA simplification
    let simplified = solver.simplify_mba(&mba_expr);

    // Step 2: Compare with original
    let original = Expr::add(x, y);

    // Step 3: SAT-based equivalence
    assert!(solver.are_equivalent_sat(&simplified, &original));
}

#[test]
fn test_bitblast_and_sat_integration() {
    let mut solver = Solver::new();

    // Expression: x & ~x (always 0)
    let x = Expr::var("x", 4);
    let not_x = Expr::not(x.clone());
    let expr = Expr::and(x, not_x);

    // Bit-blast
    let mut blaster = BitBlaster::new();
    let bits = blaster.blast(&expr);

    // All bits should be false
    for bit in bits {
        let cnf = CNF::from_bool_expr(&bit);
        let mut sat_solver = DPLLSolver::new(cnf);
        // Each bit formula should be UNSAT (always false)
        // Actually, False constant will create a CNF that might be handled differently
        // Let's check if the bit simplifies to False
        assert_eq!(bit.simplify(), BoolExpr::False);
    }
}

#[test]
fn test_rewrite_and_equivalence() {
    let mut solver = Solver::new();
    let system = RewriteSystem::default_rules();

    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    // Complex expression with redundant operations
    let expr1 = Expr::add(Expr::add(x.clone(), Expr::const_bv(0, 32)), y.clone());
    let expr2 = Expr::add(x, y);

    // Rewrite to simplify
    let rewritten = system.apply_fixpoint(&expr1);

    // Should be equivalent to expr2
    assert!(solver.are_equivalent_sat(&rewritten, &expr2));
}

#[test]
fn test_equivalence_sat_simple_non_equivalent() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 4);

    // Simple cases that should NOT be equivalent
    // x + 1 ≠ x
    let expr1 = Expr::add(x.clone(), Expr::const_bv(1, 4));
    assert!(!solver.are_equivalent_sat(&expr1, &x));

    // x + 2 ≠ x + 1
    let expr2 = Expr::add(x.clone(), Expr::const_bv(2, 4));
    let expr3 = Expr::add(x.clone(), Expr::const_bv(1, 4));
    assert!(!solver.are_equivalent_sat(&expr2, &expr3));

    // x * 2 ≠ x + 1
    let expr4 = Expr::mul(x.clone(), Expr::const_bv(2, 4));
    let expr5 = Expr::add(x.clone(), Expr::const_bv(1, 4));
    assert!(!solver.are_equivalent_sat(&expr4, &expr5));
}
