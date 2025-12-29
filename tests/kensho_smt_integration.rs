//! Integration tests for kensho SMT solver
//!
//! Tests for MBA deobfuscation, bitmask analysis, and solver functionality

use kensho_mcp::kensho_smt::{BitMask, Expr, Solver};

#[test]
fn test_mba_simplification_xor_add_and() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    // MBA pattern: (x ^ y) + 2 * (x & y) = x + y
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 32), and);
    let mba_expr = Expr::add(xor, mul);

    let simplified = solver.simplify_mba(&mba_expr);
    let expected = Expr::add(x.clone(), y.clone());
    let expected_simplified = solver.simplify(&expected);

    assert_eq!(solver.simplify(&simplified), expected_simplified);
}

#[test]
fn test_mba_simplification_or_add_and() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    // MBA pattern: (x | y) + (x & y) = x + y
    let or = Expr::or(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mba_expr = Expr::add(or, and);

    let simplified = solver.simplify_mba(&mba_expr);
    let expected = Expr::add(x.clone(), y.clone());
    let expected_simplified = solver.simplify(&expected);

    assert_eq!(solver.simplify(&simplified), expected_simplified);
}

#[test]
fn test_mba_simplification_xor_sub_not_and() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    // MBA pattern: (x ^ y) - 2 * (~x & y) = x - y
    let xor = Expr::xor(x.clone(), y.clone());
    let not_x = Expr::not(x.clone());
    let and = Expr::and(not_x, y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 32), and);
    let mba_expr = Expr::sub(xor, mul);

    let simplified = solver.simplify_mba(&mba_expr);
    let expected = Expr::sub(x.clone(), y.clone());
    let expected_simplified = solver.simplify(&expected);

    assert_eq!(solver.simplify(&simplified), expected_simplified);
}

#[test]
fn test_mba_simplification_or_sub() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    // MBA pattern: (x | y) - y = x & ~y
    let or = Expr::or(x.clone(), y.clone());
    let mba_expr = Expr::sub(or, y.clone());

    let simplified = solver.simplify_mba(&mba_expr);
    let expected = Expr::and(x.clone(), Expr::not(y.clone()));
    let expected_simplified = solver.simplify(&expected);

    assert_eq!(solver.simplify(&simplified), expected_simplified);
}

#[test]
fn test_bitmask_constant_propagation() {
    let solver = Solver::new();

    // 0b1100 & 0b1010 = 0b1000
    let x = Expr::const_bv(0b1100, 4);
    let y = Expr::const_bv(0b1010, 4);
    let expr = Expr::and(x, y);

    let bitmask = solver.compute_bitmask(&expr);
    assert!(bitmask.is_constant());
    assert_eq!(bitmask.constant_value(), Some(0b1000));
}

#[test]
fn test_bitmask_or_propagation() {
    let solver = Solver::new();

    // 0b1100 | 0b1010 = 0b1110
    let x = Expr::const_bv(0b1100, 4);
    let y = Expr::const_bv(0b1010, 4);
    let expr = Expr::or(x, y);

    let bitmask = solver.compute_bitmask(&expr);
    assert!(bitmask.is_constant());
    assert_eq!(bitmask.constant_value(), Some(0b1110));
}

#[test]
fn test_bitmask_xor_propagation() {
    let solver = Solver::new();

    // 0b1100 ^ 0b1010 = 0b0110
    let x = Expr::const_bv(0b1100, 4);
    let y = Expr::const_bv(0b1010, 4);
    let expr = Expr::xor(x, y);

    let bitmask = solver.compute_bitmask(&expr);
    assert!(bitmask.is_constant());
    assert_eq!(bitmask.constant_value(), Some(0b0110));
}

#[test]
fn test_bitmask_shl_propagation() {
    let solver = Solver::new();

    // 0b0011 << 2 = 0b1100
    let x = Expr::const_bv(0b0011, 8);
    let shift = Expr::const_bv(2, 8);
    let expr = Expr::shl(x, shift);

    let bitmask = solver.compute_bitmask(&expr);
    assert!(bitmask.is_constant());
    assert_eq!(bitmask.constant_value(), Some(0b1100));
}

#[test]
fn test_nzmask_calculation() {
    let solver = Solver::new();

    // known_zeros = 0b1010, known_ones = 0b0100
    // nzmask = !known_zeros & mask = 0b0101
    let bitmask = BitMask {
        known_zeros: 0b1010,
        known_ones: 0b0100,
        width: 4,
    };

    assert_eq!(bitmask.nzmask(), 0b0101);
}

#[test]
fn test_simplify_full_mba_complex() {
    let solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    // Complex MBA: (x ^ y) + 2 * (x & y) [which equals x + y]
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 32), and);
    let mba_expr = Expr::add(xor, mul);

    // Apply full simplification (MBA + algebraic + bitmask)
    let simplified = solver.simplify_full(&mba_expr);

    // Should be simplified to x + y
    let expected = solver.simplify(&Expr::add(x, y));
    assert_eq!(simplified, expected);
}

#[test]
fn test_simplify_with_bitmask_constant_detection() {
    let solver = Solver::new();

    // Create expression that should be fully constant
    let x = Expr::const_bv(5, 8);
    let y = Expr::const_bv(3, 8);
    let expr = Expr::add(x, y);

    let simplified = solver.simplify_with_bitmask(&expr);

    // Should be simplified to constant 8
    assert_eq!(simplified, Expr::const_bv(8, 8));
}

#[test]
fn test_equivalence_with_mba() {
    let mut solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);

    // Original: x + y
    let original = Expr::add(x.clone(), y.clone());

    // MBA obfuscated: (x ^ y) + 2 * (x & y)
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 32), and);
    let obfuscated = Expr::add(xor, mul);

    // Simplify both
    let orig_simplified = solver.simplify_mba(&original);
    let obf_simplified = solver.simplify_mba(&obfuscated);

    // They should be equivalent after MBA simplification
    assert!(solver.are_equivalent(&orig_simplified, &obf_simplified));
}

#[test]
fn test_complex_nested_mba() {
    let solver = Solver::new();
    let x = Expr::var("x", 32);
    let y = Expr::var("y", 32);
    let z = Expr::var("z", 32);

    // Nested MBA: ((x ^ y) + 2 * (x & y)) + z
    let xor = Expr::xor(x.clone(), y.clone());
    let and = Expr::and(x.clone(), y.clone());
    let mul = Expr::mul(Expr::const_bv(2, 32), and);
    let mba_add = Expr::add(xor, mul);
    let nested = Expr::add(mba_add, z.clone());

    let simplified = solver.simplify_full(&nested);

    // Should simplify to (x + y) + z
    let expected = Expr::add(Expr::add(x, y), z);
    let expected_simplified = solver.simplify(&expected);

    assert_eq!(simplified, expected_simplified);
}

#[test]
fn test_bitmask_unknown_bits() {
    let bitmask = BitMask {
        known_zeros: 0b1010,
        known_ones: 0b0100,
        width: 4,
    };

    // Unknown bits = bits that are neither known_zero nor known_one
    // known_zeros = 0b1010, known_ones = 0b0100
    // unknown = 0b0001
    assert_eq!(bitmask.unknown_bits(), 0b0001);
}

#[test]
fn test_bitmask_min_max_value() {
    let bitmask = BitMask {
        known_zeros: 0b1010,
        known_ones: 0b0100,
        width: 4,
    };

    // min_value = known_ones = 0b0100 = 4
    assert_eq!(bitmask.min_value(), 0b0100);

    // max_value = known_ones | (!known_zeros & mask)
    // = 0b0100 | (0b0101 & 0b1111) = 0b0100 | 0b0101 = 0b0101 = 5
    assert_eq!(bitmask.max_value(), 0b0101);
}
