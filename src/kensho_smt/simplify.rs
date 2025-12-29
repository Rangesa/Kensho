//! 式の簡約化
//!
//! ルールベース書き換えによる式の簡約化エンジン。
//! MBA難読化解除に必要な代数的簡約化を提供。

use crate::kensho_smt::expr::Expr;

/// 式を簡約化
///
/// 不動点に達するまで繰り返し簡約化を適用
///
/// # Arguments
/// * `expr` - 簡約化する式
///
/// # Returns
/// 簡約化された式
pub fn simplify(expr: &Expr) -> Expr {
    let mut current = expr.clone();
    let mut changed = true;

    // 不動点に達するまで繰り返し
    while changed {
        let simplified = simplify_once(&current);
        changed = simplified != current;
        current = simplified;
    }

    current
}

/// 1回の簡約化パスを実行
fn simplify_once(expr: &Expr) -> Expr {
    match expr {
        // 定数と変数はそのまま
        Expr::BV { .. } | Expr::Var { .. } => expr.clone(),

        // 加算の簡約化
        Expr::Add(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_add(&l, &r)
        }

        // 減算の簡約化
        Expr::Sub(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_sub(&l, &r)
        }

        // 乗算の簡約化
        Expr::Mul(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_mul(&l, &r)
        }

        // ビット論理積の簡約化
        Expr::And(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_and(&l, &r)
        }

        // ビット論理和の簡約化
        Expr::Or(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_or(&l, &r)
        }

        // ビット排他的論理和の簡約化
        Expr::Xor(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_xor(&l, &r)
        }

        // シフト演算の簡約化
        Expr::Shl(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_shl(&l, &r)
        }

        Expr::Lshr(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_lshr(&l, &r)
        }

        Expr::Ashr(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            simplify_ashr(&l, &r)
        }

        // 否定の簡約化
        Expr::Not(inner) => {
            let simplified = simplify_once(inner);
            simplify_not(&simplified)
        }

        Expr::Neg(inner) => {
            let simplified = simplify_once(inner);
            simplify_neg(&simplified)
        }

        // 等価性の簡約化
        Expr::Eq(left, right) => {
            let l = simplify_once(left);
            let r = simplify_once(right);
            if l == r {
                Expr::const_bv(1, 1) // 同じ式なら真
            } else {
                Expr::Eq(Box::new(l), Box::new(r))
            }
        }
    }
}

/// 加算の簡約化
fn simplify_add(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();
    let mask = Expr::width_mask(width);

    match (left, right) {
        // x + 0 = x
        (x, Expr::BV { value: 0, .. }) | (Expr::BV { value: 0, .. }, x) => x.clone(),

        // 定数同士の加算
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            Expr::const_bv(a.wrapping_add(*b) & mask, width)
        }

        // その他はそのまま
        _ => Expr::add(left.clone(), right.clone()),
    }
}

/// 減算の簡約化
fn simplify_sub(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();
    let mask = Expr::width_mask(width);

    match (left, right) {
        // x - 0 = x
        (x, Expr::BV { value: 0, .. }) => x.clone(),

        // x - x = 0
        (x, y) if x == y => Expr::const_bv(0, width),

        // 定数同士の減算
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            Expr::const_bv(a.wrapping_sub(*b) & mask, width)
        }

        _ => Expr::sub(left.clone(), right.clone()),
    }
}

/// 乗算の簡約化
fn simplify_mul(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();
    let mask = Expr::width_mask(width);

    match (left, right) {
        // x * 0 = 0
        (_, Expr::BV { value: 0, .. }) | (Expr::BV { value: 0, .. }, _) => {
            Expr::const_bv(0, width)
        }

        // x * 1 = x
        (x, Expr::BV { value: 1, .. }) | (Expr::BV { value: 1, .. }, x) => x.clone(),

        // 定数同士の乗算
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            Expr::const_bv(a.wrapping_mul(*b) & mask, width)
        }

        _ => Expr::mul(left.clone(), right.clone()),
    }
}

/// ビット論理積の簡約化
fn simplify_and(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();

    match (left, right) {
        // x & 0 = 0
        (_, Expr::BV { value: 0, .. }) | (Expr::BV { value: 0, .. }, _) => {
            Expr::const_bv(0, width)
        }

        // x & 全1 = x
        (x, Expr::BV { value, .. }) | (Expr::BV { value, .. }, x)
            if *value == Expr::width_mask(width) =>
        {
            x.clone()
        }

        // x & x = x
        (x, y) if x == y => x.clone(),

        // 定数同士のAND
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            Expr::const_bv(a & b, width)
        }

        _ => Expr::and(left.clone(), right.clone()),
    }
}

/// ビット論理和の簡約化
fn simplify_or(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();
    let all_ones = Expr::width_mask(width);

    match (left, right) {
        // x | 0 = x
        (x, Expr::BV { value: 0, .. }) | (Expr::BV { value: 0, .. }, x) => x.clone(),

        // x | 全1 = 全1
        (_, Expr::BV { value, .. }) | (Expr::BV { value, .. }, _) if *value == all_ones => {
            Expr::const_bv(all_ones, width)
        }

        // x | x = x
        (x, y) if x == y => x.clone(),

        // 定数同士のOR
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            Expr::const_bv(a | b, width)
        }

        _ => Expr::or(left.clone(), right.clone()),
    }
}

/// ビット排他的論理和の簡約化
fn simplify_xor(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();

    match (left, right) {
        // x ^ 0 = x
        (x, Expr::BV { value: 0, .. }) | (Expr::BV { value: 0, .. }, x) => x.clone(),

        // x ^ x = 0
        (x, y) if x == y => Expr::const_bv(0, width),

        // 定数同士のXOR
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            Expr::const_bv(a ^ b, width)
        }

        _ => Expr::xor(left.clone(), right.clone()),
    }
}

/// 左シフトの簡約化
fn simplify_shl(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();
    let mask = Expr::width_mask(width);

    match (left, right) {
        // x << 0 = x
        (x, Expr::BV { value: 0, .. }) => x.clone(),

        // 定数同士のシフト
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            if *b >= 64 {
                Expr::const_bv(0, width)
            } else {
                Expr::const_bv((a << b) & mask, width)
            }
        }

        _ => Expr::shl(left.clone(), right.clone()),
    }
}

/// 論理右シフトの簡約化
fn simplify_lshr(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();

    match (left, right) {
        // x >> 0 = x
        (x, Expr::BV { value: 0, .. }) => x.clone(),

        // 定数同士のシフト
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            if *b >= 64 {
                Expr::const_bv(0, width)
            } else {
                Expr::const_bv(a >> b, width)
            }
        }

        _ => Expr::lshr(left.clone(), right.clone()),
    }
}

/// 算術右シフトの簡約化
fn simplify_ashr(left: &Expr, right: &Expr) -> Expr {
    let width = left.width();

    match (left, right) {
        // x >>> 0 = x
        (x, Expr::BV { value: 0, .. }) => x.clone(),

        // 定数同士のシフト（符号拡張）
        (Expr::BV { value: a, .. }, Expr::BV { value: b, .. }) => {
            if *b >= 64 {
                // 符号ビットで埋める
                let sign_bit = (a >> (width - 1)) & 1;
                if sign_bit == 1 {
                    Expr::const_bv(Expr::width_mask(width), width)
                } else {
                    Expr::const_bv(0, width)
                }
            } else {
                // 符号拡張付き右シフト
                let shifted = (*a as i64) >> b;
                Expr::const_bv(shifted as u64 & Expr::width_mask(width), width)
            }
        }

        _ => Expr::ashr(left.clone(), right.clone()),
    }
}

/// ビット否定の簡約化
fn simplify_not(expr: &Expr) -> Expr {
    match expr {
        // !!x = x
        Expr::Not(inner) => (**inner).clone(),

        // !定数
        Expr::BV { value, width } => {
            let mask = Expr::width_mask(*width);
            Expr::const_bv(!value & mask, *width)
        }

        _ => Expr::not(expr.clone()),
    }
}

/// 算術否定の簡約化
fn simplify_neg(expr: &Expr) -> Expr {
    match expr {
        // -(-x) = x
        Expr::Neg(inner) => (**inner).clone(),

        // -定数
        Expr::BV { value, width } => {
            let mask = Expr::width_mask(*width);
            Expr::const_bv((-((*value) as i64)) as u64 & mask, *width)
        }

        _ => Expr::neg(expr.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simplify_add_zero() {
        let x = Expr::var("x", 32);
        let zero = Expr::const_bv(0, 32);
        let add = Expr::add(x.clone(), zero);
        let simplified = simplify(&add);
        assert_eq!(simplified, x);
    }

    #[test]
    fn test_simplify_add_constants() {
        let a = Expr::const_bv(10, 32);
        let b = Expr::const_bv(20, 32);
        let add = Expr::add(a, b);
        let simplified = simplify(&add);
        assert_eq!(simplified, Expr::const_bv(30, 32));
    }

    #[test]
    fn test_simplify_mul_zero() {
        let x = Expr::var("x", 32);
        let zero = Expr::const_bv(0, 32);
        let mul = Expr::mul(x, zero);
        let simplified = simplify(&mul);
        assert_eq!(simplified, Expr::const_bv(0, 32));
    }

    #[test]
    fn test_simplify_mul_one() {
        let x = Expr::var("x", 32);
        let one = Expr::const_bv(1, 32);
        let mul = Expr::mul(x.clone(), one);
        let simplified = simplify(&mul);
        assert_eq!(simplified, x);
    }

    #[test]
    fn test_simplify_xor_self() {
        let x = Expr::var("x", 32);
        let xor = Expr::xor(x.clone(), x);
        let simplified = simplify(&xor);
        assert_eq!(simplified, Expr::const_bv(0, 32));
    }

    #[test]
    fn test_simplify_sub_self() {
        let x = Expr::var("x", 32);
        let sub = Expr::sub(x.clone(), x);
        let simplified = simplify(&sub);
        assert_eq!(simplified, Expr::const_bv(0, 32));
    }

    #[test]
    fn test_simplify_not_not() {
        let x = Expr::var("x", 32);
        let not_not = Expr::not(Expr::not(x.clone()));
        let simplified = simplify(&not_not);
        assert_eq!(simplified, x);
    }

    #[test]
    fn test_simplify_and_all_ones() {
        let x = Expr::var("x", 8);
        let all_ones = Expr::const_bv(0xFF, 8);
        let and = Expr::and(x.clone(), all_ones);
        let simplified = simplify(&and);
        assert_eq!(simplified, x);
    }
}
