//! ビットベクトル式の表現
//!
//! kensho SMTソルバーの中核となる式表現。
//! MBA難読化解除とP-code等価性チェックに特化。

use std::fmt;
use std::hash::Hash;

/// ビットベクトル式
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    /// 定数ビットベクトル
    /// value: ビット値、width: ビット幅
    BV { value: u64, width: u32 },

    /// 変数
    /// name: 変数名、width: ビット幅
    Var { name: String, width: u32 },

    /// 加算: left + right
    Add(Box<Expr>, Box<Expr>),

    /// 減算: left - right
    Sub(Box<Expr>, Box<Expr>),

    /// 乗算: left * right
    Mul(Box<Expr>, Box<Expr>),

    /// ビット論理積: left & right
    And(Box<Expr>, Box<Expr>),

    /// ビット論理和: left | right
    Or(Box<Expr>, Box<Expr>),

    /// ビット排他的論理和: left ^ right
    Xor(Box<Expr>, Box<Expr>),

    /// 左シフト: left << right
    Shl(Box<Expr>, Box<Expr>),

    /// 論理右シフト: left >> right (符号なし)
    Lshr(Box<Expr>, Box<Expr>),

    /// 算術右シフト: left >> right (符号あり)
    Ashr(Box<Expr>, Box<Expr>),

    /// ビット否定: !expr
    Not(Box<Expr>),

    /// 算術否定: -expr
    Neg(Box<Expr>),

    /// 等価性: left == right
    Eq(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// 定数ビットベクトルを作成
    pub fn const_bv(value: u64, width: u32) -> Self {
        Expr::BV { value, width }
    }

    /// 変数を作成
    pub fn var(name: impl Into<String>, width: u32) -> Self {
        Expr::Var {
            name: name.into(),
            width,
        }
    }

    /// 式のビット幅を取得
    pub fn width(&self) -> u32 {
        match self {
            Expr::BV { width, .. } => *width,
            Expr::Var { width, .. } => *width,
            Expr::Add(left, _) => left.width(),
            Expr::Sub(left, _) => left.width(),
            Expr::Mul(left, _) => left.width(),
            Expr::And(left, _) => left.width(),
            Expr::Or(left, _) => left.width(),
            Expr::Xor(left, _) => left.width(),
            Expr::Shl(left, _) => left.width(),
            Expr::Lshr(left, _) => left.width(),
            Expr::Ashr(left, _) => left.width(),
            Expr::Not(expr) => expr.width(),
            Expr::Neg(expr) => expr.width(),
            Expr::Eq(_, _) => 1, // 等価性チェックの結果は1ビット
        }
    }

    /// 式が定数か判定
    pub fn is_const(&self) -> bool {
        matches!(self, Expr::BV { .. })
    }

    /// 定数値を取得（定数の場合のみ）
    pub fn const_value(&self) -> Option<u64> {
        match self {
            Expr::BV { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// ビット幅に応じたマスクを取得
    pub fn width_mask(width: u32) -> u64 {
        if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        }
    }

    /// 加算式を作成
    pub fn add(left: Expr, right: Expr) -> Self {
        Expr::Add(Box::new(left), Box::new(right))
    }

    /// 減算式を作成
    pub fn sub(left: Expr, right: Expr) -> Self {
        Expr::Sub(Box::new(left), Box::new(right))
    }

    /// 乗算式を作成
    pub fn mul(left: Expr, right: Expr) -> Self {
        Expr::Mul(Box::new(left), Box::new(right))
    }

    /// ビット論理積式を作成
    pub fn and(left: Expr, right: Expr) -> Self {
        Expr::And(Box::new(left), Box::new(right))
    }

    /// ビット論理和式を作成
    pub fn or(left: Expr, right: Expr) -> Self {
        Expr::Or(Box::new(left), Box::new(right))
    }

    /// ビット排他的論理和式を作成
    pub fn xor(left: Expr, right: Expr) -> Self {
        Expr::Xor(Box::new(left), Box::new(right))
    }

    /// 左シフト式を作成
    pub fn shl(left: Expr, right: Expr) -> Self {
        Expr::Shl(Box::new(left), Box::new(right))
    }

    /// 論理右シフト式を作成
    pub fn lshr(left: Expr, right: Expr) -> Self {
        Expr::Lshr(Box::new(left), Box::new(right))
    }

    /// 算術右シフト式を作成
    pub fn ashr(left: Expr, right: Expr) -> Self {
        Expr::Ashr(Box::new(left), Box::new(right))
    }

    /// ビット否定式を作成
    pub fn not(expr: Expr) -> Self {
        Expr::Not(Box::new(expr))
    }

    /// 算術否定式を作成
    pub fn neg(expr: Expr) -> Self {
        Expr::Neg(Box::new(expr))
    }

    /// 等価性式を作成
    pub fn eq(left: Expr, right: Expr) -> Self {
        Expr::Eq(Box::new(left), Box::new(right))
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::BV { value, width } => write!(f, "0x{:x}:{}", value, width),
            Expr::Var { name, width } => write!(f, "{}:{}", name, width),
            Expr::Add(left, right) => write!(f, "({} + {})", left, right),
            Expr::Sub(left, right) => write!(f, "({} - {})", left, right),
            Expr::Mul(left, right) => write!(f, "({} * {})", left, right),
            Expr::And(left, right) => write!(f, "({} & {})", left, right),
            Expr::Or(left, right) => write!(f, "({} | {})", left, right),
            Expr::Xor(left, right) => write!(f, "({} ^ {})", left, right),
            Expr::Shl(left, right) => write!(f, "({} << {})", left, right),
            Expr::Lshr(left, right) => write!(f, "({} >> {})", left, right),
            Expr::Ashr(left, right) => write!(f, "({} >>> {})", left, right),
            Expr::Not(expr) => write!(f, "(!{})", expr),
            Expr::Neg(expr) => write!(f, "(-{})", expr),
            Expr::Eq(left, right) => write!(f, "({} == {})", left, right),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_const_creation() {
        let expr = Expr::const_bv(42, 32);
        assert_eq!(expr.width(), 32);
        assert!(expr.is_const());
        assert_eq!(expr.const_value(), Some(42));
    }

    #[test]
    fn test_var_creation() {
        let expr = Expr::var("x", 64);
        assert_eq!(expr.width(), 64);
        assert!(!expr.is_const());
        assert_eq!(expr.const_value(), None);
    }

    #[test]
    fn test_add_expression() {
        let x = Expr::var("x", 32);
        let y = Expr::var("y", 32);
        let add = Expr::add(x, y);
        assert_eq!(add.width(), 32);
    }

    #[test]
    fn test_width_mask() {
        assert_eq!(Expr::width_mask(8), 0xFF);
        assert_eq!(Expr::width_mask(16), 0xFFFF);
        assert_eq!(Expr::width_mask(32), 0xFFFF_FFFF);
    }

    #[test]
    fn test_display() {
        let expr = Expr::add(Expr::const_bv(10, 32), Expr::var("x", 32));
        let display = format!("{}", expr);
        assert!(display.contains("+"));
        assert!(display.contains("0xa"));
        assert!(display.contains("x:32"));
    }
}
