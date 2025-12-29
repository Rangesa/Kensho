//! Symbolic Address
//!
//! シンボリックアドレスの定義と操作を提供します。
//!
//! アドレスが変数に依存する場合（例: buffer[user_input]）を扱うことで、
//! ポインタ解析やバッファオーバーフロー検出が可能になります。

use std::fmt;

/// シンボリックアドレス
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolicAddress {
    /// 具体的なアドレス（例: 0x1000）
    Concrete(u64),

    /// シンボリック式（例: "buffer_base + user_input"）
    Symbolic(String),

    /// 複雑な式（ベース + オフセット）
    BaseOffset {
        base: Box<SymbolicAddress>,
        offset: Box<SymbolicAddress>,
    },

    /// 乗算（例: array_base + index * element_size）
    Multiply {
        base: Box<SymbolicAddress>,
        factor: u64,
    },
}

impl SymbolicAddress {
    /// 具体的なアドレスを作成
    pub fn concrete(addr: u64) -> Self {
        SymbolicAddress::Concrete(addr)
    }

    /// シンボリックアドレスを作成
    pub fn symbolic(expr: impl Into<String>) -> Self {
        SymbolicAddress::Symbolic(expr.into())
    }

    /// ベース + オフセット形式のアドレスを作成
    pub fn base_offset(base: SymbolicAddress, offset: SymbolicAddress) -> Self {
        SymbolicAddress::BaseOffset {
            base: Box::new(base),
            offset: Box::new(offset),
        }
    }

    /// 乗算形式のアドレスを作成
    pub fn multiply(base: SymbolicAddress, factor: u64) -> Self {
        SymbolicAddress::Multiply {
            base: Box::new(base),
            factor,
        }
    }

    /// 具体的なアドレスかどうか
    pub fn is_concrete(&self) -> bool {
        matches!(self, SymbolicAddress::Concrete(_))
    }

    /// シンボリックかどうか
    pub fn is_symbolic(&self) -> bool {
        !self.is_concrete()
    }

    /// 具体的なアドレス値を取得
    pub fn as_concrete(&self) -> Option<u64> {
        match self {
            SymbolicAddress::Concrete(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Z3式に変換
    pub fn to_z3_expr(&self) -> String {
        match self {
            SymbolicAddress::Concrete(addr) => format!("{}", addr),
            SymbolicAddress::Symbolic(expr) => expr.clone(),
            SymbolicAddress::BaseOffset { base, offset } => {
                format!("({} + {})", base.to_z3_expr(), offset.to_z3_expr())
            }
            SymbolicAddress::Multiply { base, factor } => {
                format!("({} * {})", base.to_z3_expr(), factor)
            }
        }
    }

    /// 簡約化
    ///
    /// 例: Concrete(10) + Concrete(5) → Concrete(15)
    pub fn simplify(&self) -> SymbolicAddress {
        match self {
            SymbolicAddress::BaseOffset { base, offset } => {
                let simplified_base = base.simplify();
                let simplified_offset = offset.simplify();

                // 両方が具体値なら加算
                if let (Some(b), Some(o)) = (
                    simplified_base.as_concrete(),
                    simplified_offset.as_concrete(),
                ) {
                    return SymbolicAddress::Concrete(b.wrapping_add(o));
                }

                // オフセットが0なら省略
                if let Some(0) = simplified_offset.as_concrete() {
                    return simplified_base;
                }

                SymbolicAddress::BaseOffset {
                    base: Box::new(simplified_base),
                    offset: Box::new(simplified_offset),
                }
            }
            SymbolicAddress::Multiply { base, factor } => {
                let simplified_base = base.simplify();

                // 具体値なら乗算
                if let Some(b) = simplified_base.as_concrete() {
                    return SymbolicAddress::Concrete(b.wrapping_mul(*factor));
                }

                // factor が 1 なら省略
                if *factor == 1 {
                    return simplified_base;
                }

                SymbolicAddress::Multiply {
                    base: Box::new(simplified_base),
                    factor: *factor,
                }
            }
            _ => self.clone(),
        }
    }

    /// 2つのアドレスが重なる可能性があるか判定
    ///
    /// 具体的アドレスの場合は確実に判定可能
    /// シンボリックの場合は「可能性あり」を返す（保守的）
    pub fn may_overlap(&self, other: &SymbolicAddress, size: usize) -> AddressOverlap {
        let simplified_self = self.simplify();
        let simplified_other = other.simplify();

        if let (Some(addr1), Some(addr2)) = (
            simplified_self.as_concrete(),
            simplified_other.as_concrete(),
        ) {
            // 両方が具体値の場合は確実に判定可能
            let end1 = addr1 + size as u64;
            let end2 = addr2 + size as u64;

            if end1 <= addr2 || end2 <= addr1 {
                AddressOverlap::NoOverlap
            } else {
                AddressOverlap::DefinitelyOverlap
            }
        } else if self == other {
            // 同じシンボリック式なら確実に重なる
            AddressOverlap::DefinitelyOverlap
        } else {
            // シンボリックアドレスの場合は保守的に「可能性あり」
            AddressOverlap::MaybeOverlap
        }
    }
}

/// アドレスの重なり判定結果
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressOverlap {
    /// 確実に重ならない
    NoOverlap,
    /// 確実に重なる
    DefinitelyOverlap,
    /// 重なる可能性がある（不明）
    MaybeOverlap,
}

impl fmt::Display for SymbolicAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolicAddress::Concrete(addr) => write!(f, "0x{:x}", addr),
            SymbolicAddress::Symbolic(expr) => write!(f, "{}", expr),
            SymbolicAddress::BaseOffset { base, offset } => {
                write!(f, "({} + {})", base, offset)
            }
            SymbolicAddress::Multiply { base, factor } => {
                write!(f, "({} * {})", base, factor)
            }
        }
    }
}

/// アドレス範囲
#[derive(Debug, Clone)]
pub struct AddressRange {
    pub start: SymbolicAddress,
    pub size: usize,
}

impl AddressRange {
    pub fn new(start: SymbolicAddress, size: usize) -> Self {
        Self { start, size }
    }

    /// 別の範囲と重なる可能性があるか
    pub fn may_overlap(&self, other: &AddressRange) -> AddressOverlap {
        self.start.may_overlap(&other.start, self.size.max(other.size))
    }

    /// 終端アドレスを計算
    pub fn end_address(&self) -> SymbolicAddress {
        if self.size == 0 {
            return self.start.clone();
        }

        SymbolicAddress::base_offset(
            self.start.clone(),
            SymbolicAddress::concrete(self.size as u64),
        )
        .simplify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concrete_address() {
        let addr = SymbolicAddress::concrete(0x1000);
        assert!(addr.is_concrete());
        assert_eq!(addr.as_concrete(), Some(0x1000));
        assert_eq!(addr.to_string(), "0x1000");
    }

    #[test]
    fn test_symbolic_address() {
        let addr = SymbolicAddress::symbolic("buffer_base");
        assert!(addr.is_symbolic());
        assert_eq!(addr.as_concrete(), None);
        assert_eq!(addr.to_string(), "buffer_base");
    }

    #[test]
    fn test_base_offset() {
        let base = SymbolicAddress::concrete(0x1000);
        let offset = SymbolicAddress::symbolic("user_input");
        let addr = SymbolicAddress::base_offset(base, offset);

        assert!(addr.is_symbolic());
        assert_eq!(addr.to_string(), "(0x1000 + user_input)");
    }

    #[test]
    fn test_simplify_concrete() {
        let base = SymbolicAddress::concrete(0x1000);
        let offset = SymbolicAddress::concrete(0x100);
        let addr = SymbolicAddress::base_offset(base, offset);

        let simplified = addr.simplify();
        assert!(simplified.is_concrete());
        assert_eq!(simplified.as_concrete(), Some(0x1100));
    }

    #[test]
    fn test_simplify_zero_offset() {
        let base = SymbolicAddress::symbolic("buffer");
        let offset = SymbolicAddress::concrete(0);
        let addr = SymbolicAddress::base_offset(base.clone(), offset);

        let simplified = addr.simplify();
        assert_eq!(simplified, base);
    }

    #[test]
    fn test_multiply() {
        let base = SymbolicAddress::symbolic("index");
        let addr = SymbolicAddress::multiply(base, 4);

        assert_eq!(addr.to_string(), "(index * 4)");
    }

    #[test]
    fn test_multiply_concrete() {
        let base = SymbolicAddress::concrete(10);
        let addr = SymbolicAddress::multiply(base, 4);

        let simplified = addr.simplify();
        assert_eq!(simplified.as_concrete(), Some(40));
    }

    #[test]
    fn test_may_overlap_concrete_no_overlap() {
        let addr1 = SymbolicAddress::concrete(0x1000);
        let addr2 = SymbolicAddress::concrete(0x2000);

        assert_eq!(addr1.may_overlap(&addr2, 4), AddressOverlap::NoOverlap);
    }

    #[test]
    fn test_may_overlap_concrete_overlap() {
        let addr1 = SymbolicAddress::concrete(0x1000);
        let addr2 = SymbolicAddress::concrete(0x1002);

        assert_eq!(addr1.may_overlap(&addr2, 4), AddressOverlap::DefinitelyOverlap);
    }

    #[test]
    fn test_may_overlap_symbolic() {
        let addr1 = SymbolicAddress::symbolic("ptr1");
        let addr2 = SymbolicAddress::symbolic("ptr2");

        assert_eq!(addr1.may_overlap(&addr2, 4), AddressOverlap::MaybeOverlap);
    }

    #[test]
    fn test_may_overlap_same_symbolic() {
        let addr1 = SymbolicAddress::symbolic("ptr");
        let addr2 = SymbolicAddress::symbolic("ptr");

        assert_eq!(addr1.may_overlap(&addr2, 4), AddressOverlap::DefinitelyOverlap);
    }

    #[test]
    fn test_z3_expression() {
        let base = SymbolicAddress::symbolic("buffer_base");
        let offset = SymbolicAddress::symbolic("user_input");
        let addr = SymbolicAddress::base_offset(base, offset);

        assert_eq!(addr.to_z3_expr(), "(buffer_base + user_input)");
    }

    #[test]
    fn test_address_range() {
        let range = AddressRange::new(SymbolicAddress::concrete(0x1000), 256);

        let end = range.end_address();
        assert_eq!(end.as_concrete(), Some(0x1100));
    }
}
