//! MBA (Mixed Boolean-Arithmetic) パターン認識
//!
//! MBA難読化で使われる典型的なパターンを認識し、簡約化する。
//!
//! MBA難読化の例:
//! - `x + y` → `(x ^ y) + 2 * (x & y)`
//! - `x - y` → `(x ^ y) - 2 * (~x & y)`
//! - `x` → `(x | y) - y`
//!
//! 参考文献:
//! - Liu et al. (2021): "MBA-Blast: Unveiling and Simplifying Mixed Boolean-Arithmetic Obfuscation"

use crate::kensho_smt::expr::Expr;
use crate::kensho_smt::simplify::simplify;

/// MBAパターン
///
/// 複雑な式とその簡約化された形式のペア
#[derive(Debug, Clone)]
pub struct MBAPattern {
    /// パターンの名前
    pub name: String,
    /// パターンのマッチャー関数
    matcher: fn(&Expr) -> Option<MBAMatch>,
    /// 簡約化関数
    simplifier: fn(&MBAMatch) -> Expr,
}

/// MBAパターンのマッチ結果
#[derive(Debug, Clone)]
pub struct MBAMatch {
    /// マッチしたパターンの名前
    pub pattern_name: String,
    /// 抽出された変数
    pub variables: Vec<Expr>,
}

impl MBAPattern {
    /// 新しいMBAパターンを作成
    pub fn new(
        name: impl Into<String>,
        matcher: fn(&Expr) -> Option<MBAMatch>,
        simplifier: fn(&MBAMatch) -> Expr,
    ) -> Self {
        Self {
            name: name.into(),
            matcher,
            simplifier,
        }
    }

    /// 式がこのパターンにマッチするか確認
    pub fn matches(&self, expr: &Expr) -> Option<MBAMatch> {
        (self.matcher)(expr)
    }

    /// マッチした式を簡約化
    pub fn simplify(&self, matched: &MBAMatch) -> Expr {
        (self.simplifier)(matched)
    }
}

/// MBAパターンのコレクション
pub struct MBAPatternSet {
    patterns: Vec<MBAPattern>,
}

impl MBAPatternSet {
    /// 新しいパターンセットを作成
    pub fn new() -> Self {
        let mut patterns = Vec::new();

        // パターン1: (x ^ y) + 2 * (x & y) = x + y
        patterns.push(MBAPattern::new(
            "xor_add_and",
            Self::match_xor_add_and,
            Self::simplify_xor_add_and,
        ));

        // パターン2: (x | y) + (x & y) = x + y
        patterns.push(MBAPattern::new(
            "or_add_and",
            Self::match_or_add_and,
            Self::simplify_or_add_and,
        ));

        // パターン3: (x ^ y) - 2 * (~x & y) = x - y
        patterns.push(MBAPattern::new(
            "xor_sub_not_and",
            Self::match_xor_sub_not_and,
            Self::simplify_xor_sub_not_and,
        ));

        // パターン4: (x | y) - y = x & ~y
        patterns.push(MBAPattern::new(
            "or_sub",
            Self::match_or_sub,
            Self::simplify_or_sub,
        ));

        // パターン5: (x & y) + (x | y) = x + y
        patterns.push(MBAPattern::new(
            "and_add_or",
            Self::match_and_add_or,
            Self::simplify_and_add_or,
        ));

        Self { patterns }
    }

    /// すべてのパターンを試して最初にマッチしたものを返す
    pub fn find_match(&self, expr: &Expr) -> Option<(&MBAPattern, MBAMatch)> {
        for pattern in &self.patterns {
            if let Some(matched) = pattern.matches(expr) {
                return Some((pattern, matched));
            }
        }
        None
    }

    /// 式にMBAパターンを適用して簡約化
    pub fn apply(&self, expr: &Expr) -> Option<Expr> {
        if let Some((pattern, matched)) = self.find_match(expr) {
            Some(pattern.simplify(&matched))
        } else {
            None
        }
    }

    /// 式を再帰的に簡約化（MBAパターン適用 + 通常の簡約化）
    pub fn simplify_recursive(&self, expr: &Expr) -> Expr {
        // まず通常の簡約化
        let mut current = simplify(expr);
        let mut changed = true;

        // MBAパターンを不動点まで適用
        while changed {
            if let Some(simplified) = self.apply(&current) {
                let next = simplify(&simplified);
                changed = next != current;
                current = next;
            } else {
                changed = false;
            }
        }

        current
    }

    // パターン1: (x ^ y) + 2 * (x & y) = x + y
    fn match_xor_add_and(expr: &Expr) -> Option<MBAMatch> {
        if let Expr::Add(left, right) = expr {
            // left = x ^ y, right = 2 * (x & y)
            if let (Expr::Xor(x1, y1), Expr::Mul(two, and_expr)) = (&**left, &**right) {
                if let (Expr::BV { value: 2, .. }, Expr::And(x2, y2)) = (&**two, &**and_expr) {
                    if x1 == x2 && y1 == y2 {
                        return Some(MBAMatch {
                            pattern_name: "xor_add_and".to_string(),
                            variables: vec![(**x1).clone(), (**y1).clone()],
                        });
                    }
                }
            }
        }
        None
    }

    fn simplify_xor_add_and(matched: &MBAMatch) -> Expr {
        // (x ^ y) + 2 * (x & y) → x + y
        Expr::add(matched.variables[0].clone(), matched.variables[1].clone())
    }

    // パターン2: (x | y) + (x & y) = x + y
    fn match_or_add_and(expr: &Expr) -> Option<MBAMatch> {
        if let Expr::Add(left, right) = expr {
            if let (Expr::Or(x1, y1), Expr::And(x2, y2)) = (&**left, &**right) {
                if x1 == x2 && y1 == y2 {
                    return Some(MBAMatch {
                        pattern_name: "or_add_and".to_string(),
                        variables: vec![(**x1).clone(), (**y1).clone()],
                    });
                }
            }
        }
        None
    }

    fn simplify_or_add_and(matched: &MBAMatch) -> Expr {
        Expr::add(matched.variables[0].clone(), matched.variables[1].clone())
    }

    // パターン3: (x ^ y) - 2 * (~x & y) = x - y
    fn match_xor_sub_not_and(expr: &Expr) -> Option<MBAMatch> {
        if let Expr::Sub(left, right) = expr {
            if let (Expr::Xor(x1, y1), Expr::Mul(two, and_expr)) = (&**left, &**right) {
                if let (Expr::BV { value: 2, .. }, Expr::And(not_x, y2)) = (&**two, &**and_expr) {
                    if let Expr::Not(x2) = &**not_x {
                        if x1 == x2 && y1 == y2 {
                            return Some(MBAMatch {
                                pattern_name: "xor_sub_not_and".to_string(),
                                variables: vec![(**x1).clone(), (**y1).clone()],
                            });
                        }
                    }
                }
            }
        }
        None
    }

    fn simplify_xor_sub_not_and(matched: &MBAMatch) -> Expr {
        Expr::sub(matched.variables[0].clone(), matched.variables[1].clone())
    }

    // パターン4: (x | y) - y = x & ~y
    fn match_or_sub(expr: &Expr) -> Option<MBAMatch> {
        if let Expr::Sub(left, right) = expr {
            if let Expr::Or(x, y1) = &**left {
                if y1 == right {
                    return Some(MBAMatch {
                        pattern_name: "or_sub".to_string(),
                        variables: vec![(**x).clone(), (**y1).clone()],
                    });
                }
            }
        }
        None
    }

    fn simplify_or_sub(matched: &MBAMatch) -> Expr {
        let x = matched.variables[0].clone();
        let y = matched.variables[1].clone();
        Expr::and(x, Expr::not(y))
    }

    // パターン5: (x & y) + (x | y) = x + y
    fn match_and_add_or(expr: &Expr) -> Option<MBAMatch> {
        if let Expr::Add(left, right) = expr {
            if let (Expr::And(x1, y1), Expr::Or(x2, y2)) = (&**left, &**right) {
                if x1 == x2 && y1 == y2 {
                    return Some(MBAMatch {
                        pattern_name: "and_add_or".to_string(),
                        variables: vec![(**x1).clone(), (**y1).clone()],
                    });
                }
            }
        }
        None
    }

    fn simplify_and_add_or(matched: &MBAMatch) -> Expr {
        Expr::add(matched.variables[0].clone(), matched.variables[1].clone())
    }
}

impl Default for MBAPatternSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_add_and_pattern() {
        let patterns = MBAPatternSet::new();
        let x = Expr::var("x", 32);
        let y = Expr::var("y", 32);

        // (x ^ y) + 2 * (x & y)
        let xor = Expr::xor(x.clone(), y.clone());
        let and = Expr::and(x.clone(), y.clone());
        let mul = Expr::mul(Expr::const_bv(2, 32), and);
        let mba_expr = Expr::add(xor, mul);

        let simplified = patterns.simplify_recursive(&mba_expr);
        let expected = simplify(&Expr::add(x, y));

        assert_eq!(simplified, expected);
    }

    #[test]
    fn test_or_add_and_pattern() {
        let patterns = MBAPatternSet::new();
        let x = Expr::var("x", 32);
        let y = Expr::var("y", 32);

        // (x | y) + (x & y)
        let or = Expr::or(x.clone(), y.clone());
        let and = Expr::and(x.clone(), y.clone());
        let mba_expr = Expr::add(or, and);

        let simplified = patterns.simplify_recursive(&mba_expr);
        let expected = simplify(&Expr::add(x, y));

        assert_eq!(simplified, expected);
    }

    #[test]
    fn test_no_pattern_match() {
        let patterns = MBAPatternSet::new();
        let x = Expr::var("x", 32);
        let y = Expr::var("y", 32);

        // 通常の加算（MBAパターンではない）
        let normal_add = Expr::add(x.clone(), y);

        assert!(patterns.find_match(&normal_add).is_none());
    }

    #[test]
    fn test_pattern_count() {
        let patterns = MBAPatternSet::new();
        assert_eq!(patterns.patterns.len(), 5);
    }
}
