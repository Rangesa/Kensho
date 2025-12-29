//! Rule-based expression rewriting system
//!
//! Provides a flexible pattern-matching and transformation framework
//! for bit-vector expressions. Supports custom rewrite rules that can
//! be applied systematically to simplify or transform expressions.
//!
//! Features:
//! - Pattern matching with wildcards
//! - Conditional rewrite rules
//! - Rule priorities
//! - Fixpoint iteration

use crate::kensho_smt::expr::Expr;
use std::collections::HashMap;

/// Pattern for matching expressions
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// Wildcard: matches any expression
    Wildcard(String),

    /// Constant value
    Const(u64, u32),

    /// Variable with specific name
    Var(String, u32),

    /// Binary operation
    BinOp(BinOpKind, Box<Pattern>, Box<Pattern>),

    /// Unary operation
    UnaryOp(UnaryOpKind, Box<Pattern>),
}

/// Binary operation kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Lshr,
    Ashr,
    Eq,
}

/// Unary operation kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOpKind {
    Not,
    Neg,
}

/// Rewrite rule: pattern -> replacement (with optional condition)
pub struct RewriteRule {
    /// Rule name
    pub name: String,

    /// Pattern to match
    pub pattern: Pattern,

    /// Replacement expression generator
    pub replacement: fn(&HashMap<String, Expr>) -> Expr,

    /// Optional condition checker
    pub condition: Option<fn(&HashMap<String, Expr>) -> bool>,

    /// Rule priority (higher = applied first)
    pub priority: i32,
}

impl RewriteRule {
    /// Create a new rewrite rule
    pub fn new(
        name: impl Into<String>,
        pattern: Pattern,
        replacement: fn(&HashMap<String, Expr>) -> Expr,
    ) -> Self {
        Self {
            name: name.into(),
            pattern,
            replacement,
            condition: None,
            priority: 0,
        }
    }

    /// Set condition for this rule
    pub fn with_condition(mut self, condition: fn(&HashMap<String, Expr>) -> bool) -> Self {
        self.condition = Some(condition);
        self
    }

    /// Set priority for this rule
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Try to apply this rule to an expression
    pub fn apply(&self, expr: &Expr) -> Option<Expr> {
        let mut bindings = HashMap::new();

        if self.matches(&self.pattern, expr, &mut bindings) {
            // Check condition if present
            if let Some(cond) = self.condition {
                if !cond(&bindings) {
                    return None;
                }
            }

            // Apply replacement
            Some((self.replacement)(&bindings))
        } else {
            None
        }
    }

    /// Check if pattern matches expression
    fn matches(&self, pattern: &Pattern, expr: &Expr, bindings: &mut HashMap<String, Expr>) -> bool {
        match pattern {
            Pattern::Wildcard(name) => {
                // Wildcard matches anything
                if let Some(existing) = bindings.get(name) {
                    // If already bound, must match the same expression
                    existing == expr
                } else {
                    bindings.insert(name.clone(), expr.clone());
                    true
                }
            }

            Pattern::Const(val, width) => {
                matches!(expr, Expr::BV { value, width: w } if value == val && w == width)
            }

            Pattern::Var(name, width) => {
                matches!(expr, Expr::Var { name: n, width: w } if n == name && w == width)
            }

            Pattern::BinOp(kind, left_pat, right_pat) => {
                match (kind, expr) {
                    (BinOpKind::Add, Expr::Add(l, r)) |
                    (BinOpKind::Sub, Expr::Sub(l, r)) |
                    (BinOpKind::Mul, Expr::Mul(l, r)) |
                    (BinOpKind::And, Expr::And(l, r)) |
                    (BinOpKind::Or, Expr::Or(l, r)) |
                    (BinOpKind::Xor, Expr::Xor(l, r)) |
                    (BinOpKind::Shl, Expr::Shl(l, r)) |
                    (BinOpKind::Lshr, Expr::Lshr(l, r)) |
                    (BinOpKind::Ashr, Expr::Ashr(l, r)) |
                    (BinOpKind::Eq, Expr::Eq(l, r)) => {
                        self.matches(left_pat, l, bindings) && self.matches(right_pat, r, bindings)
                    }
                    _ => false,
                }
            }

            Pattern::UnaryOp(kind, inner_pat) => {
                match (kind, expr) {
                    (UnaryOpKind::Not, Expr::Not(inner)) |
                    (UnaryOpKind::Neg, Expr::Neg(inner)) => {
                        self.matches(inner_pat, inner, bindings)
                    }
                    _ => false,
                }
            }
        }
    }
}

/// Collection of rewrite rules
pub struct RewriteSystem {
    rules: Vec<RewriteRule>,
}

impl RewriteSystem {
    /// Create a new rewrite system
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the system
    pub fn add_rule(&mut self, rule: RewriteRule) {
        self.rules.push(rule);
        // Sort by priority (descending)
        self.rules.sort_by_key(|r| -r.priority);
    }

    /// Apply all rules once to the expression (top-down, left-to-right)
    pub fn apply_once(&self, expr: &Expr) -> Expr {
        // Try to apply rules at the current level
        for rule in &self.rules {
            if let Some(replacement) = rule.apply(expr) {
                return replacement;
            }
        }

        // Recursively apply to subexpressions
        match expr {
            Expr::Add(l, r) => Expr::add(self.apply_once(l), self.apply_once(r)),
            Expr::Sub(l, r) => Expr::sub(self.apply_once(l), self.apply_once(r)),
            Expr::Mul(l, r) => Expr::mul(self.apply_once(l), self.apply_once(r)),
            Expr::And(l, r) => Expr::and(self.apply_once(l), self.apply_once(r)),
            Expr::Or(l, r) => Expr::or(self.apply_once(l), self.apply_once(r)),
            Expr::Xor(l, r) => Expr::xor(self.apply_once(l), self.apply_once(r)),
            Expr::Shl(l, r) => Expr::shl(self.apply_once(l), self.apply_once(r)),
            Expr::Lshr(l, r) => Expr::lshr(self.apply_once(l), self.apply_once(r)),
            Expr::Ashr(l, r) => Expr::ashr(self.apply_once(l), self.apply_once(r)),
            Expr::Not(inner) => Expr::not(self.apply_once(inner)),
            Expr::Neg(inner) => Expr::neg(self.apply_once(inner)),
            Expr::Eq(l, r) => Expr::eq(self.apply_once(l), self.apply_once(r)),
            _ => expr.clone(),
        }
    }

    /// Apply rules to fixpoint
    pub fn apply_fixpoint(&self, expr: &Expr) -> Expr {
        let mut current = expr.clone();
        let mut changed = true;
        let max_iterations = 100;
        let mut iteration = 0;

        while changed && iteration < max_iterations {
            iteration += 1;
            let next = self.apply_once(&current);
            changed = next != current;
            current = next;
        }

        current
    }

    /// Create a default rewrite system with common algebraic rules
    pub fn default_rules() -> Self {
        let mut system = RewriteSystem::new();

        // Identity rules
        system.add_rule(RewriteRule::new(
            "add_zero_left",
            Pattern::BinOp(
                BinOpKind::Add,
                Box::new(Pattern::Const(0, 32)),
                Box::new(Pattern::Wildcard("x".to_string())),
            ),
            |bindings| bindings.get("x").unwrap().clone(),
        ).with_priority(100));

        system.add_rule(RewriteRule::new(
            "add_zero_right",
            Pattern::BinOp(
                BinOpKind::Add,
                Box::new(Pattern::Wildcard("x".to_string())),
                Box::new(Pattern::Const(0, 32)),
            ),
            |bindings| bindings.get("x").unwrap().clone(),
        ).with_priority(100));

        // Absorption rules
        system.add_rule(RewriteRule::new(
            "and_zero",
            Pattern::BinOp(
                BinOpKind::And,
                Box::new(Pattern::Wildcard("x".to_string())),
                Box::new(Pattern::Const(0, 32)),
            ),
            |_| Expr::const_bv(0, 32),
        ).with_priority(100));

        // Idempotent rules
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
        ).with_priority(90));

        // Double negation
        system.add_rule(RewriteRule::new(
            "not_not",
            Pattern::UnaryOp(
                UnaryOpKind::Not,
                Box::new(Pattern::UnaryOp(
                    UnaryOpKind::Not,
                    Box::new(Pattern::Wildcard("x".to_string())),
                )),
            ),
            |bindings| bindings.get("x").unwrap().clone(),
        ).with_priority(90));

        system
    }
}

impl Default for RewriteSystem {
    fn default() -> Self {
        Self::default_rules()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_match_wildcard() {
        let rule = RewriteRule::new(
            "test",
            Pattern::Wildcard("x".to_string()),
            |bindings| bindings.get("x").unwrap().clone(),
        );

        let expr = Expr::var("a", 32);
        let result = rule.apply(&expr);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), expr);
    }

    #[test]
    fn test_pattern_match_const() {
        let rule = RewriteRule::new(
            "test",
            Pattern::Const(5, 32),
            |_| Expr::const_bv(10, 32),
        );

        let expr = Expr::const_bv(5, 32);
        let result = rule.apply(&expr);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Expr::const_bv(10, 32));
    }

    #[test]
    fn test_add_zero_rewrite() {
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
    fn test_xor_self_rewrite() {
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
    fn test_fixpoint_iteration() {
        let system = RewriteSystem::default_rules();

        // ((x + 0) ^ (x + 0))
        let x = Expr::var("x", 32);
        let add_zero = Expr::add(x.clone(), Expr::const_bv(0, 32));
        let expr = Expr::xor(add_zero.clone(), add_zero);

        let result = system.apply_fixpoint(&expr);
        // Should simplify to 0
        assert_eq!(result, Expr::const_bv(0, 32));
    }
}
