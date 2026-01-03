//! Boolean SAT solver using DPLL algorithm
//!
//! Implements a basic DPLL (Davis-Putnam-Logemann-Loveland) SAT solver
//! for solving Boolean satisfiability problems generated from bit-blasting.
//!
//! Features:
//! - CNF (Conjunctive Normal Form) conversion
//! - Unit propagation
//! - Pure literal elimination
//! - Backtracking search
//!
//! References:
//! - "A Machine Program for Theorem-Proving" (Davis & Putnam, 1960)
//! - "A Computing Procedure for Quantification Theory" (Davis, Logemann, Loveland, 1962)

use crate::kensho_smt::bitblast::BoolExpr;
use std::collections::{HashMap, HashSet};

/// Literal: positive or negative Boolean variable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Literal {
    /// Variable identifier
    pub var: usize,
    /// True if positive, false if negative
    pub positive: bool,
}

impl Literal {
    /// Create a positive literal
    pub fn pos(var: usize) -> Self {
        Self {
            var,
            positive: true,
        }
    }

    /// Create a negative literal
    pub fn neg(var: usize) -> Self {
        Self {
            var,
            positive: false,
        }
    }

    /// Negate the literal
    pub fn negate(&self) -> Self {
        Self {
            var: self.var,
            positive: !self.positive,
        }
    }
}

/// Clause: disjunction of literals (OR)
pub type Clause = Vec<Literal>;

/// CNF formula: conjunction of clauses (AND of ORs)
#[derive(Debug, Clone)]
pub struct CNF {
    /// List of clauses
    pub clauses: Vec<Clause>,
    /// Number of variables
    pub num_vars: usize,
}

impl CNF {
    /// Create an empty CNF
    pub fn new() -> Self {
        Self {
            clauses: Vec::new(),
            num_vars: 0,
        }
    }

    /// Add a clause
    pub fn add_clause(&mut self, clause: Clause) {
        for lit in &clause {
            self.num_vars = self.num_vars.max(lit.var + 1);
        }
        self.clauses.push(clause);
    }

    /// Create CNF from a Boolean expression
    pub fn from_bool_expr(expr: &BoolExpr) -> Self {
        let mut cnf = CNF::new();
        let mut var_map = HashMap::new();

        // Convert to CNF using Tseitin transformation
        let root_var = cnf.tseitin_transform(expr, &mut var_map);

        // Add unit clause for root (must be true)
        cnf.add_clause(vec![Literal::pos(root_var)]);

        cnf
    }

    /// Tseitin transformation: Convert Boolean expression to equisatisfiable CNF
    fn tseitin_transform(
        &mut self,
        expr: &BoolExpr,
        var_map: &mut HashMap<BoolExpr, usize>,
    ) -> usize {
        // Check cache
        if let Some(&var) = var_map.get(expr) {
            return var;
        }

        let var = match expr {
            BoolExpr::True => {
                let v = self.num_vars;
                self.num_vars += 1;
                // v = true (unit clause)
                self.add_clause(vec![Literal::pos(v)]);
                v
            }

            BoolExpr::False => {
                let v = self.num_vars;
                self.num_vars += 1;
                // v = false (empty clause conflicts immediately)
                self.add_clause(vec![Literal::neg(v)]);
                v
            }

            BoolExpr::Var(name, bit_index) => {
                let _key = format!("{}[{}]", name, bit_index);
                let v = *var_map
                    .entry(BoolExpr::Var(name.clone(), *bit_index))
                    .or_insert_with(|| {
                        let v = self.num_vars;
                        self.num_vars += 1;
                        v
                    });
                v
            }

            BoolExpr::Not(inner) => {
                let inner_var = self.tseitin_transform(inner, var_map);
                let v = self.num_vars;
                self.num_vars += 1;

                // v ↔ ¬inner
                // (v ∨ inner) ∧ (¬v ∨ ¬inner)
                self.add_clause(vec![Literal::pos(v), Literal::pos(inner_var)]);
                self.add_clause(vec![Literal::neg(v), Literal::neg(inner_var)]);

                v
            }

            BoolExpr::And(left, right) => {
                let left_var = self.tseitin_transform(left, var_map);
                let right_var = self.tseitin_transform(right, var_map);
                let v = self.num_vars;
                self.num_vars += 1;

                // v ↔ (left ∧ right)
                // (¬v ∨ left) ∧ (¬v ∨ right) ∧ (v ∨ ¬left ∨ ¬right)
                self.add_clause(vec![Literal::neg(v), Literal::pos(left_var)]);
                self.add_clause(vec![Literal::neg(v), Literal::pos(right_var)]);
                self.add_clause(vec![
                    Literal::pos(v),
                    Literal::neg(left_var),
                    Literal::neg(right_var),
                ]);

                v
            }

            BoolExpr::Or(left, right) => {
                let left_var = self.tseitin_transform(left, var_map);
                let right_var = self.tseitin_transform(right, var_map);
                let v = self.num_vars;
                self.num_vars += 1;

                // v ↔ (left ∨ right)
                // (¬v ∨ left ∨ right) ∧ (v ∨ ¬left) ∧ (v ∨ ¬right)
                self.add_clause(vec![
                    Literal::neg(v),
                    Literal::pos(left_var),
                    Literal::pos(right_var),
                ]);
                self.add_clause(vec![Literal::pos(v), Literal::neg(left_var)]);
                self.add_clause(vec![Literal::pos(v), Literal::neg(right_var)]);

                v
            }

            BoolExpr::Xor(left, right) => {
                let left_var = self.tseitin_transform(left, var_map);
                let right_var = self.tseitin_transform(right, var_map);
                let v = self.num_vars;
                self.num_vars += 1;

                // v ↔ (left ⊕ right)
                // (¬v ∨ ¬left ∨ ¬right) ∧ (¬v ∨ left ∨ right) ∧ (v ∨ ¬left ∨ right) ∧ (v ∨ left ∨ ¬right)
                self.add_clause(vec![
                    Literal::neg(v),
                    Literal::neg(left_var),
                    Literal::neg(right_var),
                ]);
                self.add_clause(vec![
                    Literal::neg(v),
                    Literal::pos(left_var),
                    Literal::pos(right_var),
                ]);
                self.add_clause(vec![
                    Literal::pos(v),
                    Literal::neg(left_var),
                    Literal::pos(right_var),
                ]);
                self.add_clause(vec![
                    Literal::pos(v),
                    Literal::pos(left_var),
                    Literal::neg(right_var),
                ]);

                v
            }

            BoolExpr::Implies(left, right) => {
                // a → b = ¬a ∨ b
                let or_expr = BoolExpr::or(BoolExpr::not((**left).clone()), (**right).clone());
                self.tseitin_transform(&or_expr, var_map)
            }

            BoolExpr::Iff(left, right) => {
                // a ↔ b = (a → b) ∧ (b → a)
                let left_var = self.tseitin_transform(left, var_map);
                let right_var = self.tseitin_transform(right, var_map);
                let v = self.num_vars;
                self.num_vars += 1;

                // v ↔ (left ↔ right)
                // (¬v ∨ ¬left ∨ right) ∧ (¬v ∨ left ∨ ¬right) ∧ (v ∨ ¬left ∨ ¬right) ∧ (v ∨ left ∨ right)
                self.add_clause(vec![
                    Literal::neg(v),
                    Literal::neg(left_var),
                    Literal::pos(right_var),
                ]);
                self.add_clause(vec![
                    Literal::neg(v),
                    Literal::pos(left_var),
                    Literal::neg(right_var),
                ]);
                self.add_clause(vec![
                    Literal::pos(v),
                    Literal::neg(left_var),
                    Literal::neg(right_var),
                ]);
                self.add_clause(vec![
                    Literal::pos(v),
                    Literal::pos(left_var),
                    Literal::pos(right_var),
                ]);

                v
            }
        };

        var_map.insert(expr.clone(), var);
        var
    }
}

/// Assignment: partial or complete variable assignment
pub type Assignment = HashMap<usize, bool>;

/// SAT solver result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SatSolverResult {
    /// Satisfiable with model
    Sat(Assignment),
    /// Unsatisfiable
    Unsat,
    /// Unknown (timeout or resource limit)
    Unknown,
}

/// DPLL-based SAT solver
pub struct DPLLSolver {
    /// CNF formula
    cnf: CNF,
    /// Maximum number of decisions before giving up
    max_decisions: usize,
    /// Current decision count
    decision_count: usize,
}

impl DPLLSolver {
    /// Create a new DPLL solver
    pub fn new(cnf: CNF) -> Self {
        Self {
            cnf,
            max_decisions: 10000,
            decision_count: 0,
        }
    }

    /// Set maximum number of decisions
    pub fn set_max_decisions(&mut self, max: usize) {
        self.max_decisions = max;
    }

    /// Solve the SAT problem
    pub fn solve(&mut self) -> SatSolverResult {
        self.decision_count = 0;
        let mut assignment = Assignment::new();
        self.dpll(&mut assignment)
    }

    /// DPLL algorithm
    fn dpll(&mut self, assignment: &mut Assignment) -> SatSolverResult {
        // Check decision limit
        if self.decision_count >= self.max_decisions {
            return SatSolverResult::Unknown;
        }

        // Unit propagation
        if !self.unit_propagation(assignment) {
            return SatSolverResult::Unsat;
        }

        // Check if all clauses are satisfied
        if self.all_clauses_satisfied(assignment) {
            return SatSolverResult::Sat(assignment.clone());
        }

        // Pure literal elimination
        self.pure_literal_elimination(assignment);

        // Check again after pure literal elimination
        if self.all_clauses_satisfied(assignment) {
            return SatSolverResult::Sat(assignment.clone());
        }

        // Choose an unassigned variable
        let var = match self.choose_variable(assignment) {
            Some(v) => v,
            None => return SatSolverResult::Sat(assignment.clone()),
        };

        self.decision_count += 1;

        // Try assigning true
        assignment.insert(var, true);
        match self.dpll(assignment) {
            SatSolverResult::Sat(model) => return SatSolverResult::Sat(model),
            _ => {}
        }
        assignment.remove(&var);

        // Try assigning false
        assignment.insert(var, false);
        match self.dpll(assignment) {
            SatSolverResult::Sat(model) => return SatSolverResult::Sat(model),
            _ => {}
        }
        assignment.remove(&var);

        SatSolverResult::Unsat
    }

    /// Unit propagation: if a clause has only one unassigned literal, assign it
    fn unit_propagation(&self, assignment: &mut Assignment) -> bool {
        let mut changed = true;

        while changed {
            changed = false;

            for clause in &self.cnf.clauses {
                let unassigned = self.count_unassigned(clause, assignment);

                if unassigned.0 == 0 {
                    // All literals are assigned
                    if !self.clause_satisfied(clause, assignment) {
                        // Conflict
                        return false;
                    }
                } else if unassigned.0 == 1 {
                    // Unit clause: exactly one unassigned literal
                    if let Some(lit) = unassigned.1 {
                        assignment.insert(lit.var, lit.positive);
                        changed = true;
                    }
                }
            }
        }

        true
    }

    /// Count unassigned literals in a clause
    fn count_unassigned(&self, clause: &Clause, assignment: &Assignment) -> (usize, Option<Literal>) {
        let mut count = 0;
        let mut last_unassigned = None;

        for lit in clause {
            if !assignment.contains_key(&lit.var) {
                count += 1;
                last_unassigned = Some(*lit);
            }
        }

        (count, last_unassigned)
    }

    /// Pure literal elimination: if a variable appears only positive or only negative, assign it
    fn pure_literal_elimination(&self, assignment: &mut Assignment) {
        let mut polarity: HashMap<usize, HashSet<bool>> = HashMap::new();

        // Collect polarities of unassigned variables
        for clause in &self.cnf.clauses {
            if self.clause_satisfied(clause, assignment) {
                continue;
            }

            for lit in clause {
                if !assignment.contains_key(&lit.var) {
                    polarity
                        .entry(lit.var)
                        .or_insert_with(HashSet::new)
                        .insert(lit.positive);
                }
            }
        }

        // Assign pure literals
        for (var, pols) in polarity {
            if pols.len() == 1 {
                let positive = *pols.iter().next().unwrap();
                assignment.insert(var, positive);
            }
        }
    }

    /// Check if a clause is satisfied
    fn clause_satisfied(&self, clause: &Clause, assignment: &Assignment) -> bool {
        for lit in clause {
            if let Some(&val) = assignment.get(&lit.var) {
                if val == lit.positive {
                    return true;
                }
            }
        }
        false
    }

    /// Check if all clauses are satisfied
    fn all_clauses_satisfied(&self, assignment: &Assignment) -> bool {
        self.cnf
            .clauses
            .iter()
            .all(|c| self.clause_satisfied(c, assignment))
    }

    /// Choose an unassigned variable (simple strategy: first unassigned)
    fn choose_variable(&self, assignment: &Assignment) -> Option<usize> {
        for var in 0..self.cnf.num_vars {
            if !assignment.contains_key(&var) {
                return Some(var);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_negate() {
        let lit = Literal::pos(0);
        let neg = lit.negate();
        assert_eq!(neg.var, 0);
        assert!(!neg.positive);
    }

    #[test]
    fn test_cnf_creation() {
        let mut cnf = CNF::new();
        cnf.add_clause(vec![Literal::pos(0), Literal::neg(1)]);
        assert_eq!(cnf.clauses.len(), 1);
        assert_eq!(cnf.num_vars, 2);
    }

    #[test]
    fn test_simple_sat() {
        // (x ∨ y) ∧ (¬x ∨ y) ∧ (x ∨ ¬y)
        let mut cnf = CNF::new();
        cnf.add_clause(vec![Literal::pos(0), Literal::pos(1)]);
        cnf.add_clause(vec![Literal::neg(0), Literal::pos(1)]);
        cnf.add_clause(vec![Literal::pos(0), Literal::neg(1)]);

        let mut solver = DPLLSolver::new(cnf);
        let result = solver.solve();

        match result {
            SatSolverResult::Sat(_) => {
                // Should be SAT
            }
            _ => panic!("Expected SAT"),
        }
    }

    #[test]
    fn test_simple_unsat() {
        // (x) ∧ (¬x)
        let mut cnf = CNF::new();
        cnf.add_clause(vec![Literal::pos(0)]);
        cnf.add_clause(vec![Literal::neg(0)]);

        let mut solver = DPLLSolver::new(cnf);
        let result = solver.solve();

        assert_eq!(result, SatSolverResult::Unsat);
    }

    #[test]
    fn test_bool_expr_to_cnf() {
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
}
