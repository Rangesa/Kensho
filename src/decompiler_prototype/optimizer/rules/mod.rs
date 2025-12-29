mod early_removal;
mod and_mask;
mod or_mask;
mod or_consume;
mod term_order;
mod and_or_lump;
mod equality;
mod negate_identity;
mod constant_fold;
mod less_one;
mod shift_bitops;
mod zero_op;

// Advanced optimization rules
mod cse;
mod loop_invariant;
mod strength_reduction;
mod induction_variable;
mod copy_propagation_advanced;

pub use early_removal::RuleEarlyRemoval;
pub use and_mask::RuleAndMask;
pub use or_mask::RuleOrMask;
pub use or_consume::RuleOrConsume;
pub use term_order::RuleTermOrder;
pub use and_or_lump::RuleAndOrLump;
pub use equality::RuleEquality;
pub use negate_identity::RuleNegateIdentity;
pub use constant_fold::RuleConstantFold;
pub use less_one::RuleLessOne;
pub use shift_bitops::RuleShiftBitops;
pub use zero_op::RuleZeroOp;

// Advanced optimization rules
pub use cse::RuleCSE;
pub use loop_invariant::RuleLICM;
pub use strength_reduction::RuleStrengthReduction;
pub use induction_variable::RuleInductionVariable;
pub use copy_propagation_advanced::RuleCopyPropagationAdvanced;
