/// Advanced SSA transformation implementation
/// Based on Ghidra's heritage.cc algorithm

use crate::decompiler_prototype::pcode::{AddressSpace, OpCode, PcodeOp, Varnode};
use crate::decompiler_prototype::cfg::{BasicBlock, BlockId, ControlFlowGraph};
use crate::decompiler_prototype::ssa::DominanceTree;
use std::collections::HashMap;

/// Stack for tracking variable versions during SSA renaming
#[derive(Debug, Clone)]
pub struct VariableStack {
    /// Maps variable addresses to their version stacks
    stacks: HashMap<VarnodeAddress, Vec<Varnode>>,
}

/// Address identifier for variables (space + offset)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VarnodeAddress {
    space: AddressSpace,
    offset: u64,
}

impl From<&Varnode> for VarnodeAddress {
    fn from(vn: &Varnode) -> Self {
        VarnodeAddress {
            space: vn.space,
            offset: vn.offset,
        }
    }
}

impl VariableStack {
    /// Create a new empty variable stack
    pub fn new() -> Self {
        Self {
            stacks: HashMap::new(),
        }
    }

    /// Push a new version of a variable
    pub fn push(&mut self, vn: Varnode) {
        let addr = VarnodeAddress::from(&vn);
        self.stacks.entry(addr).or_insert_with(Vec::new).push(vn);
    }

    /// Pop the most recent version of a variable
    pub fn pop(&mut self, addr: &VarnodeAddress) -> Option<Varnode> {
        self.stacks.get_mut(addr)?.pop()
    }

    /// Get the top of the stack for a specific address (without removing)
    pub fn top(&self, addr: &VarnodeAddress) -> Option<&Varnode> {
        self.stacks.get(addr)?.last()
    }

    /// Get the stack size for a specific address
    pub fn stack_size(&self, addr: &VarnodeAddress) -> usize {
        self.stacks.get(addr).map(|s| s.len()).unwrap_or(0)
    }

    /// Clear all stacks
    pub fn clear(&mut self) {
        self.stacks.clear();
    }
}

impl Default for VariableStack {
    fn default() -> Self {
        Self::new()
    }
}

/// SSA Renaming Context
pub struct SSARenameContext {
    /// Variable stack for tracking versions
    pub varstack: VariableStack,
    /// Counter for creating unique input varnodes
    input_counter: u64,
    /// Counter for creating unique temporary varnodes
    unique_counter: u64,
}

impl SSARenameContext {
    pub fn new() -> Self {
        Self {
            varstack: VariableStack::new(),
            input_counter: 0,
            unique_counter: 10000,
        }
    }

    /// Create a new input varnode
    pub fn create_input_varnode(&mut self, addr: &VarnodeAddress, size: usize) -> Varnode {
        let vn = Varnode::new(addr.space, addr.offset, size);
        self.input_counter += 1;
        vn
    }

    /// Create a new unique varnode
    pub fn create_unique_varnode(&mut self, size: usize) -> Varnode {
        let vn = Varnode::unique(self.unique_counter, size);
        self.unique_counter += 1;
        vn
    }
}

impl Default for SSARenameContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Advanced SSA transformation
pub struct AdvancedSSATransform {
    rename_context: SSARenameContext,
}

impl AdvancedSSATransform {
    pub fn new() -> Self {
        Self {
            rename_context: SSARenameContext::new(),
        }
    }

    /// Recursively rename variables in SSA form
    ///
    /// This implements the renaming phase of SSA construction,
    /// traversing the dominator tree and renaming variables to ensure
    /// each variable is assigned exactly once.
    pub fn rename_recurse(
        &mut self,
        block_id: BlockId,
        cfg: &mut ControlFlowGraph,
        dom_tree: &DominanceTree,
    ) {
        let mut write_list = Vec::new();

        let block = if let Some(b) = cfg.blocks.get_mut(&block_id) {
            b
        } else {
            return;
        };

        // Rename all non-phi operations
        for op in &mut block.ops {
            if op.opcode != OpCode::MultiEqual {
                // Rename inputs
                for input in &mut op.inputs {
                    if self.should_rename(input) {
                        let addr = VarnodeAddress::from(&*input);

                        if let Some(new_vn) = self.rename_context.varstack.top(&addr) {
                            *input = new_vn.clone();
                        } else {
                            let new_input = self
                                .rename_context
                                .create_input_varnode(&addr, input.size);
                            self.rename_context.varstack.push(new_input.clone());
                            *input = new_input;
                        }
                    }
                }
            }

            // Rename outputs
            if let Some(output) = &op.output {
                if self.should_rename(output) {
                    let addr = VarnodeAddress::from(output);
                    self.rename_context.varstack.push(output.clone());
                    write_list.push(addr);
                }
            }
        }

        // Update phi function inputs for successor blocks
        if let Some(children) = dom_tree.get_children(block_id) {
            for &child_id in children {
                if let Some(child_block) = cfg.blocks.get_mut(&child_id) {
                    for child_op in &mut child_block.ops {
                        if child_op.opcode == OpCode::MultiEqual {
                            for input in &mut child_op.inputs {
                                if self.should_rename(input) {
                                    let addr = VarnodeAddress::from(&*input);
                                    if let Some(new_vn) = self.rename_context.varstack.top(&addr) {
                                        *input = new_vn.clone();
                                    } else {
                                        let new_input = self
                                            .rename_context
                                            .create_input_varnode(&addr, input.size);
                                        self.rename_context.varstack.push(new_input.clone());
                                        *input = new_input;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recursively process children in dominator tree
        if let Some(children) = dom_tree.get_children(block_id) {
            for &child_id in children {
                self.rename_recurse(child_id, cfg, dom_tree);
            }
        }

        // Pop all variables written in this block
        for addr in write_list {
            self.rename_context.varstack.pop(&addr);
        }
    }

    /// Determine if a Varnode should be renamed
    fn should_rename(&self, vn: &Varnode) -> bool {
        if vn.space == AddressSpace::Const {
            return false;
        }
        true
    }

    /// Transform the CFG into SSA form
    pub fn transform(
        &mut self,
        cfg: &mut ControlFlowGraph,
        dom_tree: &DominanceTree,
    ) {
        self.rename_recurse(cfg.entry_block, cfg, dom_tree);
    }
}

impl Default for AdvancedSSATransform {
    fn default() -> Self {
        Self::new()
    }
}

/// Extension trait for DominanceTree
pub trait DominanceTreeExt {
    fn get_children(&self, block_id: BlockId) -> Option<&Vec<BlockId>>;
}

impl DominanceTreeExt for DominanceTree {
    fn get_children(&self, block_id: BlockId) -> Option<&Vec<BlockId>> {
        self.children.get(&block_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_stack() {
        let mut stack = VariableStack::new();

        let vn1 = Varnode::register(0, 8);
        let vn2 = Varnode::register(0, 8);
        let addr = VarnodeAddress::from(&vn1);

        stack.push(vn1.clone());
        assert_eq!(stack.top(&addr), Some(&vn1));

        stack.push(vn2.clone());
        assert_eq!(stack.top(&addr), Some(&vn2));

        assert_eq!(stack.pop(&addr), Some(vn2));
        assert_eq!(stack.top(&addr), Some(&vn1));

        assert_eq!(stack.pop(&addr), Some(vn1));
        assert_eq!(stack.top(&addr), None);
    }

    #[test]
    fn test_ssa_rename_context() {
        let mut ctx = SSARenameContext::new();

        let addr = VarnodeAddress {
            space: AddressSpace::Register,
            offset: 0,
        };

        let input1 = ctx.create_input_varnode(&addr, 8);
        assert_eq!(input1.space, AddressSpace::Register);

        let unique1 = ctx.create_unique_varnode(4);
        assert_eq!(unique1.space, AddressSpace::Unique);
        assert_eq!(unique1.offset, 10000);

        let unique2 = ctx.create_unique_varnode(4);
        assert_eq!(unique2.offset, 10001);
    }
}
