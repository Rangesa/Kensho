/// SSA変換の高度実装
///
/// Ghidraのheritage.ccに基づくrenameRecurseアルゴリズム
/// 支配木を再帰的に走査してSSA変数リネームを行う

use crate::decompiler_prototype::pcode::{AddressSpace, OpCode, PcodeOp, Varnode};
use crate::decompiler_prototype::cfg::{BasicBlock, BlockId, ControlFlowGraph};
use crate::decompiler_prototype::ssa::DominanceTree;
use std::collections::HashMap;

/// 変数スタック - アドレスごとにVarnodeのスタックを管理
///
/// Ghidraのheritage.ccのVariableStackに対応
/// SSAリネーム時にアドレスごとの最新定義を追跡
#[derive(Debug, Clone)]
pub struct VariableStack {
    /// Address -> Varnodeスタック のマッピング
    stacks: HashMap<VarnodeAddress, Vec<Varnode>>,
}

/// Varnodeのアドレスを識別するキー
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
    /// 新しいVariableStackを作成
    pub fn new() -> Self {
        Self {
            stacks: HashMap::new(),
        }
    }

    /// 指定アドレスのスタックにVarnodeをプッシュ
    pub fn push(&mut self, vn: Varnode) {
        let addr = VarnodeAddress::from(&vn);
        self.stacks.entry(addr).or_insert_with(Vec::new).push(vn);
    }

    /// 指定アドレスのスタックからVarnodeをポップ
    pub fn pop(&mut self, addr: &VarnodeAddress) -> Option<Varnode> {
        self.stacks.get_mut(addr)?.pop()
    }

    /// 指定アドレスのスタックトップを取得（ポップしない）
    pub fn top(&self, addr: &VarnodeAddress) -> Option<&Varnode> {
        self.stacks.get(addr)?.last()
    }

    /// スタックのサイズを取得
    pub fn stack_size(&self, addr: &VarnodeAddress) -> usize {
        self.stacks.get(addr).map(|s| s.len()).unwrap_or(0)
    }

    /// すべてのスタックをクリア
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
    /// 変数スタック
    pub varstack: VariableStack,
    /// 入力Varnodeカウンタ（新しいinputに一意なIDを割り当て）
    input_counter: u64,
    /// 一時変数カウンタ
    unique_counter: u64,
}

impl SSARenameContext {
    pub fn new() -> Self {
        Self {
            varstack: VariableStack::new(),
            input_counter: 0,
            unique_counter: 10000, // 一時変数は10000番から開始
        }
    }

    /// 新しいinput Varnodeを作成
    pub fn create_input_varnode(&mut self, addr: &VarnodeAddress, size: usize) -> Varnode {
        let vn = Varnode::new(addr.space, addr.offset, size);
        self.input_counter += 1;
        vn
    }

    /// 新しい一時Varnodeを作成
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

/// SSA変換の高度アルゴリズム
pub struct AdvancedSSATransform {
    rename_context: SSARenameContext,
}

impl AdvancedSSATransform {
    pub fn new() -> Self {
        Self {
            rename_context: SSARenameContext::new(),
        }
    }

    /// renameRecurse - 支配木を再帰的に走査してSSA変数リネーム
    ///
    /// Ghidraのheritage.cc::renameRecurse()の実装
    ///
    /// アルゴリズム:
    /// 1. ブロック内の各P-code操作を実行順に処理
    /// 2. 読み取り（入力）: スタックトップのVarnodeで置き換え
    /// 3. 書き込み（出力）: スタックにプッシュ
    /// 4. 支配子ブロックを再帰処理
    /// 5. このブロックの書き込みをポップして状態を復元
    pub fn rename_recurse(
        &mut self,
        block_id: BlockId,
        cfg: &mut ControlFlowGraph,
        dom_tree: &DominanceTree,
    ) {
        // このブロックで書き込まれたVarnodeのリスト（後でpopするため）
        let mut write_list: Vec<VarnodeAddress> = Vec::new();

        // ブロックを取得
        let block = if let Some(b) = cfg.blocks.get_mut(&block_id) {
            b
        } else {
            return;
        };

        // ブロック内の各P-code操作を処理
        for op in &mut block.ops {
            if op.opcode != OpCode::MultiEqual {
                // MultiEqual以外: まず読み取り（入力）をスタックトップで置き換え
                for input in &mut op.inputs {
                    if self.should_rename(input) {
                        let addr = VarnodeAddress::from(&*input);

                        if let Some(new_vn) = self.rename_context.varstack.top(&addr) {
                            *input = new_vn.clone();
                        } else {
                            // スタックが空: 新しいinput Varnodeに昇格
                            let new_input = self
                                .rename_context
                                .create_input_varnode(&addr, input.size);
                            self.rename_context.varstack.push(new_input.clone());
                            *input = new_input;
                        }
                    }
                }
            }

            // 書き込み（出力）: スタックにプッシュ
            if let Some(output) = &op.output {
                if self.should_rename(output) {
                    let addr = VarnodeAddress::from(output);
                    self.rename_context.varstack.push(output.clone());
                    write_list.push(addr);
                }
            }
        }

        // 支配子ブロックのMultiEqual（Phi-node）の入力を更新
        if let Some(children) = dom_tree.get_children(block_id) {
            for &child_id in children {
                if let Some(child_block) = cfg.blocks.get_mut(&child_id) {
                    for child_op in &mut child_block.ops {
                        if child_op.opcode == OpCode::MultiEqual {
                            // このブロックから来るエッジに対応する入力を更新
                            // （実際には前駆ブロックのインデックスに基づく）
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

        // 支配子ブロックを再帰処理
        if let Some(children) = dom_tree.get_children(block_id) {
            for &child_id in children {
                self.rename_recurse(child_id, cfg, dom_tree);
            }
        }

        // このブロックの書き込みをポップして状態を復元
        for addr in write_list {
            self.rename_context.varstack.pop(&addr);
        }
    }

    /// Varnodeがリネーム対象かどうか判定
    fn should_rename(&self, vn: &Varnode) -> bool {
        // 定数はリネーム不要
        if vn.space == AddressSpace::Const {
            return false;
        }

        // その他のVarnode（Register, Ram, Unique, Stack）はリネーム対象
        true
    }

    /// CFG全体にSSAリネームを適用
    pub fn transform(
        &mut self,
        cfg: &mut ControlFlowGraph,
        dom_tree: &DominanceTree,
    ) {
        // エントリブロックから再帰的にリネーム
        self.rename_recurse(cfg.entry_block, cfg, dom_tree);
    }
}

impl Default for AdvancedSSATransform {
    fn default() -> Self {
        Self::new()
    }
}

/// DominanceTreeの拡張メソッド
pub trait DominanceTreeExt {
    /// 指定ブロックの支配子を取得
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
