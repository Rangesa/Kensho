/// ジャンプテーブル検出とSwitch文復元
///
/// Ghidraのjumptable.ccに基づく実装
/// 間接ジャンプ（jmp [rip+rax*8]等）からswitch-case構造を復元

use crate::decompiler_prototype::pcode::{AddressSpace, OpCode, PcodeOp, Varnode};
use crate::decompiler_prototype::dataflow::DefUseChain;
use std::collections::{HashMap, HashSet};
use anyhow::Result;

/// ジャンプテーブル情報
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// ジャンプテーブルのアドレス
    pub table_address: u64,
    /// エントリ数
    pub num_entries: usize,
    /// エントリサイズ（バイト）
    pub entry_size: usize,
    /// ジャンプ先アドレスのリスト
    pub destinations: Vec<u64>,
    /// スイッチ変数（インデックス）
    pub switch_var: Varnode,
}

/// Switch-Case構造
#[derive(Debug, Clone)]
pub struct SwitchStatement {
    /// switch文のアドレス
    pub address: u64,
    /// スイッチ変数
    pub switch_var: Varnode,
    /// case分岐のリスト
    pub cases: Vec<CaseBranch>,
    /// defaultケース（存在する場合）
    pub default_case: Option<u64>,
}

/// Caseラベルと分岐先
#[derive(Debug, Clone)]
pub struct CaseBranch {
    /// caseラベルの値
    pub label: u64,
    /// 分岐先アドレス
    pub target: u64,
}

/// ジャンプテーブル検出器
pub struct JumpTableDetector {
    du_chain: DefUseChain,
}

impl JumpTableDetector {
    pub fn new(du_chain: DefUseChain) -> Self {
        Self { du_chain }
    }

    /// P-code操作列からジャンプテーブルを検出
    pub fn detect(&self, ops: &[PcodeOp]) -> Vec<JumpTable> {
        let mut tables = Vec::new();

        for op in ops {
            // 間接ジャンプ命令を探す
            if op.opcode == OpCode::BranchInd {
                if let Some(table) = self.analyze_indirect_branch(op, ops) {
                    tables.push(table);
                }
            }
        }

        tables
    }

    /// 間接ジャンプ命令を解析
    fn analyze_indirect_branch(&self, op: &PcodeOp, _ops: &[PcodeOp]) -> Option<JumpTable> {
        if op.inputs.is_empty() {
            return None;
        }

        // ジャンプ先アドレスを計算するVarnodeを取得
        let target_vn = &op.inputs[0];

        // Load操作からジャンプテーブルを検出
        // パターン: target = Load(table_base + index * entry_size)
        if let Some(load_op) = self.du_chain.get_def(target_vn) {
            if load_op.opcode == OpCode::Load && load_op.inputs.len() >= 2 {
                return self.analyze_load_pattern(&load_op.inputs[1], op.address);
            }
        }

        None
    }

    /// Load操作のアドレス計算パターンを解析
    ///
    /// パターン例:
    /// - [rip + index * 8]
    /// - [table_base + index * 4]
    fn analyze_load_pattern(&self, addr_vn: &Varnode, _switch_addr: u64) -> Option<JumpTable> {
        // アドレス計算の定義を取得
        let addr_op = self.du_chain.get_def(addr_vn)?;

        // PtrAdd: base + offset
        if addr_op.opcode == OpCode::PtrAdd && addr_op.inputs.len() >= 2 {
            let base = &addr_op.inputs[0];
            let offset = &addr_op.inputs[1];

            // 定数ベースアドレス
            if base.space == AddressSpace::Const {
                let table_address = base.offset;

                // オフセットが乗算（index * entry_size）の場合
                if let Some(mult_op) = self.du_chain.get_def(offset) {
                    if mult_op.opcode == OpCode::IntMult && mult_op.inputs.len() >= 2 {
                        let switch_var = mult_op.inputs[0].clone();
                        let entry_size = if mult_op.inputs[1].space == AddressSpace::Const {
                            mult_op.inputs[1].offset as usize
                        } else {
                            8 // デフォルト64bitポインタ
                        };

                        // 簡易版: エントリ数は推定（実際にはメモリ読み取りが必要）
                        let num_entries = 10; // 暫定値

                        return Some(JumpTable {
                            table_address,
                            num_entries,
                            entry_size,
                            destinations: Vec::new(), // メモリ読み取りで埋める
                            switch_var,
                        });
                    }
                }

                // 直接オフセット（entry_size=1と仮定）
                return Some(JumpTable {
                    table_address,
                    num_entries: 10,
                    entry_size: 8,
                    destinations: Vec::new(),
                    switch_var: offset.clone(),
                });
            }
        }

        None
    }

    /// ジャンプテーブルからSwitch文を復元
    pub fn recover_switch(&self, table: &JumpTable) -> SwitchStatement {
        let mut cases = Vec::new();

        // 各エントリをcaseラベルに変換
        for (label, &target) in table.destinations.iter().enumerate() {
            cases.push(CaseBranch {
                label: label as u64,
                target,
            });
        }

        SwitchStatement {
            address: table.table_address,
            switch_var: table.switch_var.clone(),
            cases,
            default_case: None,
        }
    }
}

/// Switch文のC疑似コード生成
pub struct SwitchPrinter {
    indent_level: usize,
}

impl SwitchPrinter {
    pub fn new() -> Self {
        Self { indent_level: 0 }
    }

    /// Switch文をC疑似コードに変換
    pub fn print(&mut self, switch: &SwitchStatement) -> String {
        let mut output = Vec::new();
        let indent = "  ".repeat(self.indent_level);

        // switch文ヘッダー
        output.push(format!(
            "{}switch (/* varnode at 0x{:x} */) {{",
            indent,
            switch.switch_var.offset
        ));

        // 各caseラベル
        for case in &switch.cases {
            output.push(format!("{}  case {}: goto label_0x{:x};", indent, case.label, case.target));
        }

        // defaultケース
        if let Some(default_addr) = switch.default_case {
            output.push(format!("{}  default: goto label_0x{:x};", indent, default_addr));
        }

        output.push(format!("{}}}", indent));

        output.join("\n")
    }
}

impl Default for SwitchPrinter {
    fn default() -> Self {
        Self::new()
    }
}

/// ジャンプテーブルのメモリ読み取り
///
/// 実際のバイナリからジャンプテーブルの内容を読み取る
pub struct JumpTableLoader {
    binary_data: Vec<u8>,
}

impl JumpTableLoader {
    pub fn new(binary_data: Vec<u8>) -> Self {
        Self { binary_data }
    }

    /// ジャンプテーブルのエントリを読み取り
    pub fn load_entries(&self, table: &mut JumpTable, image_base: u64) -> Result<()> {
        // RVAをファイルオフセットに変換（簡易版）
        let file_offset = self.rva_to_offset(table.table_address, image_base)?;

        table.destinations.clear();

        for i in 0..table.num_entries {
            let entry_offset = file_offset + i * table.entry_size;

            if entry_offset + table.entry_size > self.binary_data.len() {
                break;
            }

            // エントリサイズに応じて読み取り
            let entry_value = match table.entry_size {
                4 => {
                    let bytes = &self.binary_data[entry_offset..entry_offset + 4];
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
                }
                8 => {
                    let bytes = &self.binary_data[entry_offset..entry_offset + 8];
                    u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7],
                    ])
                }
                _ => continue,
            };

            table.destinations.push(entry_value);
        }

        Ok(())
    }

    /// RVAをファイルオフセットに変換
    fn rva_to_offset(&self, rva: u64, image_base: u64) -> Result<usize> {
        // 簡易変換: .textセクション仮定
        let text_rva_start = 0x1000u64;
        let text_file_offset = 0x400usize;

        let relative_rva = if rva >= image_base {
            rva - image_base
        } else {
            rva
        };

        if relative_rva >= text_rva_start {
            Ok((relative_rva - text_rva_start) as usize + text_file_offset)
        } else {
            Ok(relative_rva as usize)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_switch_printer() {
        let switch = SwitchStatement {
            address: 0x1000,
            switch_var: Varnode::register(0, 4),
            cases: vec![
                CaseBranch {
                    label: 0,
                    target: 0x2000,
                },
                CaseBranch {
                    label: 1,
                    target: 0x2010,
                },
                CaseBranch {
                    label: 2,
                    target: 0x2020,
                },
            ],
            default_case: Some(0x2030),
        };

        let mut printer = SwitchPrinter::new();
        let code = printer.print(&switch);

        assert!(code.contains("switch"));
        assert!(code.contains("case 0"));
        assert!(code.contains("case 1"));
        assert!(code.contains("default"));
    }
}
