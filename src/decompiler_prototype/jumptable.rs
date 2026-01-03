/// Jump table detection and switch statement recovery
/// Identifies indirect jumps and converts them to readable switch statements

use crate::decompiler_prototype::pcode::{AddressSpace, OpCode, PcodeOp, Varnode};
use crate::decompiler_prototype::dataflow::DefUseChain;
use anyhow::Result;

/// Represents a jump table structure
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Base address of the jump table
    pub table_address: u64,
    /// Number of entries in the table
    pub num_entries: usize,
    /// Size of each entry (4 or 8 bytes)
    pub entry_size: usize,
    /// Target addresses from the table
    pub destinations: Vec<u64>,
    /// Variable used for switching
    pub switch_var: Varnode,
}

/// Represents a switch statement
#[derive(Debug, Clone)]
pub struct SwitchStatement {
    /// Address of the switch statement
    pub address: u64,
    /// Variable being switched on
    pub switch_var: Varnode,
    /// Case branches
    pub cases: Vec<CaseBranch>,
    /// Default case target (if any)
    pub default_case: Option<u64>,
}

/// Represents a single case in a switch statement
#[derive(Debug, Clone)]
pub struct CaseBranch {
    /// Case label value
    pub label: u64,
    /// Target address for this case
    pub target: u64,
}

/// Jump table detector
pub struct JumpTableDetector {
    du_chain: DefUseChain,
}

impl JumpTableDetector {
    pub fn new(du_chain: DefUseChain) -> Self {
        Self { du_chain }
    }

    /// Detect jump tables in P-code operations
    pub fn detect(&self, ops: &[PcodeOp]) -> Vec<JumpTable> {
        let mut tables = Vec::new();

        for op in ops {
            // Look for indirect branch operations
            if op.opcode == OpCode::BranchInd {
                if let Some(table) = self.analyze_indirect_branch(op, ops) {
                    tables.push(table);
                }
            }
        }

        tables
    }

    /// Analyze indirect branch to detect jump table
    fn analyze_indirect_branch(&self, op: &PcodeOp, _ops: &[PcodeOp]) -> Option<JumpTable> {
        if op.inputs.is_empty() {
            return None;
        }

        // Get varnode that computes jump target address
        let target_vn = &op.inputs[0];

        // Detect jump table from Load operation
        // Pattern: target = Load(table_base + index * entry_size)
        if let Some(load_op) = self.du_chain.get_def(target_vn) {
            if load_op.opcode == OpCode::Load && load_op.inputs.len() >= 2 {
                return self.analyze_load_pattern(&load_op.inputs[1], op.address);
            }
        }

        None
    }

    /// Analyze address computation pattern for jump table
    /// Common patterns:
    /// - [rip + index * 8]
    /// - [table_base + index * 4]
    fn analyze_load_pattern(&self, addr_vn: &Varnode, _switch_addr: u64) -> Option<JumpTable> {
        // Get definition of address computation
        let addr_op = self.du_chain.get_def(addr_vn)?;

        // PtrAdd: base + offset
        if addr_op.opcode == OpCode::PtrAdd && addr_op.inputs.len() >= 2 {
            let base = &addr_op.inputs[0];
            let offset = &addr_op.inputs[1];

            // Constant base address
            if base.space == AddressSpace::Const {
                let table_address = base.offset;

                // If offset is multiplication (index * entry_size)
                if let Some(mult_op) = self.du_chain.get_def(offset) {
                    if mult_op.opcode == OpCode::IntMult && mult_op.inputs.len() >= 2 {
                        let switch_var = mult_op.inputs[0].clone();
                        let entry_size = if mult_op.inputs[1].space == AddressSpace::Const {
                            mult_op.inputs[1].offset as usize
                        } else {
                            8 // Default: 64bit pointer
                        };

                        // Simplified: number of entries is estimated (should read from memory)
                        let num_entries = 10; // Placeholder value

                        return Some(JumpTable {
                            table_address,
                            num_entries,
                            entry_size,
                            destinations: Vec::new(), // Fill by reading memory
                            switch_var,
                        });
                    }
                }

                // Direct offset (assume entry_size=1)
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

    /// Convert jump table to switch statement
    pub fn to_switch_statement(&self, table: &JumpTable) -> SwitchStatement {
        let mut cases = Vec::new();

        // Convert each entry to a case label
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

/// Switch statement printer
pub struct SwitchPrinter {
    indent_level: usize,
}

impl SwitchPrinter {
    pub fn new() -> Self {
        Self { indent_level: 0 }
    }

    /// Print switch statement as C-like code
    pub fn print(&mut self, switch: &SwitchStatement) -> String {
        let mut output = Vec::new();
        let indent = "  ".repeat(self.indent_level);

        // switch header
        output.push(format!(
            "{}switch (/* varnode at 0x{:x} */) {{",
            indent,
            switch.switch_var.offset
        ));

        // Each case label
        for case in &switch.cases {
            output.push(format!("{}  case {}: goto label_0x{:x};", indent, case.label, case.target));
        }

        // default case
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

/// Jump table loader
/// Reads jump table entries from binary data
pub struct JumpTableLoader {
    binary_data: Vec<u8>,
}

impl JumpTableLoader {
    pub fn new(binary_data: Vec<u8>) -> Self {
        Self { binary_data }
    }

    /// Load jump table entries from binary
    pub fn load_entries(&self, table: &mut JumpTable, image_base: u64) -> Result<()> {
        // Convert RVA to file offset (simplified)
        let file_offset = self.rva_to_offset(table.table_address, image_base)?;

        table.destinations.clear();

        for i in 0..table.num_entries {
            let entry_offset = file_offset + i * table.entry_size;

            if entry_offset + table.entry_size > self.binary_data.len() {
                break;
            }

            // Read according to entry size
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

    /// Convert RVA to file offset
    fn rva_to_offset(&self, rva: u64, image_base: u64) -> Result<usize> {
        // Simplified: assume .text section
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
