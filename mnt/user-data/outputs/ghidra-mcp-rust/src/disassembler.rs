use anyhow::{Context, Result};
use capstone::prelude::*;
use goblin::Object;
use std::fs;

pub struct Disassembler {
    binary_data: Vec<u8>,
    arch: Arch,
    mode: Mode,
}

impl Disassembler {
    pub fn new(path: &str) -> Result<Self> {
        let binary_data = fs::read(path)?;
        let object = Object::parse(&binary_data)?;

        let (arch, mode) = match object {
            Object::Elf(elf) => {
                match elf.header.e_machine {
                    0x03 => (Arch::X86, Mode::Mode32),      // x86 32-bit
                    0x3E => (Arch::X86, Mode::Mode64),      // x86-64
                    0x28 => (Arch::ARM, Mode::Arm),         // ARM
                    0xB7 => (Arch::ARM64, Mode::Arm),       // AArch64
                    0x08 => (Arch::MIPS, Mode::Mode32),     // MIPS
                    0xF3 => (Arch::RISCV, Mode::RiscV64),   // RISC-V
                    _ => (Arch::X86, Mode::Mode64),         // 繝・ヵ繧ｩ繝ｫ繝・                }
            }
            Object::PE(pe) => {
                match pe.header.coff_header.machine {
                    0x14c => (Arch::X86, Mode::Mode32),     // x86 32-bit
                    0x8664 => (Arch::X86, Mode::Mode64),    // x86-64
                    0x1c0 => (Arch::ARM, Mode::Arm),        // ARM
                    0xaa64 => (Arch::ARM64, Mode::Arm),     // ARM64
                    _ => (Arch::X86, Mode::Mode64),
                }
            }
            Object::Mach(mach) => {
                match mach {
                    goblin::mach::Mach::Binary(macho) => {
                        match macho.header.cputype {
                            0x7 => (Arch::X86, Mode::Mode32),
                            0x1000007 => (Arch::X86, Mode::Mode64),
                            0xc => (Arch::ARM, Mode::Arm),
                            0x100000c => (Arch::ARM64, Mode::Arm),
                            _ => (Arch::X86, Mode::Mode64),
                        }
                    }
                    _ => (Arch::X86, Mode::Mode64),
                }
            }
            _ => (Arch::X86, Mode::Mode64),
        };

        Ok(Self {
            binary_data,
            arch,
            mode,
        })
    }

    pub fn disassemble(&self, address: u64, count: usize) -> Result<String> {
        let cs = Capstone::new()
            .x86()
            .mode(self.mode)
            .detail(true)
            .build()
            .context("Failed to create Capstone instance")?;

        let mut output = String::new();
        output.push_str(&format!("=== Disassembly at 0x{:x} ===\n\n", address));

        // 繧｢繝峨Ξ繧ｹ縺九ｉ繝舌う繝翫Μ蜀・・繧ｪ繝輔そ繝・ヨ繧定ｨ育ｮ暦ｼ育ｰ｡譏鍋沿・・        let offset = address as usize;
        if offset >= self.binary_data.len() {
            return Ok("Address out of bounds\n".to_string());
        }

        let code = &self.binary_data[offset..];
        let insns = cs
            .disasm_count(code, address, count)
            .context("Disassembly failed")?;

        for insn in insns.iter() {
            output.push_str(&format!(
                "0x{:08x}:  {:<8}  {}\n",
                insn.address(),
                insn.mnemonic().unwrap_or("???"),
                insn.op_str().unwrap_or("")
            ));

            // 繝・ヰ繝・げ逕ｨ・壹ヰ繧､繝医さ繝ｼ繝芽｡ｨ遉ｺ
            let bytes = insn.bytes();
            let bytes_str = bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            output.push_str(&format!("            ; {}\n", bytes_str));
        }

        Ok(output)
    }

    /// 髢｢謨ｰ蜈ｨ菴薙ｒ騾・い繧ｻ繝ｳ繝悶Ν・亥宛蠕｡繝輔Ο繝ｼ霑ｽ霍｡莉倥″・・    pub fn disassemble_function(&self, start_address: u64) -> Result<(Vec<Instruction>, Vec<u64>)> {
        let cs = Capstone::new()
            .x86()
            .mode(self.mode)
            .detail(true)
            .build()?;

        let mut instructions = Vec::new();
        let mut branches = Vec::new();
        let mut current_addr = start_address;
        let mut visited = std::collections::HashSet::new();

        // 邁｡譏鍋噪縺ｪ髢｢謨ｰ邨らｫｯ讀懷・・域怙螟ｧ1000蜻ｽ莉､・・        for _ in 0..1000 {
            if visited.contains(&current_addr) {
                break;
            }
            visited.insert(current_addr);

            let offset = current_addr as usize;
            if offset >= self.binary_data.len() {
                break;
            }

            let code = &self.binary_data[offset..];
            if let Ok(insns) = cs.disasm_count(code, current_addr, 1) {
                if let Some(insn) = insns.iter().next() {
                    let mnemonic = insn.mnemonic().unwrap_or("");
                    
                    // 蜻ｽ莉､諠・ｱ繧剃ｿ晏ｭ・                    instructions.push(Instruction {
                        address: insn.address(),
                        mnemonic: mnemonic.to_string(),
                        operands: insn.op_str().unwrap_or("").to_string(),
                        size: insn.bytes().len(),
                    });

                    // 蛻・ｲ仙多莉､縺ｮ讀懷・
                    if mnemonic.starts_with('j') || mnemonic == "call" {
                        // 邁｡譏鍋噪縺ｪ蛻・ｲ仙・隗｣譫撰ｼ亥ｮ滄圀縺ｯ繧医ｊ隍・尅・・                        if let Some(op_str) = insn.op_str() {
                            if let Some(target) = parse_branch_target(op_str) {
                                branches.push(target);
                            }
                        }
                    }

                    // 髢｢謨ｰ邨らｫｯ蜻ｽ莉､
                    if mnemonic == "ret" || mnemonic == "retn" {
                        break;
                    }

                    current_addr += insn.bytes().len() as u64;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok((instructions, branches))
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub size: usize,
}

fn parse_branch_target(op_str: &str) -> Option<u64> {
    // "0x12345678" 蠖｢蠑上・繧｢繝峨Ξ繧ｹ謚ｽ蜃ｺ
    if op_str.starts_with("0x") {
        u64::from_str_radix(&op_str[2..], 16).ok()
    } else {
        None
    }
}
