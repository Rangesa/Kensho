

///







use crate::decompiler_prototype::pcode::*;
use crate::decompiler_prototype::x86_64::X86Register;
use anyhow::{anyhow, Result};
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

// build.rs gen code
    use super::*;
    use iced_x86::{Code, Instruction};
    include!(concat!(env!("OUT_DIR"), "/x86_64_lifter.rs"));
}



pub struct IcedLifter {
    unique_counter: u64,
}

impl IcedLifter {


    pub fn new() -> Self {
        Self {
            unique_counter: 0x10000,
        }
    }



    pub fn lift(&mut self, code: &[u8], base_address: u64, max_instructions: usize) -> Result<Vec<PcodeOp>> {
        let mut decoder = Decoder::with_ip(64, code, base_address, DecoderOptions::NONE);
        let mut pcodes = Vec::new();
        let mut count = 0;

        while decoder.can_decode() && count < max_instructions {
            let instr = decoder.decode();

            match self.lift_instruction(&instr) {
                Ok(mut ops) => pcodes.append(&mut ops),
                Err(e) => {
                    eprintln!("笞・・ Warning: 0x{:x}: {:?} - {}",
                              instr.ip(), instr.code(), e);
                }
            }

            count += 1;
        }

        Ok(pcodes)
    }



    pub fn lift_instruction(&mut self, instr: &Instruction) -> Result<Vec<PcodeOp>> {
        generated::lift_instruction(self, instr).map_err(|e| anyhow!(e))
    }



    pub fn new_unique(&mut self, size: usize) -> Varnode {
        let addr = self.unique_counter;
        self.unique_counter += size as u64;
        Varnode::unique(addr, size)
    }



    pub fn register_to_varnode(&self, reg: Register) -> Result<Varnode> {
        let (offset, size) = match reg {
            // 64-bit豎守畑繝ｬ繧ｸ繧ｹ繧ｿ
            Register::RAX => (X86Register::RAX as u64, 8),
            Register::RCX => (X86Register::RCX as u64, 8),
            Register::RDX => (X86Register::RDX as u64, 8),
            Register::RBX => (X86Register::RBX as u64, 8),
            Register::RSP => (X86Register::RSP as u64, 8),
            Register::RBP => (X86Register::RBP as u64, 8),
            Register::RSI => (X86Register::RSI as u64, 8),
            Register::RDI => (X86Register::RDI as u64, 8),
            Register::R8 => (X86Register::R8 as u64, 8),
            Register::R9 => (X86Register::R9 as u64, 8),
            Register::R10 => (X86Register::R10 as u64, 8),
            Register::R11 => (X86Register::R11 as u64, 8),
            Register::R12 => (X86Register::R12 as u64, 8),
            Register::R13 => (X86Register::R13 as u64, 8),
            Register::R14 => (X86Register::R14 as u64, 8),
            Register::R15 => (X86Register::R15 as u64, 8),

            // 32-bit豎守畑繝ｬ繧ｸ繧ｹ繧ｿ
            Register::EAX => (X86Register::RAX as u64, 4),
            Register::ECX => (X86Register::RCX as u64, 4),
            Register::EDX => (X86Register::RDX as u64, 4),
            Register::EBX => (X86Register::RBX as u64, 4),
            Register::ESP => (X86Register::RSP as u64, 4),
            Register::EBP => (X86Register::RBP as u64, 4),
            Register::ESI => (X86Register::RSI as u64, 4),
            Register::EDI => (X86Register::RDI as u64, 4),
            Register::R8D => (X86Register::R8 as u64, 4),
            Register::R9D => (X86Register::R9 as u64, 4),
            Register::R10D => (X86Register::R10 as u64, 4),
            Register::R11D => (X86Register::R11 as u64, 4),
            Register::R12D => (X86Register::R12 as u64, 4),
            Register::R13D => (X86Register::R13 as u64, 4),
            Register::R14D => (X86Register::R14 as u64, 4),
            Register::R15D => (X86Register::R15 as u64, 4),

            // 16-bit豎守畑繝ｬ繧ｸ繧ｹ繧ｿ
            Register::AX => (X86Register::RAX as u64, 2),
            Register::CX => (X86Register::RCX as u64, 2),
            Register::DX => (X86Register::RDX as u64, 2),
            Register::BX => (X86Register::RBX as u64, 2),
            Register::SP => (X86Register::RSP as u64, 2),
            Register::BP => (X86Register::RBP as u64, 2),
            Register::SI => (X86Register::RSI as u64, 2),
            Register::DI => (X86Register::RDI as u64, 2),

            // 8-bit registers (low)            Register::AL => (X86Register::RAX as u64, 1),
            Register::CL => (X86Register::RCX as u64, 1),
            Register::DL => (X86Register::RDX as u64, 1),
            Register::BL => (X86Register::RBX as u64, 1),

            // 8-bit registers (high)            Register::AH => (X86Register::RAX as u64 + 1, 1),
            Register::CH => (X86Register::RCX as u64 + 1, 1),
            Register::DH => (X86Register::RDX as u64 + 1, 1),
            Register::BH => (X86Register::RBX as u64 + 1, 1),

            // RIP
            Register::RIP => (X86Register::RIP as u64, 8),

            _ => return Err(anyhow!("Unsupported register: {:?}", reg)),
        };

        Ok(Varnode::register(offset, size))
    }



    pub fn operand_to_varnode(&mut self, instr: &Instruction, op_index: u32) -> Result<Varnode> {
        match instr.op_kind(op_index) {
            OpKind::Register => {
                let reg = instr.op_register(op_index);
                self.register_to_varnode(reg)
            }
            OpKind::Immediate8 => {
                Ok(Varnode::constant(instr.immediate8() as u64, 1))
            }
            OpKind::Immediate16 => {
                Ok(Varnode::constant(instr.immediate16() as u64, 2))
            }
            OpKind::Immediate32 => {
                Ok(Varnode::constant(instr.immediate32() as u64, 4))
            }
            OpKind::Immediate64 => {
                Ok(Varnode::constant(instr.immediate64() as u64, 8))
            }
            OpKind::Immediate8to16 => {
                Ok(Varnode::constant(instr.immediate8to16() as i16 as u64, 2))
            }
            OpKind::Immediate8to32 => {
                Ok(Varnode::constant(instr.immediate8to32() as i32 as u64, 4))
            }
            OpKind::Immediate8to64 => {
                Ok(Varnode::constant(instr.immediate8to64() as i64 as u64, 8))
            }
            OpKind::Immediate32to64 => {
                Ok(Varnode::constant(instr.immediate32to64() as i64 as u64, 8))
            }
            OpKind::Memory => {
                Ok(self.new_unique(8))
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Ok(Varnode::constant(instr.near_branch_target(), 8))
            }
            _ => Err(anyhow!("Unsupported operand kind: {:?}", instr.op_kind(op_index))),
        }
    }



        -> Result<(Vec<PcodeOp>, Varnode)> {
        if instr.op_kind(op_index) != OpKind::Memory {
            return Err(anyhow!("Operand is not memory"));
        }

        let mut ops = Vec::new();
        let result = self.new_unique(8);

        // Base register
        let base_reg = instr.memory_base();
        let mut has_base = false;
        if base_reg != Register::None {
            has_base = true;
            let base_vn = self.register_to_varnode(base_reg)?;
            ops.push(PcodeOp::unary(OpCode::Copy, result.clone(), base_vn, addr));
        }

        // Index register
        let index_reg = instr.memory_index();
        if index_reg != Register::None {
            let index_vn = self.register_to_varnode(index_reg)?;
            let scale = instr.memory_index_scale();

            let scaled = if scale > 1 {
                let temp = self.new_unique(8);
                ops.push(PcodeOp::binary(
                    OpCode::IntMult,
                    temp.clone(),
                    index_vn,
                    Varnode::constant(scale as u64, 8),
                    addr
                ));
                temp
            } else {
                index_vn
            };

            if has_base {
                let temp = self.new_unique(8);
                ops.push(PcodeOp::binary(OpCode::IntAdd, temp.clone(), result.clone(), scaled, addr));
                ops.push(PcodeOp::unary(OpCode::Copy, result.clone(), temp, addr));
            } else {
                ops.push(PcodeOp::unary(OpCode::Copy, result.clone(), scaled, addr));
                has_base = true;
            }
        }

        // Displacement
        let disp = instr.memory_displacement64();
        if disp != 0 {
            let disp_vn = Varnode::constant(disp, 8);
            if has_base {
                let temp = self.new_unique(8);
                ops.push(PcodeOp::binary(OpCode::IntAdd, temp.clone(), result.clone(), disp_vn, addr));
                ops.push(PcodeOp::unary(OpCode::Copy, result.clone(), temp, addr));
            } else {
                ops.push(PcodeOp::unary(OpCode::Copy, result.clone(), disp_vn, addr));
            }
        }

        Ok((ops, result))
    }
}

impl Default for IcedLifter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_lifting() {
        let mut lifter = IcedLifter::new();

        // mov rax, 42; ret
        let code = [0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00, 0xc3];

        let result = lifter.lift(&code, 0x1000, 10);
        assert!(result.is_ok());

        let pcodes = result.unwrap();
        println!("Generated {} P-code operations", pcodes.len());
        for op in &pcodes {
            println!("  0x{:x}: {}", op.address, op);
        }
    }

    #[test]
    fn test_register_conversion() {
        let lifter = IcedLifter::new();

        // RAX
        let vn = lifter.register_to_varnode(Register::RAX).unwrap();
        assert_eq!(vn.space, AddressSpace::Register);
        assert_eq!(vn.offset, 0);
        assert_eq!(vn.size, 8);

        // EAX
        let vn = lifter.register_to_varnode(Register::EAX).unwrap();
        assert_eq!(vn.offset, 0);
        assert_eq!(vn.size, 4);

        // AL
        let vn = lifter.register_to_varnode(Register::AL).unwrap();
        assert_eq!(vn.offset, 0);
        assert_eq!(vn.size, 1);

        // AH        let vn = lifter.register_to_varnode(Register::AH).unwrap();
        assert_eq!(vn.offset, 1);
        assert_eq!(vn.size, 1);
    }
}
