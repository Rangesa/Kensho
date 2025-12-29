use super::super::pcode::*;
use anyhow::{anyhow, Result};





#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Register {

    RAX = 0,
    RCX = 8,
    RDX = 16,
    RBX = 24,
    RSP = 32,
    RBP = 40,
    RSI = 48,
    RDI = 56,
    R8 = 64,
    R9 = 72,
    R10 = 80,
    R11 = 88,
    R12 = 96,
    R13 = 104,
    R14 = 112,
    R15 = 120,
    RIP = 128,


    RFLAGS = 136,


    XMM0 = 144,
    XMM1 = 160,
    XMM2 = 176,
    XMM3 = 192,
    XMM4 = 208,
    XMM5 = 224,
    XMM6 = 240,
    XMM7 = 256,
    XMM8 = 272,
    XMM9 = 288,
    XMM10 = 304,
    XMM11 = 320,
    XMM12 = 336,
    XMM13 = 352,
    XMM14 = 368,
    XMM15 = 384,
}



pub mod flags {
    pub const CF: u64 = 0;   // Carry Flag
    pub const PF: u64 = 2;   // Parity Flag
    pub const AF: u64 = 4;   // Auxiliary Carry Flag
    pub const ZF: u64 = 6;   // Zero Flag
    pub const SF: u64 = 7;   // Sign Flag
    pub const OF: u64 = 11;  // Overflow Flag
}



#[derive(Debug, Clone)]
pub enum Operand {


    Register(X86Register, usize),


    Immediate(i64, usize),


    Memory {
        base: Option<X86Register>,
        index: Option<X86Register>,
        scale: u8,
        displacement: i64,
        size: usize,
    },
}

impl X86Register {


    pub fn to_varnode(self, size: usize) -> Varnode {
        Varnode::register(self as u64, size)
    }



    pub fn to_varnode_64(self) -> Varnode {
        self.to_varnode(8)
    }



    pub fn to_varnode_32(self) -> Varnode {
        self.to_varnode(4)
    }



    pub fn to_varnode_16(self) -> Varnode {
        self.to_varnode(2)
    }



    pub fn to_varnode_8(self) -> Varnode {
        self.to_varnode(1)
    }



    pub fn from_str(s: &str) -> Result<(Self, usize)> {
        let s_lower = s.to_lowercase();
        let s_ref = s_lower.as_str();

        // 64-bit registers
        let result = match s_ref {
            "rax" => (X86Register::RAX, 8),
            "rcx" => (X86Register::RCX, 8),
            "rdx" => (X86Register::RDX, 8),
            "rbx" => (X86Register::RBX, 8),
            "rsp" => (X86Register::RSP, 8),
            "rbp" => (X86Register::RBP, 8),
            "rsi" => (X86Register::RSI, 8),
            "rdi" => (X86Register::RDI, 8),
            "r8" => (X86Register::R8, 8),
            "r9" => (X86Register::R9, 8),
            "r10" => (X86Register::R10, 8),
            "r11" => (X86Register::R11, 8),
            "r12" => (X86Register::R12, 8),
            "r13" => (X86Register::R13, 8),
            "r14" => (X86Register::R14, 8),
            "r15" => (X86Register::R15, 8),
            "rip" => (X86Register::RIP, 8),

            // 32-bit registers
            "eax" => (X86Register::RAX, 4),
            "ecx" => (X86Register::RCX, 4),
            "edx" => (X86Register::RDX, 4),
            "ebx" => (X86Register::RBX, 4),
            "esp" => (X86Register::RSP, 4),
            "ebp" => (X86Register::RBP, 4),
            "esi" => (X86Register::RSI, 4),
            "edi" => (X86Register::RDI, 4),
            "r8d" => (X86Register::R8, 4),
            "r9d" => (X86Register::R9, 4),
            "r10d" => (X86Register::R10, 4),
            "r11d" => (X86Register::R11, 4),
            "r12d" => (X86Register::R12, 4),
            "r13d" => (X86Register::R13, 4),
            "r14d" => (X86Register::R14, 4),
            "r15d" => (X86Register::R15, 4),

            // 16-bit registers
            "ax" => (X86Register::RAX, 2),
            "cx" => (X86Register::RCX, 2),
            "dx" => (X86Register::RDX, 2),
            "bx" => (X86Register::RBX, 2),
            "sp" => (X86Register::RSP, 2),
            "bp" => (X86Register::RBP, 2),
            "si" => (X86Register::RSI, 2),
            "di" => (X86Register::RDI, 2),
            "r8w" => (X86Register::R8, 2),
            "r9w" => (X86Register::R9, 2),
            "r10w" => (X86Register::R10, 2),
            "r11w" => (X86Register::R11, 2),
            "r12w" => (X86Register::R12, 2),
            "r13w" => (X86Register::R13, 2),
            "r14w" => (X86Register::R14, 2),
            "r15w" => (X86Register::R15, 2),

            // 8-bit registers (low)
            "al" => (X86Register::RAX, 1),
            "cl" => (X86Register::RCX, 1),
            "dl" => (X86Register::RDX, 1),
            "bl" => (X86Register::RBX, 1),
            "spl" => (X86Register::RSP, 1),
            "bpl" => (X86Register::RBP, 1),
            "sil" => (X86Register::RSI, 1),
            "dil" => (X86Register::RDI, 1),
            "r8b" => (X86Register::R8, 1),
            "r9b" => (X86Register::R9, 1),
            "r10b" => (X86Register::R10, 1),
            "r11b" => (X86Register::R11, 1),
            "r12b" => (X86Register::R12, 1),
            "r13b" => (X86Register::R13, 1),
            "r14b" => (X86Register::R14, 1),
            "r15b" => (X86Register::R15, 1),

            _ => return Err(anyhow!("Unknown register: {}", s)),
        };

        Ok(result)
    }
}
