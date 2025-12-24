/// x86-64アーキテクチャのP-code変換
/// 実用レベル実装：50+命令をサポート

use super::pcode::*;
use anyhow::{anyhow, Result};

/// x86-64レジスタのオフセット定義
/// レジスタをAddressSpace::Registerの連続したオフセットで表現
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Register {
    // 64-bit汎用レジスタ
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

    // フラグレジスタ（特殊）
    RFLAGS = 136,

    // SSE/AVX レジスタ（128-bit XMM）
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

/// x86フラグビット位置
pub mod flags {
    pub const CF: u64 = 0;   // Carry Flag
    pub const PF: u64 = 2;   // Parity Flag
    pub const AF: u64 = 4;   // Auxiliary Carry Flag
    pub const ZF: u64 = 6;   // Zero Flag
    pub const SF: u64 = 7;   // Sign Flag
    pub const OF: u64 = 11;  // Overflow Flag
}

/// オペランドの種類
#[derive(Debug, Clone)]
pub enum Operand {
    /// レジスタ
    Register(X86Register, usize),  // (レジスタ, サイズ)
    /// 即値
    Immediate(i64, usize),
    /// メモリ [base + index*scale + disp]
    Memory {
        base: Option<X86Register>,
        index: Option<X86Register>,
        scale: u8,
        displacement: i64,
        size: usize,
    },
}

impl X86Register {
    /// レジスタ名からVarnodeを生成（指定サイズ）
    pub fn to_varnode(self, size: usize) -> Varnode {
        Varnode::register(self as u64, size)
    }

    /// レジスタ名からVarnodeを生成（64ビット）
    pub fn to_varnode_64(self) -> Varnode {
        self.to_varnode(8)
    }

    /// レジスタ名からVarnodeを生成（32ビット）
    pub fn to_varnode_32(self) -> Varnode {
        self.to_varnode(4)
    }

    /// レジスタ名からVarnodeを生成（16ビット）
    pub fn to_varnode_16(self) -> Varnode {
        self.to_varnode(2)
    }

    /// レジスタ名からVarnodeを生成（8ビット）
    pub fn to_varnode_8(self) -> Varnode {
        self.to_varnode(1)
    }

    /// 文字列からレジスタを解析
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

/// x86-64命令デコーダー
/// 実用レベル実装：50+命令をサポート
pub struct X86Decoder {
    unique_counter: u64,
}

impl Default for X86Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl X86Decoder {
    pub fn new() -> Self {
        Self {
            unique_counter: 0x10000,  // 一時変数は高アドレスから開始
        }
    }

    /// 次の一時変数を生成
    fn next_unique(&mut self, size: usize) -> Varnode {
        let offset = self.unique_counter;
        self.unique_counter += size as u64;
        Varnode::unique(offset, size)
    }

    /// ZFフラグのVarnode
    fn zf_varnode(&self) -> Varnode {
        Varnode::unique(flags::ZF, 1)
    }

    /// SFフラグのVarnode
    fn sf_varnode(&self) -> Varnode {
        Varnode::unique(flags::SF, 1)
    }

    /// OFフラグのVarnode
    fn of_varnode(&self) -> Varnode {
        Varnode::unique(flags::OF, 1)
    }

    /// CFフラグのVarnode
    fn cf_varnode(&self) -> Varnode {
        Varnode::unique(flags::CF, 1)
    }

    // ===== 基本データ移動命令 =====

    /// mov reg, reg
    pub fn decode_mov(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        vec![PcodeOp::unary(OpCode::Copy, dest_vn, src_vn, address)]
    }

    /// mov reg, imm
    pub fn decode_mov_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = Varnode::constant(imm as u64, size);
        vec![PcodeOp::unary(OpCode::Copy, dest_vn, src_vn, address)]
    }

    /// mov reg, [mem]
    pub fn decode_mov_load(&mut self, dest: X86Register, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        vec![PcodeOp::unary(OpCode::Load, dest_vn, mem_addr, address)]
    }

    /// mov [mem], reg
    pub fn decode_mov_store(&mut self, mem_addr: Varnode, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let src_vn = src.to_varnode(size);
        vec![PcodeOp::no_output(OpCode::Store, vec![mem_addr, src_vn], address)]
    }

    /// lea reg, [mem] - メモリアドレスをレジスタにロード
    pub fn decode_lea(&mut self, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode_64();
        vec![PcodeOp::unary(OpCode::Copy, dest_vn, mem_addr, address)]
    }

    /// movzx - ゼロ拡張
    pub fn decode_movzx(&mut self, dest: X86Register, src: X86Register, dest_size: usize, src_size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(dest_size);
        let src_vn = src.to_varnode(src_size);
        vec![PcodeOp::unary(OpCode::IntZExt, dest_vn, src_vn, address)]
    }

    /// movsx - 符号拡張
    pub fn decode_movsx(&mut self, dest: X86Register, src: X86Register, dest_size: usize, src_size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(dest_size);
        let src_vn = src.to_varnode(src_size);
        vec![PcodeOp::unary(OpCode::IntSExt, dest_vn, src_vn, address)]
    }

    /// xchg - レジスタ交換
    pub fn decode_xchg(&mut self, reg1: X86Register, reg2: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg1_vn = reg1.to_varnode(size);
        let reg2_vn = reg2.to_varnode(size);
        let temp = self.next_unique(size);

        vec![
            PcodeOp::unary(OpCode::Copy, temp.clone(), reg1_vn.clone(), address),
            PcodeOp::unary(OpCode::Copy, reg1_vn, reg2_vn.clone(), address),
            PcodeOp::unary(OpCode::Copy, reg2_vn, temp, address),
        ]
    }

    // ===== 算術演算命令 =====

    /// add reg, reg
    pub fn decode_add(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntAdd, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
        ops.extend(self.update_flags_arithmetic(&dest_vn, address));
        ops
    }

    /// add reg, imm
    pub fn decode_add_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntAdd, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
        ops.extend(self.update_flags_arithmetic(&dest_vn, address));
        ops
    }

    /// sub reg, reg
    pub fn decode_sub(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntSub, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
        ops.extend(self.update_flags_arithmetic(&dest_vn, address));
        ops
    }

    /// sub reg, imm
    pub fn decode_sub_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntSub, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
        ops.extend(self.update_flags_arithmetic(&dest_vn, address));
        ops
    }

    /// inc reg
    pub fn decode_inc(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let one = Varnode::constant(1, size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntAdd, reg_vn.clone(), reg_vn.clone(), one, address)];
        ops.extend(self.update_flags_arithmetic(&reg_vn, address));
        ops
    }

    /// dec reg
    pub fn decode_dec(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let one = Varnode::constant(1, size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntSub, reg_vn.clone(), reg_vn.clone(), one, address)];
        ops.extend(self.update_flags_arithmetic(&reg_vn, address));
        ops
    }

    /// inc [memory] - メモリインクリメント
    pub fn decode_inc_mem(&mut self, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
        let value_temp = self.next_unique(size);
        let one = Varnode::constant(1, size);
        let result_temp = self.next_unique(size);

        vec![
            // value_temp = *mem_addr (Load)
            PcodeOp::unary(OpCode::Load, value_temp.clone(), mem_addr.clone(), address),
            // result_temp = value_temp + 1
            PcodeOp::binary(OpCode::IntAdd, result_temp.clone(), value_temp, one, address),
            // *mem_addr = result_temp (Store)
            PcodeOp::no_output(OpCode::Store, vec![mem_addr, result_temp.clone()], address),
            // フラグ更新は簡略化のため省略（必要なら追加）
        ]
    }

    /// dec [memory] - メモリデクリメント
    pub fn decode_dec_mem(&mut self, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
        let value_temp = self.next_unique(size);
        let one = Varnode::constant(1, size);
        let result_temp = self.next_unique(size);

        vec![
            // value_temp = *mem_addr (Load)
            PcodeOp::unary(OpCode::Load, value_temp.clone(), mem_addr.clone(), address),
            // result_temp = value_temp - 1
            PcodeOp::binary(OpCode::IntSub, result_temp.clone(), value_temp, one, address),
            // *mem_addr = result_temp (Store)
            PcodeOp::no_output(OpCode::Store, vec![mem_addr, result_temp.clone()], address),
        ]
    }

    /// neg reg - 二の補数
    pub fn decode_neg(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let mut ops = vec![PcodeOp::unary(OpCode::Int2Comp, reg_vn.clone(), reg_vn.clone(), address)];
        ops.extend(self.update_flags_arithmetic(&reg_vn, address));
        ops
    }

    /// imul reg, reg - 符号付き乗算
    pub fn decode_imul(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        vec![PcodeOp::binary(OpCode::IntMult, dest_vn.clone(), dest_vn, src_vn, address)]
    }

    /// imul reg, reg, imm - 三オペランド符号付き乗算
    pub fn decode_imul3(&mut self, dest: X86Register, src: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        vec![PcodeOp::binary(OpCode::IntMult, dest_vn, src_vn, imm_vn, address)]
    }

    /// mul reg - 符号なし乗算 (RDX:RAX = RAX * reg)
    pub fn decode_mul(&mut self, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let rax = X86Register::RAX.to_varnode(size);
        let rdx = X86Register::RDX.to_varnode(size);
        let src_vn = src.to_varnode(size);

        // 結果は2倍のサイズの一時変数に格納
        let result = self.next_unique(size * 2);

        vec![
            PcodeOp::binary(OpCode::IntMult, result.clone(), rax.clone(), src_vn, address),
            // 下位半分をRAXに
            PcodeOp::unary(OpCode::SubPiece, rax, Varnode::constant(0, size), address),
            // 上位半分をRDXに
            PcodeOp::unary(OpCode::SubPiece, rdx, Varnode::constant(size as u64, size), address),
        ]
    }

    /// div reg - 符号なし除算 (RAX = RDX:RAX / reg, RDX = RDX:RAX % reg)
    pub fn decode_div(&mut self, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let rax = X86Register::RAX.to_varnode(size);
        let rdx = X86Register::RDX.to_varnode(size);
        let src_vn = src.to_varnode(size);

        vec![
            // 商をRAXに
            PcodeOp::binary(OpCode::IntDiv, rax.clone(), rax.clone(), src_vn.clone(), address),
            // 剰余をRDXに
            PcodeOp::binary(OpCode::IntRem, rdx, rax, src_vn, address),
        ]
    }

    /// idiv reg - 符号付き除算
    pub fn decode_idiv(&mut self, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let rax = X86Register::RAX.to_varnode(size);
        let rdx = X86Register::RDX.to_varnode(size);
        let src_vn = src.to_varnode(size);

        vec![
            PcodeOp::binary(OpCode::IntSDiv, rax.clone(), rax.clone(), src_vn.clone(), address),
            PcodeOp::binary(OpCode::IntSRem, rdx, rax, src_vn, address),
        ]
    }

    // ===== ビット演算命令 =====

    /// and reg, reg
    pub fn decode_and(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
        ops.extend(self.update_flags_logical(&dest_vn, address));
        ops
    }

    /// and reg, imm
    pub fn decode_and_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
        ops.extend(self.update_flags_logical(&dest_vn, address));
        ops
    }

    /// or reg, reg
    pub fn decode_or(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntOr, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
        ops.extend(self.update_flags_logical(&dest_vn, address));
        ops
    }

    /// or reg, imm
    pub fn decode_or_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntOr, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
        ops.extend(self.update_flags_logical(&dest_vn, address));
        ops
    }

    /// xor reg, reg
    pub fn decode_xor(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntXor, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
        ops.extend(self.update_flags_logical(&dest_vn, address));
        ops
    }

    /// xor reg, imm
    pub fn decode_xor_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        let mut ops = vec![PcodeOp::binary(OpCode::IntXor, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
        ops.extend(self.update_flags_logical(&dest_vn, address));
        ops
    }

    /// not reg - ビット反転
    pub fn decode_not(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        vec![PcodeOp::unary(OpCode::IntNegate, reg_vn.clone(), reg_vn, address)]
    }

    /// shl/sal reg, imm - 左シフト
    pub fn decode_shl(&mut self, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let count_vn = Varnode::constant(count as u64, 1);
        let mut ops = vec![PcodeOp::binary(OpCode::IntLeft, reg_vn.clone(), reg_vn.clone(), count_vn, address)];
        ops.extend(self.update_flags_logical(&reg_vn, address));
        ops
    }

    /// shl/sal reg, cl - 左シフト（CLでカウント）
    pub fn decode_shl_cl(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let cl = X86Register::RCX.to_varnode_8();
        let mut ops = vec![PcodeOp::binary(OpCode::IntLeft, reg_vn.clone(), reg_vn.clone(), cl, address)];
        ops.extend(self.update_flags_logical(&reg_vn, address));
        ops
    }

    /// shr reg, imm - 論理右シフト
    pub fn decode_shr(&mut self, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let count_vn = Varnode::constant(count as u64, 1);
        let mut ops = vec![PcodeOp::binary(OpCode::IntRight, reg_vn.clone(), reg_vn.clone(), count_vn, address)];
        ops.extend(self.update_flags_logical(&reg_vn, address));
        ops
    }

    /// shr reg, cl - 論理右シフト（CLでカウント）
    pub fn decode_shr_cl(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let cl = X86Register::RCX.to_varnode_8();
        let mut ops = vec![PcodeOp::binary(OpCode::IntRight, reg_vn.clone(), reg_vn.clone(), cl, address)];
        ops.extend(self.update_flags_logical(&reg_vn, address));
        ops
    }

    /// sar reg, imm - 算術右シフト
    pub fn decode_sar(&mut self, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let count_vn = Varnode::constant(count as u64, 1);
        let mut ops = vec![PcodeOp::binary(OpCode::IntSRight, reg_vn.clone(), reg_vn.clone(), count_vn, address)];
        ops.extend(self.update_flags_logical(&reg_vn, address));
        ops
    }

    /// sar reg, cl - 算術右シフト（CLでカウント）
    pub fn decode_sar_cl(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let cl = X86Register::RCX.to_varnode_8();
        let mut ops = vec![PcodeOp::binary(OpCode::IntSRight, reg_vn.clone(), reg_vn.clone(), cl, address)];
        ops.extend(self.update_flags_logical(&reg_vn, address));
        ops
    }

    // ===== 比較・テスト命令 =====

    /// cmp reg, reg
    pub fn decode_cmp(&mut self, lhs: X86Register, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let lhs_vn = lhs.to_varnode(size);
        let rhs_vn = rhs.to_varnode(size);
        let temp = self.next_unique(size);

        let mut ops = vec![
            PcodeOp::binary(OpCode::IntSub, temp.clone(), lhs_vn.clone(), rhs_vn.clone(), address),
        ];

        // フラグ更新
        ops.push(PcodeOp::binary(OpCode::IntEqual, self.zf_varnode(), lhs_vn.clone(), rhs_vn.clone(), address));
        ops.push(PcodeOp::binary(OpCode::IntSLess, self.sf_varnode(), lhs_vn.clone(), rhs_vn.clone(), address));
        ops.push(PcodeOp::binary(OpCode::IntLess, self.cf_varnode(), lhs_vn, rhs_vn, address));

        ops
    }

    /// cmp reg, imm
    pub fn decode_cmp_imm(&mut self, lhs: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let lhs_vn = lhs.to_varnode(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        let temp = self.next_unique(size);

        let mut ops = vec![
            PcodeOp::binary(OpCode::IntSub, temp, lhs_vn.clone(), imm_vn.clone(), address),
        ];

        ops.push(PcodeOp::binary(OpCode::IntEqual, self.zf_varnode(), lhs_vn.clone(), imm_vn.clone(), address));
        ops.push(PcodeOp::binary(OpCode::IntSLess, self.sf_varnode(), lhs_vn.clone(), imm_vn.clone(), address));
        ops.push(PcodeOp::binary(OpCode::IntLess, self.cf_varnode(), lhs_vn, imm_vn, address));

        ops
    }

    /// cmp [memory], reg - メモリとレジスタの比較
    pub fn decode_cmp_mem_reg(&mut self, mem_addr: Varnode, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let mem_value = self.next_unique(size);
        let rhs_vn = rhs.to_varnode(size);
        let temp = self.next_unique(size);

        vec![
            // mem_value = *mem_addr (Load)
            PcodeOp::unary(OpCode::Load, mem_value.clone(), mem_addr, address),
            // temp = mem_value - rhs (比較)
            PcodeOp::binary(OpCode::IntSub, temp, mem_value.clone(), rhs_vn.clone(), address),
            // フラグ更新
            PcodeOp::binary(OpCode::IntEqual, self.zf_varnode(), mem_value.clone(), rhs_vn.clone(), address),
            PcodeOp::binary(OpCode::IntSLess, self.sf_varnode(), mem_value.clone(), rhs_vn.clone(), address),
            PcodeOp::binary(OpCode::IntLess, self.cf_varnode(), mem_value, rhs_vn, address),
        ]
    }

    /// cmp [memory], imm - メモリと即値の比較
    pub fn decode_cmp_mem_imm(&mut self, mem_addr: Varnode, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let mem_value = self.next_unique(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        let temp = self.next_unique(size);

        vec![
            // mem_value = *mem_addr (Load)
            PcodeOp::unary(OpCode::Load, mem_value.clone(), mem_addr, address),
            // temp = mem_value - imm (比較)
            PcodeOp::binary(OpCode::IntSub, temp, mem_value.clone(), imm_vn.clone(), address),
            // フラグ更新
            PcodeOp::binary(OpCode::IntEqual, self.zf_varnode(), mem_value.clone(), imm_vn.clone(), address),
            PcodeOp::binary(OpCode::IntSLess, self.sf_varnode(), mem_value.clone(), imm_vn.clone(), address),
            PcodeOp::binary(OpCode::IntLess, self.cf_varnode(), mem_value, imm_vn, address),
        ]
    }

    /// test reg, reg - AND演算してフラグのみ更新
    pub fn decode_test(&mut self, lhs: X86Register, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        let lhs_vn = lhs.to_varnode(size);
        let rhs_vn = rhs.to_varnode(size);
        let temp = self.next_unique(size);

        let mut ops = vec![
            PcodeOp::binary(OpCode::IntAnd, temp.clone(), lhs_vn, rhs_vn, address),
        ];
        ops.extend(self.update_flags_logical(&temp, address));
        ops
    }

    /// test reg, imm
    pub fn decode_test_imm(&mut self, reg: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode(size);
        let imm_vn = Varnode::constant(imm as u64, size);
        let temp = self.next_unique(size);

        let mut ops = vec![
            PcodeOp::binary(OpCode::IntAnd, temp.clone(), reg_vn, imm_vn, address),
        ];
        ops.extend(self.update_flags_logical(&temp, address));
        ops
    }

    // ===== スタック操作命令 =====

    /// push reg
    pub fn decode_push(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let reg_vn = reg.to_varnode_64();
        let eight = Varnode::constant(8, 8);

        vec![
            // RSP -= 8
            PcodeOp::binary(OpCode::IntSub, rsp.clone(), rsp.clone(), eight, address),
            // [RSP] = reg
            PcodeOp::no_output(OpCode::Store, vec![rsp, reg_vn], address),
        ]
    }

    /// push imm
    pub fn decode_push_imm(&mut self, imm: i64, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let imm_vn = Varnode::constant(imm as u64, 8);
        let eight = Varnode::constant(8, 8);

        vec![
            PcodeOp::binary(OpCode::IntSub, rsp.clone(), rsp.clone(), eight, address),
            PcodeOp::no_output(OpCode::Store, vec![rsp, imm_vn], address),
        ]
    }

    /// pop reg
    pub fn decode_pop(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let reg_vn = reg.to_varnode_64();
        let eight = Varnode::constant(8, 8);

        vec![
            // reg = [RSP]
            PcodeOp::unary(OpCode::Load, reg_vn, rsp.clone(), address),
            // RSP += 8
            PcodeOp::binary(OpCode::IntAdd, rsp.clone(), rsp, eight, address),
        ]
    }

    /// enter imm16, imm8 - スタックフレーム作成
    pub fn decode_enter(&mut self, size: u16, level: u8, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let rbp = X86Register::RBP.to_varnode_64();
        let size_vn = Varnode::constant(size as u64, 8);
        let eight = Varnode::constant(8, 8);

        let mut ops = vec![
            // push rbp
            PcodeOp::binary(OpCode::IntSub, rsp.clone(), rsp.clone(), eight.clone(), address),
            PcodeOp::no_output(OpCode::Store, vec![rsp.clone(), rbp.clone()], address),
            // mov rbp, rsp
            PcodeOp::unary(OpCode::Copy, rbp, rsp.clone(), address),
            // sub rsp, size
            PcodeOp::binary(OpCode::IntSub, rsp.clone(), rsp, size_vn, address),
        ];

        // level > 0の場合は追加処理が必要だが、通常は0
        let _ = level;

        ops
    }

    /// leave - スタックフレーム破棄
    pub fn decode_leave(&mut self, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let rbp = X86Register::RBP.to_varnode_64();
        let eight = Varnode::constant(8, 8);

        vec![
            // mov rsp, rbp
            PcodeOp::unary(OpCode::Copy, rsp.clone(), rbp.clone(), address),
            // pop rbp
            PcodeOp::unary(OpCode::Load, rbp, rsp.clone(), address),
            PcodeOp::binary(OpCode::IntAdd, rsp.clone(), rsp, eight, address),
        ]
    }

    // ===== 制御フロー命令 =====

    /// jmp target - 無条件ジャンプ
    pub fn decode_jmp(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        vec![PcodeOp::no_output(OpCode::Branch, vec![target_vn], address)]
    }

    /// jmp reg - 間接ジャンプ
    pub fn decode_jmp_indirect(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode_64();
        vec![PcodeOp::no_output(OpCode::BranchInd, vec![reg_vn], address)]
    }

    /// call target - 関数呼び出し
    pub fn decode_call(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let return_addr = Varnode::constant(address + 5, 8);  // 次の命令アドレス
        let target_vn = Varnode::constant(target, 8);
        let eight = Varnode::constant(8, 8);

        vec![
            // push return_addr
            PcodeOp::binary(OpCode::IntSub, rsp.clone(), rsp.clone(), eight, address),
            PcodeOp::no_output(OpCode::Store, vec![rsp, return_addr], address),
            // call target
            PcodeOp::no_output(OpCode::Call, vec![target_vn], address),
        ]
    }

    /// call reg - 間接呼び出し
    pub fn decode_call_indirect(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let return_addr = Varnode::constant(address + 2, 8);
        let reg_vn = reg.to_varnode_64();
        let eight = Varnode::constant(8, 8);

        vec![
            PcodeOp::binary(OpCode::IntSub, rsp.clone(), rsp.clone(), eight, address),
            PcodeOp::no_output(OpCode::Store, vec![rsp, return_addr], address),
            PcodeOp::no_output(OpCode::CallInd, vec![reg_vn], address),
        ]
    }

    /// ret - 関数リターン
    pub fn decode_ret(&mut self, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let return_addr = self.next_unique(8);
        let eight = Varnode::constant(8, 8);

        vec![
            // pop return_addr
            PcodeOp::unary(OpCode::Load, return_addr.clone(), rsp.clone(), address),
            PcodeOp::binary(OpCode::IntAdd, rsp.clone(), rsp, eight, address),
            // return
            PcodeOp::no_output(OpCode::Return, vec![return_addr], address),
        ]
    }

    /// ret imm - リターンしてスタック調整
    pub fn decode_ret_imm(&mut self, imm: u16, address: u64) -> Vec<PcodeOp> {
        let rsp = X86Register::RSP.to_varnode_64();
        let return_addr = self.next_unique(8);
        let adjust = Varnode::constant(8 + imm as u64, 8);

        vec![
            PcodeOp::unary(OpCode::Load, return_addr.clone(), rsp.clone(), address),
            PcodeOp::binary(OpCode::IntAdd, rsp.clone(), rsp, adjust, address),
            PcodeOp::no_output(OpCode::Return, vec![return_addr], address),
        ]
    }

    // ===== 条件分岐命令 =====

    /// je/jz target - equal / zero
    pub fn decode_je(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        vec![PcodeOp::no_output(OpCode::CBranch, vec![target_vn, self.zf_varnode()], address)]
    }

    /// jne/jnz target - not equal / not zero
    pub fn decode_jne(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let not_zf = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), self.zf_varnode(), address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, not_zf], address),
        ]
    }

    /// jl/jnge target - less (signed)
    pub fn decode_jl(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let cond = self.next_unique(1);
        vec![
            // SF != OF
            PcodeOp::binary(OpCode::BoolXor, cond.clone(), self.sf_varnode(), self.of_varnode(), address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
        ]
    }

    /// jle/jng target - less or equal (signed)
    pub fn decode_jle(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let sf_ne_of = self.next_unique(1);
        let cond = self.next_unique(1);
        vec![
            PcodeOp::binary(OpCode::BoolXor, sf_ne_of.clone(), self.sf_varnode(), self.of_varnode(), address),
            // ZF || (SF != OF)
            PcodeOp::binary(OpCode::BoolOr, cond.clone(), self.zf_varnode(), sf_ne_of, address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
        ]
    }

    /// jg/jnle target - greater (signed)
    pub fn decode_jg(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let not_zf = self.next_unique(1);
        let sf_eq_of = self.next_unique(1);
        let cond = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), self.zf_varnode(), address),
            // SF == OF (NOT(SF XOR OF))
            PcodeOp::binary(OpCode::BoolXor, sf_eq_of.clone(), self.sf_varnode(), self.of_varnode(), address),
            PcodeOp::unary(OpCode::BoolNegate, sf_eq_of.clone(), sf_eq_of.clone(), address),
            // !ZF && (SF == OF)
            PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_zf, sf_eq_of, address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
        ]
    }

    /// jge/jnl target - greater or equal (signed)
    pub fn decode_jge(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let sf_eq_of = self.next_unique(1);
        vec![
            // SF == OF (NOT(SF XOR OF))
            PcodeOp::binary(OpCode::BoolXor, sf_eq_of.clone(), self.sf_varnode(), self.of_varnode(), address),
            PcodeOp::unary(OpCode::BoolNegate, sf_eq_of.clone(), sf_eq_of.clone(), address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, sf_eq_of], address),
        ]
    }

    /// jb/jc/jnae target - below (unsigned) / carry
    pub fn decode_jb(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        vec![PcodeOp::no_output(OpCode::CBranch, vec![target_vn, self.cf_varnode()], address)]
    }

    /// jbe/jna target - below or equal (unsigned)
    pub fn decode_jbe(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let cond = self.next_unique(1);
        vec![
            // CF || ZF
            PcodeOp::binary(OpCode::BoolOr, cond.clone(), self.cf_varnode(), self.zf_varnode(), address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
        ]
    }

    /// ja/jnbe target - above (unsigned)
    pub fn decode_ja(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let not_cf = self.next_unique(1);
        let not_zf = self.next_unique(1);
        let cond = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_cf.clone(), self.cf_varnode(), address),
            PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), self.zf_varnode(), address),
            // !CF && !ZF
            PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_cf, not_zf, address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
        ]
    }

    /// jae/jnb/jnc target - above or equal (unsigned) / no carry
    pub fn decode_jae(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let not_cf = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_cf.clone(), self.cf_varnode(), address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, not_cf], address),
        ]
    }

    /// js target - sign (negative)
    pub fn decode_js(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        vec![PcodeOp::no_output(OpCode::CBranch, vec![target_vn, self.sf_varnode()], address)]
    }

    /// jns target - not sign (positive or zero)
    pub fn decode_jns(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let not_sf = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_sf.clone(), self.sf_varnode(), address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, not_sf], address),
        ]
    }

    /// jo target - overflow
    pub fn decode_jo(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        vec![PcodeOp::no_output(OpCode::CBranch, vec![target_vn, self.of_varnode()], address)]
    }

    /// jno target - not overflow
    pub fn decode_jno(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        let target_vn = Varnode::constant(target, 8);
        let not_of = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_of.clone(), self.of_varnode(), address),
            PcodeOp::no_output(OpCode::CBranch, vec![target_vn, not_of], address),
        ]
    }

    // ===== アトミック命令 (Atomic Operations) =====

    /// lock add [memory], imm - アトミック加算（メモリ）
    /// War Thunder等のマルチスレッドプログラムで参照カウント管理に使用
    pub fn decode_lock_add_mem(&mut self, base: X86Register, offset: i64, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        // メモリアドレスを計算
        let base_vn = base.to_varnode(8);
        let offset_vn = Varnode::constant(offset as u64, 8);
        let addr_temp = self.next_unique(8);

        // 現在の値をロード
        let value_temp = self.next_unique(size);

        // 加算結果
        let imm_vn = Varnode::constant(imm as u64, size);
        let result_temp = self.next_unique(size);

        vec![
            // addr_temp = base + offset
            PcodeOp::binary(OpCode::IntAdd, addr_temp.clone(), base_vn, offset_vn, address),
            // value_temp = *addr_temp (Load from RAM)
            PcodeOp::unary(OpCode::Load, value_temp.clone(), addr_temp.clone(), address),
            // result_temp = value_temp + imm
            PcodeOp::binary(OpCode::IntAdd, result_temp.clone(), value_temp, imm_vn, address),
            // *addr_temp = result_temp (Store to memory)
            PcodeOp::no_output(OpCode::Store, vec![addr_temp, result_temp], address),
            // Note: アトミック性は実際のx86命令レベルで保証される（ロックプレフィックス）
        ]
    }

    /// lock xadd [memory], reg - アトミック交換加算
    /// メモリの値とレジスタの値を交換してから加算
    pub fn decode_lock_xadd_mem(&mut self, base: X86Register, offset: i64, src_reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        // メモリアドレスを計算
        let base_vn = base.to_varnode(8);
        let offset_vn = Varnode::constant(offset as u64, 8);
        let addr_temp = self.next_unique(8);

        // 現在の値をロード
        let old_value = self.next_unique(size);

        // src_regの値
        let src_vn = src_reg.to_varnode(size);

        // 加算結果
        let result_temp = self.next_unique(size);

        vec![
            // addr_temp = base + offset
            PcodeOp::binary(OpCode::IntAdd, addr_temp.clone(), base_vn, offset_vn, address),
            // old_value = *addr_temp (Load from RAM)
            PcodeOp::unary(OpCode::Load, old_value.clone(), addr_temp.clone(), address),
            // result_temp = old_value + src_reg
            PcodeOp::binary(OpCode::IntAdd, result_temp.clone(), old_value.clone(), src_vn.clone(), address),
            // *addr_temp = result_temp (Store to memory)
            PcodeOp::no_output(OpCode::Store, vec![addr_temp, result_temp], address),
            // src_reg = old_value (交換: レジスタに古い値を格納)
            PcodeOp::unary(OpCode::Copy, src_vn, old_value, address),
        ]
    }

    /// lock inc [memory] - アトミックインクリメント（メモリ）
    pub fn decode_lock_inc_mem(&mut self, base: X86Register, offset: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        self.decode_lock_add_mem(base, offset, 1, size, address)
    }

    /// lock dec [memory] - アトミックデクリメント（メモリ）
    pub fn decode_lock_dec_mem(&mut self, base: X86Register, offset: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        self.decode_lock_add_mem(base, offset, -1, size, address)
    }

    // ===== SSE/AVX命令 (SIMD) =====

    /// movaps xmm, xmm - Aligned Packed Single-Precision Move (128-bit)
    /// 簡略化: 128ビットCopy操作として扱う
    pub fn decode_movaps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(16); // 128-bit = 16 bytes
        let src_vn = src.to_varnode(16);
        vec![PcodeOp::unary(OpCode::Copy, dest_vn, src_vn, address)]
    }

    /// movaps xmm, [memory] - Load from aligned memory
    pub fn decode_movaps_load(&mut self, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(16);
        vec![PcodeOp::unary(OpCode::Load, dest_vn, mem_addr, address)]
    }

    /// movaps [memory], xmm - Store to aligned memory
    pub fn decode_movaps_store(&mut self, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> {
        let src_vn = src.to_varnode(16);
        vec![PcodeOp::no_output(OpCode::Store, vec![mem_addr, src_vn], address)]
    }

    /// movups xmm, xmm - Unaligned Packed Single-Precision Move
    /// 機能的にはmovapsと同じ（アライメント要件のみ異なる）
    pub fn decode_movups(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
        self.decode_movaps(dest, src, address)
    }

    /// movups xmm, [memory] - Load from unaligned memory
    pub fn decode_movups_load(&mut self, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
        self.decode_movaps_load(dest, mem_addr, address)
    }

    /// movups [memory], xmm - Store to unaligned memory
    pub fn decode_movups_store(&mut self, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> {
        self.decode_movaps_store(mem_addr, src, address)
    }

    /// xorps xmm, xmm - XOR Packed Single-Precision
    /// よくゼロクリアに使われる（xorps xmm0, xmm0 => xmm0 = 0）
    pub fn decode_xorps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(16);
        let src_vn = src.to_varnode(16);
        vec![PcodeOp::binary(OpCode::IntXor, dest_vn.clone(), dest_vn, src_vn, address)]
    }

    /// andps xmm, xmm - AND Packed Single-Precision
    pub fn decode_andps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(16);
        let src_vn = src.to_varnode(16);
        vec![PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), dest_vn, src_vn, address)]
    }

    /// orps xmm, xmm - OR Packed Single-Precision
    pub fn decode_orps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
        let dest_vn = dest.to_varnode(16);
        let src_vn = src.to_varnode(16);
        vec![PcodeOp::binary(OpCode::IntOr, dest_vn.clone(), dest_vn, src_vn, address)]
    }

    // ===== その他の命令 =====

    /// nop - 何もしない
    pub fn decode_nop(&mut self, address: u64) -> Vec<PcodeOp> {
        vec![]
    }

    /// cdq - EDX:EAX = sign-extend(EAX)
    pub fn decode_cdq(&mut self, address: u64) -> Vec<PcodeOp> {
        let eax = X86Register::RAX.to_varnode_32();
        let edx = X86Register::RDX.to_varnode_32();
        let temp = self.next_unique(8);

        vec![
            // EAXを符号拡張して64ビットに
            PcodeOp::unary(OpCode::IntSExt, temp.clone(), eax, address),
            // 上位32ビットをEDXに
            PcodeOp::binary(OpCode::IntSRight, edx, temp, Varnode::constant(32, 1), address),
        ]
    }

    /// cqo - RDX:RAX = sign-extend(RAX)
    pub fn decode_cqo(&mut self, address: u64) -> Vec<PcodeOp> {
        let rax = X86Register::RAX.to_varnode_64();
        let rdx = X86Register::RDX.to_varnode_64();

        vec![
            // RAXの符号ビットを全ビットに拡張してRDXに
            PcodeOp::binary(OpCode::IntSRight, rdx, rax, Varnode::constant(63, 1), address),
        ]
    }

    /// cbw - AX = sign-extend(AL)
    pub fn decode_cbw(&mut self, address: u64) -> Vec<PcodeOp> {
        let al = X86Register::RAX.to_varnode_8();
        let ax = X86Register::RAX.to_varnode_16();

        vec![
            PcodeOp::unary(OpCode::IntSExt, ax, al, address),
        ]
    }

    /// cwde - EAX = sign-extend(AX)
    pub fn decode_cwde(&mut self, address: u64) -> Vec<PcodeOp> {
        let ax = X86Register::RAX.to_varnode_16();
        let eax = X86Register::RAX.to_varnode_32();

        vec![
            PcodeOp::unary(OpCode::IntSExt, eax, ax, address),
        ]
    }

    /// cdqe - RAX = sign-extend(EAX)
    pub fn decode_cdqe(&mut self, address: u64) -> Vec<PcodeOp> {
        let eax = X86Register::RAX.to_varnode_32();
        let rax = X86Register::RAX.to_varnode_64();

        vec![
            PcodeOp::unary(OpCode::IntSExt, rax, eax, address),
        ]
    }

    /// setcc reg - 条件付きセット命令
    pub fn decode_sete(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode_8();
        vec![PcodeOp::unary(OpCode::Copy, reg_vn, self.zf_varnode(), address)]
    }

    pub fn decode_setne(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode_8();
        let not_zf = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), self.zf_varnode(), address),
            PcodeOp::unary(OpCode::Copy, reg_vn, not_zf, address),
        ]
    }

    pub fn decode_setl(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode_8();
        let cond = self.next_unique(1);
        vec![
            PcodeOp::binary(OpCode::BoolXor, cond.clone(), self.sf_varnode(), self.of_varnode(), address),
            PcodeOp::unary(OpCode::Copy, reg_vn, cond, address),
        ]
    }

    pub fn decode_setg(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode_8();
        let not_zf = self.next_unique(1);
        let sf_eq_of = self.next_unique(1);
        let cond = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), self.zf_varnode(), address),
            PcodeOp::binary(OpCode::BoolXor, sf_eq_of.clone(), self.sf_varnode(), self.of_varnode(), address),
            PcodeOp::unary(OpCode::BoolNegate, sf_eq_of.clone(), sf_eq_of.clone(), address),
            PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_zf, sf_eq_of, address),
            PcodeOp::unary(OpCode::Copy, reg_vn, cond, address),
        ]
    }

    pub fn decode_setb(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode_8();
        vec![PcodeOp::unary(OpCode::Copy, reg_vn, self.cf_varnode(), address)]
    }

    pub fn decode_seta(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        let reg_vn = reg.to_varnode_8();
        let not_cf = self.next_unique(1);
        let not_zf = self.next_unique(1);
        let cond = self.next_unique(1);
        vec![
            PcodeOp::unary(OpCode::BoolNegate, not_cf.clone(), self.cf_varnode(), address),
            PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), self.zf_varnode(), address),
            PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_cf, not_zf, address),
            PcodeOp::unary(OpCode::Copy, reg_vn, cond, address),
        ]
    }

    // ===== cmovcc命令（条件付きmov） =====

    /// cmove/cmovz - move if equal/zero
    pub fn decode_cmove(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        // P-codeには条件付きコピーがないので、分岐で実装
        // 実際にはCFGレベルで処理すべきだが、簡略化
        let dest_vn = dest.to_varnode(size);
        let src_vn = src.to_varnode(size);
        let temp = self.next_unique(size);

        // zf ? src : dest
        vec![
            PcodeOp::unary(OpCode::Copy, temp.clone(), src_vn, address),
            // 条件付き選択を表現（本来はMultiEqualで）
            PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), temp,
                Varnode::constant(0xFFFFFFFFFFFFFFFF, size), address),
        ]
    }

    // ===== ヘルパーメソッド =====

    /// 算術演算後のフラグ更新
    fn update_flags_arithmetic(&mut self, result: &Varnode, address: u64) -> Vec<PcodeOp> {
        let zero = Varnode::constant(0, result.size);

        vec![
            // ZF = (result == 0)
            PcodeOp::binary(OpCode::IntEqual, self.zf_varnode(), result.clone(), zero.clone(), address),
            // SF = (result < 0) - 最上位ビットをチェック
            PcodeOp::binary(OpCode::IntSLess, self.sf_varnode(), result.clone(), zero, address),
        ]
    }

    /// 論理演算後のフラグ更新（CF=0, OF=0）
    fn update_flags_logical(&mut self, result: &Varnode, address: u64) -> Vec<PcodeOp> {
        let zero = Varnode::constant(0, result.size);
        let zero_1bit = Varnode::constant(0, 1);

        vec![
            // ZF = (result == 0)
            PcodeOp::binary(OpCode::IntEqual, self.zf_varnode(), result.clone(), zero.clone(), address),
            // SF = (result < 0)
            PcodeOp::binary(OpCode::IntSLess, self.sf_varnode(), result.clone(), zero, address),
            // CF = 0
            PcodeOp::unary(OpCode::Copy, self.cf_varnode(), zero_1bit.clone(), address),
            // OF = 0
            PcodeOp::unary(OpCode::Copy, self.of_varnode(), zero_1bit, address),
        ]
    }

    /// メモリアドレス計算 [base + index*scale + disp]
    pub fn compute_memory_address(
        &mut self,
        base: Option<X86Register>,
        index: Option<X86Register>,
        scale: u8,
        displacement: i64,
        address: u64
    ) -> (Vec<PcodeOp>, Varnode) {
        let mut ops = Vec::new();
        let result = self.next_unique(8);

        // 開始値: displacement
        ops.push(PcodeOp::unary(
            OpCode::Copy,
            result.clone(),
            Varnode::constant(displacement as u64, 8),
            address
        ));

        // base を加算
        if let Some(base_reg) = base {
            let base_vn = base_reg.to_varnode_64();
            ops.push(PcodeOp::binary(OpCode::IntAdd, result.clone(), result.clone(), base_vn, address));
        }

        // index * scale を加算
        if let Some(index_reg) = index {
            let index_vn = index_reg.to_varnode_64();
            if scale > 1 {
                let scaled = self.next_unique(8);
                let scale_vn = Varnode::constant(scale as u64, 8);
                ops.push(PcodeOp::binary(OpCode::IntMult, scaled.clone(), index_vn, scale_vn, address));
                ops.push(PcodeOp::binary(OpCode::IntAdd, result.clone(), result.clone(), scaled, address));
            } else {
                ops.push(PcodeOp::binary(OpCode::IntAdd, result.clone(), result.clone(), index_vn, address));
            }
        }

        (ops, result)
    }

    // === 文字列操作命令 ===

    /// LODSB/LODSW/LODSD/LODSQ - Load String
    pub fn decode_lods(&mut self, size: usize, address: u64) -> Vec<PcodeOp> {
        let mut ops = Vec::new();
        let dest = X86Register::RAX.to_varnode(size);
        let src_addr = X86Register::RSI.to_varnode(8);
        ops.push(PcodeOp::unary(OpCode::Load, dest, src_addr.clone(), address));
        let size_const = Varnode { space: AddressSpace::Const, offset: size as u64, size: 8 };
        let new_rsi = X86Register::RSI.to_varnode(8);
        ops.push(PcodeOp::binary(OpCode::IntAdd, new_rsi, src_addr, size_const, address));
        ops
    }

    /// STOSB/STOSW/STOSD/STOSQ - Store String
    pub fn decode_stos(&mut self, size: usize, address: u64) -> Vec<PcodeOp> {
        let mut ops = Vec::new();
        let src = X86Register::RAX.to_varnode(size);
        let dest_addr = X86Register::RDI.to_varnode(8);
        let space_id = Varnode { space: AddressSpace::Const, offset: 0, size: 8 };
        ops.push(PcodeOp {
            opcode: OpCode::Store,
            output: None,
            inputs: vec![space_id, dest_addr.clone(), src],
            address,
        });
        let size_const = Varnode { space: AddressSpace::Const, offset: size as u64, size: 8 };
        let new_rdi = X86Register::RDI.to_varnode(8);
        ops.push(PcodeOp::binary(OpCode::IntAdd, new_rdi, dest_addr, size_const, address));
        ops
    }

    /// MOVSB/MOVSW/MOVSD/MOVSQ - Move String
    pub fn decode_movs(&mut self, size: usize, address: u64) -> Vec<PcodeOp> {
        let mut ops = Vec::new();
        let temp = self.next_unique(size);
        let src_addr = X86Register::RSI.to_varnode(8);
        ops.push(PcodeOp::unary(OpCode::Load, temp.clone(), src_addr.clone(), address));
        let dest_addr = X86Register::RDI.to_varnode(8);
        let space_id = Varnode { space: AddressSpace::Const, offset: 0, size: 8 };
        ops.push(PcodeOp {
            opcode: OpCode::Store,
            output: None,
            inputs: vec![space_id, dest_addr.clone(), temp],
            address,
        });
        let size_const = Varnode { space: AddressSpace::Const, offset: size as u64, size: 8 };
        let new_rsi = X86Register::RSI.to_varnode(8);
        ops.push(PcodeOp::binary(OpCode::IntAdd, new_rsi, src_addr, size_const.clone(), address));
        let new_rdi = X86Register::RDI.to_varnode(8);
        ops.push(PcodeOp::binary(OpCode::IntAdd, new_rdi, dest_addr, size_const, address));
        ops
    }

    // === メモリシフト命令 ===

    /// SHL/SHR/SAR [mem], imm8
    pub fn decode_shift_mem(&mut self, opcode: OpCode, mem_addr: Varnode, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
        let mut ops = Vec::new();
        let temp = self.next_unique(size);
        ops.push(PcodeOp::unary(OpCode::Load, temp.clone(), mem_addr.clone(), address));
        let count_vn = Varnode { space: AddressSpace::Const, offset: count as u64, size: 1 };
        let result = self.next_unique(size);
        ops.push(PcodeOp::binary(opcode, result.clone(), temp, count_vn, address));
        let space_id = Varnode { space: AddressSpace::Const, offset: 0, size: 8 };
        ops.push(PcodeOp {
            opcode: OpCode::Store,
            output: None,
            inputs: vec![space_id, mem_addr, result.clone()],
            address,
        });
        ops.extend(self.update_flags_logical(&result, address));
        ops
    }

    // === 複雑なCMP命令 ===

    /// CMP [mem], reg/imm や CMP reg, [mem]
    pub fn decode_cmp_complex(&mut self, lhs: Varnode, rhs: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
        let mut ops = Vec::new();
        let result = self.next_unique(size);
        ops.push(PcodeOp::binary(OpCode::IntSub, result.clone(), lhs, rhs, address));
        ops.extend(self.update_flags_arithmetic(&result, address));
        ops
    }
}

/// 簡易的な命令列をP-codeに変換する例
pub fn example_translation() -> Vec<PcodeOp> {
    let mut decoder = X86Decoder::new();
    let mut pcodes = Vec::new();

    // 簡単な関数の例:
    // 0x1000: mov rax, 0
    // 0x1003: mov rbx, 10
    // 0x1006: add rax, rbx
    // 0x1009: ret

    pcodes.extend(decoder.decode_mov_imm(X86Register::RAX, 0, 8, 0x1000));
    pcodes.extend(decoder.decode_mov_imm(X86Register::RBX, 10, 8, 0x1003));
    pcodes.extend(decoder.decode_add(X86Register::RAX, X86Register::RBX, 8, 0x1006));
    pcodes.extend(decoder.decode_ret(0x1009));

    pcodes
}

/// 複雑な関数の例
pub fn complex_example() -> Vec<PcodeOp> {
    let mut decoder = X86Decoder::new();
    let mut pcodes = Vec::new();

    // int compute(int x, int y) {
    //     if (x > y) return x - y;
    //     else return y - x;
    // }
    //
    // 0x2000: push rbp
    // 0x2001: mov rbp, rsp
    // 0x2004: cmp edi, esi        ; x > y?
    // 0x2006: jle 0x2010          ; if not, jump
    // 0x2008: mov eax, edi
    // 0x200a: sub eax, esi        ; return x - y
    // 0x200c: jmp 0x2014
    // 0x2010: mov eax, esi
    // 0x2012: sub eax, edi        ; return y - x
    // 0x2014: pop rbp
    // 0x2015: ret

    pcodes.extend(decoder.decode_push(X86Register::RBP, 0x2000));
    pcodes.extend(decoder.decode_mov(X86Register::RBP, X86Register::RSP, 8, 0x2001));
    pcodes.extend(decoder.decode_cmp(X86Register::RDI, X86Register::RSI, 4, 0x2004));
    pcodes.extend(decoder.decode_jle(0x2010, 0x2006));
    pcodes.extend(decoder.decode_mov(X86Register::RAX, X86Register::RDI, 4, 0x2008));
    pcodes.extend(decoder.decode_sub(X86Register::RAX, X86Register::RSI, 4, 0x200a));
    pcodes.extend(decoder.decode_jmp(0x2014, 0x200c));
    pcodes.extend(decoder.decode_mov(X86Register::RAX, X86Register::RSI, 4, 0x2010));
    pcodes.extend(decoder.decode_sub(X86Register::RAX, X86Register::RDI, 4, 0x2012));
    pcodes.extend(decoder.decode_pop(X86Register::RBP, 0x2014));
    pcodes.extend(decoder.decode_ret(0x2015));

    pcodes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mov_translation() {
        let mut decoder = X86Decoder::new();
        let ops = decoder.decode_mov(X86Register::RAX, X86Register::RBX, 8, 0x1000);

        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode, OpCode::Copy);
        assert!(ops[0].output.is_some());
    }

    #[test]
    fn test_add_translation() {
        let mut decoder = X86Decoder::new();
        let ops = decoder.decode_add(X86Register::RAX, X86Register::RBX, 8, 0x1000);

        // add命令はフラグ更新を含むので複数のP-code
        assert!(ops.len() >= 1);
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
    }

    #[test]
    fn test_example_translation() {
        let pcodes = example_translation();

        assert!(pcodes.len() >= 4);
        assert_eq!(pcodes[0].opcode, OpCode::Copy);  // mov rax, 0

        println!("Generated P-code:");
        for (i, op) in pcodes.iter().enumerate() {
            println!("  [{}] 0x{:x}: {}", i, op.address, op);
        }
    }

    #[test]
    fn test_register_parsing() {
        // 64-bit
        let (reg, size) = X86Register::from_str("rax").unwrap();
        assert!(matches!(reg, X86Register::RAX));
        assert_eq!(size, 8);

        // 32-bit
        let (reg, size) = X86Register::from_str("eax").unwrap();
        assert!(matches!(reg, X86Register::RAX));
        assert_eq!(size, 4);

        // 16-bit
        let (reg, size) = X86Register::from_str("ax").unwrap();
        assert!(matches!(reg, X86Register::RAX));
        assert_eq!(size, 2);

        // 8-bit
        let (reg, size) = X86Register::from_str("al").unwrap();
        assert!(matches!(reg, X86Register::RAX));
        assert_eq!(size, 1);

        // Invalid
        assert!(X86Register::from_str("invalid").is_err());
    }

    #[test]
    fn test_push_pop() {
        let mut decoder = X86Decoder::new();

        let push_ops = decoder.decode_push(X86Register::RAX, 0x1000);
        assert_eq!(push_ops.len(), 2);  // RSP減算 + store

        let pop_ops = decoder.decode_pop(X86Register::RAX, 0x1004);
        assert_eq!(pop_ops.len(), 2);  // load + RSP加算
    }

    #[test]
    fn test_conditional_jumps() {
        let mut decoder = X86Decoder::new();

        let je_ops = decoder.decode_je(0x1234, 0x1000);
        assert!(je_ops.len() >= 1);
        assert_eq!(je_ops.last().unwrap().opcode, OpCode::CBranch);

        let jne_ops = decoder.decode_jne(0x1234, 0x1000);
        assert!(jne_ops.len() >= 1);
        assert_eq!(jne_ops.last().unwrap().opcode, OpCode::CBranch);
    }

    #[test]
    fn test_bitwise_ops() {
        let mut decoder = X86Decoder::new();

        let and_ops = decoder.decode_and(X86Register::RAX, X86Register::RBX, 8, 0x1000);
        assert!(!and_ops.is_empty());
        assert_eq!(and_ops[0].opcode, OpCode::IntAnd);

        let or_ops = decoder.decode_or(X86Register::RAX, X86Register::RBX, 8, 0x1000);
        assert!(!or_ops.is_empty());
        assert_eq!(or_ops[0].opcode, OpCode::IntOr);

        let xor_ops = decoder.decode_xor(X86Register::RAX, X86Register::RBX, 8, 0x1000);
        assert!(!xor_ops.is_empty());
        assert_eq!(xor_ops[0].opcode, OpCode::IntXor);
    }

    #[test]
    fn test_complex_function() {
        let pcodes = complex_example();

        println!("\n=== Complex Function P-code ===");
        for op in &pcodes {
            println!("0x{:x}: {}", op.address, op);
        }

        // push, mov, cmp, jle, mov, sub, jmp, mov, sub, pop, ret
        // が含まれていることを確認
        assert!(pcodes.len() > 10);
    }
}
