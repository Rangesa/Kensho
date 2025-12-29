




use super::pcode::*;

pub mod registers;
pub mod instructions;

pub use registers::{X86Register, Operand, flags};
use instructions::*;





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
            unique_counter: 0x10000,
        }
    }



    pub(crate) fn next_unique(&mut self, size: usize) -> Varnode {
        let offset = self.unique_counter;
        self.unique_counter += size as u64;
        Varnode::unique(offset, size)
    }



    pub(crate) fn zf_varnode(&self) -> Varnode {
        Varnode::unique(flags::ZF, 1)
    }



    pub(crate) fn sf_varnode(&self) -> Varnode {
        Varnode::unique(flags::SF, 1)
    }



    pub(crate) fn of_varnode(&self) -> Varnode {
        Varnode::unique(flags::OF, 1)
    }



    pub(crate) fn cf_varnode(&self) -> Varnode {
        Varnode::unique(flags::CF, 1)
    }



    pub(crate) fn pf_varnode(&self) -> Varnode {
        Varnode::unique(flags::PF, 1)
    }

    // ===== Flag update helpers =====



    pub(crate) fn update_flags_arithmetic(&mut self, _result: &Varnode, _address: u64) -> Vec<PcodeOp> {
        // Simple impl: update result only
        // Flag calculation is complex, using placeholders here
        // OF, CF need inputs, P-code detail level TBD
        vec![]
    }



    pub(crate) fn update_flags_logical(&mut self, result: &Varnode, address: u64) -> Vec<PcodeOp> {
        let zero = Varnode::constant(0, 1);
        let result_size = result.size;
        let zero_val = Varnode::constant(0, result_size);

        vec![
            // ZF = (result == 0)
            PcodeOp::binary(OpCode::IntEqual, self.zf_varnode(), result.clone(), zero_val, address),
            // SF = result < 0 (signed) - 譛荳贋ｽ阪ン繝・ヨ
            PcodeOp::binary(OpCode::IntSLess, self.sf_varnode(), result.clone(), Varnode::constant(0, result_size), address),
            // OF = 0
            PcodeOp::unary(OpCode::Copy, self.of_varnode(), zero.clone(), address),
            // CF = 0
            PcodeOp::unary(OpCode::Copy, self.cf_varnode(), zero, address),
        ]
    }

    // ===== Basic Data Transfer =====

    pub fn decode_mov(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_mov(self, dest, src, size, address)
    }

    pub fn decode_mov_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_mov_imm(self, dest, imm, size, address)
    }

    pub fn decode_mov_load(&mut self, dest: X86Register, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_mov_load(self, dest, mem_addr, size, address)
    }

    pub fn decode_mov_store(&mut self, mem_addr: Varnode, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_mov_store(self, mem_addr, src, size, address)
    }

    pub fn decode_lea(&mut self, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_lea(self, dest, mem_addr, address)
    }

    pub fn decode_movzx(&mut self, dest: X86Register, src: X86Register, dest_size: usize, src_size: usize, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_movzx(self, dest, src, dest_size, src_size, address)
    }

    pub fn decode_movsx(&mut self, dest: X86Register, src: X86Register, dest_size: usize, src_size: usize, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_movsx(self, dest, src, dest_size, src_size, address)
    }

    pub fn decode_xchg(&mut self, reg1: X86Register, reg2: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_xchg(self, reg1, reg2, size, address)
    }

    // ===== Arithmetic =====

    pub fn decode_add(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_add(self, dest, src, size, address)
    }

    pub fn decode_add_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_add_imm(self, dest, imm, size, address)
    }

    pub fn decode_sub(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_sub(self, dest, src, size, address)
    }

    pub fn decode_sub_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_sub_imm(self, dest, imm, size, address)
    }

    pub fn decode_inc(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_inc(self, reg, size, address)
    }

    pub fn decode_dec(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_dec(self, reg, size, address)
    }

    pub fn decode_inc_mem(&mut self, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_inc_mem(self, mem_addr, size, address)
    }

    pub fn decode_dec_mem(&mut self, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_dec_mem(self, mem_addr, size, address)
    }

    pub fn decode_neg(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_neg(self, reg, size, address)
    }

    pub fn decode_imul(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_imul(self, dest, src, size, address)
    }

    pub fn decode_imul3(&mut self, dest: X86Register, src: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_imul3(self, dest, src, imm, size, address)
    }

    pub fn decode_mul(&mut self, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_mul(self, src, size, address)
    }

    pub fn decode_div(&mut self, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_div(self, src, size, address)
    }

    pub fn decode_idiv(&mut self, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        arithmetic::decode_idiv(self, src, size, address)
    }

    // ===== Bitwise =====

    pub fn decode_and(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_and(self, dest, src, size, address)
    }

    pub fn decode_and_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_and_imm(self, dest, imm, size, address)
    }

    pub fn decode_or(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_or(self, dest, src, size, address)
    }

    pub fn decode_or_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_or_imm(self, dest, imm, size, address)
    }

    pub fn decode_xor(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_xor(self, dest, src, size, address)
    }

    pub fn decode_xor_imm(&mut self, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_xor_imm(self, dest, imm, size, address)
    }

    pub fn decode_not(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_not(self, reg, size, address)
    }

    pub fn decode_shl(&mut self, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_shl(self, reg, count, size, address)
    }

    pub fn decode_shl_cl(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_shl_cl(self, reg, size, address)
    }

    pub fn decode_shr(&mut self, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_shr(self, reg, count, size, address)
    }

    pub fn decode_shr_cl(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_shr_cl(self, reg, size, address)
    }

    pub fn decode_sar(&mut self, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_sar(self, reg, count, size, address)
    }

    pub fn decode_sar_cl(&mut self, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_sar_cl(self, reg, size, address)
    }

    pub fn decode_test(&mut self, lhs: X86Register, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_test(self, lhs, rhs, size, address)
    }

    pub fn decode_test_imm(&mut self, reg: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        logic::decode_test_imm(self, reg, imm, size, address)
    }

    // ===== Stack Ops =====

    pub fn decode_push(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_push(self, reg, address)
    }

    pub fn decode_push_imm(&mut self, imm: i64, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_push_imm(self, imm, address)
    }

    pub fn decode_pop(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_pop(self, reg, address)
    }

    pub fn decode_enter(&mut self, size: u16, level: u8, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_enter(self, size, level, address)
    }

    pub fn decode_leave(&mut self, address: u64) -> Vec<PcodeOp> {
        data_transfer::decode_leave(self, address)
    }

    // ===== Control Flow =====

    pub fn decode_jmp(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jmp(self, target, address)
    }

    pub fn decode_jmp_indirect(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jmp_indirect(self, reg, address)
    }

    pub fn decode_call(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_call(self, target, address)
    }

    pub fn decode_call_indirect(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_call_indirect(self, reg, address)
    }

    pub fn decode_ret(&mut self, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_ret(self, address)
    }

    pub fn decode_ret_imm(&mut self, imm: u16, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_ret_imm(self, imm, address)
    }

    // ===== Compare / Conditional =====

    pub fn decode_cmp(&mut self, lhs: X86Register, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmp(self, lhs, rhs, size, address)
    }

    pub fn decode_cmp_imm(&mut self, lhs: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmp_imm(self, lhs, imm, size, address)
    }

    pub fn decode_cmp_mem_reg(&mut self, mem_addr: Varnode, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmp_mem_reg(self, mem_addr, rhs, size, address)
    }

    pub fn decode_cmp_mem_imm(&mut self, mem_addr: Varnode, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmp_mem_imm(self, mem_addr, imm, size, address)
    }

    pub fn decode_je(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_je(self, target, address)
    }

    pub fn decode_jne(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jne(self, target, address)
    }

    pub fn decode_jl(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jl(self, target, address)
    }

    pub fn decode_jle(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jle(self, target, address)
    }

    pub fn decode_jg(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jg(self, target, address)
    }

    pub fn decode_jge(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jge(self, target, address)
    }

    pub fn decode_jb(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jb(self, target, address)
    }

    pub fn decode_jbe(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jbe(self, target, address)
    }

    pub fn decode_ja(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_ja(self, target, address)
    }

    pub fn decode_jae(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jae(self, target, address)
    }

    pub fn decode_js(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_js(self, target, address)
    }

    pub fn decode_jns(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jns(self, target, address)
    }

    pub fn decode_jo(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jo(self, target, address)
    }

    pub fn decode_jno(&mut self, target: u64, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_jno(self, target, address)
    }

    pub fn decode_sete(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_sete(self, reg, address)
    }

    pub fn decode_setne(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_setne(self, reg, address)
    }

    pub fn decode_setl(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_setl(self, reg, address)
    }

    pub fn decode_setg(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_setg(self, reg, address)
    }

    pub fn decode_setb(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_setb(self, reg, address)
    }

    pub fn decode_seta(&mut self, reg: X86Register, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_seta(self, reg, address)
    }

    pub fn decode_cmove(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmove(self, dest, src, size, address)
    }

    pub fn decode_cmovne(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovne(self, dest, src, size, address)
    }

    pub fn decode_cmovl(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovl(self, dest, src, size, address)
    }

    pub fn decode_cmovle(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovle(self, dest, src, size, address)
    }

    pub fn decode_cmovge(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovge(self, dest, src, size, address)
    }

    pub fn decode_cmovg(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovg(self, dest, src, size, address)
    }

    pub fn decode_cmovb(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovb(self, dest, src, size, address)
    }

    pub fn decode_cmovbe(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovbe(self, dest, src, size, address)
    }

    pub fn decode_cmova(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmova(self, dest, src, size, address)
    }

    pub fn decode_cmovae(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovae(self, dest, src, size, address)
    }

    pub fn decode_cmovs(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovs(self, dest, src, size, address)
    }

    pub fn decode_cmovns(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovns(self, dest, src, size, address)
    }

    pub fn decode_cmovo(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovo(self, dest, src, size, address)
    }

    pub fn decode_cmovno(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovno(self, dest, src, size, address)
    }

    pub fn decode_cmovp(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovp(self, dest, src, size, address)
    }

    pub fn decode_cmovnp(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        control_flow::decode_cmovnp(self, dest, src, size, address)
    }

    // ===== Atomic / Misc =====

    pub fn decode_lock_add_mem(&mut self, base: X86Register, offset: i64, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        atomic::decode_lock_add_mem(self, base, offset, imm, size, address)
    }

    pub fn decode_lock_xadd_mem(&mut self, base: X86Register, offset: i64, src_reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
        atomic::decode_lock_xadd_mem(self, base, offset, src_reg, size, address)
    }

    pub fn decode_lock_inc_mem(&mut self, base: X86Register, offset: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        atomic::decode_lock_inc_mem(self, base, offset, size, address)
    }

    pub fn decode_lock_dec_mem(&mut self, base: X86Register, offset: i64, size: usize, address: u64) -> Vec<PcodeOp> {
        atomic::decode_lock_dec_mem(self, base, offset, size, address)
    }

    pub fn decode_nop(&mut self, address: u64) -> Vec<PcodeOp> {
        misc::decode_nop(self, address)
    }

    pub fn decode_cdq(&mut self, address: u64) -> Vec<PcodeOp> {
        misc::decode_cdq(self, address)
    }

    pub fn decode_cqo(&mut self, address: u64) -> Vec<PcodeOp> {
        misc::decode_cqo(self, address)
    }

    pub fn decode_cbw(&mut self, address: u64) -> Vec<PcodeOp> {
        misc::decode_cbw(self, address)
    }

    pub fn decode_cwde(&mut self, address: u64) -> Vec<PcodeOp> {
        misc::decode_cwde(self, address)
    }

    pub fn decode_cdqe(&mut self, address: u64) -> Vec<PcodeOp> {
        misc::decode_cdqe(self, address)
    }

    // ===== SIMD =====
    // Many ops, partial implementation
    
    pub fn decode_movaps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
        simd::decode_movaps(self, dest, src, address)
    }

    pub fn decode_movaps_load(&mut self, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
        simd::decode_movaps_load(self, dest, mem_addr, address)
    }

    pub fn decode_movaps_store(&mut self, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> {
        simd::decode_movaps_store(self, mem_addr, src, address)
    }

    pub fn decode_movups(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
        simd::decode_movups(self, dest, src, address)
    }

    pub fn decode_movups_load(&mut self, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
        simd::decode_movups_load(self, dest, mem_addr, address)
    }

    pub fn decode_movups_store(&mut self, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> {
        simd::decode_movups_store(self, mem_addr, src, address)
    }
    
    // (Remaining SIMD op, skipping some)
    pub fn decode_xorps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_xorps(self, dest, src, address) }
    pub fn decode_andps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_andps(self, dest, src, address) }
    pub fn decode_orps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_orps(self, dest, src, address) }

    pub fn decode_movss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_movss(self, dest, src, address) }
    pub fn decode_movss_load(&mut self, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> { simd::decode_movss_load(self, dest, mem_addr, address) }
    pub fn decode_movss_store(&mut self, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_movss_store(self, mem_addr, src, address) }
    pub fn decode_movsd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_movsd(self, dest, src, address) }
    pub fn decode_movsd_load(&mut self, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> { simd::decode_movsd_load(self, dest, mem_addr, address) }
    pub fn decode_movsd_store(&mut self, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_movsd_store(self, mem_addr, src, address) }
    
    pub fn decode_addps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_addps(self, dest, src, address) }
    pub fn decode_addss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_addss(self, dest, src, address) }
    pub fn decode_addpd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_addpd(self, dest, src, address) }
    pub fn decode_addsd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_addsd(self, dest, src, address) }

    pub fn decode_subps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_subps(self, dest, src, address) }
    pub fn decode_subss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_subss(self, dest, src, address) }
    pub fn decode_subpd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_subpd(self, dest, src, address) }
    pub fn decode_subsd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_subsd(self, dest, src, address) }

    pub fn decode_mulps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_mulps(self, dest, src, address) }
    pub fn decode_mulss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_mulss(self, dest, src, address) }
    pub fn decode_mulpd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_mulpd(self, dest, src, address) }
    pub fn decode_mulsd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_mulsd(self, dest, src, address) }

    pub fn decode_divps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_divps(self, dest, src, address) }
    pub fn decode_divss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_divss(self, dest, src, address) }
    pub fn decode_divpd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_divpd(self, dest, src, address) }
    pub fn decode_divsd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_divsd(self, dest, src, address) }

    pub fn decode_sqrtps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_sqrtps(self, dest, src, address) }
    pub fn decode_sqrtss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_sqrtss(self, dest, src, address) }
    pub fn decode_sqrtpd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_sqrtpd(self, dest, src, address) }
    pub fn decode_sqrtsd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_sqrtsd(self, dest, src, address) }

    pub fn decode_maxps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_maxps(self, dest, src, address) }
    pub fn decode_maxss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_maxss(self, dest, src, address) }
    pub fn decode_minps(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_minps(self, dest, src, address) }
    pub fn decode_minss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_minss(self, dest, src, address) }

    pub fn decode_cmpps(&mut self, dest: X86Register, src: X86Register, imm: u8, address: u64) -> Vec<PcodeOp> { simd::decode_cmpps(self, dest, src, imm, address) }
    pub fn decode_cmpss(&mut self, dest: X86Register, src: X86Register, imm: u8, address: u64) -> Vec<PcodeOp> { simd::decode_cmpss(self, dest, src, imm, address) }
    pub fn decode_ucomiss(&mut self, lhs: X86Register, rhs: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_ucomiss(self, lhs, rhs, address) }
    pub fn decode_ucomisd(&mut self, lhs: X86Register, rhs: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_ucomisd(self, lhs, rhs, address) }

    pub fn decode_cvtss2sd(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_cvtss2sd(self, dest, src, address) }
    pub fn decode_cvtsd2ss(&mut self, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> { simd::decode_cvtsd2ss(self, dest, src, address) }
    pub fn decode_cvtsi2ss(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> { simd::decode_cvtsi2ss(self, dest, src, size, address) }
    pub fn decode_cvtsi2sd(&mut self, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> { simd::decode_cvtsi2sd(self, dest, src, size, address) }
    pub fn decode_cvtss2si(&mut self, dest: X86Register, src: X86Register, dest_size: usize, address: u64) -> Vec<PcodeOp> { simd::decode_cvtss2si(self, dest, src, dest_size, address) }
    pub fn decode_cvtsd2si(&mut self, dest: X86Register, src: X86Register, dest_size: usize, address: u64) -> Vec<PcodeOp> { simd::decode_cvtsd2si(self, dest, src, dest_size, address) }

    // ===== String Operations =====

    /// LODSx - Load String
    pub fn decode_lods(&mut self, size: usize, address: u64) -> Vec<PcodeOp> {
        misc::decode_lods(self, size, address)
    }

    /// STOSx - Store String
    pub fn decode_stos(&mut self, size: usize, address: u64) -> Vec<PcodeOp> {
        misc::decode_stos(self, size, address)
    }

    /// MOVSx - Move String
    pub fn decode_movs(&mut self, size: usize, address: u64) -> Vec<PcodeOp> {
        misc::decode_movs(self, size, address)
    }

    // ===== Memory Address Computation =====



    pub fn compute_memory_address(
        &mut self,
        base: Option<X86Register>,
        index: Option<X86Register>,
        scale: u8,
        displacement: i64,
        address: u64
    ) -> (Vec<PcodeOp>, Varnode) {
        let mut ops = Vec::new();
        let mut result = self.next_unique(8);

        // Base
        if let Some(base_reg) = base {
            let base_vn = base_reg.to_varnode(8);
            ops.push(PcodeOp::unary(OpCode::Copy, result.clone(), base_vn, address));
        } else if displacement != 0 {
            let const_vn = Varnode::constant(displacement as u64, 8);
            ops.push(PcodeOp::unary(OpCode::Copy, result.clone(), const_vn, address));
            return (ops, result);
        } else {
            return (ops, Varnode::constant(0, 8));
        }

        // Index * Scale
        if let Some(index_reg) = index {
            let index_vn = index_reg.to_varnode(8);
            let temp = if scale > 1 {
                let scaled = self.next_unique(8);
                ops.push(PcodeOp::binary(
                    OpCode::IntMult,
                    scaled.clone(),
                    index_vn,
                    Varnode::constant(scale as u64, 8),
                    address
                ));
                scaled
            } else {
                index_vn
            };

            let sum = self.next_unique(8);
            ops.push(PcodeOp::binary(OpCode::IntAdd, sum.clone(), result.clone(), temp, address));
            result = sum;
        }

        // Displacement
        if displacement != 0 {
            let final_result = self.next_unique(8);
            ops.push(PcodeOp::binary(
                OpCode::IntAdd,
                final_result.clone(),
                result,
                Varnode::constant(displacement as u64, 8),
                address
            ));
            result = final_result;
        }

        (ops, result)
    }
}
