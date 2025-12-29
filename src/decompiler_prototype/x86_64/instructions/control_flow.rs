use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode};
use super::super::registers::X86Register;
use super::super::X86Decoder;



pub fn decode_jmp(_decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    vec![PcodeOp::no_output(OpCode::Branch, vec![target_vn], address)]
}



pub fn decode_jmp_indirect(_decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode_64();
    vec![PcodeOp::no_output(OpCode::BranchInd, vec![reg_vn], address)]
}



pub fn decode_call(_decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let rsp = X86Register::RSP.to_varnode_64();
    let return_addr = Varnode::constant(address + 5, 8);  // Next instruction address
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



pub fn decode_call_indirect(_decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
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



pub fn decode_ret(decoder: &mut X86Decoder, address: u64) -> Vec<PcodeOp> {
    let rsp = X86Register::RSP.to_varnode_64();
    let return_addr = decoder.next_unique(8);
    let eight = Varnode::constant(8, 8);

    vec![
        // pop return_addr
        PcodeOp::unary(OpCode::Load, return_addr.clone(), rsp.clone(), address),
        PcodeOp::binary(OpCode::IntAdd, rsp.clone(), rsp, eight, address),
        // return
        PcodeOp::no_output(OpCode::Return, vec![return_addr], address),
    ]
}



pub fn decode_ret_imm(decoder: &mut X86Decoder, imm: u16, address: u64) -> Vec<PcodeOp> {
    let rsp = X86Register::RSP.to_varnode_64();
    let return_addr = decoder.next_unique(8);
    let adjust = Varnode::constant(8 + imm as u64, 8);

    vec![
        PcodeOp::unary(OpCode::Load, return_addr.clone(), rsp.clone(), address),
        PcodeOp::binary(OpCode::IntAdd, rsp.clone(), rsp, adjust, address),
        PcodeOp::no_output(OpCode::Return, vec![return_addr], address),
    ]
}

// ===== Compare Ops =====

/// cmp reg, reg
pub fn decode_cmp(decoder: &mut X86Decoder, lhs: X86Register, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let lhs_vn = lhs.to_varnode(size);
    let rhs_vn = rhs.to_varnode(size);
    let temp = decoder.next_unique(size);

    let mut ops = vec![
        PcodeOp::binary(OpCode::IntSub, temp.clone(), lhs_vn.clone(), rhs_vn.clone(), address),
    ];

    // Update flags
    ops.push(PcodeOp::binary(OpCode::IntEqual, decoder.zf_varnode(), lhs_vn.clone(), rhs_vn.clone(), address));
    ops.push(PcodeOp::binary(OpCode::IntSLess, decoder.sf_varnode(), lhs_vn.clone(), rhs_vn.clone(), address));
    ops.push(PcodeOp::binary(OpCode::IntLess, decoder.cf_varnode(), lhs_vn, rhs_vn, address));

    ops
}

/// cmp reg, imm
pub fn decode_cmp_imm(decoder: &mut X86Decoder, lhs: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let lhs_vn = lhs.to_varnode(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    let temp = decoder.next_unique(size);

    let mut ops = vec![
        PcodeOp::binary(OpCode::IntSub, temp, lhs_vn.clone(), imm_vn.clone(), address),
    ];

    ops.push(PcodeOp::binary(OpCode::IntEqual, decoder.zf_varnode(), lhs_vn.clone(), imm_vn.clone(), address));
    ops.push(PcodeOp::binary(OpCode::IntSLess, decoder.sf_varnode(), lhs_vn.clone(), imm_vn.clone(), address));
    ops.push(PcodeOp::binary(OpCode::IntLess, decoder.cf_varnode(), lhs_vn, imm_vn, address));

    ops
}



pub fn decode_cmp_mem_reg(decoder: &mut X86Decoder, mem_addr: Varnode, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let mem_value = decoder.next_unique(size);
    let rhs_vn = rhs.to_varnode(size);
    let temp = decoder.next_unique(size);

    vec![
        // mem_value = *mem_addr (Load)
        PcodeOp::unary(OpCode::Load, mem_value.clone(), mem_addr, address),
        // temp = mem_value - rhs (Compare)
        PcodeOp::binary(OpCode::IntSub, temp, mem_value.clone(), rhs_vn.clone(), address),
        // Update flags
        PcodeOp::binary(OpCode::IntEqual, decoder.zf_varnode(), mem_value.clone(), rhs_vn.clone(), address),
        PcodeOp::binary(OpCode::IntSLess, decoder.sf_varnode(), mem_value.clone(), rhs_vn.clone(), address),
        PcodeOp::binary(OpCode::IntLess, decoder.cf_varnode(), mem_value, rhs_vn, address),
    ]
}



pub fn decode_cmp_mem_imm(decoder: &mut X86Decoder, mem_addr: Varnode, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let mem_value = decoder.next_unique(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    let temp = decoder.next_unique(size);

    vec![
        // mem_value = *mem_addr (Load)
        PcodeOp::unary(OpCode::Load, mem_value.clone(), mem_addr, address),
        // temp = mem_value - rhs (Compare)
        PcodeOp::binary(OpCode::IntSub, temp, mem_value.clone(), imm_vn.clone(), address),
        // Update flags
        PcodeOp::binary(OpCode::IntEqual, decoder.zf_varnode(), mem_value.clone(), imm_vn.clone(), address),
        PcodeOp::binary(OpCode::IntSLess, decoder.sf_varnode(), mem_value.clone(), imm_vn.clone(), address),
        PcodeOp::binary(OpCode::IntLess, decoder.cf_varnode(), mem_value, imm_vn, address),
    ]
}

// ===== Conditional Jumps =====

/// je/jz target - equal / zero
pub fn decode_je(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    vec![PcodeOp::no_output(OpCode::CBranch, vec![target_vn, decoder.zf_varnode()], address)]
}

/// jne/jnz target - not equal / not zero
pub fn decode_jne(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let not_zf = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, not_zf], address),
    ]
}

/// jl/jnge target - less (signed)
pub fn decode_jl(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let cond = decoder.next_unique(1);
    vec![
        // SF != OF
        PcodeOp::binary(OpCode::BoolXor, cond.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
    ]
}

/// jle/jng target - less or equal (signed)
pub fn decode_jle(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let sf_ne_of = decoder.next_unique(1);
    let cond = decoder.next_unique(1);
    vec![
        PcodeOp::binary(OpCode::BoolXor, sf_ne_of.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        // ZF || (SF != OF)
        PcodeOp::binary(OpCode::BoolOr, cond.clone(), decoder.zf_varnode(), sf_ne_of, address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
    ]
}

/// jg/jnle target - greater (signed)
pub fn decode_jg(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let not_zf = decoder.next_unique(1);
    let sf_eq_of = decoder.next_unique(1);
    let cond = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        // SF == OF (NOT(SF XOR OF))
        PcodeOp::binary(OpCode::BoolXor, sf_eq_of.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::unary(OpCode::BoolNegate, sf_eq_of.clone(), sf_eq_of.clone(), address),
        // !ZF && (SF == OF)
        PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_zf, sf_eq_of, address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
    ]
}

/// jge/jnl target - greater or equal (signed)
pub fn decode_jge(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let sf_eq_of = decoder.next_unique(1);
    vec![
        // SF == OF (NOT(SF XOR OF))
        PcodeOp::binary(OpCode::BoolXor, sf_eq_of.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::unary(OpCode::BoolNegate, sf_eq_of.clone(), sf_eq_of.clone(), address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, sf_eq_of], address),
    ]
}

/// jb/jc/jnae target - below (unsigned) / carry
pub fn decode_jb(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    vec![PcodeOp::no_output(OpCode::CBranch, vec![target_vn, decoder.cf_varnode()], address)]
}

/// jbe/jna target - below or equal (unsigned)
pub fn decode_jbe(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let cond = decoder.next_unique(1);
    vec![
        // CF || ZF
        PcodeOp::binary(OpCode::BoolOr, cond.clone(), decoder.cf_varnode(), decoder.zf_varnode(), address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
    ]
}

/// ja/jnbe target - above (unsigned)
pub fn decode_ja(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let not_cf = decoder.next_unique(1);
    let not_zf = decoder.next_unique(1);
    let cond = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_cf.clone(), decoder.cf_varnode(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        // !CF && !ZF
        PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_cf, not_zf, address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, cond], address),
    ]
}

/// jae/jnb/jnc target - above or equal (unsigned) / no carry
pub fn decode_jae(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let not_cf = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_cf.clone(), decoder.cf_varnode(), address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, not_cf], address),
    ]
}

/// js target - sign (negative)
pub fn decode_js(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    vec![PcodeOp::no_output(OpCode::CBranch, vec![target_vn, decoder.sf_varnode()], address)]
}

/// jns target - not sign (positive or zero)
pub fn decode_jns(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let not_sf = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_sf.clone(), decoder.sf_varnode(), address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, not_sf], address),
    ]
}

/// jo target - overflow
pub fn decode_jo(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    vec![PcodeOp::no_output(OpCode::CBranch, vec![target_vn, decoder.of_varnode()], address)]
}

/// jno target - not overflow
pub fn decode_jno(decoder: &mut X86Decoder, target: u64, address: u64) -> Vec<PcodeOp> {
    let target_vn = Varnode::constant(target, 8);
    let not_of = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_of.clone(), decoder.of_varnode(), address),
        PcodeOp::no_output(OpCode::CBranch, vec![target_vn, not_of], address),
    ]
}

// ===== setcc (Conditional Set) =====



pub fn decode_sete(decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode_8();
    vec![PcodeOp::unary(OpCode::Copy, reg_vn, decoder.zf_varnode(), address)]
}

pub fn decode_setne(decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode_8();
    let not_zf = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        PcodeOp::unary(OpCode::Copy, reg_vn, not_zf, address),
    ]
}

pub fn decode_setl(decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode_8();
    let cond = decoder.next_unique(1);
    vec![
        PcodeOp::binary(OpCode::BoolXor, cond.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::unary(OpCode::Copy, reg_vn, cond, address),
    ]
}

pub fn decode_setg(decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode_8();
    let not_zf = decoder.next_unique(1);
    let sf_eq_of = decoder.next_unique(1);
    let cond = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        PcodeOp::binary(OpCode::BoolXor, sf_eq_of.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::unary(OpCode::BoolNegate, sf_eq_of.clone(), sf_eq_of.clone(), address),
        PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_zf, sf_eq_of, address),
        PcodeOp::unary(OpCode::Copy, reg_vn, cond, address),
    ]
}

pub fn decode_setb(decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode_8();
    vec![PcodeOp::unary(OpCode::Copy, reg_vn, decoder.cf_varnode(), address)]
}

pub fn decode_seta(decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode_8();
    let not_cf = decoder.next_unique(1);
    let not_zf = decoder.next_unique(1);
    let cond = decoder.next_unique(1);
    vec![
        PcodeOp::unary(OpCode::BoolNegate, not_cf.clone(), decoder.cf_varnode(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_cf, not_zf, address),
        PcodeOp::unary(OpCode::Copy, reg_vn, cond, address),
    ]
}

// ===== cmovcc (Conditional Move) =====

/// cmove/cmovz - move if equal/zero (ZF=1)
pub fn decode_cmove(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![decoder.zf_varnode(), src_vn, old_dest], address),
    ]
}

/// cmovne/cmovnz - move if not equal/not zero (ZF=0)
pub fn decode_cmovne(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let not_zf = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![not_zf, src_vn, old_dest], address),
    ]
}



pub fn decode_cmovl(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let cond = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::binary(OpCode::BoolXor, cond.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![cond, src_vn, old_dest], address),
    ]
}

/// cmovle/cmovng - move if less or equal (ZF=1 or SF!=OF)
pub fn decode_cmovle(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let sf_ne_of = decoder.next_unique(1);
    let cond = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::binary(OpCode::BoolXor, sf_ne_of.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::binary(OpCode::BoolOr, cond.clone(), decoder.zf_varnode(), sf_ne_of, address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![cond, src_vn, old_dest], address),
    ]
}

/// cmovge/cmovnl - move if greater or equal (SF==OF)
pub fn decode_cmovge(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let sf_eq_of = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::binary(OpCode::BoolXor, sf_eq_of.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::unary(OpCode::BoolNegate, sf_eq_of.clone(), sf_eq_of.clone(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![sf_eq_of, src_vn, old_dest], address),
    ]
}

/// cmovg/cmovnle - move if greater (ZF=0 and SF==OF)
pub fn decode_cmovg(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let not_zf = decoder.next_unique(1);
    let sf_eq_of = decoder.next_unique(1);
    let cond = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        PcodeOp::binary(OpCode::BoolXor, sf_eq_of.clone(), decoder.sf_varnode(), decoder.of_varnode(), address),
        PcodeOp::unary(OpCode::BoolNegate, sf_eq_of.clone(), sf_eq_of.clone(), address),
        PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_zf, sf_eq_of, address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![cond, src_vn, old_dest], address),
    ]
}

/// cmovb/cmovc/cmovnae - move if below (CF=1)
pub fn decode_cmovb(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![decoder.cf_varnode(), src_vn, old_dest], address),
    ]
}

/// cmovbe/cmovna - move if below or equal (CF=1 or ZF=1)
pub fn decode_cmovbe(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let cond = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::binary(OpCode::BoolOr, cond.clone(), decoder.cf_varnode(), decoder.zf_varnode(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![cond, src_vn, old_dest], address),
    ]
}

/// cmova/cmovnbe - move if above (CF=0 and ZF=0)
pub fn decode_cmova(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let not_cf = decoder.next_unique(1);
    let not_zf = decoder.next_unique(1);
    let cond = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_cf.clone(), decoder.cf_varnode(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_zf.clone(), decoder.zf_varnode(), address),
        PcodeOp::binary(OpCode::BoolAnd, cond.clone(), not_cf, not_zf, address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![cond, src_vn, old_dest], address),
    ]
}

/// cmovae/cmovnb/cmovnc - move if above or equal (CF=0)
pub fn decode_cmovae(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let not_cf = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_cf.clone(), decoder.cf_varnode(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![not_cf, src_vn, old_dest], address),
    ]
}

/// cmovs - move if sign (SF=1)
pub fn decode_cmovs(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![decoder.sf_varnode(), src_vn, old_dest], address),
    ]
}

/// cmovns - move if not sign (SF=0)
pub fn decode_cmovns(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let not_sf = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_sf.clone(), decoder.sf_varnode(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![not_sf, src_vn, old_dest], address),
    ]
}

/// cmovo - move if overflow (OF=1)
pub fn decode_cmovo(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![decoder.of_varnode(), src_vn, old_dest], address),
    ]
}

/// cmovno - move if not overflow (OF=0)
pub fn decode_cmovno(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let not_of = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_of.clone(), decoder.of_varnode(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![not_of, src_vn, old_dest], address),
    ]
}

/// cmovp/cmovpe - move if parity (PF=1)
pub fn decode_cmovp(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![decoder.pf_varnode(), src_vn, old_dest], address),
    ]
}

/// cmovnp/cmovpo - move if not parity (PF=0)
pub fn decode_cmovnp(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let old_dest = decoder.next_unique(size);
    let not_pf = decoder.next_unique(1);

    vec![
        PcodeOp::unary(OpCode::Copy, old_dest.clone(), dest_vn.clone(), address),
        PcodeOp::unary(OpCode::BoolNegate, not_pf.clone(), decoder.pf_varnode(), address),
        PcodeOp::new(OpCode::MultiEqual, Some(dest_vn), vec![not_pf, src_vn, old_dest], address),
    ]
}
