use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode};
use super::super::registers::X86Register;
use super::super::X86Decoder;

/// and reg, reg
pub fn decode_and(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
    ops.extend(decoder.update_flags_logical(&dest_vn, address));
    ops
}

/// and reg, imm
pub fn decode_and_imm(decoder: &mut X86Decoder, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
    ops.extend(decoder.update_flags_logical(&dest_vn, address));
    ops
}

/// or reg, reg
pub fn decode_or(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntOr, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
    ops.extend(decoder.update_flags_logical(&dest_vn, address));
    ops
}

/// or reg, imm
pub fn decode_or_imm(decoder: &mut X86Decoder, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntOr, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
    ops.extend(decoder.update_flags_logical(&dest_vn, address));
    ops
}

/// xor reg, reg
pub fn decode_xor(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntXor, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
    ops.extend(decoder.update_flags_logical(&dest_vn, address));
    ops
}

/// xor reg, imm
pub fn decode_xor_imm(decoder: &mut X86Decoder, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntXor, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
    ops.extend(decoder.update_flags_logical(&dest_vn, address));
    ops
}



pub fn decode_not(_decoder: &mut X86Decoder, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    vec![PcodeOp::unary(OpCode::IntNegate, reg_vn.clone(), reg_vn, address)]
}



pub fn decode_shl(decoder: &mut X86Decoder, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let count_vn = Varnode::constant(count as u64, 1);
    let mut ops = vec![PcodeOp::binary(OpCode::IntLeft, reg_vn.clone(), reg_vn.clone(), count_vn, address)];
    ops.extend(decoder.update_flags_logical(&reg_vn, address));
    ops
}



pub fn decode_shl_cl(decoder: &mut X86Decoder, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let cl = X86Register::RCX.to_varnode_8();
    let mut ops = vec![PcodeOp::binary(OpCode::IntLeft, reg_vn.clone(), reg_vn.clone(), cl, address)];
    ops.extend(decoder.update_flags_logical(&reg_vn, address));
    ops
}



pub fn decode_shr(decoder: &mut X86Decoder, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let count_vn = Varnode::constant(count as u64, 1);
    let mut ops = vec![PcodeOp::binary(OpCode::IntRight, reg_vn.clone(), reg_vn.clone(), count_vn, address)];
    ops.extend(decoder.update_flags_logical(&reg_vn, address));
    ops
}



pub fn decode_shr_cl(decoder: &mut X86Decoder, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let cl = X86Register::RCX.to_varnode_8();
    let mut ops = vec![PcodeOp::binary(OpCode::IntRight, reg_vn.clone(), reg_vn.clone(), cl, address)];
    ops.extend(decoder.update_flags_logical(&reg_vn, address));
    ops
}



pub fn decode_sar(decoder: &mut X86Decoder, reg: X86Register, count: u8, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let count_vn = Varnode::constant(count as u64, 1);
    let mut ops = vec![PcodeOp::binary(OpCode::IntSRight, reg_vn.clone(), reg_vn.clone(), count_vn, address)];
    ops.extend(decoder.update_flags_logical(&reg_vn, address));
    ops
}



pub fn decode_sar_cl(decoder: &mut X86Decoder, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let cl = X86Register::RCX.to_varnode_8();
    let mut ops = vec![PcodeOp::binary(OpCode::IntSRight, reg_vn.clone(), reg_vn.clone(), cl, address)];
    ops.extend(decoder.update_flags_logical(&reg_vn, address));
    ops
}



pub fn decode_test(decoder: &mut X86Decoder, lhs: X86Register, rhs: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let lhs_vn = lhs.to_varnode(size);
    let rhs_vn = rhs.to_varnode(size);
    let temp = decoder.next_unique(size);

    let mut ops = vec![
        PcodeOp::binary(OpCode::IntAnd, temp.clone(), lhs_vn, rhs_vn, address),
    ];
    ops.extend(decoder.update_flags_logical(&temp, address));
    ops
}

/// test reg, imm
pub fn decode_test_imm(decoder: &mut X86Decoder, reg: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    let temp = decoder.next_unique(size);

    let mut ops = vec![
        PcodeOp::binary(OpCode::IntAnd, temp.clone(), reg_vn, imm_vn, address),
    ];
    ops.extend(decoder.update_flags_logical(&temp, address));
    ops
}
