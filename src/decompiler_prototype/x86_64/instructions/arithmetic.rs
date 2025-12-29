use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode};
use super::super::registers::X86Register;
use super::super::X86Decoder;

/// add reg, reg
pub fn decode_add(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntAdd, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
    ops.extend(decoder.update_flags_arithmetic(&dest_vn, address));
    ops
}

/// add reg, imm
pub fn decode_add_imm(decoder: &mut X86Decoder, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntAdd, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
    ops.extend(decoder.update_flags_arithmetic(&dest_vn, address));
    ops
}

/// sub reg, reg
pub fn decode_sub(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntSub, dest_vn.clone(), dest_vn.clone(), src_vn, address)];
    ops.extend(decoder.update_flags_arithmetic(&dest_vn, address));
    ops
}

/// sub reg, imm
pub fn decode_sub_imm(decoder: &mut X86Decoder, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntSub, dest_vn.clone(), dest_vn.clone(), imm_vn, address)];
    ops.extend(decoder.update_flags_arithmetic(&dest_vn, address));
    ops
}

/// inc reg
pub fn decode_inc(decoder: &mut X86Decoder, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let one = Varnode::constant(1, size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntAdd, reg_vn.clone(), reg_vn.clone(), one, address)];
    ops.extend(decoder.update_flags_arithmetic(&reg_vn, address));
    ops
}

/// dec reg
pub fn decode_dec(decoder: &mut X86Decoder, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let one = Varnode::constant(1, size);
    let mut ops = vec![PcodeOp::binary(OpCode::IntSub, reg_vn.clone(), reg_vn.clone(), one, address)];
    ops.extend(decoder.update_flags_arithmetic(&reg_vn, address));
    ops
}



pub fn decode_inc_mem(decoder: &mut X86Decoder, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
    let value_temp = decoder.next_unique(size);
    let one = Varnode::constant(1, size);
    let result_temp = decoder.next_unique(size);

    vec![
        // value_temp = *mem_addr (Load)
        PcodeOp::unary(OpCode::Load, value_temp.clone(), mem_addr.clone(), address),
        // result_temp = value_temp + 1
        PcodeOp::binary(OpCode::IntAdd, result_temp.clone(), value_temp, one, address),
        // *mem_addr = result_temp (Store)
        PcodeOp::no_output(OpCode::Store, vec![mem_addr, result_temp.clone()], address),
        // Flags update omitted for simplification (TODO)
    ]
}



pub fn decode_dec_mem(decoder: &mut X86Decoder, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
    let value_temp = decoder.next_unique(size);
    let one = Varnode::constant(1, size);
    let result_temp = decoder.next_unique(size);

    vec![
        // value_temp = *mem_addr (Load)
        PcodeOp::unary(OpCode::Load, value_temp.clone(), mem_addr.clone(), address),
        // result_temp = value_temp - 1
        PcodeOp::binary(OpCode::IntSub, result_temp.clone(), value_temp, one, address),
        // *mem_addr = result_temp (Store)
        PcodeOp::no_output(OpCode::Store, vec![mem_addr, result_temp.clone()], address),
    ]
}



pub fn decode_neg(decoder: &mut X86Decoder, reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg_vn = reg.to_varnode(size);
    let mut ops = vec![PcodeOp::unary(OpCode::Int2Comp, reg_vn.clone(), reg_vn.clone(), address)];
    ops.extend(decoder.update_flags_arithmetic(&reg_vn, address));
    ops
}



pub fn decode_imul(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    vec![PcodeOp::binary(OpCode::IntMult, dest_vn.clone(), dest_vn, src_vn, address)]
}



pub fn decode_imul3(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    let imm_vn = Varnode::constant(imm as u64, size);
    vec![PcodeOp::binary(OpCode::IntMult, dest_vn, src_vn, imm_vn, address)]
}



pub fn decode_mul(decoder: &mut X86Decoder, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let rax = X86Register::RAX.to_varnode(size);
    let rdx = X86Register::RDX.to_varnode(size);
    let src_vn = src.to_varnode(size);

    // Result stored in temp of double size
    let result = decoder.next_unique(size * 2);

    vec![
        PcodeOp::binary(OpCode::IntMult, result.clone(), rax.clone(), src_vn, address),
        // Low part to RAX
        PcodeOp::unary(OpCode::SubPiece, rax, Varnode::constant(0, size), address),
        // High part to RDX
        PcodeOp::unary(OpCode::SubPiece, rdx, Varnode::constant(size as u64, size), address),
    ]
}



pub fn decode_div(_decoder: &mut X86Decoder, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let rax = X86Register::RAX.to_varnode(size);
    let rdx = X86Register::RDX.to_varnode(size);
    let src_vn = src.to_varnode(size);

    vec![
        // Quotient to RAX
        PcodeOp::binary(OpCode::IntDiv, rax.clone(), rax.clone(), src_vn.clone(), address),
        // Remainder to RDX
        PcodeOp::binary(OpCode::IntRem, rdx, rax, src_vn, address),
    ]
}



pub fn decode_idiv(_decoder: &mut X86Decoder, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let rax = X86Register::RAX.to_varnode(size);
    let rdx = X86Register::RDX.to_varnode(size);
    let src_vn = src.to_varnode(size);

    vec![
        PcodeOp::binary(OpCode::IntSDiv, rax.clone(), rax.clone(), src_vn.clone(), address),
        PcodeOp::binary(OpCode::IntSRem, rdx, rax, src_vn, address),
    ]
}
