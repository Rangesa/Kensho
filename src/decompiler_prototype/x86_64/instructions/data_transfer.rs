use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode};
use super::super::registers::X86Register;
use super::super::X86Decoder;

/// mov reg, reg
pub fn decode_mov(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = src.to_varnode(size);
    vec![PcodeOp::unary(OpCode::Copy, dest_vn, src_vn, address)]
}

/// mov reg, imm
pub fn decode_mov_imm(_decoder: &mut X86Decoder, dest: X86Register, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    let src_vn = Varnode::constant(imm as u64, size);
    vec![PcodeOp::unary(OpCode::Copy, dest_vn, src_vn, address)]
}

/// mov reg, [mem]
pub fn decode_mov_load(_decoder: &mut X86Decoder, dest: X86Register, mem_addr: Varnode, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(size);
    vec![PcodeOp::unary(OpCode::Load, dest_vn, mem_addr, address)]
}

/// mov [mem], reg
pub fn decode_mov_store(_decoder: &mut X86Decoder, mem_addr: Varnode, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let src_vn = src.to_varnode(size);
    vec![PcodeOp::no_output(OpCode::Store, vec![mem_addr, src_vn], address)]
}



pub fn decode_lea(_decoder: &mut X86Decoder, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode_64();
    vec![PcodeOp::unary(OpCode::Copy, dest_vn, mem_addr, address)]
}



pub fn decode_movzx(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, dest_size: usize, src_size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(dest_size);
    let src_vn = src.to_varnode(src_size);
    vec![PcodeOp::unary(OpCode::IntZExt, dest_vn, src_vn, address)]
}



pub fn decode_movsx(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, dest_size: usize, src_size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(dest_size);
    let src_vn = src.to_varnode(src_size);
    vec![PcodeOp::unary(OpCode::IntSExt, dest_vn, src_vn, address)]
}



pub fn decode_xchg(decoder: &mut X86Decoder, reg1: X86Register, reg2: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let reg1_vn = reg1.to_varnode(size);
    let reg2_vn = reg2.to_varnode(size);
    let temp = decoder.next_unique(size);

    vec![
        PcodeOp::unary(OpCode::Copy, temp.clone(), reg1_vn.clone(), address),
        PcodeOp::unary(OpCode::Copy, reg1_vn, reg2_vn.clone(), address),
        PcodeOp::unary(OpCode::Copy, reg2_vn, temp, address),
    ]
}

/// push reg
pub fn decode_push(_decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
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
pub fn decode_push_imm(_decoder: &mut X86Decoder, imm: i64, address: u64) -> Vec<PcodeOp> {
    let rsp = X86Register::RSP.to_varnode_64();
    let imm_vn = Varnode::constant(imm as u64, 8);
    let eight = Varnode::constant(8, 8);

    vec![
        PcodeOp::binary(OpCode::IntSub, rsp.clone(), rsp.clone(), eight, address),
        PcodeOp::no_output(OpCode::Store, vec![rsp, imm_vn], address),
    ]
}

/// pop reg
pub fn decode_pop(_decoder: &mut X86Decoder, reg: X86Register, address: u64) -> Vec<PcodeOp> {
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



pub fn decode_enter(_decoder: &mut X86Decoder, size: u16, level: u8, address: u64) -> Vec<PcodeOp> {
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

    // Handle level > 0 if needed (usually 0)
    let _ = level;

    ops
}



pub fn decode_leave(_decoder: &mut X86Decoder, address: u64) -> Vec<PcodeOp> {
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
