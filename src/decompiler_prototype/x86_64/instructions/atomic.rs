use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode};
use super::super::registers::X86Register;
use super::super::X86Decoder;





pub fn decode_lock_add_mem(decoder: &mut X86Decoder, base: X86Register, offset: i64, imm: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    // Calculate memory address
    let base_vn = base.to_varnode(8);
    let offset_vn = Varnode::constant(offset as u64, 8);
    let addr_temp = decoder.next_unique(8);

    // Load current value
    let value_temp = decoder.next_unique(size);

    // Addition result
    let imm_vn = Varnode::constant(imm as u64, size);
    let result_temp = decoder.next_unique(size);

    vec![
        // addr_temp = base + offset
        PcodeOp::binary(OpCode::IntAdd, addr_temp.clone(), base_vn, offset_vn, address),
        // value_temp = *addr_temp (Load from RAM)
        PcodeOp::unary(OpCode::Load, value_temp.clone(), addr_temp.clone(), address),
        // result_temp = value_temp + imm
        PcodeOp::binary(OpCode::IntAdd, result_temp.clone(), value_temp, imm_vn, address),
        // *addr_temp = result_temp (Store to memory)
        PcodeOp::no_output(OpCode::Store, vec![addr_temp, result_temp], address),
        // Note: Atomicity guaranteed at instruction level (lock prefix)
    ]
}





pub fn decode_lock_xadd_mem(decoder: &mut X86Decoder, base: X86Register, offset: i64, src_reg: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    // Calculate memory address
    let base_vn = base.to_varnode(8);
    let offset_vn = Varnode::constant(offset as u64, 8);
    let addr_temp = decoder.next_unique(8);

    // Load current value
    let old_value = decoder.next_unique(size);

    // Value from src_reg
    let src_vn = src_reg.to_varnode(size);

    // Addition result
    let result_temp = decoder.next_unique(size);

    vec![
        // addr_temp = base + offset
        PcodeOp::binary(OpCode::IntAdd, addr_temp.clone(), base_vn, offset_vn, address),
        // old_value = *addr_temp (Load from RAM)
        PcodeOp::unary(OpCode::Load, old_value.clone(), addr_temp.clone(), address),
        // result_temp = old_value + src_reg
        PcodeOp::binary(OpCode::IntAdd, result_temp.clone(), old_value.clone(), src_vn.clone(), address),
        // *addr_temp = result_temp (Store to memory)
        PcodeOp::no_output(OpCode::Store, vec![addr_temp, result_temp], address),
        // src_reg = old_value (Exchange)
        PcodeOp::unary(OpCode::Copy, src_vn, old_value, address),
    ]
}



pub fn decode_lock_inc_mem(decoder: &mut X86Decoder, base: X86Register, offset: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    decode_lock_add_mem(decoder, base, offset, 1, size, address)
}



pub fn decode_lock_dec_mem(decoder: &mut X86Decoder, base: X86Register, offset: i64, size: usize, address: u64) -> Vec<PcodeOp> {
    decode_lock_add_mem(decoder, base, offset, -1, size, address)
}
