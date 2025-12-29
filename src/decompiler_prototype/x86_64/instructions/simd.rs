use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode};
use super::super::registers::X86Register;
use super::super::X86Decoder;

// ===== SSE/AVX Ops (SIMD) =====

/// movaps xmm, xmm - Aligned Packed Single-Precision Move (128-bit)


pub fn decode_movaps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16); // 128-bit = 16 bytes
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::unary(OpCode::Copy, dest_vn, src_vn, address)]
}

/// movaps xmm, [memory] - Load from aligned memory
pub fn decode_movaps_load(_decoder: &mut X86Decoder, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    vec![PcodeOp::unary(OpCode::Load, dest_vn, mem_addr, address)]
}

/// movaps [memory], xmm - Store to aligned memory
pub fn decode_movaps_store(_decoder: &mut X86Decoder, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::no_output(OpCode::Store, vec![mem_addr, src_vn], address)]
}

/// movups xmm, xmm - Unaligned Packed Single-Precision Move


pub fn decode_movups(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    decode_movaps(decoder, dest, src, address)
}

/// movups xmm, [memory] - Load from unaligned memory
pub fn decode_movups_load(decoder: &mut X86Decoder, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
    decode_movaps_load(decoder, dest, mem_addr, address)
}

/// movups [memory], xmm - Store to unaligned memory
pub fn decode_movups_store(decoder: &mut X86Decoder, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> {
    decode_movaps_store(decoder, mem_addr, src, address)
}

/// xorps xmm, xmm - XOR Packed Single-Precision


pub fn decode_xorps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntXor, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// andps xmm, xmm - AND Packed Single-Precision
pub fn decode_andps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// orps xmm, xmm - OR Packed Single-Precision
pub fn decode_orps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntOr, dest_vn.clone(), dest_vn, src_vn, address)]
}

// ===== SSE Scalar Move Ops =====

/// movss xmm, xmm - Move Scalar Single-Precision (32-bit)
pub fn decode_movss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    // Copy lower 32 bits only (preserve upper 96)
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::unary(OpCode::Copy, dest_vn, src_vn, address)]
}

/// movss xmm, [memory] - Load scalar from memory
pub fn decode_movss_load(_decoder: &mut X86Decoder, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    vec![PcodeOp::unary(OpCode::Load, dest_vn, mem_addr, address)]
}

/// movss [memory], xmm - Store scalar to memory
pub fn decode_movss_store(_decoder: &mut X86Decoder, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::no_output(OpCode::Store, vec![mem_addr, src_vn], address)]
}

/// movsd xmm, xmm - Move Scalar Double-Precision (64-bit)
pub fn decode_movsd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    // Copy lower 64 bits only (preserve upper 64)
    let dest_vn = dest.to_varnode(8);
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::unary(OpCode::Copy, dest_vn, src_vn, address)]
}

/// movsd xmm, [memory] - Load scalar double from memory
pub fn decode_movsd_load(_decoder: &mut X86Decoder, dest: X86Register, mem_addr: Varnode, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(8);
    vec![PcodeOp::unary(OpCode::Load, dest_vn, mem_addr, address)]
}

/// movsd [memory], xmm - Store scalar double to memory
pub fn decode_movsd_store(_decoder: &mut X86Decoder, mem_addr: Varnode, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::no_output(OpCode::Store, vec![mem_addr, src_vn], address)]
}

// ===== SSE Arithmetic Ops =====

/// addps xmm, xmm - Add Packed Single-Precision (4x32-bit floats)
pub fn decode_addps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    // Simplified: treated as 128-bit add
    vec![PcodeOp::binary(OpCode::IntAdd, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// addss xmm, xmm - Add Scalar Single-Precision (32-bit float)
pub fn decode_addss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::binary(OpCode::FloatAdd, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// addpd xmm, xmm - Add Packed Double-Precision (2x64-bit floats)
pub fn decode_addpd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    // Simplified: treated as 128-bit add
    vec![PcodeOp::binary(OpCode::IntAdd, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// addsd xmm, xmm - Add Scalar Double-Precision (64-bit float)
pub fn decode_addsd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(8);
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::binary(OpCode::FloatAdd, dest_vn.clone(), dest_vn, src_vn, address)]
}

// ===== SSE Subtract Ops =====

/// subps xmm, xmm - Subtract Packed Single-Precision
pub fn decode_subps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntSub, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// subss xmm, xmm - Subtract Scalar Single-Precision
pub fn decode_subss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::binary(OpCode::FloatSub, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// subpd xmm, xmm - Subtract Packed Double-Precision
pub fn decode_subpd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntSub, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// subsd xmm, xmm - Subtract Scalar Double-Precision
pub fn decode_subsd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(8);
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::binary(OpCode::FloatSub, dest_vn.clone(), dest_vn, src_vn, address)]
}

// ===== SSE Multiply Ops =====

/// mulps xmm, xmm - Multiply Packed Single-Precision
pub fn decode_mulps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntMult, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// mulss xmm, xmm - Multiply Scalar Single-Precision
pub fn decode_mulss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::binary(OpCode::FloatMult, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// mulpd xmm, xmm - Multiply Packed Double-Precision
pub fn decode_mulpd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntMult, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// mulsd xmm, xmm - Multiply Scalar Double-Precision
pub fn decode_mulsd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(8);
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::binary(OpCode::FloatMult, dest_vn.clone(), dest_vn, src_vn, address)]
}

// ===== SSE Divide Ops =====

/// divps xmm, xmm - Divide Packed Single-Precision
pub fn decode_divps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntDiv, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// divss xmm, xmm - Divide Scalar Single-Precision
pub fn decode_divss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::binary(OpCode::FloatDiv, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// divpd xmm, xmm - Divide Packed Double-Precision
pub fn decode_divpd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::binary(OpCode::IntDiv, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// divsd xmm, xmm - Divide Scalar Double-Precision
pub fn decode_divsd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(8);
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::binary(OpCode::FloatDiv, dest_vn.clone(), dest_vn, src_vn, address)]
}

// ===== SSE Sqrt Ops =====

/// sqrtps xmm, xmm - Square Root Packed Single-Precision
pub fn decode_sqrtps(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    // Simplified: treated as single op
    vec![PcodeOp::unary(OpCode::FloatSqrt, dest_vn, src_vn, address)]
}

/// sqrtss xmm, xmm - Square Root Scalar Single-Precision
pub fn decode_sqrtss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::unary(OpCode::FloatSqrt, dest_vn, src_vn, address)]
}

/// sqrtpd xmm, xmm - Square Root Packed Double-Precision
pub fn decode_sqrtpd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    vec![PcodeOp::unary(OpCode::FloatSqrt, dest_vn, src_vn, address)]
}

/// sqrtsd xmm, xmm - Square Root Scalar Double-Precision
pub fn decode_sqrtsd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(8);
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::unary(OpCode::FloatSqrt, dest_vn, src_vn, address)]
}

// ===== SSE Max/Min Ops =====

/// maxps xmm, xmm - Maximum Packed Single-Precision
pub fn decode_maxps(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    let temp = decoder.next_unique(1);
    // dest = (dest > src) ? dest : src
    vec![
        PcodeOp::binary(OpCode::FloatLess, temp.clone(), dest_vn.clone(), src_vn.clone(), address),
        // Simplified conditional choice approximation
        PcodeOp::binary(OpCode::IntOr, dest_vn.clone(), dest_vn, src_vn, address),
    ]
}

/// maxss xmm, xmm - Maximum Scalar Single-Precision
pub fn decode_maxss(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);
    let temp = decoder.next_unique(1);
    vec![
        PcodeOp::binary(OpCode::FloatLess, temp.clone(), dest_vn.clone(), src_vn.clone(), address),
        // Simplified max(a, b) approximation
        PcodeOp::binary(OpCode::IntOr, dest_vn.clone(), dest_vn, src_vn, address),
    ]
}

/// minps xmm, xmm - Minimum Packed Single-Precision
pub fn decode_minps(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    let temp = decoder.next_unique(1);
    vec![
        PcodeOp::binary(OpCode::FloatLess, temp.clone(), dest_vn.clone(), src_vn.clone(), address),
        PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), dest_vn, src_vn, address),
    ]
}

/// minss xmm, xmm - Minimum Scalar Single-Precision
pub fn decode_minss(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);
    let temp = decoder.next_unique(1);
    vec![
        PcodeOp::binary(OpCode::FloatLess, temp.clone(), dest_vn.clone(), src_vn.clone(), address),
        PcodeOp::binary(OpCode::IntAnd, dest_vn.clone(), dest_vn, src_vn, address),
    ]
}

// ===== SSE Compare Ops =====

/// cmpps xmm, xmm, imm8 - Compare Packed Single-Precision
pub fn decode_cmpps(decoder: &mut X86Decoder, dest: X86Register, src: X86Register, imm: u8, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(16);
    let src_vn = src.to_varnode(16);
    let result = decoder.next_unique(16);

    // imm8 determines compare type (0=EQ, 1=LT, 2=LE...);
    let opcode = match imm {
        0 => OpCode::FloatEqual,
        1 => OpCode::FloatLess,
        2 => OpCode::FloatLessEqual,
        4 => OpCode::FloatNotEqual,
        _ => OpCode::FloatEqual, // Default EQ
    };

    vec![PcodeOp::binary(opcode, result.clone(), dest_vn.clone(), src_vn, address)]
}

/// cmpss xmm, xmm, imm8 - Compare Scalar Single-Precision
pub fn decode_cmpss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, imm: u8, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(4);

    let opcode = match imm {
        0 => OpCode::FloatEqual,
        1 => OpCode::FloatLess,
        2 => OpCode::FloatLessEqual,
        4 => OpCode::FloatNotEqual,
        _ => OpCode::FloatEqual,
    };

    vec![PcodeOp::binary(opcode, dest_vn.clone(), dest_vn, src_vn, address)]
}

/// ucomiss xmm, xmm - Unordered Compare Scalar Single-Precision
pub fn decode_ucomiss(decoder: &mut X86Decoder, lhs: X86Register, rhs: X86Register, address: u64) -> Vec<PcodeOp> {
    let lhs_vn = lhs.to_varnode(4);
    let rhs_vn = rhs.to_varnode(4);

    // Flag update (ZF, PF, CF)
    vec![
        PcodeOp::binary(OpCode::FloatEqual, decoder.zf_varnode(), lhs_vn.clone(), rhs_vn.clone(), address),
        PcodeOp::binary(OpCode::FloatLess, decoder.cf_varnode(), lhs_vn, rhs_vn, address),
    ]
}

/// ucomisd xmm, xmm - Unordered Compare Scalar Double-Precision
pub fn decode_ucomisd(decoder: &mut X86Decoder, lhs: X86Register, rhs: X86Register, address: u64) -> Vec<PcodeOp> {
    let lhs_vn = lhs.to_varnode(8);
    let rhs_vn = rhs.to_varnode(8);

    vec![
        PcodeOp::binary(OpCode::FloatEqual, decoder.zf_varnode(), lhs_vn.clone(), rhs_vn.clone(), address),
        PcodeOp::binary(OpCode::FloatLess, decoder.cf_varnode(), lhs_vn, rhs_vn, address),
    ]
}

// ===== SSE Convert Ops =====

/// cvtss2sd xmm, xmm - Convert Scalar Single to Double
pub fn decode_cvtss2sd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(8);
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::unary(OpCode::FloatFloat2Float, dest_vn, src_vn, address)]
}

/// cvtsd2ss xmm, xmm - Convert Scalar Double to Single
pub fn decode_cvtsd2ss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::unary(OpCode::FloatFloat2Float, dest_vn, src_vn, address)]
}

/// cvtsi2ss xmm, reg - Convert Signed Integer to Scalar Single
pub fn decode_cvtsi2ss(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(4);
    let src_vn = src.to_varnode(size);
    vec![PcodeOp::unary(OpCode::FloatInt2Float, dest_vn, src_vn, address)]
}

/// cvtsi2sd xmm, reg - Convert Signed Integer to Scalar Double
pub fn decode_cvtsi2sd(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(8);
    let src_vn = src.to_varnode(size);
    vec![PcodeOp::unary(OpCode::FloatInt2Float, dest_vn, src_vn, address)]
}

/// cvtss2si reg, xmm - Convert Scalar Single to Signed Integer
pub fn decode_cvtss2si(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, dest_size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(dest_size);
    let src_vn = src.to_varnode(4);
    vec![PcodeOp::unary(OpCode::FloatTrunc, dest_vn, src_vn, address)]
}

/// cvtsd2si reg, xmm - Convert Scalar Double to Signed Integer
pub fn decode_cvtsd2si(_decoder: &mut X86Decoder, dest: X86Register, src: X86Register, dest_size: usize, address: u64) -> Vec<PcodeOp> {
    let dest_vn = dest.to_varnode(dest_size);
    let src_vn = src.to_varnode(8);
    vec![PcodeOp::unary(OpCode::FloatTrunc, dest_vn, src_vn, address)]
}
