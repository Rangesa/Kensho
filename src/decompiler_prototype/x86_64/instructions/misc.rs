use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode};
use super::super::registers::X86Register;
use super::super::X86Decoder;



pub fn decode_nop(_decoder: &mut X86Decoder, _address: u64) -> Vec<PcodeOp> {
    vec![]
}

/// cdq - EDX:EAX = sign-extend(EAX)
pub fn decode_cdq(decoder: &mut X86Decoder, address: u64) -> Vec<PcodeOp> {
    let eax = X86Register::RAX.to_varnode_32();
    let edx = X86Register::RDX.to_varnode_32();
    let temp = decoder.next_unique(8);

    vec![
        // EAX sign-extend to 64-bit
        PcodeOp::unary(OpCode::IntSExt, temp.clone(), eax, address),
        // Upper 32 bits to EDX
        PcodeOp::binary(OpCode::IntSRight, edx, temp, Varnode::constant(32, 1), address),
    ]
}

/// cqo - RDX:RAX = sign-extend(RAX)
pub fn decode_cqo(_decoder: &mut X86Decoder, address: u64) -> Vec<PcodeOp> {
    let rax = X86Register::RAX.to_varnode_64();
    let rdx = X86Register::RDX.to_varnode_64();

    vec![
        // RAX sign bit extend to RDX
        PcodeOp::binary(OpCode::IntSRight, rdx, rax, Varnode::constant(63, 1), address),
    ]
}

/// cbw - AX = sign-extend(AL)
pub fn decode_cbw(_decoder: &mut X86Decoder, address: u64) -> Vec<PcodeOp> {
    let al = X86Register::RAX.to_varnode_8();
    let ax = X86Register::RAX.to_varnode_16();

    vec![
        PcodeOp::unary(OpCode::IntSExt, ax, al, address),
    ]
}

/// cwde - EAX = sign-extend(AX)
pub fn decode_cwde(_decoder: &mut X86Decoder, address: u64) -> Vec<PcodeOp> {
    let ax = X86Register::RAX.to_varnode_16();
    let eax = X86Register::RAX.to_varnode_32();

    vec![
        PcodeOp::unary(OpCode::IntSExt, eax, ax, address),
    ]
}

/// cdqe - RAX = sign-extend(EAX)
pub fn decode_cdqe(_decoder: &mut X86Decoder, address: u64) -> Vec<PcodeOp> {
    let eax = X86Register::RAX.to_varnode_32();
    let rax = X86Register::RAX.to_varnode_64();

    vec![
        PcodeOp::unary(OpCode::IntSExt, rax, eax, address),
    ]
}

// ===== String Operations =====

/// LODSx - Load String (RSI -> RAX/EAX/AX/AL, RSI += size)
pub fn decode_lods(decoder: &mut X86Decoder, size: usize, address: u64) -> Vec<PcodeOp> {
    let mut ops = Vec::new();
    let rsi = X86Register::RSI.to_varnode_64();
    let rax = X86Register::RAX.to_varnode(size);

    // Load from [RSI]
    ops.push(PcodeOp::unary(OpCode::Load, rax, rsi.clone(), address));

    // RSI += size
    let new_rsi = decoder.next_unique(8);
    ops.push(PcodeOp::binary(OpCode::IntAdd, new_rsi.clone(), rsi.clone(), Varnode::constant(size as u64, 8), address));
    ops.push(PcodeOp::unary(OpCode::Copy, rsi, new_rsi, address));

    ops
}

/// STOSx - Store String (RAX/EAX/AX/AL -> [RDI], RDI += size)
pub fn decode_stos(decoder: &mut X86Decoder, size: usize, address: u64) -> Vec<PcodeOp> {
    let mut ops = Vec::new();
    let rdi = X86Register::RDI.to_varnode_64();
    let rax = X86Register::RAX.to_varnode(size);

    // Store to [RDI]
    ops.push(PcodeOp::no_output(OpCode::Store, vec![rdi.clone(), rax], address));

    // RDI += size
    let new_rdi = decoder.next_unique(8);
    ops.push(PcodeOp::binary(OpCode::IntAdd, new_rdi.clone(), rdi.clone(), Varnode::constant(size as u64, 8), address));
    ops.push(PcodeOp::unary(OpCode::Copy, rdi, new_rdi, address));

    ops
}

/// MOVSx - Move String ([RSI] -> [RDI], RSI += size, RDI += size)
pub fn decode_movs(decoder: &mut X86Decoder, size: usize, address: u64) -> Vec<PcodeOp> {
    let mut ops = Vec::new();
    let rsi = X86Register::RSI.to_varnode_64();
    let rdi = X86Register::RDI.to_varnode_64();
    let temp = decoder.next_unique(size);

    // Load from [RSI]
    ops.push(PcodeOp::unary(OpCode::Load, temp.clone(), rsi.clone(), address));

    // Store to [RDI]
    ops.push(PcodeOp::no_output(OpCode::Store, vec![rdi.clone(), temp], address));

    // RSI += size
    let new_rsi = decoder.next_unique(8);
    ops.push(PcodeOp::binary(OpCode::IntAdd, new_rsi.clone(), rsi.clone(), Varnode::constant(size as u64, 8), address));
    ops.push(PcodeOp::unary(OpCode::Copy, rsi, new_rsi, address));

    // RDI += size
    let new_rdi = decoder.next_unique(8);
    ops.push(PcodeOp::binary(OpCode::IntAdd, new_rdi.clone(), rdi.clone(), Varnode::constant(size as u64, 8), address));
    ops.push(PcodeOp::unary(OpCode::Copy, rdi, new_rdi, address));

    ops
}
