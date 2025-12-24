/// Capstone逆アセンブラからP-codeへの自動変換
/// 実際のバイナリを解析してP-codeを生成する

use super::pcode::*;
use super::x86_64::{X86Decoder, X86Register};
use anyhow::{anyhow, Result};
use capstone::prelude::*;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86Reg;

/// Capstone命令をP-codeに変換するトランスレータ
pub struct CapstoneTranslator {
    decoder: X86Decoder,
    cs: Capstone,
}

impl CapstoneTranslator {
    /// 新しいトランスレータを作成
    pub fn new() -> Result<Self> {
        let cs = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .map_err(|e| anyhow!("Failed to create Capstone engine: {}", e))?;

        Ok(Self {
            decoder: X86Decoder::new(),
            cs,
        })
    }

    /// バイナリデータをP-codeに変換
    pub fn translate(&mut self, code: &[u8], base_address: u64, max_instructions: usize) -> Result<Vec<PcodeOp>> {
        // Step 1: 逆アセンブルして必要な情報を全部収集
        let insns = self.cs
            .disasm_count(code, base_address, max_instructions)
            .map_err(|e| anyhow!("Disassembly failed: {}", e))?;

        // 命令情報とオペランド情報を収集
        let mut insn_data = Vec::new();
        for insn in insns.iter() {
            let addr = insn.address();
            let mnemonic = insn.mnemonic().unwrap_or("???").to_string();
            let op_str = insn.op_str().unwrap_or("").to_string();

            // 詳細情報を取得してオペランドを収集
            let operands = if let Ok(detail) = self.cs.insn_detail(&insn) {
                let arch_detail = detail.arch_detail();
                if let Some(x86_detail) = arch_detail.x86() {
                    x86_detail.operands().collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            insn_data.push((addr, mnemonic, op_str, operands));
        }

        // insnsをドロップ（borrowを解放）
        drop(insns);

        // Step 2: 収集した情報を使ってP-codeに変換
        let mut pcodes = Vec::new();
        for (addr, mnemonic, op_str, operands) in insn_data {
            match self.translate_from_operands(&mnemonic, &op_str, &operands, addr) {
                Ok(ops) => pcodes.extend(ops),
                Err(e) => {
                    eprintln!("Warning: 0x{:x}: {} {} - {}", addr, mnemonic, op_str, e);
                }
            }
        }

        Ok(pcodes)
    }

    /// オペランド情報からP-codeに変換
    fn translate_from_operands(
        &mut self,
        mnemonic: &str,
        op_str: &str,
        operands: &[capstone::arch::x86::X86Operand],
        address: u64,
    ) -> Result<Vec<PcodeOp>> {
        match mnemonic.to_lowercase().as_str() {
            // ===== データ移動命令 =====
            "mov" => self.translate_mov(operands, address),
            "movzx" => self.translate_movzx(operands, address),
            "movsx" | "movsxd" => self.translate_movsx(operands, address),
            "lea" => self.translate_lea(operands, address),
            "xchg" => self.translate_xchg(operands, address),

            // ===== スタック操作 =====
            "push" => self.translate_push(operands, address),
            "pop" => self.translate_pop(operands, address),
            "enter" => self.translate_enter(op_str, address),
            "leave" => Ok(self.decoder.decode_leave(address)),

            // ===== 算術演算 =====
            "add" => self.translate_binary_arithmetic(operands, OpCode::IntAdd, address),
            "sub" => self.translate_binary_arithmetic(operands, OpCode::IntSub, address),
            "inc" => self.translate_inc(operands, address),
            "dec" => self.translate_dec(operands, address),
            "neg" => self.translate_neg(operands, address),
            "mul" => self.translate_mul(operands, address),
            "imul" => self.translate_imul(operands, address),
            "div" => self.translate_div(operands, address),
            "idiv" => self.translate_idiv(operands, address),

            // ===== ビット演算 =====
            "and" => self.translate_binary_logic(operands, OpCode::IntAnd, address),
            "or" => self.translate_binary_logic(operands, OpCode::IntOr, address),
            "xor" => self.translate_binary_logic(operands, OpCode::IntXor, address),
            "not" => self.translate_not(operands, address),
            "shl" | "sal" => self.translate_shift(operands, OpCode::IntLeft, address),
            "shr" => self.translate_shift(operands, OpCode::IntRight, address),
            "sar" => self.translate_shift(operands, OpCode::IntSRight, address),

            // ===== 比較・テスト =====
            "cmp" => self.translate_cmp(operands, address),
            "test" => self.translate_test(operands, address),

            // ===== 制御フロー =====
            "jmp" => self.translate_jmp(operands, address),
            "call" => self.translate_call(operands, address),
            "ret" | "retn" => self.translate_ret(op_str, address),

            // ===== 条件分岐 =====
            "je" | "jz" => self.translate_jcc(|d, t, a| d.decode_je(t, a), operands, address),
            "jne" | "jnz" => self.translate_jcc(|d, t, a| d.decode_jne(t, a), operands, address),
            "jl" | "jnge" => self.translate_jcc(|d, t, a| d.decode_jl(t, a), operands, address),
            "jle" | "jng" => self.translate_jcc(|d, t, a| d.decode_jle(t, a), operands, address),
            "jg" | "jnle" => self.translate_jcc(|d, t, a| d.decode_jg(t, a), operands, address),
            "jge" | "jnl" => self.translate_jcc(|d, t, a| d.decode_jge(t, a), operands, address),
            "jb" | "jc" | "jnae" => self.translate_jcc(|d, t, a| d.decode_jb(t, a), operands, address),
            "jbe" | "jna" => self.translate_jcc(|d, t, a| d.decode_jbe(t, a), operands, address),
            "ja" | "jnbe" => self.translate_jcc(|d, t, a| d.decode_ja(t, a), operands, address),
            "jae" | "jnb" | "jnc" => self.translate_jcc(|d, t, a| d.decode_jae(t, a), operands, address),
            "js" => self.translate_jcc(|d, t, a| d.decode_js(t, a), operands, address),
            "jns" => self.translate_jcc(|d, t, a| d.decode_jns(t, a), operands, address),
            "jo" => self.translate_jcc(|d, t, a| d.decode_jo(t, a), operands, address),
            "jno" => self.translate_jcc(|d, t, a| d.decode_jno(t, a), operands, address),

            // ===== SETcc命令 =====
            "sete" | "setz" => self.translate_setcc(|d, r, a| d.decode_sete(r, a), operands, address),
            "setne" | "setnz" => self.translate_setcc(|d, r, a| d.decode_setne(r, a), operands, address),
            "setl" | "setnge" => self.translate_setcc(|d, r, a| d.decode_setl(r, a), operands, address),
            "setg" | "setnle" => self.translate_setcc(|d, r, a| d.decode_setg(r, a), operands, address),
            "setb" | "setc" | "setnae" => self.translate_setcc(|d, r, a| d.decode_setb(r, a), operands, address),
            "seta" | "setnbe" => self.translate_setcc(|d, r, a| d.decode_seta(r, a), operands, address),

            // ===== その他 =====
            "nop" | "fnop" | "int3" => Ok(vec![]),
            "cdq" => Ok(self.decoder.decode_cdq(address)),
            "cqo" => Ok(self.decoder.decode_cqo(address)),
            "cbw" => Ok(self.decoder.decode_cbw(address)),
            "cwde" => Ok(self.decoder.decode_cwde(address)),
            "cdqe" => Ok(self.decoder.decode_cdqe(address)),

            // ===== 文字列操作命令 =====
            "lodsb" => Ok(self.decoder.decode_lods(1, address)),
            "lodsw" => Ok(self.decoder.decode_lods(2, address)),
            "lodsd" => Ok(self.decoder.decode_lods(4, address)),
            "lodsq" => Ok(self.decoder.decode_lods(8, address)),
            "stosb" => Ok(self.decoder.decode_stos(1, address)),
            "stosw" => Ok(self.decoder.decode_stos(2, address)),
            "stosd" => Ok(self.decoder.decode_stos(4, address)),
            "stosq" => Ok(self.decoder.decode_stos(8, address)),
            "movsb" => Ok(self.decoder.decode_movs(1, address)),
            "movsw" => Ok(self.decoder.decode_movs(2, address)),
            "movsq" => Ok(self.decoder.decode_movs(8, address)),

            // ===== SSE/AVX命令 =====
            "movaps" => self.translate_movaps(operands, address),
            "movups" => self.translate_movups(operands, address),
            "xorps" => self.translate_xorps(operands, address),
            "andps" => self.translate_andps(operands, address),
            "orps" => self.translate_orps(operands, address),

            // ===== アトミック命令 =====
            "lock add" => self.translate_lock_add(operands, address),
            "lock xadd" => self.translate_lock_xadd(operands, address),
            "lock inc" => self.translate_lock_inc(operands, address),
            "lock dec" => self.translate_lock_dec(operands, address),

            // ===== 未サポート =====
            _ => Err(anyhow!("Unsupported instruction: {}", mnemonic)),
        }
    }

    /// 命令を直接P-codeに変換（詳細情報から）
    fn translate_instruction_direct(
        &mut self,
        detail_result: &Result<capstone::InsnDetail, capstone::Error>,
        mnemonic: &str,
        op_str: &str,
        address: u64,
    ) -> Result<Vec<PcodeOp>> {
        let detail = detail_result.as_ref().map_err(|e| anyhow!("Failed to get instruction detail: {}", e))?;
        let arch_detail = detail.arch_detail();
        let x86_detail = arch_detail.x86()
            .ok_or_else(|| anyhow!("Not an x86 instruction"))?;

        let operands: Vec<_> = x86_detail.operands().collect();

        // ここから元のtranslate_instructionのmatch文と同じ
        match mnemonic.to_lowercase().as_str() {
            // ===== データ移動命令 =====
            "mov" => self.translate_mov(&operands, address),
            "movzx" => self.translate_movzx(&operands, address),
            "movsx" | "movsxd" => self.translate_movsx(&operands, address),
            "lea" => self.translate_lea(&operands, address),
            "xchg" => self.translate_xchg(&operands, address),

            // ===== スタック操作 =====
            "push" => self.translate_push(&operands, address),
            "pop" => self.translate_pop(&operands, address),
            "enter" => self.translate_enter(op_str, address),
            "leave" => Ok(self.decoder.decode_leave(address)),

            // ===== 算術演算 =====
            "add" => self.translate_binary_arithmetic(&operands, OpCode::IntAdd, address),
            "sub" => self.translate_binary_arithmetic(&operands, OpCode::IntSub, address),
            "inc" => self.translate_inc(&operands, address),
            "dec" => self.translate_dec(&operands, address),
            "neg" => self.translate_neg(&operands, address),
            "mul" => self.translate_mul(&operands, address),
            "imul" => self.translate_imul(&operands, address),
            "div" => self.translate_div(&operands, address),
            "idiv" => self.translate_idiv(&operands, address),

            // ===== ビット演算 =====
            "and" => self.translate_binary_logic(&operands, OpCode::IntAnd, address),
            "or" => self.translate_binary_logic(&operands, OpCode::IntOr, address),
            "xor" => self.translate_binary_logic(&operands, OpCode::IntXor, address),
            "not" => self.translate_not(&operands, address),
            "shl" | "sal" => self.translate_shift(&operands, OpCode::IntLeft, address),
            "shr" => self.translate_shift(&operands, OpCode::IntRight, address),
            "sar" => self.translate_shift(&operands, OpCode::IntSRight, address),

            // ===== 比較・テスト =====
            "cmp" => self.translate_cmp(&operands, address),
            "test" => self.translate_test(&operands, address),

            // ===== 制御フロー =====
            "jmp" => self.translate_jmp(&operands, address),
            "call" => self.translate_call(&operands, address),
            "ret" | "retn" => self.translate_ret(op_str, address),

            // ===== 条件分岐 =====
            "je" | "jz" => self.translate_jcc(|d, t, a| d.decode_je(t, a), &operands, address),
            "jne" | "jnz" => self.translate_jcc(|d, t, a| d.decode_jne(t, a), &operands, address),
            "jl" | "jnge" => self.translate_jcc(|d, t, a| d.decode_jl(t, a), &operands, address),
            "jle" | "jng" => self.translate_jcc(|d, t, a| d.decode_jle(t, a), &operands, address),
            "jg" | "jnle" => self.translate_jcc(|d, t, a| d.decode_jg(t, a), &operands, address),
            "jge" | "jnl" => self.translate_jcc(|d, t, a| d.decode_jge(t, a), &operands, address),
            "jb" | "jc" | "jnae" => self.translate_jcc(|d, t, a| d.decode_jb(t, a), &operands, address),
            "jbe" | "jna" => self.translate_jcc(|d, t, a| d.decode_jbe(t, a), &operands, address),
            "ja" | "jnbe" => self.translate_jcc(|d, t, a| d.decode_ja(t, a), &operands, address),
            "jae" | "jnb" | "jnc" => self.translate_jcc(|d, t, a| d.decode_jae(t, a), &operands, address),
            "js" => self.translate_jcc(|d, t, a| d.decode_js(t, a), &operands, address),
            "jns" => self.translate_jcc(|d, t, a| d.decode_jns(t, a), &operands, address),
            "jo" => self.translate_jcc(|d, t, a| d.decode_jo(t, a), &operands, address),
            "jno" => self.translate_jcc(|d, t, a| d.decode_jno(t, a), &operands, address),

            // ===== SETcc命令 =====
            "sete" | "setz" => self.translate_setcc(|d, r, a| d.decode_sete(r, a), &operands, address),
            "setne" | "setnz" => self.translate_setcc(|d, r, a| d.decode_setne(r, a), &operands, address),
            "setl" | "setnge" => self.translate_setcc(|d, r, a| d.decode_setl(r, a), &operands, address),
            "setg" | "setnle" => self.translate_setcc(|d, r, a| d.decode_setg(r, a), &operands, address),
            "setb" | "setc" | "setnae" => self.translate_setcc(|d, r, a| d.decode_setb(r, a), &operands, address),
            "seta" | "setnbe" => self.translate_setcc(|d, r, a| d.decode_seta(r, a), &operands, address),

            // ===== その他 =====
            "nop" | "fnop" | "int3" => Ok(vec![]),
            "cdq" => Ok(self.decoder.decode_cdq(address)),
            "cqo" => Ok(self.decoder.decode_cqo(address)),
            "cbw" => Ok(self.decoder.decode_cbw(address)),
            "cwde" => Ok(self.decoder.decode_cwde(address)),
            "cdqe" => Ok(self.decoder.decode_cdqe(address)),

            // ===== 未サポート =====
            _ => Err(anyhow!("Unsupported instruction: {}", mnemonic)),
        }
    }

    /// 単一の命令をP-codeに変換
    fn translate_instruction(
        &mut self,
        insn: &capstone::Insn,
        address: u64,
        mnemonic: &str,
        op_str: &str,
    ) -> Result<Vec<PcodeOp>> {
        // 命令の詳細情報を取得
        let detail = self.cs.insn_detail(insn)
            .map_err(|e| anyhow!("Failed to get instruction detail: {}", e))?;

        let arch_detail = detail.arch_detail();
        let x86_detail = arch_detail.x86()
            .ok_or_else(|| anyhow!("Not an x86 instruction"))?;

        let operands: Vec<_> = x86_detail.operands().collect();

        match mnemonic.to_lowercase().as_str() {
            // ===== データ移動命令 =====
            "mov" => self.translate_mov(&operands, address),
            "movzx" => self.translate_movzx(&operands, address),
            "movsx" | "movsxd" => self.translate_movsx(&operands, address),
            "lea" => self.translate_lea(&operands, address),
            "xchg" => self.translate_xchg(&operands, address),

            // ===== スタック操作 =====
            "push" => self.translate_push(&operands, address),
            "pop" => self.translate_pop(&operands, address),
            "enter" => self.translate_enter(op_str, address),
            "leave" => Ok(self.decoder.decode_leave(address)),

            // ===== 算術演算 =====
            "add" => self.translate_binary_arithmetic(&operands, OpCode::IntAdd, address),
            "sub" => self.translate_binary_arithmetic(&operands, OpCode::IntSub, address),
            "inc" => self.translate_inc(&operands, address),
            "dec" => self.translate_dec(&operands, address),
            "neg" => self.translate_neg(&operands, address),
            "mul" => self.translate_mul(&operands, address),
            "imul" => self.translate_imul(&operands, address),
            "div" => self.translate_div(&operands, address),
            "idiv" => self.translate_idiv(&operands, address),

            // ===== ビット演算 =====
            "and" => self.translate_binary_logic(&operands, OpCode::IntAnd, address),
            "or" => self.translate_binary_logic(&operands, OpCode::IntOr, address),
            "xor" => self.translate_binary_logic(&operands, OpCode::IntXor, address),
            "not" => self.translate_not(&operands, address),
            "shl" | "sal" => self.translate_shift(&operands, OpCode::IntLeft, address),
            "shr" => self.translate_shift(&operands, OpCode::IntRight, address),
            "sar" => self.translate_shift(&operands, OpCode::IntSRight, address),

            // ===== 比較・テスト =====
            "cmp" => self.translate_cmp(&operands, address),
            "test" => self.translate_test(&operands, address),

            // ===== 制御フロー =====
            "jmp" => self.translate_jmp(&operands, address),
            "call" => self.translate_call(&operands, address),
            "ret" | "retn" => self.translate_ret(op_str, address),

            // ===== 条件分岐 =====
            "je" | "jz" => self.translate_jcc(|d, t, a| d.decode_je(t, a), &operands, address),
            "jne" | "jnz" => self.translate_jcc(|d, t, a| d.decode_jne(t, a), &operands, address),
            "jl" | "jnge" => self.translate_jcc(|d, t, a| d.decode_jl(t, a), &operands, address),
            "jle" | "jng" => self.translate_jcc(|d, t, a| d.decode_jle(t, a), &operands, address),
            "jg" | "jnle" => self.translate_jcc(|d, t, a| d.decode_jg(t, a), &operands, address),
            "jge" | "jnl" => self.translate_jcc(|d, t, a| d.decode_jge(t, a), &operands, address),
            "jb" | "jc" | "jnae" => self.translate_jcc(|d, t, a| d.decode_jb(t, a), &operands, address),
            "jbe" | "jna" => self.translate_jcc(|d, t, a| d.decode_jbe(t, a), &operands, address),
            "ja" | "jnbe" => self.translate_jcc(|d, t, a| d.decode_ja(t, a), &operands, address),
            "jae" | "jnb" | "jnc" => self.translate_jcc(|d, t, a| d.decode_jae(t, a), &operands, address),
            "js" => self.translate_jcc(|d, t, a| d.decode_js(t, a), &operands, address),
            "jns" => self.translate_jcc(|d, t, a| d.decode_jns(t, a), &operands, address),
            "jo" => self.translate_jcc(|d, t, a| d.decode_jo(t, a), &operands, address),
            "jno" => self.translate_jcc(|d, t, a| d.decode_jno(t, a), &operands, address),

            // ===== SETcc命令 =====
            "sete" | "setz" => self.translate_setcc(|d, r, a| d.decode_sete(r, a), &operands, address),
            "setne" | "setnz" => self.translate_setcc(|d, r, a| d.decode_setne(r, a), &operands, address),
            "setl" | "setnge" => self.translate_setcc(|d, r, a| d.decode_setl(r, a), &operands, address),
            "setg" | "setnle" => self.translate_setcc(|d, r, a| d.decode_setg(r, a), &operands, address),
            "setb" | "setc" | "setnae" => self.translate_setcc(|d, r, a| d.decode_setb(r, a), &operands, address),
            "seta" | "setnbe" => self.translate_setcc(|d, r, a| d.decode_seta(r, a), &operands, address),

            // ===== その他 =====
            "nop" | "fnop" | "int3" => Ok(vec![]),
            "cdq" => Ok(self.decoder.decode_cdq(address)),
            "cqo" => Ok(self.decoder.decode_cqo(address)),
            "cbw" => Ok(self.decoder.decode_cbw(address)),
            "cwde" => Ok(self.decoder.decode_cwde(address)),
            "cdqe" => Ok(self.decoder.decode_cdqe(address)),

            // ===== 未サポート =====
            _ => Err(anyhow!("Unsupported instruction: {}", mnemonic)),
        }
    }

    // ===== 変換ヘルパー =====

    /// mov命令の変換
    fn translate_mov(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("mov requires 2 operands"));
        }

        let dest = &operands[0];
        let src = &operands[1];

        match (&dest.op_type, &src.op_type) {
            // mov reg, reg
            (X86OperandType::Reg(dest_reg), X86OperandType::Reg(src_reg)) => {
                let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                let src_r = self.capstone_reg_to_x86(*src_reg)?;
                let size = dest.size as usize;
                Ok(self.decoder.decode_mov(dest_r, src_r, size, address))
            }
            // mov reg, imm
            (X86OperandType::Reg(dest_reg), X86OperandType::Imm(imm)) => {
                let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                let size = dest.size as usize;
                Ok(self.decoder.decode_mov_imm(dest_r, *imm, size, address))
            }
            // mov reg, [mem]
            (X86OperandType::Reg(dest_reg), X86OperandType::Mem(mem)) => {
                let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let mut ops = addr_ops;
                ops.extend(self.decoder.decode_mov_load(dest_r, mem_addr, dest.size as usize, address));
                Ok(ops)
            }
            // mov [mem], reg
            (X86OperandType::Mem(mem), X86OperandType::Reg(src_reg)) => {
                let src_r = self.capstone_reg_to_x86(*src_reg)?;
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let mut ops = addr_ops;
                ops.extend(self.decoder.decode_mov_store(mem_addr, src_r, src.size as usize, address));
                Ok(ops)
            }
            // mov [mem], imm
            (X86OperandType::Mem(mem), X86OperandType::Imm(imm)) => {
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let imm_vn = Varnode::constant(*imm as u64, dest.size as usize);
                let mut ops = addr_ops;
                ops.push(PcodeOp::no_output(OpCode::Store, vec![mem_addr, imm_vn], address));
                Ok(ops)
            }
            _ => Err(anyhow!("Unsupported mov operand combination")),
        }
    }

    /// movzx命令の変換
    fn translate_movzx(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("movzx requires 2 operands"));
        }

        let dest = &operands[0];
        let src = &operands[1];

        if let X86OperandType::Reg(dest_reg) = &dest.op_type {
            let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
            let dest_size = dest.size as usize;
            let src_size = src.size as usize;

            match &src.op_type {
                X86OperandType::Reg(src_reg) => {
                    let src_r = self.capstone_reg_to_x86(*src_reg)?;
                    Ok(self.decoder.decode_movzx(dest_r, src_r, dest_size, src_size, address))
                }
                X86OperandType::Mem(mem) => {
                    let (mut ops, mem_addr) = self.compute_mem_address(mem, address)?;
                    let temp = Varnode::unique(0x20000, src_size);
                    ops.push(PcodeOp::unary(OpCode::Load, temp.clone(), mem_addr, address));
                    ops.push(PcodeOp::unary(OpCode::IntZExt, dest_r.to_varnode(dest_size), temp, address));
                    Ok(ops)
                }
                _ => Err(anyhow!("Unsupported movzx source operand")),
            }
        } else {
            Err(anyhow!("movzx destination must be a register"))
        }
    }

    /// movsx命令の変換
    fn translate_movsx(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("movsx requires 2 operands"));
        }

        let dest = &operands[0];
        let src = &operands[1];

        if let X86OperandType::Reg(dest_reg) = &dest.op_type {
            let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
            let dest_size = dest.size as usize;
            let src_size = src.size as usize;

            match &src.op_type {
                X86OperandType::Reg(src_reg) => {
                    let src_r = self.capstone_reg_to_x86(*src_reg)?;
                    Ok(self.decoder.decode_movsx(dest_r, src_r, dest_size, src_size, address))
                }
                X86OperandType::Mem(mem) => {
                    let (mut ops, mem_addr) = self.compute_mem_address(mem, address)?;
                    let temp = Varnode::unique(0x20000, src_size);
                    ops.push(PcodeOp::unary(OpCode::Load, temp.clone(), mem_addr, address));
                    ops.push(PcodeOp::unary(OpCode::IntSExt, dest_r.to_varnode(dest_size), temp, address));
                    Ok(ops)
                }
                _ => Err(anyhow!("Unsupported movsx source operand")),
            }
        } else {
            Err(anyhow!("movsx destination must be a register"))
        }
    }

    /// lea命令の変換
    fn translate_lea(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("lea requires 2 operands"));
        }

        let dest = &operands[0];
        let src = &operands[1];

        if let (X86OperandType::Reg(dest_reg), X86OperandType::Mem(mem)) = (&dest.op_type, &src.op_type) {
            let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
            let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
            let mut ops = addr_ops;
            ops.extend(self.decoder.decode_lea(dest_r, mem_addr, address));
            Ok(ops)
        } else {
            Err(anyhow!("lea requires register destination and memory source"))
        }
    }

    /// xchg命令の変換
    fn translate_xchg(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("xchg requires 2 operands"));
        }

        if let (X86OperandType::Reg(reg1), X86OperandType::Reg(reg2)) = (&operands[0].op_type, &operands[1].op_type) {
            let r1 = self.capstone_reg_to_x86(*reg1)?;
            let r2 = self.capstone_reg_to_x86(*reg2)?;
            let size = operands[0].size as usize;
            Ok(self.decoder.decode_xchg(r1, r2, size, address))
        } else {
            Err(anyhow!("xchg requires two register operands"))
        }
    }

    /// push命令の変換
    fn translate_push(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.is_empty() {
            return Err(anyhow!("push requires an operand"));
        }

        match &operands[0].op_type {
            X86OperandType::Reg(reg) => {
                let r = self.capstone_reg_to_x86(*reg)?;
                Ok(self.decoder.decode_push(r, address))
            }
            X86OperandType::Imm(imm) => {
                Ok(self.decoder.decode_push_imm(*imm, address))
            }
            _ => Err(anyhow!("Unsupported push operand")),
        }
    }

    /// pop命令の変換
    fn translate_pop(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.is_empty() {
            return Err(anyhow!("pop requires an operand"));
        }

        if let X86OperandType::Reg(reg) = &operands[0].op_type {
            let r = self.capstone_reg_to_x86(*reg)?;
            Ok(self.decoder.decode_pop(r, address))
        } else {
            Err(anyhow!("pop requires a register operand"))
        }
    }

    /// enter命令の変換
    fn translate_enter(&mut self, op_str: &str, address: u64) -> Result<Vec<PcodeOp>> {
        // "0x20, 0" のような形式をパース
        let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Err(anyhow!("enter requires 2 operands"));
        }

        let size = parse_imm(parts[0])? as u16;
        let level = parse_imm(parts[1])? as u8;
        Ok(self.decoder.decode_enter(size, level, address))
    }

    /// 二項算術演算（add, sub）
    fn translate_binary_arithmetic(
        &mut self,
        operands: &[capstone::arch::x86::X86Operand],
        _opcode: OpCode,
        address: u64,
    ) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("Binary arithmetic requires 2 operands"));
        }

        let dest = &operands[0];
        let src = &operands[1];
        let size = dest.size as usize;

        match (&dest.op_type, &src.op_type) {
            (X86OperandType::Reg(dest_reg), X86OperandType::Reg(src_reg)) => {
                let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                let src_r = self.capstone_reg_to_x86(*src_reg)?;
                if _opcode == OpCode::IntAdd {
                    Ok(self.decoder.decode_add(dest_r, src_r, size, address))
                } else {
                    Ok(self.decoder.decode_sub(dest_r, src_r, size, address))
                }
            }
            (X86OperandType::Reg(dest_reg), X86OperandType::Imm(imm)) => {
                let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                if _opcode == OpCode::IntAdd {
                    Ok(self.decoder.decode_add_imm(dest_r, *imm, size, address))
                } else {
                    Ok(self.decoder.decode_sub_imm(dest_r, *imm, size, address))
                }
            }
            _ => Err(anyhow!("Unsupported binary arithmetic operand combination")),
        }
    }

    /// 二項論理演算（and, or, xor）
    fn translate_binary_logic(
        &mut self,
        operands: &[capstone::arch::x86::X86Operand],
        opcode: OpCode,
        address: u64,
    ) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("Binary logic requires 2 operands"));
        }

        let dest = &operands[0];
        let src = &operands[1];
        let size = dest.size as usize;

        match (&dest.op_type, &src.op_type) {
            (X86OperandType::Reg(dest_reg), X86OperandType::Reg(src_reg)) => {
                let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                let src_r = self.capstone_reg_to_x86(*src_reg)?;
                match opcode {
                    OpCode::IntAnd => Ok(self.decoder.decode_and(dest_r, src_r, size, address)),
                    OpCode::IntOr => Ok(self.decoder.decode_or(dest_r, src_r, size, address)),
                    OpCode::IntXor => Ok(self.decoder.decode_xor(dest_r, src_r, size, address)),
                    _ => Err(anyhow!("Invalid opcode for binary logic")),
                }
            }
            (X86OperandType::Reg(dest_reg), X86OperandType::Imm(imm)) => {
                let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                match opcode {
                    OpCode::IntAnd => Ok(self.decoder.decode_and_imm(dest_r, *imm, size, address)),
                    OpCode::IntOr => Ok(self.decoder.decode_or_imm(dest_r, *imm, size, address)),
                    OpCode::IntXor => Ok(self.decoder.decode_xor_imm(dest_r, *imm, size, address)),
                    _ => Err(anyhow!("Invalid opcode for binary logic")),
                }
            }
            _ => Err(anyhow!("Unsupported binary logic operand combination")),
        }
    }

    /// inc命令
    fn translate_inc(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.is_empty() {
            return Err(anyhow!("inc requires an operand"));
        }

        match &operands[0].op_type {
            X86OperandType::Reg(reg) => {
                let r = self.capstone_reg_to_x86(*reg)?;
                let size = operands[0].size as usize;
                Ok(self.decoder.decode_inc(r, size, address))
            }
            X86OperandType::Mem(mem) => {
                let size = operands[0].size as usize;
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let mut ops = addr_ops;
                ops.extend(self.decoder.decode_inc_mem(mem_addr, size, address));
                Ok(ops)
            }
            _ => Err(anyhow!("inc requires register or memory operand")),
        }
    }

    /// dec命令
    fn translate_dec(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.is_empty() {
            return Err(anyhow!("dec requires an operand"));
        }

        match &operands[0].op_type {
            X86OperandType::Reg(reg) => {
                let r = self.capstone_reg_to_x86(*reg)?;
                let size = operands[0].size as usize;
                Ok(self.decoder.decode_dec(r, size, address))
            }
            X86OperandType::Mem(mem) => {
                let size = operands[0].size as usize;
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let mut ops = addr_ops;
                ops.extend(self.decoder.decode_dec_mem(mem_addr, size, address));
                Ok(ops)
            }
            _ => Err(anyhow!("dec requires register or memory operand")),
        }
    }

    /// neg命令
    fn translate_neg(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.is_empty() {
            return Err(anyhow!("neg requires an operand"));
        }

        if let X86OperandType::Reg(reg) = &operands[0].op_type {
            let r = self.capstone_reg_to_x86(*reg)?;
            let size = operands[0].size as usize;
            Ok(self.decoder.decode_neg(r, size, address))
        } else {
            Err(anyhow!("neg requires a register operand"))
        }
    }

    /// not命令
    fn translate_not(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.is_empty() {
            return Err(anyhow!("not requires an operand"));
        }

        if let X86OperandType::Reg(reg) = &operands[0].op_type {
            let r = self.capstone_reg_to_x86(*reg)?;
            let size = operands[0].size as usize;
            Ok(self.decoder.decode_not(r, size, address))
        } else {
            Err(anyhow!("not requires a register operand"))
        }
    }

    /// mul命令
    fn translate_mul(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.is_empty() {
            return Err(anyhow!("mul requires an operand"));
        }

        if let X86OperandType::Reg(reg) = &operands[0].op_type {
            let r = self.capstone_reg_to_x86(*reg)?;
            let size = operands[0].size as usize;
            Ok(self.decoder.decode_mul(r, size, address))
        } else {
            Err(anyhow!("mul requires a register operand"))
        }
    }

    /// imul命令
    fn translate_imul(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.is_empty() {
            return Err(anyhow!("imul requires at least one operand"));
        }

        let size = operands[0].size as usize;

        match operands.len() {
            1 => {
                // imul src (RAX = RAX * src)
                if let X86OperandType::Reg(reg) = &operands[0].op_type {
                    let r = self.capstone_reg_to_x86(*reg)?;
                    Ok(self.decoder.decode_mul(r, size, address))
                } else {
                    Err(anyhow!("imul single operand must be a register"))
                }
            }
            2 => {
                // imul dest, src
                if let (X86OperandType::Reg(dest_reg), X86OperandType::Reg(src_reg)) =
                    (&operands[0].op_type, &operands[1].op_type)
                {
                    let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                    let src_r = self.capstone_reg_to_x86(*src_reg)?;
                    Ok(self.decoder.decode_imul(dest_r, src_r, size, address))
                } else {
                    Err(anyhow!("Unsupported imul operand combination"))
                }
            }
            3 => {
                // imul dest, src, imm
                if let (X86OperandType::Reg(dest_reg), X86OperandType::Reg(src_reg), X86OperandType::Imm(imm)) =
                    (&operands[0].op_type, &operands[1].op_type, &operands[2].op_type)
                {
                    let dest_r = self.capstone_reg_to_x86(*dest_reg)?;
                    let src_r = self.capstone_reg_to_x86(*src_reg)?;
                    Ok(self.decoder.decode_imul3(dest_r, src_r, *imm, size, address))
                } else {
                    Err(anyhow!("Unsupported imul operand combination"))
                }
            }
            _ => Err(anyhow!("Invalid number of operands for imul")),
        }
    }

    /// div命令
    fn translate_div(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.is_empty() {
            return Err(anyhow!("div requires an operand"));
        }

        if let X86OperandType::Reg(reg) = &operands[0].op_type {
            let r = self.capstone_reg_to_x86(*reg)?;
            let size = operands[0].size as usize;
            Ok(self.decoder.decode_div(r, size, address))
        } else {
            Err(anyhow!("div requires a register operand"))
        }
    }

    /// idiv命令
    fn translate_idiv(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.is_empty() {
            return Err(anyhow!("idiv requires an operand"));
        }

        if let X86OperandType::Reg(reg) = &operands[0].op_type {
            let r = self.capstone_reg_to_x86(*reg)?;
            let size = operands[0].size as usize;
            Ok(self.decoder.decode_idiv(r, size, address))
        } else {
            Err(anyhow!("idiv requires a register operand"))
        }
    }

    /// シフト命令（shl, shr, sar）
    fn translate_shift(
        &mut self,
        operands: &[capstone::arch::x86::X86Operand],
        opcode: OpCode,
        address: u64,
    ) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("Shift requires 2 operands"));
        }

        if let X86OperandType::Reg(reg) = &operands[0].op_type {
            let r = self.capstone_reg_to_x86(*reg)?;
            let size = operands[0].size as usize;

            match &operands[1].op_type {
                X86OperandType::Imm(count) => {
                    let count = *count as u8;
                    match opcode {
                        OpCode::IntLeft => Ok(self.decoder.decode_shl(r, count, size, address)),
                        OpCode::IntRight => Ok(self.decoder.decode_shr(r, count, size, address)),
                        OpCode::IntSRight => Ok(self.decoder.decode_sar(r, count, size, address)),
                        _ => Err(anyhow!("Invalid shift opcode")),
                    }
                }
                X86OperandType::Reg(_) => {
                    // CLでシフト
                    match opcode {
                        OpCode::IntLeft => Ok(self.decoder.decode_shl_cl(r, size, address)),
                        OpCode::IntRight => Ok(self.decoder.decode_shr_cl(r, size, address)),
                        OpCode::IntSRight => Ok(self.decoder.decode_sar_cl(r, size, address)),
                        _ => Err(anyhow!("Invalid shift opcode")),
                    }
                }
                _ => Err(anyhow!("Unsupported shift count operand")),
            }
        } else {
            Err(anyhow!("Shift destination must be a register"))
        }
    }

    /// cmp命令
    fn translate_cmp(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 2 {
            return Err(anyhow!("cmp requires 2 operands"));
        }

        let dest = &operands[0];
        let src = &operands[1];
        let size = dest.size as usize;

        match (&dest.op_type, &src.op_type) {
            (X86OperandType::Reg(lhs_reg), X86OperandType::Reg(rhs_reg)) => {
                let lhs_r = self.capstone_reg_to_x86(*lhs_reg)?;
                let rhs_r = self.capstone_reg_to_x86(*rhs_reg)?;
                Ok(self.decoder.decode_cmp(lhs_r, rhs_r, size, address))
            }
            (X86OperandType::Reg(lhs_reg), X86OperandType::Imm(imm)) => {
                let lhs_r = self.capstone_reg_to_x86(*lhs_reg)?;
                Ok(self.decoder.decode_cmp_imm(lhs_r, *imm, size, address))
            }
            (X86OperandType::Mem(mem), X86OperandType::Reg(rhs_reg)) => {
                let rhs_r = self.capstone_reg_to_x86(*rhs_reg)?;
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let mut ops = addr_ops;
                ops.extend(self.decoder.decode_cmp_mem_reg(mem_addr, rhs_r, size, address));
                Ok(ops)
            }
            (X86OperandType::Mem(mem), X86OperandType::Imm(imm)) => {
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let mut ops = addr_ops;
                ops.extend(self.decoder.decode_cmp_mem_imm(mem_addr, *imm, size, address));
                Ok(ops)
            }
            _ => Err(anyhow!("Unsupported cmp operand combination")),
        }
    }

    /// test命令
    fn translate_test(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        if operands.len() != 2 {
            return Err(anyhow!("test requires 2 operands"));
        }

        let dest = &operands[0];
        let src = &operands[1];
        let size = dest.size as usize;

        match (&dest.op_type, &src.op_type) {
            (X86OperandType::Reg(lhs_reg), X86OperandType::Reg(rhs_reg)) => {
                let lhs_r = self.capstone_reg_to_x86(*lhs_reg)?;
                let rhs_r = self.capstone_reg_to_x86(*rhs_reg)?;
                Ok(self.decoder.decode_test(lhs_r, rhs_r, size, address))
            }
            (X86OperandType::Reg(reg), X86OperandType::Imm(imm)) => {
                let r = self.capstone_reg_to_x86(*reg)?;
                Ok(self.decoder.decode_test_imm(r, *imm, size, address))
            }
            _ => Err(anyhow!("Unsupported test operand combination")),
        }
    }

    /// jmp命令
    fn translate_jmp(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.is_empty() {
            return Err(anyhow!("jmp requires an operand"));
        }

        match &operands[0].op_type {
            X86OperandType::Imm(target) => {
                Ok(self.decoder.decode_jmp(*target as u64, address))
            }
            X86OperandType::Reg(reg) => {
                let r = self.capstone_reg_to_x86(*reg)?;
                Ok(self.decoder.decode_jmp_indirect(r, address))
            }
            X86OperandType::Mem(mem) => {
                // jmp [memory] - メモリから間接ジャンプ
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let target_temp = Varnode { space: AddressSpace::Unique, offset: 0x2000, size: 8 };
                let mut ops = addr_ops;
                // target_temp = *mem_addr (Load jump target)
                ops.push(PcodeOp::unary(OpCode::Load, target_temp.clone(), mem_addr, address));
                // branch target_temp (indirect jump)
                ops.push(PcodeOp::no_output(OpCode::BranchInd, vec![target_temp], address));
                Ok(ops)
            }
            _ => Err(anyhow!("Unsupported jmp operand")),
        }
    }

    /// call命令
    fn translate_call(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.is_empty() {
            return Err(anyhow!("call requires an operand"));
        }

        match &operands[0].op_type {
            X86OperandType::Imm(target) => {
                Ok(self.decoder.decode_call(*target as u64, address))
            }
            X86OperandType::Reg(reg) => {
                let r = self.capstone_reg_to_x86(*reg)?;
                Ok(self.decoder.decode_call_indirect(r, address))
            }
            X86OperandType::Mem(mem) => {
                // call [memory] - メモリから間接コール
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let target_temp = Varnode { space: AddressSpace::Unique, offset: 0x2100, size: 8 };
                let mut ops = addr_ops;
                // target_temp = *mem_addr (Load call target)
                ops.push(PcodeOp::unary(OpCode::Load, target_temp.clone(), mem_addr, address));
                // call target_temp (indirect call)
                ops.push(PcodeOp::no_output(OpCode::CallInd, vec![target_temp], address));
                Ok(ops)
            }
            _ => Err(anyhow!("Unsupported call operand")),
        }
    }

    /// ret命令
    fn translate_ret(&mut self, op_str: &str, address: u64) -> Result<Vec<PcodeOp>> {
        if op_str.is_empty() {
            Ok(self.decoder.decode_ret(address))
        } else {
            let imm = parse_imm(op_str)? as u16;
            Ok(self.decoder.decode_ret_imm(imm, address))
        }
    }

    /// 条件分岐命令の汎用変換
    fn translate_jcc<F>(&mut self, decode_fn: F, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>>
    where
        F: Fn(&mut X86Decoder, u64, u64) -> Vec<PcodeOp>,
    {
        if operands.is_empty() {
            return Err(anyhow!("Conditional jump requires an operand"));
        }

        if let X86OperandType::Imm(target) = &operands[0].op_type {
            Ok(decode_fn(&mut self.decoder, *target as u64, address))
        } else {
            Err(anyhow!("Conditional jump requires immediate target"))
        }
    }

    /// SETcc命令の汎用変換
    fn translate_setcc<F>(&mut self, decode_fn: F, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>>
    where
        F: Fn(&mut X86Decoder, X86Register, u64) -> Vec<PcodeOp>,
    {
        if operands.is_empty() {
            return Err(anyhow!("setcc requires an operand"));
        }

        if let X86OperandType::Reg(reg) = &operands[0].op_type {
            let r = self.capstone_reg_to_x86(*reg)?;
            Ok(decode_fn(&mut self.decoder, r, address))
        } else {
            Err(anyhow!("setcc requires a register operand"))
        }
    }

    /// Capstoneレジスタ番号をX86Registerに変換
    fn capstone_reg_to_x86(&self, reg: RegId) -> Result<X86Register> {
        // Capstoneのレジスタ番号からX86Registerへのマッピング
        let reg_id = reg.0 as u32;

        // x86_64レジスタのマッピング
        match reg_id {
            x if x == X86Reg::X86_REG_RAX as u32 || x == X86Reg::X86_REG_EAX as u32 || x == X86Reg::X86_REG_AX as u32 || x == X86Reg::X86_REG_AL as u32 => Ok(X86Register::RAX),
            x if x == X86Reg::X86_REG_RCX as u32 || x == X86Reg::X86_REG_ECX as u32 || x == X86Reg::X86_REG_CX as u32 || x == X86Reg::X86_REG_CL as u32 => Ok(X86Register::RCX),
            x if x == X86Reg::X86_REG_RDX as u32 || x == X86Reg::X86_REG_EDX as u32 || x == X86Reg::X86_REG_DX as u32 || x == X86Reg::X86_REG_DL as u32 => Ok(X86Register::RDX),
            x if x == X86Reg::X86_REG_RBX as u32 || x == X86Reg::X86_REG_EBX as u32 || x == X86Reg::X86_REG_BX as u32 || x == X86Reg::X86_REG_BL as u32 => Ok(X86Register::RBX),
            x if x == X86Reg::X86_REG_RSP as u32 || x == X86Reg::X86_REG_ESP as u32 || x == X86Reg::X86_REG_SP as u32 || x == X86Reg::X86_REG_SPL as u32 => Ok(X86Register::RSP),
            x if x == X86Reg::X86_REG_RBP as u32 || x == X86Reg::X86_REG_EBP as u32 || x == X86Reg::X86_REG_BP as u32 || x == X86Reg::X86_REG_BPL as u32 => Ok(X86Register::RBP),
            x if x == X86Reg::X86_REG_RSI as u32 || x == X86Reg::X86_REG_ESI as u32 || x == X86Reg::X86_REG_SI as u32 || x == X86Reg::X86_REG_SIL as u32 => Ok(X86Register::RSI),
            x if x == X86Reg::X86_REG_RDI as u32 || x == X86Reg::X86_REG_EDI as u32 || x == X86Reg::X86_REG_DI as u32 || x == X86Reg::X86_REG_DIL as u32 => Ok(X86Register::RDI),
            x if x == X86Reg::X86_REG_R8 as u32 || x == X86Reg::X86_REG_R8D as u32 || x == X86Reg::X86_REG_R8W as u32 || x == X86Reg::X86_REG_R8B as u32 => Ok(X86Register::R8),
            x if x == X86Reg::X86_REG_R9 as u32 || x == X86Reg::X86_REG_R9D as u32 || x == X86Reg::X86_REG_R9W as u32 || x == X86Reg::X86_REG_R9B as u32 => Ok(X86Register::R9),
            x if x == X86Reg::X86_REG_R10 as u32 || x == X86Reg::X86_REG_R10D as u32 || x == X86Reg::X86_REG_R10W as u32 || x == X86Reg::X86_REG_R10B as u32 => Ok(X86Register::R10),
            x if x == X86Reg::X86_REG_R11 as u32 || x == X86Reg::X86_REG_R11D as u32 || x == X86Reg::X86_REG_R11W as u32 || x == X86Reg::X86_REG_R11B as u32 => Ok(X86Register::R11),
            x if x == X86Reg::X86_REG_R12 as u32 || x == X86Reg::X86_REG_R12D as u32 || x == X86Reg::X86_REG_R12W as u32 || x == X86Reg::X86_REG_R12B as u32 => Ok(X86Register::R12),
            x if x == X86Reg::X86_REG_R13 as u32 || x == X86Reg::X86_REG_R13D as u32 || x == X86Reg::X86_REG_R13W as u32 || x == X86Reg::X86_REG_R13B as u32 => Ok(X86Register::R13),
            x if x == X86Reg::X86_REG_R14 as u32 || x == X86Reg::X86_REG_R14D as u32 || x == X86Reg::X86_REG_R14W as u32 || x == X86Reg::X86_REG_R14B as u32 => Ok(X86Register::R14),
            x if x == X86Reg::X86_REG_R15 as u32 || x == X86Reg::X86_REG_R15D as u32 || x == X86Reg::X86_REG_R15W as u32 || x == X86Reg::X86_REG_R15B as u32 => Ok(X86Register::R15),
            x if x == X86Reg::X86_REG_RIP as u32 || x == X86Reg::X86_REG_EIP as u32 => Ok(X86Register::RIP),
            // SSE/AVX XMMレジスタ
            x if x == X86Reg::X86_REG_XMM0 as u32 => Ok(X86Register::XMM0),
            x if x == X86Reg::X86_REG_XMM1 as u32 => Ok(X86Register::XMM1),
            x if x == X86Reg::X86_REG_XMM2 as u32 => Ok(X86Register::XMM2),
            x if x == X86Reg::X86_REG_XMM3 as u32 => Ok(X86Register::XMM3),
            x if x == X86Reg::X86_REG_XMM4 as u32 => Ok(X86Register::XMM4),
            x if x == X86Reg::X86_REG_XMM5 as u32 => Ok(X86Register::XMM5),
            x if x == X86Reg::X86_REG_XMM6 as u32 => Ok(X86Register::XMM6),
            x if x == X86Reg::X86_REG_XMM7 as u32 => Ok(X86Register::XMM7),
            x if x == X86Reg::X86_REG_XMM8 as u32 => Ok(X86Register::XMM8),
            x if x == X86Reg::X86_REG_XMM9 as u32 => Ok(X86Register::XMM9),
            x if x == X86Reg::X86_REG_XMM10 as u32 => Ok(X86Register::XMM10),
            x if x == X86Reg::X86_REG_XMM11 as u32 => Ok(X86Register::XMM11),
            x if x == X86Reg::X86_REG_XMM12 as u32 => Ok(X86Register::XMM12),
            x if x == X86Reg::X86_REG_XMM13 as u32 => Ok(X86Register::XMM13),
            x if x == X86Reg::X86_REG_XMM14 as u32 => Ok(X86Register::XMM14),
            x if x == X86Reg::X86_REG_XMM15 as u32 => Ok(X86Register::XMM15),
            _ => Err(anyhow!("Unknown register ID: {}", reg_id)),
        }
    }

    /// メモリアドレスの計算
    fn compute_mem_address(
        &mut self,
        mem: &capstone::arch::x86::X86OpMem,
        address: u64,
    ) -> Result<(Vec<PcodeOp>, Varnode)> {
        let base = if mem.base().0 != 0 {
            Some(self.capstone_reg_to_x86(mem.base())?)
        } else {
            None
        };

        let index = if mem.index().0 != 0 {
            Some(self.capstone_reg_to_x86(mem.index())?)
        } else {
            None
        };

        let scale = mem.scale() as u8;
        let displacement = mem.disp();

        Ok(self.decoder.compute_memory_address(base, index, scale, displacement, address))
    }

    // ===== アトミック命令の翻訳 =====

    /// lock add [memory], imm
    fn translate_lock_add(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 2 {
            return Err(anyhow!("lock add requires 2 operands"));
        }

        // 第1オペランド: メモリ [base + disp]
        let mem = match &operands[0].op_type {
            X86OperandType::Mem(mem) => mem,
            _ => return Err(anyhow!("lock add first operand must be memory")),
        };

        // 第2オペランド: 即値
        let imm = match operands[1].op_type {
            X86OperandType::Imm(imm) => imm,
            _ => return Err(anyhow!("lock add second operand must be immediate")),
        };

        let base_reg = self.capstone_reg_to_x86(mem.base())?;
        let disp = mem.disp();
        let size = operands[0].size as usize;

        Ok(self.decoder.decode_lock_add_mem(base_reg, disp, imm, size, address))
    }

    /// lock xadd [memory], reg
    fn translate_lock_xadd(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 2 {
            return Err(anyhow!("lock xadd requires 2 operands"));
        }

        // 第1オペランド: メモリ
        let mem = match &operands[0].op_type {
            X86OperandType::Mem(mem) => mem,
            _ => return Err(anyhow!("lock xadd first operand must be memory")),
        };

        // 第2オペランド: レジスタ
        let src_reg = match operands[1].op_type {
            X86OperandType::Reg(reg_id) => self.capstone_reg_to_x86(reg_id)?,
            _ => return Err(anyhow!("lock xadd second operand must be register")),
        };

        let base_reg = self.capstone_reg_to_x86(mem.base())?;
        let disp = mem.disp();
        let size = operands[0].size as usize;

        Ok(self.decoder.decode_lock_xadd_mem(base_reg, disp, src_reg, size, address))
    }

    /// lock inc [memory]
    fn translate_lock_inc(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 1 {
            return Err(anyhow!("lock inc requires 1 operand"));
        }

        // メモリオペランド
        let mem = match &operands[0].op_type {
            X86OperandType::Mem(mem) => mem,
            _ => return Err(anyhow!("lock inc operand must be memory")),
        };

        let base_reg = self.capstone_reg_to_x86(mem.base())?;
        let disp = mem.disp();
        let size = operands[0].size as usize;

        Ok(self.decoder.decode_lock_inc_mem(base_reg, disp, size, address))
    }

    /// lock dec [memory]
    fn translate_lock_dec(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 1 {
            return Err(anyhow!("lock dec requires 1 operand"));
        }

        // メモリオペランド
        let mem = match &operands[0].op_type {
            X86OperandType::Mem(mem) => mem,
            _ => return Err(anyhow!("lock dec operand must be memory")),
        };

        let base_reg = self.capstone_reg_to_x86(mem.base())?;
        let disp = mem.disp();
        let size = operands[0].size as usize;

        Ok(self.decoder.decode_lock_dec_mem(base_reg, disp, size, address))
    }

    // ===== SSE/AVX命令の翻訳 =====

    /// movaps xmm, xmm / movaps xmm, [mem] / movaps [mem], xmm
    fn translate_movaps(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 2 {
            return Err(anyhow!("movaps requires 2 operands"));
        }

        match (&operands[0].op_type, &operands[1].op_type) {
            // xmm, xmm
            (X86OperandType::Reg(dest_id), X86OperandType::Reg(src_id)) => {
                let dest_reg = self.capstone_reg_to_x86(*dest_id)?;
                let src_reg = self.capstone_reg_to_x86(*src_id)?;
                Ok(self.decoder.decode_movaps(dest_reg, src_reg, address))
            }
            // xmm, [mem]
            (X86OperandType::Reg(dest_id), X86OperandType::Mem(mem)) => {
                let dest_reg = self.capstone_reg_to_x86(*dest_id)?;
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let mut ops = addr_ops;
                ops.extend(self.decoder.decode_movaps_load(dest_reg, mem_addr, address));
                Ok(ops)
            }
            // [mem], xmm
            (X86OperandType::Mem(mem), X86OperandType::Reg(src_id)) => {
                let src_reg = self.capstone_reg_to_x86(*src_id)?;
                let (addr_ops, mem_addr) = self.compute_mem_address(mem, address)?;
                let mut ops = addr_ops;
                ops.extend(self.decoder.decode_movaps_store(mem_addr, src_reg, address));
                Ok(ops)
            }
            _ => Err(anyhow!("Invalid operand combination for movaps")),
        }
    }

    /// movups (movapsと同じ実装)
    fn translate_movups(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        self.translate_movaps(operands, address)
    }

    /// xorps xmm, xmm
    fn translate_xorps(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 2 {
            return Err(anyhow!("xorps requires 2 operands"));
        }

        match (&operands[0].op_type, &operands[1].op_type) {
            (X86OperandType::Reg(dest_id), X86OperandType::Reg(src_id)) => {
                let dest_reg = self.capstone_reg_to_x86(*dest_id)?;
                let src_reg = self.capstone_reg_to_x86(*src_id)?;
                Ok(self.decoder.decode_xorps(dest_reg, src_reg, address))
            }
            _ => Err(anyhow!("xorps only supports register operands")),
        }
    }

    /// andps xmm, xmm
    fn translate_andps(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 2 {
            return Err(anyhow!("andps requires 2 operands"));
        }

        match (&operands[0].op_type, &operands[1].op_type) {
            (X86OperandType::Reg(dest_id), X86OperandType::Reg(src_id)) => {
                let dest_reg = self.capstone_reg_to_x86(*dest_id)?;
                let src_reg = self.capstone_reg_to_x86(*src_id)?;
                Ok(self.decoder.decode_andps(dest_reg, src_reg, address))
            }
            _ => Err(anyhow!("andps only supports register operands")),
        }
    }

    /// orps xmm, xmm
    fn translate_orps(&mut self, operands: &[capstone::arch::x86::X86Operand], address: u64) -> Result<Vec<PcodeOp>> {
        use capstone::arch::x86::X86OperandType;

        if operands.len() != 2 {
            return Err(anyhow!("orps requires 2 operands"));
        }

        match (&operands[0].op_type, &operands[1].op_type) {
            (X86OperandType::Reg(dest_id), X86OperandType::Reg(src_id)) => {
                let dest_reg = self.capstone_reg_to_x86(*dest_id)?;
                let src_reg = self.capstone_reg_to_x86(*src_id)?;
                Ok(self.decoder.decode_orps(dest_reg, src_reg, address))
            }
            _ => Err(anyhow!("orps only supports register operands")),
        }
    }
}

/// 即値文字列をパース
fn parse_imm(s: &str) -> Result<i64> {
    let s = s.trim();

    if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16)
            .map_err(|e| anyhow!("Failed to parse hex: {}", e))
    } else if s.starts_with('-') {
        s.parse::<i64>()
            .map_err(|e| anyhow!("Failed to parse signed int: {}", e))
    } else {
        s.parse::<i64>()
            .map_err(|e| anyhow!("Failed to parse int: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_translation() {
        let mut translator = CapstoneTranslator::new().unwrap();

        // 簡単なコードをテスト
        // mov rax, 42; ret
        let code = [0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00, 0xc3];

        let pcodes = translator.translate(&code, 0x1000, 10).unwrap();

        println!("Generated P-code:");
        for op in &pcodes {
            println!("  0x{:x}: {}", op.address, op);
        }

        assert!(!pcodes.is_empty());
    }

    #[test]
    fn test_arithmetic() {
        let mut translator = CapstoneTranslator::new().unwrap();

        // add rax, rbx; sub rcx, rdx
        let code = [
            0x48, 0x01, 0xd8,  // add rax, rbx
            0x48, 0x29, 0xd1,  // sub rcx, rdx
        ];

        let pcodes = translator.translate(&code, 0x2000, 10).unwrap();

        println!("Arithmetic P-code:");
        for op in &pcodes {
            println!("  0x{:x}: {}", op.address, op);
        }

        // add/subがあることを確認
        assert!(pcodes.iter().any(|op| op.opcode == OpCode::IntAdd));
        assert!(pcodes.iter().any(|op| op.opcode == OpCode::IntSub));
    }

    #[test]
    fn test_control_flow() {
        let mut translator = CapstoneTranslator::new().unwrap();

        // cmp rax, rbx; je 0x3010; jmp 0x3020
        let code = [
            0x48, 0x39, 0xd8,        // cmp rax, rbx
            0x74, 0x05,              // je +5
            0xe9, 0x10, 0x00, 0x00, 0x00,  // jmp +16
        ];

        let pcodes = translator.translate(&code, 0x3000, 10).unwrap();

        println!("Control flow P-code:");
        for op in &pcodes {
            println!("  0x{:x}: {}", op.address, op);
        }

        // 分岐があることを確認
        assert!(pcodes.iter().any(|op| op.opcode == OpCode::CBranch || op.opcode == OpCode::Branch));
    }
}
