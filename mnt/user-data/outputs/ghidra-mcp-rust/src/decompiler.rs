use anyhow::Result;
use std::collections::{HashMap, HashSet};
use crate::disassembler::{Disassembler, Instruction};

pub struct Decompiler {
    disasm: Disassembler,
}

impl Decompiler {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            disasm: Disassembler::new(path)?,
        })
    }

    /// 関数をC疑似コードにデコンパイル
    pub fn decompile(&self, function_identifier: &str) -> Result<String> {
        // 関数アドレスの解析（アドレス or 関数名）
        let address = if function_identifier.starts_with("0x") {
            u64::from_str_radix(&function_identifier[2..], 16)?
        } else {
            // TODO: シンボルテーブルから関数名解決
            return Ok(format!("Function name lookup not yet implemented. Please use address (e.g., 0x1000)"));
        };

        // 関数の逆アセンブル
        let (instructions, branches) = self.disasm.disassemble_function(address)?;

        if instructions.is_empty() {
            return Ok("No instructions found at this address".to_string());
        }

        // 制御フロー解析
        let cfg = self.build_control_flow_graph(&instructions, &branches);

        // C疑似コード生成
        let pseudo_code = self.generate_pseudo_code(&instructions, &cfg);

        let mut output = String::new();
        output.push_str(&format!("=== Decompiled Function at 0x{:x} ===\n\n", address));
        output.push_str("/* WARNING: This is a simplified decompilation */\n");
        output.push_str("/* Full type inference and advanced optimizations not implemented */\n\n");
        output.push_str(&pseudo_code);

        Ok(output)
    }

    /// 制御フローグラフ構築
    fn build_control_flow_graph(
        &self,
        instructions: &[Instruction],
        branches: &[u64],
    ) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let mut leaders = HashSet::new();

        // リーダー命令の特定
        leaders.insert(instructions[0].address);
        for branch_target in branches {
            leaders.insert(*branch_target);
        }

        for (i, insn) in instructions.iter().enumerate() {
            // 分岐命令の次もリーダー
            if insn.mnemonic.starts_with('j') || insn.mnemonic == "call" {
                if i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].address);
                }
            }
        }

        // 基本ブロックの構築
        let mut current_block_start = None;
        for (i, insn) in instructions.iter().enumerate() {
            if leaders.contains(&insn.address) {
                if let Some(start) = current_block_start {
                    // 前のブロックを完成させる
                    cfg.add_block(start, instructions[i - 1].address);
                }
                current_block_start = Some(insn.address);
            }

            // 最後の命令
            if i == instructions.len() - 1 {
                if let Some(start) = current_block_start {
                    cfg.add_block(start, insn.address);
                }
            }
        }

        cfg
    }

    /// C疑似コード生成
    fn generate_pseudo_code(&self, instructions: &[Instruction], cfg: &ControlFlowGraph) -> String {
        let mut code = String::new();
        
        // 関数シグネチャ（簡易版）
        code.push_str("void function() {\n");

        // ローカル変数宣言（簡易版：レジスタベース）
        code.push_str("    // Local variables (registers)\n");
        code.push_str("    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;\n");
        code.push_str("    uint32_t eax, ebx, ecx, edx;\n\n");

        // 命令を疑似コードに変換
        let mut indent = 1;
        let mut prev_was_conditional = false;

        for insn in instructions {
            let spaces = "    ".repeat(indent);
            
            match insn.mnemonic.as_str() {
                // データ移動
                "mov" | "movzx" | "movsx" => {
                    let pseudo = self.translate_mov(&insn.operands);
                    code.push_str(&format!("{}{}\n", spaces, pseudo));
                }

                // 算術演算
                "add" => {
                    let pseudo = self.translate_binary_op(&insn.operands, "+");
                    code.push_str(&format!("{}{}\n", spaces, pseudo));
                }
                "sub" => {
                    let pseudo = self.translate_binary_op(&insn.operands, "-");
                    code.push_str(&format!("{}{}\n", spaces, pseudo));
                }
                "imul" | "mul" => {
                    let pseudo = self.translate_binary_op(&insn.operands, "*");
                    code.push_str(&format!("{}{}\n", spaces, pseudo));
                }

                // 比較
                "cmp" | "test" => {
                    // 次の条件分岐のための準備
                    prev_was_conditional = true;
                }

                // 条件分岐
                mnem if mnem.starts_with('j') && mnem != "jmp" => {
                    let condition = match mnem {
                        "je" | "jz" => "==",
                        "jne" | "jnz" => "!=",
                        "jl" | "jb" => "<",
                        "jle" | "jbe" => "<=",
                        "jg" | "ja" => ">",
                        "jge" | "jae" => ">=",
                        _ => "/* condition */",
                    };
                    
                    code.push_str(&format!("{}if (/* flags */ {}) {{\n", spaces, condition));
                    indent += 1;
                }

                // 無条件ジャンプ
                "jmp" => {
                    // ループまたはgotoとして扱う
                    code.push_str(&format!("{}goto label_{};\n", spaces, insn.operands));
                }

                // 関数呼び出し
                "call" => {
                    code.push_str(&format!("{}function_{}();\n", spaces, insn.operands));
                }

                // リターン
                "ret" | "retn" => {
                    code.push_str(&format!("{}return;\n", spaces));
                }

                // スタック操作
                "push" => {
                    code.push_str(&format!("{}/* push {} */\n", spaces, insn.operands));
                }
                "pop" => {
                    code.push_str(&format!("{}/* pop {} */\n", spaces, insn.operands));
                }

                // その他
                _ => {
                    code.push_str(&format!(
                        "{}/* {} {} */\n",
                        spaces, insn.mnemonic, insn.operands
                    ));
                }
            }

            // 条件分岐の終了を検出（簡易版）
            if prev_was_conditional && !insn.mnemonic.starts_with('j') {
                indent = indent.saturating_sub(1);
                let spaces = "    ".repeat(indent);
                code.push_str(&format!("{}}}\n", spaces));
                prev_was_conditional = false;
            }
        }

        code.push_str("}\n");
        code
    }

    fn translate_mov(&self, operands: &str) -> String {
        let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
        if parts.len() == 2 {
            format!("{} = {};", parts[0], parts[1])
        } else {
            format!("/* mov {} */", operands)
        }
    }

    fn translate_binary_op(&self, operands: &str, op: &str) -> String {
        let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
        if parts.len() == 2 {
            format!("{} = {} {} {};", parts[0], parts[0], op, parts[1])
        } else {
            format!("/* {} {} */", op, operands)
        }
    }
}

#[derive(Debug)]
struct ControlFlowGraph {
    blocks: HashMap<u64, BasicBlock>,
}

impl ControlFlowGraph {
    fn new() -> Self {
        Self {
            blocks: HashMap::new(),
        }
    }

    fn add_block(&mut self, start: u64, end: u64) {
        self.blocks.insert(
            start,
            BasicBlock {
                start_address: start,
                end_address: end,
                successors: Vec::new(),
            },
        );
    }
}

#[derive(Debug)]
struct BasicBlock {
    start_address: u64,
    end_address: u64,
    successors: Vec<u64>,
}
