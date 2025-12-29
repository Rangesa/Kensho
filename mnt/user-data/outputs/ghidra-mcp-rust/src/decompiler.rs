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

    /// 髢｢謨ｰ繧辰逍台ｼｼ繧ｳ繝ｼ繝峨↓繝・さ繝ｳ繝代う繝ｫ
    pub fn decompile(&self, function_identifier: &str) -> Result<String> {
        // 髢｢謨ｰ繧｢繝峨Ξ繧ｹ縺ｮ隗｣譫撰ｼ医い繝峨Ξ繧ｹ or 髢｢謨ｰ蜷搾ｼ・        let address = if function_identifier.starts_with("0x") {
            u64::from_str_radix(&function_identifier[2..], 16)?
        } else {
            // TODO: 繧ｷ繝ｳ繝懊Ν繝・・繝悶Ν縺九ｉ髢｢謨ｰ蜷崎ｧ｣豎ｺ
            return Ok(format!("Function name lookup not yet implemented. Please use address (e.g., 0x1000)"));
        };

        // 髢｢謨ｰ縺ｮ騾・い繧ｻ繝ｳ繝悶Ν
        let (instructions, branches) = self.disasm.disassemble_function(address)?;

        if instructions.is_empty() {
            return Ok("No instructions found at this address".to_string());
        }

        // 蛻ｶ蠕｡繝輔Ο繝ｼ隗｣譫・        let cfg = self.build_control_flow_graph(&instructions, &branches);

        // C逍台ｼｼ繧ｳ繝ｼ繝臥函謌・        let pseudo_code = self.generate_pseudo_code(&instructions, &cfg);

        let mut output = String::new();
        output.push_str(&format!("=== Decompiled Function at 0x{:x} ===\n\n", address));
        output.push_str("/* WARNING: This is a simplified decompilation */\n");
        output.push_str("/* Full type inference and advanced optimizations not implemented */\n\n");
        output.push_str(&pseudo_code);

        Ok(output)
    }

    /// 蛻ｶ蠕｡繝輔Ο繝ｼ繧ｰ繝ｩ繝墓ｧ狗ｯ・    fn build_control_flow_graph(
        &self,
        instructions: &[Instruction],
        branches: &[u64],
    ) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let mut leaders = HashSet::new();

        // 繝ｪ繝ｼ繝繝ｼ蜻ｽ莉､縺ｮ迚ｹ螳・        leaders.insert(instructions[0].address);
        for branch_target in branches {
            leaders.insert(*branch_target);
        }

        for (i, insn) in instructions.iter().enumerate() {
            // 蛻・ｲ仙多莉､縺ｮ谺｡繧ゅΜ繝ｼ繝繝ｼ
            if insn.mnemonic.starts_with('j') || insn.mnemonic == "call" {
                if i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].address);
                }
            }
        }

        // 蝓ｺ譛ｬ繝悶Ο繝・け縺ｮ讒狗ｯ・        let mut current_block_start = None;
        for (i, insn) in instructions.iter().enumerate() {
            if leaders.contains(&insn.address) {
                if let Some(start) = current_block_start {
                    // 蜑阪・繝悶Ο繝・け繧貞ｮ梧・縺輔○繧・                    cfg.add_block(start, instructions[i - 1].address);
                }
                current_block_start = Some(insn.address);
            }

            // 譛蠕後・蜻ｽ莉､
            if i == instructions.len() - 1 {
                if let Some(start) = current_block_start {
                    cfg.add_block(start, insn.address);
                }
            }
        }

        cfg
    }

    /// C逍台ｼｼ繧ｳ繝ｼ繝臥函謌・    fn generate_pseudo_code(&self, instructions: &[Instruction], cfg: &ControlFlowGraph) -> String {
        let mut code = String::new();
        
        // 髢｢謨ｰ繧ｷ繧ｰ繝阪メ繝｣・育ｰ｡譏鍋沿・・        code.push_str("void function() {\n");

        // 繝ｭ繝ｼ繧ｫ繝ｫ螟画焚螳｣險・育ｰ｡譏鍋沿・壹Ξ繧ｸ繧ｹ繧ｿ繝吶・繧ｹ・・        code.push_str("    // Local variables (registers)\n");
        code.push_str("    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;\n");
        code.push_str("    uint32_t eax, ebx, ecx, edx;\n\n");

        // 蜻ｽ莉､繧堤桝莨ｼ繧ｳ繝ｼ繝峨↓螟画鋤
        let mut indent = 1;
        let mut prev_was_conditional = false;

        for insn in instructions {
            let spaces = "    ".repeat(indent);
            
            match insn.mnemonic.as_str() {
                // 繝・・繧ｿ遘ｻ蜍・                "mov" | "movzx" | "movsx" => {
                    let pseudo = self.translate_mov(&insn.operands);
                    code.push_str(&format!("{}{}\n", spaces, pseudo));
                }

                // 邂苓｡捺ｼ皮ｮ・                "add" => {
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

                // 豈碑ｼ・                "cmp" | "test" => {
                    // 谺｡縺ｮ譚｡莉ｶ蛻・ｲ舌・縺溘ａ縺ｮ貅門ｙ
                    prev_was_conditional = true;
                }

                // 譚｡莉ｶ蛻・ｲ・                mnem if mnem.starts_with('j') && mnem != "jmp" => {
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

                // 辟｡譚｡莉ｶ繧ｸ繝｣繝ｳ繝・                "jmp" => {
                    // 繝ｫ繝ｼ繝励∪縺溘・goto縺ｨ縺励※謇ｱ縺・                    code.push_str(&format!("{}goto label_{};\n", spaces, insn.operands));
                }

                // 髢｢謨ｰ蜻ｼ縺ｳ蜃ｺ縺・                "call" => {
                    code.push_str(&format!("{}function_{}();\n", spaces, insn.operands));
                }

                // 繝ｪ繧ｿ繝ｼ繝ｳ
                "ret" | "retn" => {
                    code.push_str(&format!("{}return;\n", spaces));
                }

                // 繧ｹ繧ｿ繝・け謫堺ｽ・                "push" => {
                    code.push_str(&format!("{}/* push {} */\n", spaces, insn.operands));
                }
                "pop" => {
                    code.push_str(&format!("{}/* pop {} */\n", spaces, insn.operands));
                }

                // 縺昴・莉・                _ => {
                    code.push_str(&format!(
                        "{}/* {} {} */\n",
                        spaces, insn.mnemonic, insn.operands
                    ));
                }
            }

            // 譚｡莉ｶ蛻・ｲ舌・邨ゆｺ・ｒ讀懷・・育ｰ｡譏鍋沿・・            if prev_was_conditional && !insn.mnemonic.starts_with('j') {
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
