/// C言語疑似コード出力
/// P-codeからシンプルなC言語風の出力を生成

use super::pcode::{AddressSpace, OpCode, PcodeOp, Varnode};
use super::cfg::ControlFlowGraph;

/// シンプルなC言語プリンター
pub struct SimplePrinter {
    indent_level: usize,
}

impl SimplePrinter {
    pub fn new() -> Self {
        Self { indent_level: 0 }
    }

    /// インデント文字列を生成
    fn indent(&self) -> String {
        "  ".repeat(self.indent_level)
    }

    /// Varnodeを変数名に変換
    fn varnode_to_string(&self, vn: &Varnode) -> String {
        match vn.space {
            AddressSpace::Register => {
                // レジスタを認識可能な名前に変換
                match vn.offset {
                    0 => "rax".to_string(),
                    8 => "rcx".to_string(),
                    16 => "rdx".to_string(),
                    24 => "rbx".to_string(),
                    32 => "rsp".to_string(),
                    40 => "rbp".to_string(),
                    48 => "rsi".to_string(),
                    56 => "rdi".to_string(),
                    64 => "r8".to_string(),
                    72 => "r9".to_string(),
                    _ => format!("reg_{}", vn.offset),
                }
            }
            AddressSpace::Ram => format!("*((uint{}*)0x{:x})", vn.size * 8, vn.offset),
            AddressSpace::Const => format!("0x{:x}", vn.offset),
            AddressSpace::Unique => format!("t{}", vn.offset),
            AddressSpace::Stack => format!("stack[0x{:x}]", vn.offset),
        }
    }

    /// P-code命令をC言語式に変換
    fn pcode_to_c_expr(&self, op: &PcodeOp) -> Option<String> {
        let output = op.output.as_ref()?;
        let output_str = self.varnode_to_string(output);

        let expr = match op.opcode {
            OpCode::Copy => {
                if op.inputs.is_empty() {
                    return None;
                }
                self.varnode_to_string(&op.inputs[0])
            }
            OpCode::IntAdd => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} + {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntSub => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} - {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntMult => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} * {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntDiv => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} / {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntAnd => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} & {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntOr => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} | {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntXor => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} ^ {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntEqual => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} == {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntNotEqual => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} != {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::IntSLess => {
                if op.inputs.len() < 2 {
                    return None;
                }
                format!(
                    "{} < {}",
                    self.varnode_to_string(&op.inputs[0]),
                    self.varnode_to_string(&op.inputs[1])
                )
            }
            OpCode::Load => {
                if op.inputs.is_empty() {
                    return None;
                }
                format!("*{}", self.varnode_to_string(&op.inputs[0]))
            }
            OpCode::IntNegate => {
                if op.inputs.is_empty() {
                    return None;
                }
                format!("~{}", self.varnode_to_string(&op.inputs[0]))
            }
            _ => {
                // 未実装の命令は関数呼び出し風に出力
                let args: Vec<_> = op.inputs.iter().map(|v| self.varnode_to_string(v)).collect();
                format!("{}({})", op.opcode, args.join(", "))
            }
        };

        Some(format!("{} = {};", output_str, expr))
    }

    /// P-code命令を文に変換
    fn pcode_to_statement(&self, op: &PcodeOp) -> String {
        match op.opcode {
            OpCode::Return => {
                if op.inputs.is_empty() {
                    "return;".to_string()
                } else {
                    format!("return {};", self.varnode_to_string(&op.inputs[0]))
                }
            }
            OpCode::Branch => {
                if op.inputs.is_empty() {
                    "goto unknown;".to_string()
                } else {
                    format!("goto 0x{:x};", op.inputs[0].offset)
                }
            }
            OpCode::CBranch => {
                if op.inputs.len() < 2 {
                    "if (unknown) goto unknown;".to_string()
                } else {
                    format!(
                        "if ({}) goto 0x{:x};",
                        self.varnode_to_string(&op.inputs[1]),
                        op.inputs[0].offset
                    )
                }
            }
            OpCode::Call => {
                if op.inputs.is_empty() {
                    "call_unknown();".to_string()
                } else {
                    format!("call_0x{:x}();", op.inputs[0].offset)
                }
            }
            OpCode::Store => {
                if op.inputs.len() < 2 {
                    "store_unknown;".to_string()
                } else {
                    format!(
                        "*{} = {};",
                        self.varnode_to_string(&op.inputs[0]),
                        self.varnode_to_string(&op.inputs[1])
                    )
                }
            }
            _ => {
                // 出力がある命令は代入文
                if let Some(expr) = self.pcode_to_c_expr(op) {
                    expr
                } else {
                    format!("// {}", op)
                }
            }
        }
    }

    /// P-code列をC言語疑似コードに変換
    pub fn print_pcodes(&mut self, pcodes: &[PcodeOp]) -> String {
        let mut output = String::new();

        output.push_str(&format!("{}void function_0x{:x}() {{\n", self.indent(), pcodes[0].address));
        self.indent_level += 1;

        for op in pcodes {
            let stmt = self.pcode_to_statement(op);
            output.push_str(&format!("{}{}  // 0x{:x}\n", self.indent(), stmt, op.address));
        }

        self.indent_level -= 1;
        output.push_str(&format!("{}}}\n", self.indent()));

        output
    }

    /// 制御フローグラフをC言語疑似コードに変換
    pub fn print_cfg(&mut self, cfg: &ControlFlowGraph) -> String {
        let mut output = String::new();

        if let Some(entry) = cfg.entry() {
            output.push_str(&format!("{}void function_0x{:x}() {{\n", self.indent(), entry.start_address));
            self.indent_level += 1;

            for block in cfg.blocks_in_order() {
                output.push_str(&format!("{}// Block {}\n", self.indent(), block.id));

                for op in &block.ops {
                    let stmt = self.pcode_to_statement(op);
                    output.push_str(&format!("{}{}  // 0x{:x}\n", self.indent(), stmt, op.address));
                }

                output.push_str("\n");
            }

            self.indent_level -= 1;
            output.push_str(&format!("{}}}\n", self.indent()));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::x86_64::example_translation;

    #[test]
    fn test_simple_print() {
        let pcodes = example_translation();
        let mut printer = SimplePrinter::new();
        let c_code = printer.print_pcodes(&pcodes);

        println!("Generated C code:\n{}", c_code);

        assert!(c_code.contains("rax"));
        assert!(c_code.contains("rbx"));
        assert!(c_code.contains("return"));
    }

    #[test]
    fn test_cfg_print() {
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);
        let mut printer = SimplePrinter::new();
        let c_code = printer.print_cfg(&cfg);

        println!("Generated C code from CFG:\n{}", c_code);

        assert!(c_code.contains("void function"));
        assert!(c_code.contains("Block"));
    }
}
