/// C-like code printer for P-code decompilation
/// Converts P-code operations into readable C-style pseudocode

use crate::decompiler_prototype::pcode::{AddressSpace, OpCode, PcodeOp, Varnode};
use crate::decompiler_prototype::type_inference::TypeInference;
use std::collections::HashMap;

/// C code printer
pub struct CPrinter {
    /// Type inference information
    #[allow(dead_code)]
    type_info: TypeInference,
    /// Variable name mapping
    var_names: HashMap<VarnodeKey, String>,
    /// Temporary variable counter
    temp_counter: usize,
    /// Output buffer
    output: Vec<String>,
    /// Current indentation level
    indent_level: usize,
}

/// Key for identifying varnodes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VarnodeKey {
    space: AddressSpace,
    offset: u64,
    size: usize,
}

impl From<&Varnode> for VarnodeKey {
    fn from(vn: &Varnode) -> Self {
        VarnodeKey {
            space: vn.space,
            offset: vn.offset,
            size: vn.size,
        }
    }
}

impl CPrinter {
    /// Create new C printer with type information
    pub fn new(type_info: TypeInference) -> Self {
        Self {
            type_info,
            var_names: HashMap::new(),
            temp_counter: 0,
            output: Vec::new(),
            indent_level: 0,
        }
    }

    /// Get or generate variable name for a varnode
    fn get_var_name(&mut self, vn: &Varnode) -> String {
        let key = VarnodeKey::from(vn);

        if let Some(name) = self.var_names.get(&key) {
            return name.clone();
        }

        // Generate variable name based on address space
        let name = match vn.space {
            AddressSpace::Register => {
                // Registers: rN format
                format!("r{}", vn.offset)
            }
            AddressSpace::Ram => {
                // Memory: ptr_ADDR format
                format!("ptr_0x{:x}", vn.offset)
            }
            AddressSpace::Stack => {
                // Stack: stack_N format
                format!("stack_{}", vn.offset)
            }
            AddressSpace::Unique => {
                // Temporary variables: tmp_N format
                let name = format!("tmp_{}", self.temp_counter);
                self.temp_counter += 1;
                name
            }
            AddressSpace::Const => {
                // Constants: use value directly
                return format!("{}", vn.offset);
            }
        };

        self.var_names.insert(key, name.clone());
        name
    }

    /// Get C type name for a varnode
    fn get_type_name(&self, vn: &Varnode) -> String {
        

        let _key = VarnodeKey::from(vn);

        // Type information available - use it (currently not implemented, commented out)
        // if let Some(ty) = self.type_info.get_type(&key) {
        //     match ty {
        //         Type::Int(int_ty) => {
        //             match int_ty {
        //                 IntType::I8 => "int8_t".to_string(),
        //                 IntType::I16 => "int16_t".to_string(),
        //                 IntType::I32 => "int32_t".to_string(),
        //                 IntType::I64 => "int64_t".to_string(),
        //                 IntType::U8 => "uint8_t".to_string(),
        //                 IntType::U16 => "uint16_t".to_string(),
        //                 IntType::U32 => "uint32_t".to_string(),
        //                 IntType::U64 => "uint64_t".to_string(),
        //             }
        //         }
        //         Type::Float(float_ty) => match float_ty {
        //             FloatType::F32 => "float".to_string(),
        //             FloatType::F64 => "double".to_string(),
        //         },
        //         Type::Pointer(_) => "void*".to_string(),
        //         Type::Unknown => "var".to_string(),
        //         _ => "var".to_string(),
        //     }
        // } else {
        //     // Default: size-based type
        //     match vn.size {
        //         1 => "uint8_t".to_string(),
        //         2 => "uint16_t".to_string(),
        //         4 => "uint32_t".to_string(),
        //         8 => "uint64_t".to_string(),
        //         _ => "var".to_string(),
        //     }
        // }

        // Simplified: size-based types only
        match vn.size {
            1 => "uint8_t".to_string(),
            2 => "uint16_t".to_string(),
            4 => "uint32_t".to_string(),
            8 => "uint64_t".to_string(),
            _ => "var".to_string(),
        }
    }

    /// Increase indentation level
    fn indent(&mut self) {
        self.indent_level += 1;
    }

    /// Decrease indentation level
    fn dedent(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }

    /// Get current indentation string
    fn current_indent(&self) -> String {
        "  ".repeat(self.indent_level)
    }

    /// Emit a line of code with current indentation
    fn emit_line(&mut self, line: String) {
        self.output.push(format!("{}{}", self.current_indent(), line));
    }

    /// Print a single P-code operation as C expression
    fn print_op(&mut self, op: &PcodeOp) -> String {
        use OpCode::*;

        match op.opcode {
            // Copy: output = input
            Copy => {
                if let Some(_output) = &op.output {
                    let input_str = self.get_var_name(&op.inputs[0]);
                    format!("{}", input_str)
                } else {
                    String::new()
                }
            }

            // Integer arithmetic operations
            IntAdd => self.binary_op("+", &op.inputs[0], &op.inputs[1]),
            IntSub => self.binary_op("-", &op.inputs[0], &op.inputs[1]),
            IntMult => self.binary_op("*", &op.inputs[0], &op.inputs[1]),
            IntDiv => self.binary_op("/", &op.inputs[0], &op.inputs[1]),
            IntSDiv => self.binary_op("/", &op.inputs[0], &op.inputs[1]),
            IntRem => self.binary_op("%", &op.inputs[0], &op.inputs[1]),
            IntSRem => self.binary_op("%", &op.inputs[0], &op.inputs[1]),

            // Bitwise operations
            IntAnd => self.binary_op("&", &op.inputs[0], &op.inputs[1]),
            IntOr => self.binary_op("|", &op.inputs[0], &op.inputs[1]),
            IntXor => self.binary_op("^", &op.inputs[0], &op.inputs[1]),
            IntNegate => self.unary_op("~", &op.inputs[0]),
            Int2Comp => self.unary_op("-", &op.inputs[0]),

            // Shift operations
            IntLeft => self.binary_op("<<", &op.inputs[0], &op.inputs[1]),
            IntRight => self.binary_op(">>", &op.inputs[0], &op.inputs[1]),
            IntSRight => self.binary_op(">>", &op.inputs[0], &op.inputs[1]),

            // Comparison operations
            IntEqual => self.binary_op("==", &op.inputs[0], &op.inputs[1]),
            IntNotEqual => self.binary_op("!=", &op.inputs[0], &op.inputs[1]),
            IntLess => self.binary_op("<", &op.inputs[0], &op.inputs[1]),
            IntLessEqual => self.binary_op("<=", &op.inputs[0], &op.inputs[1]),
            IntSLess => self.binary_op("<", &op.inputs[0], &op.inputs[1]),
            IntSLessEqual => self.binary_op("<=", &op.inputs[0], &op.inputs[1]),

            // Boolean operations
            BoolNegate => self.unary_op("!", &op.inputs[0]),
            BoolAnd => self.binary_op("&&", &op.inputs[0], &op.inputs[1]),
            BoolOr => self.binary_op("||", &op.inputs[0], &op.inputs[1]),
            BoolXor => self.binary_op("^", &op.inputs[0], &op.inputs[1]),

            // Memory operations
            Load => {
                if op.inputs.len() >= 2 {
                    let addr = self.get_var_name(&op.inputs[1]);
                    format!("*(({}*)({}))",
                        self.get_type_name(&op.output.as_ref().unwrap()),
                        addr)
                } else if !op.inputs.is_empty() {
                    let addr = self.get_var_name(&op.inputs[0]);
                    format!("*(({}*)({}))",
                        self.get_type_name(&op.output.as_ref().unwrap()),
                        addr)
                } else {
                    String::new()
                }
            }
            Store => {
                if op.inputs.len() >= 3 {
                    let addr = self.get_var_name(&op.inputs[1]);
                    let value = self.get_var_name(&op.inputs[2]);
                    format!("*({}) = {}", addr, value)
                } else if op.inputs.len() >= 2 {
                    let addr = self.get_var_name(&op.inputs[0]);
                    let value = self.get_var_name(&op.inputs[1]);
                    format!("*({}) = {}", addr, value)
                } else {
                    String::new()
                }
            }

            // Type conversions
            IntZExt => {
                let input_str = self.get_var_name(&op.inputs[0]);
                if let Some(output) = &op.output {
                    format!("({}) {}", self.get_type_name(output), input_str)
                } else {
                    input_str
                }
            }
            IntSExt => {
                let input_str = self.get_var_name(&op.inputs[0]);
                if let Some(output) = &op.output {
                    format!("({}) {}", self.get_type_name(output), input_str)
                } else {
                    input_str
                }
            }

            // Pointer operations
            PtrAdd => {
                let base = self.get_var_name(&op.inputs[0]);
                let offset = self.get_var_name(&op.inputs[1]);
                format!("({} + {})", base, offset)
            }

            // SubPiece: bit extraction
            SubPiece => {
                let input_str = self.get_var_name(&op.inputs[0]);
                if op.inputs.len() > 1 && op.inputs[1].space == AddressSpace::Const {
                    let offset = op.inputs[1].offset;
                    if offset == 0 {
                        format!("({})({})",
                            self.get_type_name(&op.output.as_ref().unwrap()),
                            input_str)
                    } else {
                        format!("({})(({}) >> {})",
                            self.get_type_name(&op.output.as_ref().unwrap()),
                            input_str,
                            offset * 8)
                    }
                } else {
                    input_str
                }
            }

            // Control flow (handled separately)
            Branch | CBranch | Call | Return => {
                String::new()
            }

            // SSA
            MultiEqual => {
                // Phi-node: handle as variable assignment
                if op.inputs.is_empty() {
                    "0".to_string()
                } else {
                    self.get_var_name(&op.inputs[0])
                }
            }

            _ => {
                // Other operations: output as comment
                format!("/* {:?} */", op.opcode)
            }
        }
    }

    /// Format binary operation
    fn binary_op(&mut self, op: &str, left: &Varnode, right: &Varnode) -> String {
        let left_str = self.get_var_name(left);
        let right_str = self.get_var_name(right);
        format!("({} {} {})", left_str, op, right_str)
    }

    /// Format unary operation
    fn unary_op(&mut self, op: &str, operand: &Varnode) -> String {
        let operand_str = self.get_var_name(operand);
        format!("{}({})", op, operand_str)
    }

    /// Print P-code operations as C function
    pub fn print(&mut self, ops: &[PcodeOp]) -> String {
        self.output.clear();
        self.emit_line("void decompiled_function(void) {".to_string());
        self.indent();

        // Variable declaration section
        let mut declared_vars = std::collections::HashSet::new();

        for op in ops {
            if let Some(output) = &op.output {
                let key = VarnodeKey::from(output);
                if !declared_vars.contains(&key) {
                    let type_name = self.get_type_name(output);
                    let var_name = self.get_var_name(output);
                    self.emit_line(format!("{} {};", type_name, var_name));
                    declared_vars.insert(key);
                }
            }
        }

        if !declared_vars.is_empty() {
            self.emit_line(String::new()); // Blank line
        }

        // Translate P-code operations sequentially
        for op in ops {
            match op.opcode {
                OpCode::Branch => {
                    if let Some(target) = op.inputs.get(0) {
                        self.emit_line(format!("goto label_0x{:x};", target.offset));
                    }
                }
                OpCode::CBranch => {
                    if op.inputs.len() >= 2 {
                        let cond = self.get_var_name(&op.inputs[1]);
                        let target = &op.inputs[0];
                        self.emit_line(format!("if ({}) goto label_0x{:x};", cond, target.offset));
                    }
                }
                OpCode::Call => {
                    if let Some(target) = op.inputs.get(0) {
                        self.emit_line(format!("call_0x{:x}();", target.offset));
                    }
                }
                OpCode::Return => {
                    if let Some(retval) = op.inputs.get(0) {
                        let val_str = self.get_var_name(retval);
                        self.emit_line(format!("return {};", val_str));
                    } else {
                        self.emit_line("return;".to_string());
                    }
                }
                _ => {
                    if let Some(output) = &op.output {
                        let expr = self.print_op(op);
                        if !expr.is_empty() {
                            let var_name = self.get_var_name(output);
                            self.emit_line(format!("{} = {};", var_name, expr));
                        }
                    }
                }
            }
        }

        self.dedent();
        self.emit_line("}".to_string());

        self.output.join("\n")
    }

    /// Get generated output
    pub fn get_output(&self) -> String {
        self.output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_arithmetic() {
        let type_info = TypeInference::new();
        let mut printer = CPrinter::new(type_info);

        let v1 = Varnode::register(0, 4);
        let v2 = Varnode::constant(10, 4);
        let v3 = Varnode::unique(0, 4);

        let ops = vec![PcodeOp::binary(
            OpCode::IntAdd,
            v3.clone(),
            v1,
            v2,
            0x1000,
        )];

        let code = printer.print(&ops);
        assert!(code.contains("uint32_t"));
        assert!(code.contains("+"));
    }
}
