/// C疑似コード生成エンジン
///
/// Ghidraのprintc.ccに基づくP-code→C言語変換
/// 式の優先順位、括弧の最小化、型キャストなどを処理

use crate::decompiler_prototype::pcode::{AddressSpace, OpCode, PcodeOp, Varnode};
use crate::decompiler_prototype::type_inference::{Type, TypeInference};
use std::collections::HashMap;

/// C疑似コード生成器
pub struct CPrinter {
    /// 型推論結果
    type_info: TypeInference,
    /// 変数名マッピング
    var_names: HashMap<VarnodeKey, String>,
    /// 一時変数カウンタ
    temp_counter: usize,
    /// 生成されたコード
    output: Vec<String>,
    /// インデントレベル
    indent_level: usize,
}

/// Varnodeを一意に識別するキー
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
    /// 新しいC疑似コード生成器を作成
    pub fn new(type_info: TypeInference) -> Self {
        Self {
            type_info,
            var_names: HashMap::new(),
            temp_counter: 0,
            output: Vec::new(),
            indent_level: 0,
        }
    }

    /// Varnodeの変数名を取得または生成
    fn get_var_name(&mut self, vn: &Varnode) -> String {
        let key = VarnodeKey::from(vn);

        if let Some(name) = self.var_names.get(&key) {
            return name.clone();
        }

        // 変数名を生成
        let name = match vn.space {
            AddressSpace::Register => {
                // レジスタは rN 形式
                format!("r{}", vn.offset)
            }
            AddressSpace::Ram => {
                // メモリは ptr_ADDR 形式
                format!("ptr_0x{:x}", vn.offset)
            }
            AddressSpace::Stack => {
                // スタックは stack_N 形式
                format!("stack_{}", vn.offset)
            }
            AddressSpace::Unique => {
                // 一時変数は tmp_N 形式
                let name = format!("tmp_{}", self.temp_counter);
                self.temp_counter += 1;
                name
            }
            AddressSpace::Const => {
                // 定数は値そのまま
                return format!("{}", vn.offset);
            }
        };

        self.var_names.insert(key, name.clone());
        name
    }

    /// Varnodeの型名を取得
    fn get_type_name(&self, vn: &Varnode) -> String {
        use crate::decompiler_prototype::type_inference::{IntType, FloatType};

        let _key = VarnodeKey::from(vn);

        // 型情報がある場合はそれを使用（現在は未実装のためコメントアウト）
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
        //     // デフォルトはサイズベースの型
        //     match vn.size {
        //         1 => "uint8_t".to_string(),
        //         2 => "uint16_t".to_string(),
        //         4 => "uint32_t".to_string(),
        //         8 => "uint64_t".to_string(),
        //         _ => "var".to_string(),
        //     }
        // }

        // 簡易版: サイズベースの型のみ
        match vn.size {
            1 => "uint8_t".to_string(),
            2 => "uint16_t".to_string(),
            4 => "uint32_t".to_string(),
            8 => "uint64_t".to_string(),
            _ => "var".to_string(),
        }
    }

    /// インデントを追加
    fn indent(&mut self) {
        self.indent_level += 1;
    }

    /// インデントを削除
    fn dedent(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }

    /// 現在のインデントを取得
    fn current_indent(&self) -> String {
        "  ".repeat(self.indent_level)
    }

    /// 行を追加
    fn emit_line(&mut self, line: String) {
        self.output.push(format!("{}{}", self.current_indent(), line));
    }

    /// P-code操作をC式に変換
    fn print_op(&mut self, op: &PcodeOp) -> String {
        use OpCode::*;

        match op.opcode {
            // 代入: output = input
            Copy => {
                if let Some(output) = &op.output {
                    let input_str = self.get_var_name(&op.inputs[0]);
                    format!("{}", input_str)
                } else {
                    String::new()
                }
            }

            // 算術演算
            IntAdd => self.binary_op("+", &op.inputs[0], &op.inputs[1]),
            IntSub => self.binary_op("-", &op.inputs[0], &op.inputs[1]),
            IntMult => self.binary_op("*", &op.inputs[0], &op.inputs[1]),
            IntDiv => self.binary_op("/", &op.inputs[0], &op.inputs[1]),
            IntSDiv => self.binary_op("/", &op.inputs[0], &op.inputs[1]),
            IntRem => self.binary_op("%", &op.inputs[0], &op.inputs[1]),
            IntSRem => self.binary_op("%", &op.inputs[0], &op.inputs[1]),

            // ビット演算
            IntAnd => self.binary_op("&", &op.inputs[0], &op.inputs[1]),
            IntOr => self.binary_op("|", &op.inputs[0], &op.inputs[1]),
            IntXor => self.binary_op("^", &op.inputs[0], &op.inputs[1]),
            IntNegate => self.unary_op("~", &op.inputs[0]),
            Int2Comp => self.unary_op("-", &op.inputs[0]),

            // シフト演算
            IntLeft => self.binary_op("<<", &op.inputs[0], &op.inputs[1]),
            IntRight => self.binary_op(">>", &op.inputs[0], &op.inputs[1]),
            IntSRight => self.binary_op(">>", &op.inputs[0], &op.inputs[1]),

            // 比較演算
            IntEqual => self.binary_op("==", &op.inputs[0], &op.inputs[1]),
            IntNotEqual => self.binary_op("!=", &op.inputs[0], &op.inputs[1]),
            IntLess => self.binary_op("<", &op.inputs[0], &op.inputs[1]),
            IntLessEqual => self.binary_op("<=", &op.inputs[0], &op.inputs[1]),
            IntSLess => self.binary_op("<", &op.inputs[0], &op.inputs[1]),
            IntSLessEqual => self.binary_op("<=", &op.inputs[0], &op.inputs[1]),

            // ブール演算
            BoolNegate => self.unary_op("!", &op.inputs[0]),
            BoolAnd => self.binary_op("&&", &op.inputs[0], &op.inputs[1]),
            BoolOr => self.binary_op("||", &op.inputs[0], &op.inputs[1]),
            BoolXor => self.binary_op("^", &op.inputs[0], &op.inputs[1]),

            // メモリ操作
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

            // 型変換
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

            // ポインタ演算
            PtrAdd => {
                let base = self.get_var_name(&op.inputs[0]);
                let offset = self.get_var_name(&op.inputs[1]);
                format!("({} + {})", base, offset)
            }

            // SubPiece: ビット抽出
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

            // 制御フロー
            Branch | CBranch | Call | Return => {
                // 制御フローは別途処理
                String::new()
            }

            // SSA
            MultiEqual => {
                // Phi-nodeは変数定義として扱う
                if op.inputs.is_empty() {
                    "0".to_string()
                } else {
                    self.get_var_name(&op.inputs[0])
                }
            }

            _ => {
                // その他の操作はコメントとして出力
                format!("/* {:?} */", op.opcode)
            }
        }
    }

    /// 二項演算子の文字列化
    fn binary_op(&mut self, op: &str, left: &Varnode, right: &Varnode) -> String {
        let left_str = self.get_var_name(left);
        let right_str = self.get_var_name(right);
        format!("({} {} {})", left_str, op, right_str)
    }

    /// 単項演算子の文字列化
    fn unary_op(&mut self, op: &str, operand: &Varnode) -> String {
        let operand_str = self.get_var_name(operand);
        format!("{}({})", op, operand_str)
    }

    /// P-code操作列をC疑似コードに変換
    pub fn print(&mut self, ops: &[PcodeOp]) -> String {
        self.output.clear();
        self.emit_line("void decompiled_function(void) {".to_string());
        self.indent();

        // 変数宣言セクション
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
            self.emit_line(String::new()); // 空行
        }

        // P-code操作を順次変換
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

    /// 生成されたコードを取得
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
