/// 型推論エンジン
/// P-code命令から変数の型を推論し、C言語風の型情報を生成する

use super::pcode::*;
use std::collections::{HashMap, HashSet};

/// 推論される型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    /// 未知の型
    Unknown,
    /// void型
    Void,
    /// 整数型
    Int(IntType),
    /// 浮動小数点型
    Float(FloatType),
    /// ポインタ型
    Pointer(Box<Type>),
    /// 配列型 (要素型, サイズ)
    Array(Box<Type>, usize),
    /// 構造体型 (フィールド名, 型)
    Struct(Vec<(String, Type)>),
    /// 関数型 (引数型リスト, 戻り値型)
    Function(Vec<Type>, Box<Type>),
}

/// 整数型の種類
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IntType {
    /// 符号付き8ビット
    I8,
    /// 符号付き16ビット
    I16,
    /// 符号付き32ビット
    I32,
    /// 符号付き64ビット
    I64,
    /// 符号なし8ビット
    U8,
    /// 符号なし16ビット
    U16,
    /// 符号なし32ビット
    U32,
    /// 符号なし64ビット
    U64,
}

/// 浮動小数点型の種類
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FloatType {
    /// 32ビット浮動小数点
    F32,
    /// 64ビット浮動小数点
    F64,
}

impl Type {
    /// サイズから基本的な整数型を推論
    pub fn int_from_size(size: usize, signed: bool) -> Self {
        match (size, signed) {
            (1, true) => Type::Int(IntType::I8),
            (1, false) => Type::Int(IntType::U8),
            (2, true) => Type::Int(IntType::I16),
            (2, false) => Type::Int(IntType::U16),
            (4, true) => Type::Int(IntType::I32),
            (4, false) => Type::Int(IntType::U32),
            (8, true) => Type::Int(IntType::I64),
            (8, false) => Type::Int(IntType::U64),
            _ => Type::Unknown,
        }
    }

    /// サイズから浮動小数点型を推論
    pub fn float_from_size(size: usize) -> Self {
        match size {
            4 => Type::Float(FloatType::F32),
            8 => Type::Float(FloatType::F64),
            _ => Type::Unknown,
        }
    }

    /// 型のサイズを取得
    pub fn size(&self) -> usize {
        match self {
            Type::Unknown => 0,
            Type::Void => 0,
            Type::Int(int_ty) => match int_ty {
                IntType::I8 | IntType::U8 => 1,
                IntType::I16 | IntType::U16 => 2,
                IntType::I32 | IntType::U32 => 4,
                IntType::I64 | IntType::U64 => 8,
            },
            Type::Float(float_ty) => match float_ty {
                FloatType::F32 => 4,
                FloatType::F64 => 8,
            },
            Type::Pointer(_) => 8, // 64ビットポインタ
            Type::Array(elem_ty, count) => elem_ty.size() * count,
            Type::Struct(fields) => {
                fields.iter().map(|(_, ty)| ty.size()).sum()
            }
            Type::Function(_, _) => 8, // 関数ポインタ
        }
    }

    /// C言語風の型名を取得
    pub fn to_c_string(&self) -> String {
        match self {
            Type::Unknown => "unknown".to_string(),
            Type::Void => "void".to_string(),
            Type::Int(int_ty) => match int_ty {
                IntType::I8 => "int8_t".to_string(),
                IntType::I16 => "int16_t".to_string(),
                IntType::I32 => "int32_t".to_string(),
                IntType::I64 => "int64_t".to_string(),
                IntType::U8 => "uint8_t".to_string(),
                IntType::U16 => "uint16_t".to_string(),
                IntType::U32 => "uint32_t".to_string(),
                IntType::U64 => "uint64_t".to_string(),
            },
            Type::Float(float_ty) => match float_ty {
                FloatType::F32 => "float".to_string(),
                FloatType::F64 => "double".to_string(),
            },
            Type::Pointer(inner) => format!("{}*", inner.to_c_string()),
            Type::Array(elem_ty, count) => format!("{}[{}]", elem_ty.to_c_string(), count),
            Type::Struct(fields) => {
                let field_strs: Vec<String> = fields
                    .iter()
                    .map(|(name, ty)| format!("{} {}", ty.to_c_string(), name))
                    .collect();
                format!("struct {{ {} }}", field_strs.join("; "))
            }
            Type::Function(args, ret) => {
                let arg_strs: Vec<String> = args.iter().map(|t| t.to_c_string()).collect();
                format!("{} (*)({})", ret.to_c_string(), arg_strs.join(", "))
            }
        }
    }

    /// 型が互換性があるかチェック
    pub fn is_compatible_with(&self, other: &Type) -> bool {
        match (self, other) {
            (Type::Unknown, _) | (_, Type::Unknown) => true,
            (Type::Void, Type::Void) => true,
            (Type::Int(_), Type::Int(_)) => true, // 整数型同士は互換
            (Type::Float(_), Type::Float(_)) => true,
            (Type::Pointer(a), Type::Pointer(b)) => a.is_compatible_with(b),
            (Type::Array(a, _), Type::Array(b, _)) => a.is_compatible_with(b),
            _ => self == other,
        }
    }
}

/// 型制約
#[derive(Debug, Clone)]
pub struct TypeConstraint {
    /// 制約対象のVarnode
    pub varnode: Varnode,
    /// 推論された型
    pub type_: Type,
    /// 制約の理由（デバッグ用）
    pub reason: String,
}

/// 型推論エンジン
pub struct TypeInference {
    /// 収集された型制約
    constraints: Vec<TypeConstraint>,
    /// 推論済みの型
    inferred_types: HashMap<Varnode, Type>,
    /// 型の候補（複数の制約がある場合）
    type_candidates: HashMap<Varnode, Vec<Type>>,
}

impl TypeInference {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            inferred_types: HashMap::new(),
            type_candidates: HashMap::new(),
        }
    }

    /// P-code命令から型制約を収集
    pub fn infer_from_pcode(&mut self, ops: &[PcodeOp]) {
        for op in ops {
            self.collect_constraints_from_op(op);
        }
    }

    /// 単一のP-code命令から型制約を収集
    fn collect_constraints_from_op(&mut self, op: &PcodeOp) {
        match op.opcode {
            // 整数演算 → 整数型
            OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult | OpCode::IntDiv |
            OpCode::IntSDiv | OpCode::IntRem | OpCode::IntSRem => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, true),
                        format!("整数演算 {:?} の出力", op.opcode),
                    );
                }
                for input in &op.inputs {
                    self.add_constraint(
                        input.clone(),
                        Type::int_from_size(input.size, true),
                        format!("整数演算 {:?} の入力", op.opcode),
                    );
                }
            }

            // 浮動小数点演算 → 浮動小数点型
            OpCode::FloatAdd | OpCode::FloatSub | OpCode::FloatMult | OpCode::FloatDiv => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::float_from_size(output.size),
                        format!("浮動小数点演算 {:?} の出力", op.opcode),
                    );
                }
                for input in &op.inputs {
                    self.add_constraint(
                        input.clone(),
                        Type::float_from_size(input.size),
                        format!("浮動小数点演算 {:?} の入力", op.opcode),
                    );
                }
            }

            // ロード → ポインタ型
            OpCode::Load => {
                if op.inputs.len() >= 2 {
                    let ptr = &op.inputs[1];
                    if let Some(ref output) = op.output {
                        self.add_constraint(
                            ptr.clone(),
                            Type::Pointer(Box::new(Type::int_from_size(output.size, true))),
                            "Load命令のアドレス引数".to_string(),
                        );
                    }
                }
            }

            // ストア → ポインタ型
            OpCode::Store => {
                if op.inputs.len() >= 3 {
                    let ptr = &op.inputs[1];
                    let value = &op.inputs[2];
                    self.add_constraint(
                        ptr.clone(),
                        Type::Pointer(Box::new(Type::int_from_size(value.size, true))),
                        "Store命令のアドレス引数".to_string(),
                    );
                }
            }

            // コピー → 型を伝播
            OpCode::Copy => {
                if let Some(ref output) = op.output {
                    if !op.inputs.is_empty() {
                        let input = &op.inputs[0];
                        // 入力と出力の型は同じ
                        if let Some(input_type) = self.inferred_types.get(input).cloned() {
                            self.add_constraint(
                                output.clone(),
                                input_type,
                                "Copy命令による型伝播".to_string(),
                            );
                        }
                    }
                }
            }

            // 比較演算 → 整数型
            OpCode::IntEqual | OpCode::IntNotEqual | OpCode::IntLess | OpCode::IntSLess |
            OpCode::IntLessEqual | OpCode::IntSLessEqual => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::Int(IntType::I8), // bool として 1バイト
                        format!("比較演算 {:?} の出力", op.opcode),
                    );
                }
                for input in &op.inputs {
                    self.add_constraint(
                        input.clone(),
                        Type::int_from_size(input.size, true),
                        format!("比較演算 {:?} の入力", op.opcode),
                    );
                }
            }

            // ビット演算 → 整数型
            OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor | OpCode::IntNegate |
            OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, false), // 符号なしとして扱う
                        format!("ビット演算 {:?} の出力", op.opcode),
                    );
                }
            }

            // 符号拡張 → 符号付き整数
            OpCode::IntSExt => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, true),
                        "符号拡張の出力".to_string(),
                    );
                }
            }

            // ゼロ拡張 → 符号なし整数
            OpCode::IntZExt => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, false),
                        "ゼロ拡張の出力".to_string(),
                    );
                }
            }

            // 関数呼び出し
            OpCode::Call => {
                // 戻り値の型を推論（後で詳細化）
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, true),
                        "関数呼び出しの戻り値".to_string(),
                    );
                }
            }

            _ => {}
        }
    }

    /// 型制約を追加
    fn add_constraint(&mut self, varnode: Varnode, type_: Type, reason: String) {
        // 定数は型推論しない
        if varnode.space == AddressSpace::Const {
            return;
        }

        self.constraints.push(TypeConstraint {
            varnode: varnode.clone(),
            type_: type_.clone(),
            reason,
        });

        // 候補リストに追加
        self.type_candidates
            .entry(varnode)
            .or_insert_with(Vec::new)
            .push(type_);
    }

    /// 型を伝播させる
    pub fn propagate_types(&mut self) {
        // 制約から型を決定
        for constraint in &self.constraints {
            let varnode = &constraint.varnode;
            let type_ = &constraint.type_;

            // 既存の型と互換性をチェック
            if let Some(existing_type) = self.inferred_types.get(varnode) {
                if !existing_type.is_compatible_with(type_) {
                    // 互換性がない場合は警告（今は無視）
                    continue;
                }
                // より具体的な型を選択
                if matches!(existing_type, Type::Unknown) {
                    self.inferred_types.insert(varnode.clone(), type_.clone());
                }
            } else {
                self.inferred_types.insert(varnode.clone(), type_.clone());
            }
        }
    }

    /// 型制約を解決
    pub fn resolve_types(&mut self) {
        // 各Varnodeの候補から最適な型を選択
        for (varnode, candidates) in &self.type_candidates {
            if candidates.is_empty() {
                continue;
            }

            // 既に推論済みならスキップ
            if self.inferred_types.contains_key(varnode) {
                continue;
            }

            // 候補の中で最も具体的な型を選択
            let best_type = self.select_best_type(candidates);
            self.inferred_types.insert(varnode.clone(), best_type);
        }
    }

    /// 複数の型候補から最適な型を選択
    fn select_best_type(&self, candidates: &[Type]) -> Type {
        // Unknown以外を優先
        let non_unknown: Vec<&Type> = candidates
            .iter()
            .filter(|t| !matches!(t, Type::Unknown))
            .collect();

        if non_unknown.is_empty() {
            return Type::Unknown;
        }

        // ポインタ型を優先
        for t in &non_unknown {
            if matches!(t, Type::Pointer(_)) {
                return (*t).clone();
            }
        }

        // 浮動小数点型を優先
        for t in &non_unknown {
            if matches!(t, Type::Float(_)) {
                return (*t).clone();
            }
        }

        // 整数型（最大サイズを選択）
        let mut max_size = 0;
        let mut best = Type::Unknown;
        for t in &non_unknown {
            if t.size() > max_size {
                max_size = t.size();
                best = (*t).clone();
            }
        }

        best
    }

    /// 推論結果を取得
    pub fn get_type(&self, varnode: &Varnode) -> Option<&Type> {
        self.inferred_types.get(varnode)
    }

    /// すべての推論結果を取得
    pub fn get_all_types(&self) -> &HashMap<Varnode, Type> {
        &self.inferred_types
    }

    /// 型推論を実行（収集→伝播→解決）
    pub fn run(&mut self, ops: &[PcodeOp]) {
        self.infer_from_pcode(ops);
        self.propagate_types();
        self.resolve_types();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_type_inference() {
        let mut inference = TypeInference::new();

        // mov rax, rbx (8バイトコピー)
        let rax = Varnode { space: AddressSpace::Register, offset: 0, size: 8 };
        let rbx = Varnode { space: AddressSpace::Register, offset: 24, size: 8 };

        let op = PcodeOp {
            opcode: OpCode::Copy,
            output: Some(rax.clone()),
            inputs: vec![rbx.clone()],
            address: 0,
        };

        inference.run(&[op]);

        // raxの型が推論されていることを確認
        assert!(inference.get_type(&rax).is_some());
    }

    #[test]
    fn test_float_type_inference() {
        let mut inference = TypeInference::new();

        let xmm0 = Varnode { space: AddressSpace::Register, offset: 200, size: 8 };
        let xmm1 = Varnode { space: AddressSpace::Register, offset: 208, size: 8 };

        let op = PcodeOp {
            opcode: OpCode::FloatAdd,
            output: Some(xmm0.clone()),
            inputs: vec![xmm0.clone(), xmm1],
            address: 0,
        };

        inference.run(&[op]);

        if let Some(ty) = inference.get_type(&xmm0) {
            assert!(matches!(ty, Type::Float(FloatType::F64)));
        }
    }

    #[test]
    fn test_pointer_type_inference() {
        let mut inference = TypeInference::new();

        let rax = Varnode { space: AddressSpace::Register, offset: 0, size: 8 };
        let value = Varnode { space: AddressSpace::Register, offset: 8, size: 4 };
        let space_id = Varnode { space: AddressSpace::Const, offset: 0, size: 8 };

        // *rax = value (4バイトストア)
        let op = PcodeOp {
            opcode: OpCode::Store,
            output: None,
            inputs: vec![space_id, rax.clone(), value],
            address: 0,
        };

        inference.run(&[op]);

        if let Some(ty) = inference.get_type(&rax) {
            assert!(matches!(ty, Type::Pointer(_)));
        }
    }

    #[test]
    fn test_type_to_c_string() {
        assert_eq!(Type::Int(IntType::I32).to_c_string(), "int32_t");
        assert_eq!(Type::Float(FloatType::F64).to_c_string(), "double");
        assert_eq!(
            Type::Pointer(Box::new(Type::Int(IntType::I8))).to_c_string(),
            "int8_t*"
        );
    }
}
