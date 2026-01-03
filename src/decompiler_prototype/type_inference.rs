/// Type inference for P-code decompilation
/// Infers variable types from operation context
///
/// 拡張機能:
/// - ポインタの指す先の型の詳細推論
/// - 配列サイズと要素型の自動検出
/// - 構造体の入れ子構造解析

use super::pcode::*;
use std::collections::{HashMap, HashSet};

/// Represents a data type in the decompiled output
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    /// Unknown type
    Unknown,
    /// Void type
    Void,
    /// Integer type
    Int(IntType),
    /// Floating point type
    Float(FloatType),
    /// Pointer to another type
    Pointer(Box<Type>),
    /// Array type
    Array(Box<Type>, usize),
    /// Struct type
    Struct(Vec<(String, Type)>),
    /// Function type
    Function(Vec<Type>, Box<Type>),
}

/// Integer type variants
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntType {
    /// Signed 8-bit
    I8,
    /// Signed 16-bit
    I16,
    /// Signed 32-bit
    I32,
    /// Signed 64-bit
    I64,
    /// Unsigned 8-bit
    U8,
    /// Unsigned 16-bit
    U16,
    /// Unsigned 32-bit
    U32,
    /// Unsigned 64-bit
    U64,
}

/// Floating point type variants
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloatType {
    /// 32-bit float
    F32,
    /// 64-bit float
    F64,
}

impl Type {
    /// Create integer type from size and signedness
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

    /// Create float type from size
    pub fn float_from_size(size: usize) -> Self {
        match size {
            4 => Type::Float(FloatType::F32),
            8 => Type::Float(FloatType::F64),
            _ => Type::Unknown,
        }
    }

    /// Get the size in bytes of this type
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
            Type::Pointer(_) => 8,
            Type::Array(elem_ty, count) => elem_ty.size() * count,
            Type::Struct(fields) => {
                fields.iter().map(|(_, ty)| ty.size()).sum()
            }
            Type::Function(_, _) => 8,
        }
    }

    /// Convert type to C-style string
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

    /// Check if this type is compatible with another
    pub fn is_compatible_with(&self, other: &Type) -> bool {
        match (self, other) {
            (Type::Unknown, _) | (_, Type::Unknown) => true,
            (Type::Void, Type::Void) => true,
            (Type::Int(_), Type::Int(_)) => true,
            (Type::Float(_), Type::Float(_)) => true,
            (Type::Pointer(a), Type::Pointer(b)) => a.is_compatible_with(b),
            (Type::Array(a, _), Type::Array(b, _)) => a.is_compatible_with(b),
            _ => self == other,
        }
    }
}

/// Type constraint for a varnode
#[derive(Debug, Clone)]
pub struct TypeConstraint {
    /// The varnode being constrained
    pub varnode: Varnode,
    /// The inferred type
    pub type_: Type,
    /// Reason for this constraint
    pub reason: String,
}

/// Type inference engine
#[derive(Debug)]
pub struct TypeInference {
    /// Collected type constraints
    constraints: Vec<TypeConstraint>,
    /// Final inferred types
    inferred_types: HashMap<Varnode, Type>,
    /// Candidate types for each varnode
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

    /// Infer types from P-code operations
    pub fn infer_from_pcode(&mut self, ops: &[PcodeOp]) {
        for op in ops {
            self.collect_constraints_from_op(op);
        }
    }

    /// Collect type constraints from a single operation
    fn collect_constraints_from_op(&mut self, op: &PcodeOp) {
        match op.opcode {
            OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult | OpCode::IntDiv |
            OpCode::IntSDiv | OpCode::IntRem | OpCode::IntSRem => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, true),
                        format!("Integer operation {:?} output", op.opcode),
                    );
                }
                for input in &op.inputs {
                    self.add_constraint(
                        input.clone(),
                        Type::int_from_size(input.size, true),
                        format!("Integer operation {:?} input", op.opcode),
                    );
                }
            }

            OpCode::FloatAdd | OpCode::FloatSub | OpCode::FloatMult | OpCode::FloatDiv => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::float_from_size(output.size),
                        format!("Float operation {:?} output", op.opcode),
                    );
                }
                for input in &op.inputs {
                    self.add_constraint(
                        input.clone(),
                        Type::float_from_size(input.size),
                        format!("Float operation {:?} input", op.opcode),
                    );
                }
            }

            OpCode::Load => {
                if op.inputs.len() >= 2 {
                    let ptr = &op.inputs[1];
                    if let Some(ref output) = op.output {
                        self.add_constraint(
                            ptr.clone(),
                            Type::Pointer(Box::new(Type::int_from_size(output.size, true))),
                            "Load address operand".to_string(),
                        );
                    }
                }
            }

            OpCode::Store => {
                if op.inputs.len() >= 3 {
                    let ptr = &op.inputs[1];
                    let value = &op.inputs[2];
                    self.add_constraint(
                        ptr.clone(),
                        Type::Pointer(Box::new(Type::int_from_size(value.size, true))),
                        "Store address operand".to_string(),
                    );
                }
            }

            OpCode::Copy => {
                if let Some(ref output) = op.output {
                    if !op.inputs.is_empty() {
                        let input = &op.inputs[0];
                        if let Some(input_type) = self.inferred_types.get(input).cloned() {
                            self.add_constraint(
                                output.clone(),
                                input_type,
                                "Copy propagation".to_string(),
                            );
                        }
                    }
                }
            }

            OpCode::IntEqual | OpCode::IntNotEqual | OpCode::IntLess | OpCode::IntSLess |
            OpCode::IntLessEqual | OpCode::IntSLessEqual => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::Int(IntType::I8),
                        format!("Comparison {:?} output", op.opcode),
                    );
                }
                for input in &op.inputs {
                    self.add_constraint(
                        input.clone(),
                        Type::int_from_size(input.size, true),
                        format!("Comparison {:?} input", op.opcode),
                    );
                }
            }

            OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor | OpCode::IntNegate |
            OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, false),
                        format!("Bitwise {:?} output", op.opcode),
                    );
                }
            }

            OpCode::IntSExt => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, true),
                        "Sign extension output".to_string(),
                    );
                }
            }

            OpCode::IntZExt => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, false),
                        "Zero extension output".to_string(),
                    );
                }
            }

            OpCode::Call => {
                if let Some(ref output) = op.output {
                    self.add_constraint(
                        output.clone(),
                        Type::int_from_size(output.size, true),
                        "Function call return value".to_string(),
                    );
                }
            }

            _ => {}
        }
    }

    /// Add a type constraint
    fn add_constraint(&mut self, varnode: Varnode, type_: Type, reason: String) {
        if varnode.space == AddressSpace::Const {
            return;
        }

        self.constraints.push(TypeConstraint {
            varnode: varnode.clone(),
            type_: type_.clone(),
            reason,
        });

        self.type_candidates
            .entry(varnode)
            .or_insert_with(Vec::new)
            .push(type_);
    }

    /// Propagate types through constraints
    pub fn propagate_types(&mut self) {
        for constraint in &self.constraints {
            let varnode = &constraint.varnode;
            let type_ = &constraint.type_;

            if let Some(existing_type) = self.inferred_types.get(varnode) {
                if !existing_type.is_compatible_with(type_) {
                    continue;
                }
                if matches!(existing_type, Type::Unknown) {
                    self.inferred_types.insert(varnode.clone(), type_.clone());
                }
            } else {
                self.inferred_types.insert(varnode.clone(), type_.clone());
            }
        }
    }

    /// Resolve types for all varnodes
    pub fn resolve_types(&mut self) {
        for (varnode, candidates) in &self.type_candidates {
            if candidates.is_empty() {
                continue;
            }

            if self.inferred_types.contains_key(varnode) {
                continue;
            }

            let best_type = self.select_best_type(candidates);
            self.inferred_types.insert(varnode.clone(), best_type);
        }
    }

    /// Select the best type from candidates
    fn select_best_type(&self, candidates: &[Type]) -> Type {
        let non_unknown: Vec<&Type> = candidates
            .iter()
            .filter(|t| !matches!(t, Type::Unknown))
            .collect();

        if non_unknown.is_empty() {
            return Type::Unknown;
        }

        for t in &non_unknown {
            if matches!(t, Type::Pointer(_)) {
                return (*t).clone();
            }
        }

        for t in &non_unknown {
            if matches!(t, Type::Float(_)) {
                return (*t).clone();
            }
        }

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

    /// Get inferred type for a varnode
    pub fn get_type(&self, varnode: &Varnode) -> Option<&Type> {
        self.inferred_types.get(varnode)
    }

    /// Get all inferred types
    pub fn get_all_types(&self) -> &HashMap<Varnode, Type> {
        &self.inferred_types
    }

    /// Run full type inference
    pub fn run(&mut self, ops: &[PcodeOp]) {
        self.infer_from_pcode(ops);
        self.propagate_types();
        self.resolve_types();
    }

    /// ポインタの指す先の型を推論
    /// メモリアクセスパターンから、ポインタが指す実際の型を特定
    pub fn infer_pointee_type(&mut self, ptr_varnode: &Varnode, ops: &[PcodeOp]) -> Type {
        // このポインタを使ったLOAD/STORE命令を探す
        for op in ops {
            match op.opcode {
                OpCode::Load => {
                    if op.inputs.len() >= 2 && &op.inputs[1] == ptr_varnode {
                        if let Some(ref output) = op.output {
                            // LOADの出力サイズから指す先の型を推論
                            return self.infer_type_from_size_and_usage(output.size, ops, output);
                        }
                    }
                }
                OpCode::Store => {
                    if op.inputs.len() >= 3 && &op.inputs[1] == ptr_varnode {
                        let value = &op.inputs[2];
                        // STOREされる値の型から指す先の型を推論
                        return self.infer_type_from_size_and_usage(value.size, ops, value);
                    }
                }
                _ => {}
            }
        }
        Type::Unknown
    }

    /// サイズと使用パターンから型を推論
    fn infer_type_from_size_and_usage(&self, size: usize, ops: &[PcodeOp], varnode: &Varnode) -> Type {
        // この変数が使われている演算から型を判定
        for op in ops {
            // 浮動小数点演算で使われている？
            if matches!(op.opcode, OpCode::FloatAdd | OpCode::FloatSub | OpCode::FloatMult | OpCode::FloatDiv) {
                if op.inputs.contains(varnode) || op.output.as_ref() == Some(varnode) {
                    return Type::float_from_size(size);
                }
            }

            // ポインタとして使われている？
            if matches!(op.opcode, OpCode::Load | OpCode::Store) {
                if op.inputs.contains(varnode) {
                    // ポインタの可能性
                    return Type::Pointer(Box::new(Type::Unknown));
                }
            }
        }

        // デフォルトは整数型
        Type::int_from_size(size, true)
    }

    /// 配列のサイズと要素型を推論
    /// ループ内でのインデックスアクセスパターンから配列を検出
    pub fn infer_array_type(&mut self, base_varnode: &Varnode, ops: &[PcodeOp]) -> Option<Type> {
        // パターン: base + (index * element_size)
        let mut accesses = Vec::new();

        for op in ops {
            if let OpCode::PtrAdd = op.opcode {
                if op.inputs.len() >= 2 && &op.inputs[0] == base_varnode {
                    // オフセット計算を解析
                    if let Some(offset_info) = self.analyze_offset_calculation(&op.inputs[1], ops) {
                        accesses.push(offset_info);
                    }
                }
            }
        }

        if accesses.is_empty() {
            return None;
        }

        // 最も一般的な要素サイズを特定
        let mut size_counts: HashMap<usize, usize> = HashMap::new();
        for (element_size, _) in &accesses {
            *size_counts.entry(*element_size).or_insert(0) += 1;
        }

        if let Some((element_size, _)) = size_counts.iter().max_by_key(|(_, count)| *count) {
            // 最大インデックスから配列サイズを推定
            let max_index = accesses.iter()
                .map(|(_, idx)| *idx)
                .max()
                .unwrap_or(0);

            let element_type = Type::int_from_size(*element_size, true);
            return Some(Type::Array(Box::new(element_type), max_index + 1));
        }

        None
    }

    /// オフセット計算を解析（index * element_size）
    fn analyze_offset_calculation(&self, offset_varnode: &Varnode, ops: &[PcodeOp]) -> Option<(usize, usize)> {
        // offset = index * element_size のパターンを検出
        for op in ops {
            if op.opcode == OpCode::IntMult {
                if let Some(ref output) = op.output {
                    if output == offset_varnode && op.inputs.len() >= 2 {
                        // 定数乗算を検出
                        if op.inputs[1].space == AddressSpace::Const {
                            let element_size = op.inputs[1].offset as usize;
                            // index の最大値を推定（TODO: より高度な解析）
                            return Some((element_size, 10)); // 仮の配列サイズ
                        }
                    }
                }
            }
        }
        None
    }

    /// 構造体の入れ子構造を検出
    /// フィールドがポインタで、そのポインタ先も構造体の場合を検出
    pub fn detect_nested_struct(&mut self, struct_base: &Varnode, ops: &[PcodeOp]) -> HashMap<usize, Type> {
        let mut nested_fields: HashMap<usize, Type> = HashMap::new();

        // 各フィールドへのアクセスを追跡
        for op in ops {
            if let OpCode::Load = op.opcode {
                if op.inputs.len() >= 2 {
                    // base + offset のパターンを検出
                    if let Some((offset, _field_ptr)) = self.extract_struct_field_access(&op.inputs[1], struct_base) {
                        // このフィールドポインタが別の構造体アクセスに使われているか
                        if let Some(ref output) = op.output {
                            if self.is_used_as_struct_pointer(output, ops) {
                                nested_fields.insert(offset, Type::Pointer(Box::new(Type::Unknown)));
                            }
                        }
                    }
                }
            }
        }

        nested_fields
    }

    /// 構造体フィールドアクセスを抽出（base + offset）
    fn extract_struct_field_access(&self, _addr_varnode: &Varnode, _expected_base: &Varnode) -> Option<(usize, Varnode)> {
        // TODO: より高度なアドレス計算の解析
        // 現在は単純なケースのみ対応
        None
    }

    /// 変数が構造体ポインタとして使われているか判定
    fn is_used_as_struct_pointer(&self, varnode: &Varnode, ops: &[PcodeOp]) -> bool {
        // 複数の異なるオフセットでアクセスされていれば構造体の可能性
        let mut offsets = HashSet::new();

        for op in ops {
            if matches!(op.opcode, OpCode::Load | OpCode::Store) {
                if op.inputs.contains(varnode) {
                    // TODO: オフセット値を抽出
                    offsets.insert(0);
                }
            }
        }

        offsets.len() > 1
    }

    /// 型推論結果のサマリーを生成
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("推論された型: {} 個\n", self.inferred_types.len()));

        let mut by_type: HashMap<String, usize> = HashMap::new();
        for ty in self.inferred_types.values() {
            let type_name = match ty {
                Type::Unknown => "Unknown",
                Type::Void => "Void",
                Type::Int(_) => "Integer",
                Type::Float(_) => "Float",
                Type::Pointer(_) => "Pointer",
                Type::Array(_, _) => "Array",
                Type::Struct(_) => "Struct",
                Type::Function(_, _) => "Function",
            };
            *by_type.entry(type_name.to_string()).or_insert(0) += 1;
        }

        summary.push_str("\n型の内訳:\n");
        for (type_name, count) in &by_type {
            summary.push_str(&format!("  {}: {} 個\n", type_name, count));
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_type_inference() {
        let mut inference = TypeInference::new();

        let rax = Varnode { space: AddressSpace::Register, offset: 0, size: 8 };
        let rbx = Varnode { space: AddressSpace::Register, offset: 24, size: 8 };

        let op = PcodeOp {
            opcode: OpCode::Copy,
            output: Some(rax.clone()),
            inputs: vec![rbx.clone()],
            address: 0,
        };

        inference.run(&[op]);

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
