// 構造体フィールド推論モジュール
// メモリアクセスパターンから構造体のフィールド構成を自動推論

use super::pcode::{PcodeOp, OpCode, Varnode, AddressSpace};
use super::cfg::ControlFlowGraph;
use std::collections::{HashMap, HashSet, BTreeMap};
use anyhow::Result;

/// 推論された型の種類
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    /// 整数型（ビット幅）
    Integer(usize),
    /// 浮動小数点型（ビット幅）
    Float(usize),
    /// ポインタ（指す先の型）
    Pointer(Box<InferredType>),
    /// 配列（要素型、要素数）
    Array(Box<InferredType>, usize),
    /// 構造体（フィールド情報）
    Struct(StructLayout),
    /// 不明な型
    Unknown,
}

/// 構造体のレイアウト情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructLayout {
    /// 構造体の総サイズ（バイト）
    pub total_size: usize,
    /// フィールドのリスト（オフセット順）
    pub fields: Vec<InferredField>,
    /// 構造体の名前（推論または既知）
    pub name: Option<String>,
}

/// 推論されたフィールド情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredField {
    /// フィールドのオフセット（バイト）
    pub offset: usize,
    /// フィールドのサイズ（バイト）
    pub size: usize,
    /// フィールドの型
    pub field_type: InferredType,
    /// アクセス種別
    pub access_type: FieldAccessType,
    /// アクセス回数（重要度の指標）
    pub access_count: usize,
    /// 推論されたフィールド名
    pub name: Option<String>,
}

/// フィールドへのアクセス種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldAccessType {
    /// 読み取りのみ
    ReadOnly,
    /// 書き込みのみ
    WriteOnly,
    /// 読み書き両方
    ReadWrite,
}

/// メモリアクセスパターン
#[derive(Debug, Clone)]
struct MemoryAccess {
    /// アクセス先のベースアドレス（変数）
    base: Varnode,
    /// オフセット（バイト）
    offset: i64,
    /// アクセスサイズ（バイト）
    size: usize,
    /// 読み取りか書き込みか
    is_write: bool,
    /// アクセス元の命令アドレス
    instruction_addr: u64,
}

/// 構造体解析器
pub struct StructAnalyzer {
    /// 検出されたメモリアクセスパターン
    memory_accesses: Vec<MemoryAccess>,
    /// ベース変数ごとのアクセスパターン
    base_to_accesses: HashMap<String, Vec<MemoryAccess>>,
    /// 推論された構造体レイアウト
    inferred_structs: HashMap<String, StructLayout>,
}

impl StructAnalyzer {
    /// 新しい構造体解析器を作成
    pub fn new() -> Self {
        Self {
            memory_accesses: Vec::new(),
            base_to_accesses: HashMap::new(),
            inferred_structs: HashMap::new(),
        }
    }

    /// P-code命令列から構造体フィールドを推論
    pub fn analyze_struct_fields(&mut self, ops: &[PcodeOp], cfg: &ControlFlowGraph) -> Result<()> {
        // ステップ1: メモリアクセスパターンを収集
        self.collect_memory_accesses(ops)?;

        // ステップ2: ベース変数ごとにグループ化
        self.group_accesses_by_base();

        // ステップ3: 各ベース変数の構造体レイアウトを推論
        self.infer_struct_layouts();

        // ステップ4: フィールドの型を推論
        self.infer_field_types(ops)?;

        Ok(())
    }

    /// メモリアクセスパターンを収集
    fn collect_memory_accesses(&mut self, ops: &[PcodeOp]) -> Result<()> {
        for op in ops {
            match op.opcode {
                OpCode::Load => {
                    // LOAD: [base + offset] -> output
                    if op.inputs.len() >= 1 {
                        if let Some(access) = self.parse_memory_access(&op.inputs[0], false, op.address) {
                            self.memory_accesses.push(access);
                        }
                    }
                }
                OpCode::Store => {
                    // STORE: value -> [base + offset]
                    if op.inputs.len() >= 2 {
                        if let Some(access) = self.parse_memory_access(&op.inputs[1], true, op.address) {
                            self.memory_accesses.push(access);
                        }
                    }
                }
                OpCode::IntAdd | OpCode::PtrAdd => {
                    // ポインタ演算も追跡（間接的なアクセスパターン）
                    // base + offset のパターンを検出
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// メモリアクセスをパース
    fn parse_memory_access(&self, addr_varnode: &Varnode, is_write: bool, instruction_addr: u64) -> Option<MemoryAccess> {
        // TODO: より高度なアドレス計算の解析
        // 現在は単純なケースのみ対応

        // 定数オフセットの検出
        if addr_varnode.space == AddressSpace::Const {
            // 絶対アドレスアクセス
            return Some(MemoryAccess {
                base: addr_varnode.clone(),
                offset: 0,
                size: addr_varnode.size,
                is_write,
                instruction_addr,
            });
        }

        // レジスタベースのアクセス
        if addr_varnode.space == AddressSpace::Register {
            return Some(MemoryAccess {
                base: addr_varnode.clone(),
                offset: 0,
                size: addr_varnode.size,
                is_write,
                instruction_addr,
            });
        }

        None
    }

    /// ベース変数ごとにアクセスをグループ化
    fn group_accesses_by_base(&mut self) {
        for access in &self.memory_accesses {
            let key = format!("{}_{:x}",
                match access.base.space {
                    AddressSpace::Register => "reg",
                    AddressSpace::Ram => "ram",
                    AddressSpace::Const => "const",
                    AddressSpace::Unique => "unique",
                    _ => "other",
                },
                access.base.offset
            );

            self.base_to_accesses
                .entry(key)
                .or_insert_with(Vec::new)
                .push(access.clone());
        }
    }

    /// 構造体レイアウトを推論
    fn infer_struct_layouts(&mut self) {
        for (base_key, accesses) in &self.base_to_accesses {
            // オフセットごとにアクセスを集約
            let mut offset_map: BTreeMap<i64, Vec<&MemoryAccess>> = BTreeMap::new();
            for access in accesses {
                offset_map
                    .entry(access.offset)
                    .or_insert_with(Vec::new)
                    .push(access);
            }

            // フィールドを構築
            let mut fields = Vec::new();
            for (offset, offset_accesses) in &offset_map {
                let size = offset_accesses[0].size;
                let mut read_count = 0;
                let mut write_count = 0;

                for access in offset_accesses {
                    if access.is_write {
                        write_count += 1;
                    } else {
                        read_count += 1;
                    }
                }

                let access_type = match (read_count > 0, write_count > 0) {
                    (true, true) => FieldAccessType::ReadWrite,
                    (true, false) => FieldAccessType::ReadOnly,
                    (false, true) => FieldAccessType::WriteOnly,
                    (false, false) => continue,
                };

                fields.push(InferredField {
                    offset: *offset as usize,
                    size,
                    field_type: InferredType::Unknown,
                    access_type,
                    access_count: read_count + write_count,
                    name: Some(format!("field_{:x}", offset)),
                });
            }

            // 構造体の総サイズを計算
            let total_size = fields.iter()
                .map(|f| f.offset + f.size)
                .max()
                .unwrap_or(0);

            let layout = StructLayout {
                total_size,
                fields,
                name: Some(base_key.clone()),
            };

            self.inferred_structs.insert(base_key.clone(), layout);
        }
    }

    /// フィールドの型を推論
    fn infer_field_types(&mut self, ops: &[PcodeOp]) -> Result<()> {
        // データフロー解析を使用してフィールドの使われ方から型を推論
        for (base_key, layout) in &mut self.inferred_structs {
            for field in &mut layout.fields {
                // サイズベースの基本的な型推論
                field.field_type = match field.size {
                    1 => InferredType::Integer(8),
                    2 => InferredType::Integer(16),
                    4 => InferredType::Integer(32),
                    8 => {
                        // 8バイトはポインタまたは64bit整数の可能性
                        // TODO: データフロー解析でポインタとして使われているか判定
                        InferredType::Integer(64)
                    }
                    _ => InferredType::Unknown,
                };
            }
        }
        Ok(())
    }

    /// 推論された構造体レイアウトを取得
    pub fn get_inferred_structs(&self) -> &HashMap<String, StructLayout> {
        &self.inferred_structs
    }

    /// 特定のベース変数の構造体レイアウトを取得
    pub fn get_struct_layout(&self, base_key: &str) -> Option<&StructLayout> {
        self.inferred_structs.get(base_key)
    }

    /// 構造体解析結果のサマリーを生成
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("検出された構造体: {} 個\n", self.inferred_structs.len()));

        for (base_key, layout) in &self.inferred_structs {
            summary.push_str(&format!("\n構造体: {} (サイズ: {} バイト)\n",
                layout.name.as_ref().unwrap_or(&"unknown".to_string()),
                layout.total_size));

            for field in &layout.fields {
                summary.push_str(&format!("  +0x{:x}: {:?} (サイズ: {}, アクセス: {:?}, 回数: {})\n",
                    field.offset,
                    field.field_type,
                    field.size,
                    field.access_type,
                    field.access_count));
            }
        }

        summary
    }
}

impl Default for StructAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
