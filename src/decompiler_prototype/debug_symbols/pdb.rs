use pdb::{PDB, FallibleIterator, SymbolData, TypeData, TypeIndex};
use anyhow::{Result, Context};
use std::collections::HashMap;
use std::io::Cursor;
use super::{TypeInfo, TypeKind, BaseType};
pub struct PdbSymbolParser {
    functions: HashMap<u64, String>,
    variables: HashMap<u64, String>,
    types: HashMap<u32, TypeInfo>,
    line_info: HashMap<u64, (String, u32)>,
}
impl PdbSymbolParser {
    pub fn parse_from_pdb_data(pdb_data: &[u8]) -> Result<Self> {
        let cursor = Cursor::new(pdb_data);
        let mut pdb = PDB::open(cursor)
            .context("Failed to parse PDB data")?;

        let mut parser = Self {
            functions: HashMap::new(),
            variables: HashMap::new(),
            types: HashMap::new(),
            line_info: HashMap::new(),
        };
        if let Ok(symbol_table) = pdb.global_symbols() {
            let mut symbols = symbol_table.iter();
            while let Some(symbol) = symbols.next()? {
                let _ = parser.parse_symbol(&symbol);
            }
        }
        if let Ok(dbi) = pdb.debug_information() {
            let mut modules = dbi.modules()?;
            while let Some(module) = modules.next()? {
                if let Some(info) = pdb.module_info(&module)? {
                    if let Ok(mut symbols) = info.symbols() {
                        while let Some(symbol) = symbols.next()? {
                            let _ = parser.parse_symbol(&symbol);
                        }
                    }
                }
            }
        }
        if let Ok(type_information) = pdb.type_information() {
            let mut type_iter = type_information.iter();
            while let Some(item) = type_iter.next()? {
                if let Ok(type_data) = item.parse() {
                    let _ = parser.parse_type_data(item.index(), &type_data);
                }
            }
        }

        // ソースロケーション情報をパース
        if let Ok(dbi) = pdb.debug_information() {
            let mut modules = dbi.modules()?;
            while let Some(module) = modules.next()? {
                if let Some(info) = pdb.module_info(&module)? {
                    if let Ok(line_program) = info.line_program() {
                        let _ = parser.parse_line_info(line_program);
                    }
                }
            }
        }

        Ok(parser)
    }
    fn parse_symbol(&mut self, symbol: &pdb::Symbol) -> Result<()> {
        match symbol.parse() {
            Ok(SymbolData::Procedure(proc)) => {
                let name = proc.name.to_string();
                let address = proc.offset.offset as u64;
                self.functions.insert(address, name.to_string());
            }
            Ok(SymbolData::Data(data)) => {
                let name = data.name.to_string();
                let address = data.offset.offset as u64;
                self.variables.insert(address, name.to_string());
            }
            Ok(SymbolData::Public(public)) => {
                let name = public.name.to_string();
                let address = public.offset.offset as u64;
                if public.function {
                    self.functions.insert(address, name.to_string());
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn parse_type_data(&mut self, index: TypeIndex, type_data: &TypeData) -> Result<()> {
        let type_info = match type_data {
            TypeData::Primitive(prim) => {
                let name = format!("{:?}", prim.kind);
                let size = match prim.kind {
                    pdb::PrimitiveKind::Char | pdb::PrimitiveKind::UChar | pdb::PrimitiveKind::I8 | pdb::PrimitiveKind::U8 => 1,
                    pdb::PrimitiveKind::Short | pdb::PrimitiveKind::UShort | pdb::PrimitiveKind::I16 | pdb::PrimitiveKind::U16 => 2,
                    pdb::PrimitiveKind::Long | pdb::PrimitiveKind::ULong | pdb::PrimitiveKind::I32 | pdb::PrimitiveKind::U32 | pdb::PrimitiveKind::F32 => 4,
                    pdb::PrimitiveKind::Quad | pdb::PrimitiveKind::UQuad | pdb::PrimitiveKind::I64 | pdb::PrimitiveKind::U64 | pdb::PrimitiveKind::F64 => 8,
                    _ => 0,
                };
                TypeInfo {
                    name: name.clone(),
                    size,
                    kind: TypeKind::Base(BaseType {
                        name,
                        encoding: 0,
                    }),
                }
            }
            TypeData::Class(class_type) => {
                let name = class_type.name.to_string().to_string();
                let size = class_type.size as usize;
                TypeInfo {
                    name,
                    size,
                    kind: TypeKind::Struct { fields: Vec::new() }, // 繝輔ぅ繝ｼ繝ｫ繝峨・邁｡譏灘ｮ溯｣・〒逵∫払
                }
            }
            TypeData::Union(union_type) => {
                let name = union_type.name.to_string().to_string();
                let size = union_type.size as usize;
                TypeInfo {
                    name,
                    size,
                    kind: TypeKind::Union { members: Vec::new() },
                }
            }
            TypeData::Pointer(ptr_type) => {
                TypeInfo {
                    name: format!("*{:?}", ptr_type.underlying_type),
                    size: 8,
                    kind: TypeKind::Pointer(Box::new(TypeInfo {
                        name: "void".to_string(),
                        size: 0,
                        kind: TypeKind::Unknown,
                    })),
                }
            }
            TypeData::Array(array_type) => {
                let length = array_type.dimensions.first().copied().unwrap_or(0) as usize;
                TypeInfo {
                    name: format!("[{:?}; {}]", array_type.element_type, length),
                    size: length,
                    kind: TypeKind::Array {
                        element_type: Box::new(TypeInfo {
                            name: "unknown".to_string(),
                            size: 1,
                            kind: TypeKind::Unknown,
                        }),
                        length,
                    },
                }
            }
            _ => {
                TypeInfo {
                    name: format!("unknown_type_{:?}", index),
                    size: 0,
                    kind: TypeKind::Unknown,
                }
            }
        };
        self.types.insert(index.0, type_info);
        Ok(())
    }
    pub fn get_function_name(&self, address: u64) -> Option<&str> {
        self.functions.get(&address).map(|s| s.as_str())
    }
    pub fn get_variable_name(&self, address: u64) -> Option<&str> {
        self.variables.get(&address).map(|s| s.as_str())
    }
    pub fn functions(&self) -> &HashMap<u64, String> {
        &self.functions
    }
    pub fn variables(&self) -> &HashMap<u64, String> {
        &self.variables
    }
    pub fn get_type_info(&self, type_index: u32) -> Option<&TypeInfo> {
        self.types.get(&type_index)
    }
    pub fn types(&self) -> &HashMap<u32, TypeInfo> {
        &self.types
    }

    pub fn get_source_location(&self, address: u64) -> Option<&(String, u32)> {
        self.line_info.get(&address)
    }

    fn parse_line_info(&mut self, line_program: pdb::LineProgram) -> Result<()> {
        let mut lines = line_program.lines();
        while let Some(line_info) = lines.next()? {
            let file_info = line_program.get_file_info(line_info.file_index)?;
            let file_name = file_info.name.to_string().to_string();
            let address = line_info.offset.offset as u64;
            let line_number = line_info.line_start;

            self.line_info.insert(address, (file_name, line_number));
        }
        Ok(())
    }
}
