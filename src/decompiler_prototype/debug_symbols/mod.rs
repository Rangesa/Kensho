mod dwarf;
mod pdb;

pub use dwarf::DwarfSymbolParser;
pub use pdb::PdbSymbolParser;
pub trait DebugSymbolProvider {
    fn get_function_name(&self, address: u64) -> Option<&str>;
    fn get_variable_name(&self, address: u64) -> Option<&str>;
    fn get_source_location(&self, address: u64) -> Option<SourceLocation>;
    fn get_type_info(&self, type_id: u64) -> Option<&TypeInfo>;
}

#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub size: usize,
    pub kind: TypeKind,
}

#[derive(Debug, Clone)]
pub enum TypeKind {
    Base(BaseType),
    Pointer(Box<TypeInfo>),
    Array { element_type: Box<TypeInfo>, length: usize },
    Struct { fields: Vec<StructField> },
    Union { members: Vec<UnionMember> },
    Unknown,
}
#[derive(Debug, Clone)]
pub struct BaseType {
    pub name: String,
    pub encoding: u8,
}
#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub offset: usize,
    pub type_info: TypeInfo,
}
#[derive(Debug, Clone)]
pub struct UnionMember {
    pub name: String,
    pub offset: usize,
    pub type_info: TypeInfo,
}
impl DebugSymbolProvider for DwarfSymbolParser {
    fn get_function_name(&self, address: u64) -> Option<&str> {
        self.get_function_name(address)
    }
    fn get_variable_name(&self, address: u64) -> Option<&str> {
        self.get_variable_name(address)
    }
    fn get_source_location(&self, address: u64) -> Option<SourceLocation> {
        self.get_source_location(address).map(|(file, line)| {
            SourceLocation {
                file: file.clone(),
                line: *line,
                column: None,
            }
        })
    }

    fn get_type_info(&self, type_id: u64) -> Option<&TypeInfo> {
        self.get_type_info(type_id)
    }
}
impl DebugSymbolProvider for PdbSymbolParser {
    fn get_function_name(&self, address: u64) -> Option<&str> {
        self.get_function_name(address)
    }
    fn get_variable_name(&self, address: u64) -> Option<&str> {
        self.get_variable_name(address)
    }
    fn get_source_location(&self, address: u64) -> Option<SourceLocation> {
        self.get_source_location(address).map(|(file, line)| {
            SourceLocation {
                file: file.clone(),
                line: *line,
                column: None,
            }
        })
    }
    fn get_type_info(&self, type_id: u64) -> Option<&TypeInfo> {
        // PDB uses u32 for type indices
        self.get_type_info(type_id as u32)
    }
}
