use gimli::{
    Dwarf, Unit, DebuggingInformationEntry, AttributeValue, Reader, EndianSlice, RunTimeEndian, UnitOffset, ReaderOffset
};
use anyhow::{Result, Context};
use std::collections::HashMap;
use super::{TypeInfo, TypeKind, BaseType, StructField, UnionMember};
pub struct DwarfSymbolParser {
    functions: HashMap<u64, String>,
    variables: HashMap<u64, String>,
    types: HashMap<u64, TypeInfo>,
    line_info: HashMap<u64, (String, u32)>,
    // 型参照解決のための中間データ
    type_refs: HashMap<u64, u64>, // オフセット -> 参照先型のオフセット
}
impl DwarfSymbolParser {
    pub fn parse_from_elf(binary_data: &[u8]) -> Result<Self> {
        use object::{Object, ObjectSection};

        let obj_file = object::File::parse(binary_data)
            .context("Failed to parse ELF binary")?;

        let endian = if obj_file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        let load_section = |id: gimli::SectionId| -> Result<&[u8]> {
            let section_name = id.name();
            if let Some(section) = obj_file.section_by_name(section_name) {
                Ok(section.data().unwrap_or(&[]))
            } else {
                Ok(&[])
            }
        };

        let debug_abbrev = load_section(gimli::SectionId::DebugAbbrev)?;
        let debug_info = load_section(gimli::SectionId::DebugInfo)?;
        let debug_str = load_section(gimli::SectionId::DebugStr)?;
        let debug_line = load_section(gimli::SectionId::DebugLine)?;

        let dwarf = Dwarf::load(|section| -> Result<_, gimli::Error> {
            let data = match section {
                gimli::SectionId::DebugAbbrev => debug_abbrev,
                gimli::SectionId::DebugInfo => debug_info,
                gimli::SectionId::DebugStr => debug_str,
                gimli::SectionId::DebugLine => debug_line,
                _ => &[],
            };
            Ok(EndianSlice::new(data, endian))
        })?;

        let mut parser = Self {
            functions: HashMap::new(),
            variables: HashMap::new(),
            types: HashMap::new(),
            line_info: HashMap::new(),
            type_refs: HashMap::new(),
        };

        // 1パス目: 基本的な型情報とシンボルを収集
        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            parser.parse_unit(&dwarf, header)?;
        }

        // 行番号情報をパース
        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            if let Some(program) = unit.line_program.clone() {
                parser.parse_line_program(&dwarf, &unit, program)?;
            }
        }

        Ok(parser)
    }
    fn parse_unit<R: Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        header: gimli::UnitHeader<R>
    ) -> Result<()> {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();

        while let Some((_, entry)) = entries.next_dfs()? {
            match entry.tag() {
                gimli::DW_TAG_subprogram => {
                    self.parse_function(dwarf, &unit, entry)?;
                }
                gimli::DW_TAG_variable => {
                    self.parse_variable(dwarf, &unit, entry)?;
                }
                gimli::DW_TAG_base_type |
                gimli::DW_TAG_structure_type |
                gimli::DW_TAG_union_type |
                gimli::DW_TAG_pointer_type |
                gimli::DW_TAG_array_type |
                gimli::DW_TAG_typedef => {
                    let offset = entry.offset();
                    let _ = self.parse_type_entry(dwarf, &unit, entry, offset);
                }
                _ => {}
            }
        }

        Ok(())
    }
    fn parse_function<R: Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>
    ) -> Result<()> {
        let name = if let Some(attr) = entry.attr(gimli::DW_AT_name)? {
            match attr.value() {
                AttributeValue::DebugStrRef(offset) => {
                    let name_str = dwarf.debug_str.get_str(offset)?;
                    let bytes = name_str.to_slice()?;
                    String::from_utf8_lossy(&bytes).to_string()
                }
                AttributeValue::String(s) => {
                    let bytes = s.to_slice()?;
                    String::from_utf8_lossy(&bytes).to_string()
                }
                _ => return Ok(()),
            }
        } else {
            return Ok(());
        };

        if let Some(attr) = entry.attr(gimli::DW_AT_low_pc)? {
            if let AttributeValue::Addr(addr) = attr.value() {
                self.functions.insert(addr, name);
            }
        }

        Ok(())
    }
    fn parse_variable<R: Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>
    ) -> Result<()> {
        let name = if let Some(attr) = entry.attr(gimli::DW_AT_name)? {
            match attr.value() {
                AttributeValue::DebugStrRef(offset) => {
                    let name_str = dwarf.debug_str.get_str(offset)?;
                    let bytes = name_str.to_slice()?;
                    String::from_utf8_lossy(&bytes).to_string()
                }
                AttributeValue::String(s) => {
                    let bytes = s.to_slice()?;
                    String::from_utf8_lossy(&bytes).to_string()
                }
                _ => return Ok(()),
            }
        } else {
            return Ok(());
        };

        if let Some(attr) = entry.attr(gimli::DW_AT_low_pc)? {
            if let AttributeValue::Addr(addr) = attr.value() {
                self.variables.insert(addr, name);
            }
        }

        Ok(())
    }
    fn parse_type_entry<R: Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
        offset: UnitOffset<R::Offset>
    ) -> Result<()> {
        let name = if let Some(attr) = entry.attr(gimli::DW_AT_name)? {
            match attr.value() {
                AttributeValue::DebugStrRef(str_offset) => {
                    let name_str = dwarf.debug_str.get_str(str_offset)?;
                    let bytes = name_str.to_slice()?;
                    String::from_utf8_lossy(&bytes).to_string()
                }
                AttributeValue::String(s) => {
                    let bytes = s.to_slice()?;
                    String::from_utf8_lossy(&bytes).to_string()
                }
                _ => String::new(),
            }
        } else {
            format!("anon_type_{:x}", offset.0.into_u64())
        };

        let size = if let Some(attr) = entry.attr(gimli::DW_AT_byte_size)? {
            match attr.value() {
                AttributeValue::Udata(s) => s as usize,
                AttributeValue::Data1(s) => s as usize,
                AttributeValue::Data2(s) => s as usize,
                AttributeValue::Data4(s) => s as usize,
                _ => 0,
            }
        } else {
            0
        };
        let kind = match entry.tag() {
            gimli::DW_TAG_base_type => {
                let encoding = if let Some(attr) = entry.attr(gimli::DW_AT_encoding)? {
                    match attr.value() {
                        AttributeValue::Encoding(enc) => enc.0,
                        AttributeValue::Data1(enc) => enc,
                        _ => 0,
                    }
                } else {
                    0
                };
                TypeKind::Base(BaseType {
                    name: name.clone(),
                    encoding,
                })
            }
            gimli::DW_TAG_structure_type => {
                TypeKind::Struct { fields: Vec::new() }
            }
            gimli::DW_TAG_union_type => {
                TypeKind::Union { members: Vec::new() }
            }
            gimli::DW_TAG_pointer_type => {
                TypeKind::Pointer(Box::new(TypeInfo {
                    name: "void".to_string(),
                    size: 8,
                    kind: TypeKind::Unknown,
                }))
            }
            gimli::DW_TAG_array_type => {
                TypeKind::Array {
                    element_type: Box::new(TypeInfo {
                        name: "unknown".to_string(),
                        size: 1,
                        kind: TypeKind::Unknown,
                    }),
                    length: size,
                }
            }
            _ => TypeKind::Unknown,
        };
        let type_info = TypeInfo { name, size, kind };
        let offset_val = offset.0.into_u64();
        self.types.insert(offset_val, type_info);
        Ok(())
    }
    fn parse_line_program<R: Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        incomplete_program: gimli::IncompleteLineProgram<R>
    ) -> Result<()> {
        let (program, sequences) = incomplete_program.sequences()?;

        for sequence in &sequences {
            let mut rows = program.resume_from(sequence);

            while let Some((header, row)) = rows.next_row()? {
                if let Some(file_entry) = row.file(header) {
                    let path_attr = file_entry.path_name();
                    let path_str = dwarf.attr_string(unit, path_attr)?;
                    let path = path_str.to_string_lossy()?.to_string();

                    let full_path: String = if let Some(dir_attr) = file_entry.directory(header) {
                        let dir_str = dwarf.attr_string(unit, dir_attr)?;
                        let dir = dir_str.to_string_lossy()?.to_string();
                        format!("{}/{}", dir, path)
                    } else {
                        path
                    };

                    if let Some(line) = row.line() {
                        let address = row.address();
                        self.line_info.insert(address, (full_path, line.get() as u32));
                    }
                }
            }
        }

        Ok(())
    }
    pub fn get_function_name(&self, address: u64) -> Option<&str> {
        self.functions.get(&address).map(|s| s.as_str())
    }
    pub fn get_variable_name(&self, address: u64) -> Option<&str> {
        self.variables.get(&address).map(|s| s.as_str())
    }
    pub fn get_source_location(&self, address: u64) -> Option<&(String, u32)> {
        self.line_info.get(&address)
    }
    pub fn functions(&self) -> &HashMap<u64, String> {
        &self.functions
    }
    pub fn variables(&self) -> &HashMap<u64, String> {
        &self.variables
    }
    pub fn get_type_info(&self, type_id: u64) -> Option<&TypeInfo> {
        self.types.get(&type_id)
    }
    pub fn types(&self) -> &HashMap<u64, TypeInfo> {
        &self.types
    }
}
