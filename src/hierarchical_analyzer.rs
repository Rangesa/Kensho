use anyhow::Result;
use serde::Serialize;
use goblin::Object;
use std::fs;
use std::path::Path;

/// 階層1: バイナリ概要（軽量、文脈最小）
#[derive(Debug, Serialize)]
pub struct BinarySummary {
    pub file_path: String,
    pub file_size: u64,
    pub format: String,
    pub architecture: String,
    pub entry_point: u64,
    
    // 統計のみを保持
    pub stats: BinaryStats,
}

#[derive(Debug, Serialize)]
pub struct BinaryStats {
    pub section_count: usize,
    pub function_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub string_count_estimate: usize,
}

/// 階層2: セクション一覧（ページネーション対応）
#[derive(Debug, Serialize)]
pub struct SectionList {
    pub total_count: usize,
    pub page: usize,
    pub page_size: usize,
    pub sections: Vec<SectionInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub index: usize,
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub section_type: String,
}

/// 階層2: 関数一覧（ページネーション + フィルタリング対応）
#[derive(Debug, Serialize)]
pub struct FunctionList {
    pub total_count: usize,
    pub page: usize,
    pub page_size: usize,
    pub functions: Vec<FunctionInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub section: Option<String>,
}

/// 階層2: 文字列一覧（ページネーション + 長さフィルタ対応）
#[derive(Debug, Serialize)]
pub struct StringList {
    pub total_count: usize,
    pub page: usize,
    pub page_size: usize,
    pub strings: Vec<StringInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringInfo {
    pub address: u64,
    pub value: String,
    pub length: usize,
}

/// 階層2: インポート一覧
#[derive(Debug, Serialize)]
pub struct ImportList {
    pub total_dll_count: usize,
    pub total_import_count: usize,
    pub imports: Vec<ImportInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportInfo {
    pub dll: String,
    pub functions: Vec<String>,
}

/// 階層3: 関数詳細解析（重い、オンデマンド実行）
#[derive(Debug, Serialize)]
pub struct FunctionDetail {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub disassembly: Vec<InstructionInfo>,
    pub decompiled: Option<String>,
    pub cross_references: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct InstructionInfo {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: String,
}

/// 階層型解析エンジン
pub struct HierarchicalAnalyzer {
    // 解析済データのキャッシュ（将来の拡張用）
    cache: std::collections::HashMap<String, CachedBinaryData>,
}

struct CachedBinaryData {
    #[allow(dead_code)]
    object: Vec<u8>,
    parsed: ParsedBinaryCache,
}

struct ParsedBinaryCache {
    functions: Vec<FunctionInfo>,
    #[allow(dead_code)]
    strings: Vec<StringInfo>,
    #[allow(dead_code)]
    sections: Vec<SectionInfo>,
}

impl HierarchicalAnalyzer {
    pub fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
        }
    }

    /// 階層1: 概要を取得（常に軽量）
    pub fn get_summary(&mut self, path: &str) -> Result<BinarySummary> {
        let path_obj = Path::new(path);
        let metadata = fs::metadata(path)?;
        let buffer = fs::read(path)?;
        let object = Object::parse(&buffer)?;

        let (format, architecture, entry_point, stats) = match &object {
            Object::Elf(elf) => {
                let arch = match elf.header.e_machine {
                    0x03 => "x86",
                    0x3E => "x86-64",
                    0x28 => "ARM",
                    0xB7 => "ARM64",
                    _ => "Unknown",
                };
                
                // 統計のみを計算
                let function_count = elf.syms.iter()
                    .filter(|s| s.st_type() == 2)
                    .count();
                
                let stats = BinaryStats {
                    section_count: elf.section_headers.len(),
                    function_count,
                    import_count: elf.dynsyms.len(),
                    export_count: elf.dynsyms.iter()
                        .filter(|s| s.st_bind() == 1 && s.st_shndx != 0)
                        .count(),
                    string_count_estimate: self.estimate_string_count(&buffer),
                };
                
                ("ELF".to_string(), arch.to_string(), elf.header.e_entry, stats)
            }
            Object::PE(pe) => {
                let arch = match pe.header.coff_header.machine {
                    0x14c => "x86",
                    0x8664 => "x86-64",
                    _ => "Unknown",
                };
                
                let entry = pe.header.optional_header
                    .as_ref()
                    .map(|h| h.standard_fields.address_of_entry_point as u64)
                    .unwrap_or(0);
                
                let export_count = pe.exports.len();
                
                let stats = BinaryStats {
                    section_count: pe.sections.len(),
                    function_count: export_count, // PEではエクスポートを関数とみなす（簡易）
                    import_count: pe.imports.len(),
                    export_count,
                    string_count_estimate: self.estimate_string_count(&buffer),
                };
                
                ("PE".to_string(), arch.to_string(), entry, stats)
            }
            _ => {
                let stats = BinaryStats {
                    section_count: 0,
                    function_count: 0,
                    import_count: 0,
                    export_count: 0,
                    string_count_estimate: 0,
                };
                ("Unknown".to_string(), "Unknown".to_string(), 0, stats)
            }
        };

        Ok(BinarySummary {
            file_path: path_obj.display().to_string(),
            file_size: metadata.len(),
            format,
            architecture,
            entry_point,
            stats,
        })
    }

    /// 階層2: 関数一覧（ページネーション対応）
    pub fn list_functions(
        &mut self,
        path: &str,
        page: usize,
        page_size: usize,
        name_filter: Option<&str>,
    ) -> Result<FunctionList> {
        let functions = self.get_or_cache_functions(path)?;
        
        // フィルタリング
        let filtered: Vec<_> = if let Some(filter) = name_filter {
            functions.iter()
                .filter(|f| f.name.contains(filter))
                .cloned()
                .collect()
        } else {
            functions.clone()
        };
        
        let total_count = filtered.len();
        
        // ページネーション
        let start = page * page_size;
        let end = std::cmp::min(start + page_size, total_count);
        let page_data = if start < total_count {
            filtered[start..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(FunctionList {
            total_count,
            page,
            page_size,
            functions: page_data,
        })
    }

    /// 階層2: セクション一覧
    pub fn list_sections(
        &mut self,
        path: &str,
        page: usize,
        page_size: usize,
    ) -> Result<SectionList> {
        let sections = self.get_or_cache_sections(path)?;
        
        let total_count = sections.len();
        let start = page * page_size;
        let end = std::cmp::min(start + page_size, total_count);
        let page_data =  if start < total_count {
            sections[start..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(SectionList {
            total_count,
            page,
            page_size,
            sections: page_data,
        })
    }

    /// 階層2: 文字列一覧
    pub fn list_strings(
        &mut self,
        path: &str,
        page: usize,
        page_size: usize,
        min_length: usize,
    ) -> Result<StringList> {
        let strings = self.get_or_cache_strings(path)?;
        
        // 最小長フィルタ
        let filtered: Vec<_> = strings.iter()
            .filter(|s| s.length >= min_length)
            .cloned()
            .collect();
        
        let total_count = filtered.len();
        let start = page * page_size;
        let end = std::cmp::min(start + page_size, total_count);
        let page_data = if start < total_count {
            filtered[start..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(StringList {
            total_count,
            page,
            page_size,
            strings: page_data,
        })
    }

    /// 階層3: 関数詳細解析
    pub fn analyze_function_detail(
        &mut self,
        path: &str,
        function_address: u64,
    ) -> Result<FunctionDetail> {
        // 特定の関数についてのみ重い処理（逆アセンブル等）を行う
        use crate::disassembler::Disassembler;
        use crate::decompiler::Decompiler;
        
        let functions = self.get_or_cache_functions(path)?;
        let func = functions.iter()
            .find(|f| f.address == function_address)
            .ok_or_else(|| anyhow::anyhow!("Function not found"))?;
        
        // 逆アセンブル（制限付き：100命令まで）
        let disasm = Disassembler::new(path)?;
        let (instructions, _) = disasm.disassemble_function(function_address)?;
        
        let disassembly: Vec<_> = instructions.iter()
            .take(100) // コンテキスト保護のため制限
            .map(|insn| InstructionInfo {
                address: insn.address,
                mnemonic: insn.mnemonic.clone(),
                operands: insn.operands.clone(),
                bytes: format!("{:02x}", insn.size),
            })
            .collect();
        
        // 簡易デコンパイル（オプション）
        let decompiler = Decompiler::new(path)?;
        let decompiled = decompiler.decompile(&format!("0x{:x}", function_address)).ok();
        
        Ok(FunctionDetail {
            address: func.address,
            name: func.name.clone(),
            size: func.size,
            disassembly,
            decompiled,
            cross_references: vec![], // TODO: クロスリファレンス実装
        })
    }

    /// 階層2: インポート一覧
    pub fn list_imports(&mut self, path: &str) -> Result<ImportList> {
        let buffer = fs::read(path)?;
        let object = Object::parse(&buffer)?;

        let mut imports_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        let mut total_import_count = 0;

        if let Object::PE(pe) = &object {
            for import in &pe.imports {
                let functions = imports_map.entry(import.dll.to_string()).or_default();
                functions.push(import.name.to_string());
                total_import_count += 1;
            }
        }
        
        let mut imports_vec: Vec<ImportInfo> = imports_map.into_iter().map(|(dll, functions)| {
            ImportInfo { dll, functions }
        }).collect();

        imports_vec.sort_by_key(|i| i.dll.clone());

        Ok(ImportList {
            total_dll_count: imports_vec.len(),
            total_import_count,
            imports: imports_vec,
        })
    }

    // === キャッシュヘルパー ===

    fn get_or_cache_functions(&mut self, path: &str) -> Result<Vec<FunctionInfo>> {
        if let Some(cached) = self.cache.get(path) {
            return Ok(cached.parsed.functions.clone());
        }
        
        let functions = self.extract_functions(path)?;
        // TODO: キャッシュへの保存
        Ok(functions)
    }

    fn get_or_cache_sections(&mut self, path: &str) -> Result<Vec<SectionInfo>> {
        self.extract_sections(path)
    }

    fn get_or_cache_strings(&mut self, path: &str) -> Result<Vec<StringInfo>> {
        self.extract_strings(path)
    }

    fn extract_functions(&self, path: &str) -> Result<Vec<FunctionInfo>> {
        let buffer = fs::read(path)?;
        let object = Object::parse(&buffer)?;
        let mut functions = Vec::new();

        match object {
            Object::Elf(elf) => {
                for sym in &elf.syms {
                    if sym.st_type() == 2 {  // STT_FUNC
                        if let Some(name) = elf.strtab.get_at(sym.st_name) {
                            if !name.is_empty() {
                                functions.push(FunctionInfo {
                                    address: sym.st_value,
                                    name: name.to_string(),
                                    size: sym.st_size,
                                    section: None,
                                });
                            }
                        }
                    }
                }
            }
            Object::PE(pe) => {
                // エクスポートテーブルから抽出
                for export in &pe.exports {
                    if let Some(name) = &export.name {
                        functions.push(FunctionInfo {
                            address: export.rva as u64,
                            name: name.to_string(),
                            size: 0, // PEではサイズ不明なことが多い
                            section: None,
                        });
                    }
                }
            }
            _ => {}
        }

        Ok(functions)
    }

    fn extract_sections(&self, path: &str) -> Result<Vec<SectionInfo>> {
        let buffer = fs::read(path)?;
        let object = Object::parse(&buffer)?;
        let mut sections = Vec::new();

        match object {
            Object::Elf(elf) => {
                for (i, section) in elf.section_headers.iter().enumerate() {
                    if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                        sections.push(SectionInfo {
                            index: i,
                            name: name.to_string(),
                            address: section.sh_addr,
                            size: section.sh_size,
                            section_type: format!("{:?}", section.sh_type),
                        });
                    }
                }
            }
            Object::PE(pe) => {
                for (i, section) in pe.sections.iter().enumerate() {
                    let name = String::from_utf8_lossy(&section.name)
                        .trim_end_matches('\0')
                        .to_string();
                    sections.push(SectionInfo {
                        index: i,
                        name,
                        address: section.virtual_address as u64,
                        size: section.virtual_size as u64,
                        section_type: "PE_SECTION".to_string(),
                    });
                }
            }
            _ => {}
        }

        Ok(sections)
    }

    fn extract_strings(&self, path: &str) -> Result<Vec<StringInfo>> {
        let buffer = fs::read(path)?;
        let mut strings = Vec::new();
        let mut current_string = Vec::new();
        let mut offset = 0;

        for (i, &byte) in buffer.iter().enumerate() {
            if byte >= 0x20 && byte <= 0x7E {
                if current_string.is_empty() {
                    offset = i;
                }
                current_string.push(byte);
            } else {
                if current_string.len() >= 4 {
                    let s = String::from_utf8_lossy(&current_string).to_string();
                    strings.push(StringInfo {
                        address: offset as u64,
                        value: s,
                        length: current_string.len(),
                    });
                }
                current_string.clear();
            }
        }

        Ok(strings)
    }

    fn estimate_string_count(&self, buffer: &[u8]) -> usize {
        let mut count = 0;
        let mut in_string = false;
        let mut current_len = 0;

        for &byte in buffer {
            if byte >= 0x20 && byte <= 0x7E {
                if !in_string {
                    in_string = true;
                    current_len = 1;
                } else {
                    current_len += 1;
                }
            } else {
                if in_string && current_len >= 4 {
                    count += 1;
                }
                in_string = false;
                current_len = 0;
            }
        }

        count
    }
}
