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
    
    // エントロピー・パッキング分析結果
    pub entropy_analysis: Option<EntropyAnalysis>,
}

#[derive(Debug, Serialize)]
pub struct EntropyAnalysis {
    pub average_entropy: f64,
    pub is_packed: bool,
    pub packed_score: f64, // 0.0 - 1.0 (パッキングの確信度)
    pub suspicious_sections: Vec<String>,
}

#[derive(Debug, Serialize, Clone, Copy)]
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
    pub entropy: f64, // 追加: 0.0 - 8.0
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

        let entropy_analysis = self.analyze_entropy_summary(path, &format, &architecture, &stats).ok();

        Ok(BinarySummary {
            file_path: path_obj.display().to_string(),
            file_size: metadata.len(),
            format,
            architecture,
            entry_point,
            stats,
            entropy_analysis,
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

    /// パッキング解析（セクションベース）
    fn analyze_entropy_summary(
        &self,
        path: &str,
        _format: &str,
        _arch: &str,
        stats: &BinaryStats,
    ) -> Result<EntropyAnalysis> {
        // セクション情報を取得（ここでエントロピーも計算される）
        let sections = self.extract_sections(path)?;
        
        let mut suspicious_sections = Vec::new();
        let mut total_entropy = 0.0;
        let mut weighted_entropy = 0.0;
        let mut total_size = 0;
        
        for section in &sections {
            total_entropy += section.entropy;
            
            // 加重平均用
            weighted_entropy += section.entropy * (section.size as f64);
            total_size += section.size;
            
            // 判定基準: エントロピー > 7.2 (かなり高い/圧縮レベル)
            // かつ、名前が標準的でない、またはサイズが大きい
            if section.entropy > 7.2 && section.size > 1024 {
                suspicious_sections.push(section.name.clone());
            } else if section.entropy > 6.8 && section.name == ".std" {
                 // ユーザー報告の特異なケース対応
                 suspicious_sections.push(section.name.clone());
            }
        }
        
        let _average_entropy = if !sections.is_empty() {
            total_entropy / sections.len() as f64
        } else {
            0.0
        };
        
        let global_weighted_entropy = if total_size > 0 {
            weighted_entropy / total_size as f64
        } else {
            0.0
        };

        // パッキング判定スコア (ヒューリスティック)
        let mut packed_score = 0.0;
        
        // 1. 全体のエントロピーが高い
        if global_weighted_entropy > 6.8 { packed_score += 0.4; }
        if global_weighted_entropy > 7.2 { packed_score += 0.4; }
        
        // 2. インポート関数が極端に少ない (パッカーの特徴)
        if stats.import_count < 5 && stats.function_count > 0 {
            packed_score += 0.3;
        }

        // 3. 怪しいセクションが存在するか
        if !suspicious_sections.is_empty() {
            packed_score += 0.3;
        }
        
        // 4. セクション名異常 (.stdなど)
        if suspicious_sections.iter().any(|s| s.starts_with(".std")) {
             packed_score += 0.2;
        }

        let is_packed = packed_score >= 0.5;

        Ok(EntropyAnalysis {
            average_entropy: global_weighted_entropy, // 単純平均より加重平均の方が実態に近い
            is_packed,
            packed_score: if packed_score > 1.0 { 1.0 } else { packed_score },
            suspicious_sections,
        })

    }

    fn extract_sections(&self, path: &str) -> Result<Vec<SectionInfo>> {
        let buffer = fs::read(path)?;
        let object = Object::parse(&buffer)?;
        let mut sections = Vec::new();

        match object {
            Object::Elf(elf) => {
                for (i, section) in elf.section_headers.iter().enumerate() {
                    if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                        // エントロピー計算
                        let start = section.sh_offset as usize;
                        let size = section.sh_size as usize;
                        let entropy = if start + size <= buffer.len() {
                            Self::calculate_entropy(&buffer[start..start + size])
                        } else {
                            0.0
                        };

                        sections.push(SectionInfo {
                            index: i,
                            name: name.to_string(),
                            address: section.sh_addr,
                            size: section.sh_size,
                            section_type: format!("{:?}", section.sh_type),
                            entropy,
                        });
                    }
                }
            }
            Object::PE(pe) => {
                for (i, section) in pe.sections.iter().enumerate() {
                    let name = String::from_utf8_lossy(&section.name)
                        .trim_end_matches('\0')
                        .to_string();
                    
                    // エントロピー計算
                    let start = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    let entropy = if start + size <= buffer.len() {
                        Self::calculate_entropy(&buffer[start..start + size])
                    } else {
                        0.0
                    };

                    sections.push(SectionInfo {
                        index: i,
                        name,
                        address: section.virtual_address as u64,
                        size: section.virtual_size as u64,
                        section_type: "PE_SECTION".to_string(),
                        entropy,
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

    /// Shannon Entropyを計算 (0.0 - 8.0)
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequencies = [0usize; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }

        let total = data.len() as f64;
        let mut entropy = 0.0;

        for &count in frequencies.iter() {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}
