//! Robust Binary Loader
//!
//! 堅牢なバイナリローダー - 破損したPEヘッダやマルウェアの特殊な形式にも対応
//!
//! 機能:
//! - goblinによる標準的なパース
//! - パース失敗時のフォールバック処理
//! - 手動PEヘッダーパース
//! - 部分的な情報抽出
//! - 詳細なエラーレポート

use anyhow::{Context, Result, anyhow};
use goblin::pe::PE;
use goblin::Object;
use std::fs;
use std::path::Path;

pub mod pe_manual;
pub mod error_recovery;

/// バイナリファイルの情報
#[derive(Debug, Clone)]
pub struct BinaryInfo {
    /// ファイルパス
    pub path: String,
    /// ファイルサイズ
    pub size: usize,
    /// バイナリタイプ
    pub binary_type: BinaryType,
    /// エントリーポイント
    pub entry_point: Option<u64>,
    /// セクション情報
    pub sections: Vec<SectionInfo>,
    /// インポート関数
    pub imports: Vec<ImportInfo>,
    /// エクスポート関数
    pub exports: Vec<ExportInfo>,
    /// パース状態
    pub parse_status: ParseStatus,
}

/// バイナリタイプ
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryType {
    PE32,
    PE64,
    ELF32,
    ELF64,
    MachO32,
    MachO64,
    Unknown,
}

/// セクション情報
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_data_offset: u64,
    pub raw_data_size: u64,
    pub characteristics: u32,
}

/// インポート情報
#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub dll: String,
    pub function: String,
    pub ordinal: Option<u16>,
}

/// エクスポート情報
#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
}

/// パース状態
#[derive(Debug, Clone)]
pub enum ParseStatus {
    /// 完全成功
    Success,
    /// 部分的成功（一部のデータが欠損）
    Partial { warnings: Vec<String> },
    /// フォールバックパーサーで解析
    Fallback { reason: String },
    /// 失敗
    Failed { error: String },
}

/// 堅牢なバイナリローダー
pub struct RobustBinaryLoader {
    /// フォールバックパーサーを使用するか
    use_fallback: bool,
    /// 詳細ログを出力するか
    verbose: bool,
}

impl RobustBinaryLoader {
    pub fn new() -> Self {
        Self {
            use_fallback: true,
            verbose: false,
        }
    }

    /// フォールバックパーサーの使用を設定
    pub fn set_fallback(&mut self, enable: bool) -> &mut Self {
        self.use_fallback = enable;
        self
    }

    /// 詳細ログの出力を設定
    pub fn set_verbose(&mut self, enable: bool) -> &mut Self {
        self.verbose = enable;
        self
    }

    /// バイナリファイルを読み込む
    pub fn load<P: AsRef<Path>>(&self, path: P) -> Result<BinaryInfo> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        // ファイル読み込み
        let data = fs::read(path)
            .with_context(|| format!("Failed to read file: {}", path_str))?;

        let size = data.len();

        if self.verbose {
            println!("[BinaryLoader] Loading: {} ({} bytes)", path_str, size);
        }

        // goblinでパースを試みる
        match self.try_goblin_parse(&data, &path_str, size) {
            Ok(info) => {
                if self.verbose {
                    println!("[BinaryLoader] Successfully parsed with goblin");
                }
                Ok(info)
            }
            Err(e) => {
                if self.verbose {
                    println!("[BinaryLoader] Goblin parse failed: {}", e);
                }

                if self.use_fallback {
                    if self.verbose {
                        println!("[BinaryLoader] Attempting fallback parser...");
                    }
                    self.try_fallback_parse(&data, &path_str, size, e.to_string())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// goblinでパースを試みる
    fn try_goblin_parse(&self, data: &[u8], path: &str, size: usize) -> Result<BinaryInfo> {
        let object = Object::parse(data)
            .context("Failed to parse binary with goblin")?;

        match object {
            Object::PE(pe) => self.parse_pe(pe, path, size),
            Object::Elf(elf) => self.parse_elf(elf, path, size),
            Object::Mach(mach) => self.parse_mach(mach, path, size),
            _ => Err(anyhow!("Unsupported binary format")),
        }
    }

    /// PEファイルをパース
    fn parse_pe(&self, pe: PE, path: &str, size: usize) -> Result<BinaryInfo> {
        let binary_type = if pe.is_64 {
            BinaryType::PE64
        } else {
            BinaryType::PE32
        };

        let entry_point = Some(pe.entry as u64);

        // セクション情報を抽出
        let mut sections = Vec::new();
        for section in &pe.sections {
            sections.push(SectionInfo {
                name: String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_string(),
                virtual_address: section.virtual_address as u64,
                virtual_size: section.virtual_size as u64,
                raw_data_offset: section.pointer_to_raw_data as u64,
                raw_data_size: section.size_of_raw_data as u64,
                characteristics: section.characteristics,
            });
        }

        // インポート情報を抽出
        let mut imports = Vec::new();
        if !pe.imports.is_empty() {
            for import in &pe.imports {
                imports.push(ImportInfo {
                    dll: import.dll.to_string(),
                    function: import.name.to_string(),
                    ordinal: Some(import.ordinal as u16),
                });
            }
        }

        // エクスポート情報を抽出
        let mut exports = Vec::new();
        if !pe.exports.is_empty() {
            for export in &pe.exports {
                if let Some(name) = &export.name {
                    exports.push(ExportInfo {
                        name: name.to_string(),
                        address: export.rva as u64,
                        ordinal: 0, // Goblin v0.8 does not have ordinal field for Export
                    });
                }
            }
        }

        Ok(BinaryInfo {
            path: path.to_string(),
            size,
            binary_type,
            entry_point,
            sections,
            imports,
            exports,
            parse_status: ParseStatus::Success,
        })
    }

    /// ELFファイルをパース
    fn parse_elf(&self, elf: goblin::elf::Elf, path: &str, size: usize) -> Result<BinaryInfo> {
        let binary_type = if elf.is_64 {
            BinaryType::ELF64
        } else {
            BinaryType::ELF32
        };

        let entry_point = Some(elf.entry);

        let mut sections = Vec::new();
        for section in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                sections.push(SectionInfo {
                    name: name.to_string(),
                    virtual_address: section.sh_addr,
                    virtual_size: section.sh_size,
                    raw_data_offset: section.sh_offset,
                    raw_data_size: section.sh_size,
                    characteristics: section.sh_flags as u32,
                });
            }
        }

        Ok(BinaryInfo {
            path: path.to_string(),
            size,
            binary_type,
            entry_point,
            sections,
            imports: Vec::new(),
            exports: Vec::new(),
            parse_status: ParseStatus::Success,
        })
    }

    /// Mach-Oファイルをパース
    fn parse_mach(&self, mach: goblin::mach::Mach, path: &str, size: usize) -> Result<BinaryInfo> {
        use goblin::mach::Mach;

        let (binary_type, entry_point) = match mach {
            Mach::Binary(macho) => {
                let bt = if macho.is_64 {
                    BinaryType::MachO64
                } else {
                    BinaryType::MachO32
                };
                (bt, Some(macho.entry as u64))
            }
            Mach::Fat(_) => (BinaryType::Unknown, None),
        };

        Ok(BinaryInfo {
            path: path.to_string(),
            size,
            binary_type,
            entry_point,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            parse_status: ParseStatus::Success,
        })
    }

    /// フォールバックパーサーでパース
    fn try_fallback_parse(&self, data: &[u8], path: &str, size: usize, error: String) -> Result<BinaryInfo> {
        // PEマジックナンバーをチェック
        if data.len() >= 2 && &data[0..2] == b"MZ" {
            if self.verbose {
                println!("[BinaryLoader] Detected PE magic (MZ), attempting manual parse");
            }
            return self.manual_pe_parse(data, path, size, error);
        }

        // ELFマジックナンバーをチェック
        if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
            if self.verbose {
                println!("[BinaryLoader] Detected ELF magic, but manual parser not implemented");
            }
        }

        Err(anyhow!("Fallback parser failed: {}", error))
    }

    /// 手動PEパース
    fn manual_pe_parse(&self, data: &[u8], path: &str, size: usize, original_error: String) -> Result<BinaryInfo> {
        // 簡易的なPEヘッダーパース
        let pe_info = pe_manual::ManualPEParser::parse(data)?;

        Ok(BinaryInfo {
            path: path.to_string(),
            size,
            binary_type: if pe_info.is_64bit { BinaryType::PE64 } else { BinaryType::PE32 },
            entry_point: Some(pe_info.entry_point),
            sections: pe_info.sections.into_iter().map(|s| SectionInfo {
                name: s.name,
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_data_offset: s.raw_offset,
                raw_data_size: s.raw_size,
                characteristics: s.characteristics,
            }).collect(),
            imports: Vec::new(),
            exports: Vec::new(),
            parse_status: ParseStatus::Fallback {
                reason: format!("Goblin parse failed: {}. Used manual PE parser.", original_error),
            },
        })
    }
}

impl Default for RobustBinaryLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_creation() {
        let loader = RobustBinaryLoader::new();
        assert!(loader.use_fallback);
        assert!(!loader.verbose);
    }
}
