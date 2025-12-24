use anyhow::{Context, Result};
use goblin::{Object, pe::PE, elf::Elf, mach::Mach};
use std::fs;
use std::path::Path;

pub struct BinaryAnalyzer {
    // 将来的にキャッシュ機構などを追加
}

impl BinaryAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    /// バイナリファイルの基本情報を解析
    pub async fn analyze_binary(&self, path: &str) -> Result<String> {
        let path = Path::new(path);
        let buffer = fs::read(path)
            .with_context(|| format!("Failed to read binary: {}", path.display()))?;

        let object = Object::parse(&buffer)
            .with_context(|| "Failed to parse binary format")?;

        let mut output = String::new();
        output.push_str(&format!("=== Binary Analysis: {} ===\n\n", path.display()));

        match object {
            Object::Elf(elf) => {
                output.push_str(&self.analyze_elf(&elf)?);
            }
            Object::PE(pe) => {
                output.push_str(&self.analyze_pe(&pe)?);
            }
            Object::Mach(mach) => {
                output.push_str(&self.analyze_mach(&mach)?);
            }
            Object::Archive(_) => {
                output.push_str("Format: Archive (.a)\n");
                output.push_str("Note: Archive files contain multiple object files\n");
            }
            Object::Unknown(magic) => {
                output.push_str(&format!("Format: Unknown (magic: 0x{:x})\n", magic));
            }
        }

        Ok(output)
    }

    fn analyze_elf(&self, elf: &Elf) -> Result<String> {
        let mut output = String::new();
        
        output.push_str("Format: ELF (Executable and Linkable Format)\n");
        
        // アーキテクチャ
        let arch = match elf.header.e_machine {
            0x03 => "x86 (32-bit)",
            0x3E => "x86-64 (64-bit)",
            0x28 => "ARM",
            0xB7 => "AArch64 (ARM64)",
            0x08 => "MIPS",
            0xF3 => "RISC-V",
            _ => "Unknown",
        };
        output.push_str(&format!("Architecture: {} (0x{:x})\n", arch, elf.header.e_machine));

        // エンディアン
        let endian = if elf.little_endian { "Little Endian" } else { "Big Endian" };
        output.push_str(&format!("Endianness: {}\n", endian));

        // ビット幅
        let bits = if elf.is_64 { "64-bit" } else { "32-bit" };
        output.push_str(&format!("Bits: {}\n", bits));

        // エントリポイント
        output.push_str(&format!("Entry Point: 0x{:x}\n", elf.header.e_entry));

        // タイプ
        let etype = match elf.header.e_type {
            1 => "Relocatable",
            2 => "Executable",
            3 => "Shared Object",
            4 => "Core Dump",
            _ => "Unknown",
        };
        output.push_str(&format!("Type: {}\n", etype));

        // セクション数
        output.push_str(&format!("\nSections: {}\n", elf.section_headers.len()));
        for (i, section) in elf.section_headers.iter().take(10).enumerate() {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                output.push_str(&format!(
                    "  [{}] {} (0x{:x}, size: {} bytes)\n",
                    i, name, section.sh_addr, section.sh_size
                ));
            }
        }

        // シンボル
        output.push_str(&format!("\nSymbols: {}\n", elf.syms.len()));
        for (i, sym) in elf.syms.iter().take(10).enumerate() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    output.push_str(&format!(
                        "  [{}] {} (0x{:x})\n",
                        i, name, sym.st_value
                    ));
                }
            }
        }

        Ok(output)
    }

    fn analyze_pe(&self, pe: &PE) -> Result<String> {
        let mut output = String::new();
        
        output.push_str("Format: PE (Portable Executable)\n");

        // アーキテクチャ
        let arch = match pe.header.coff_header.machine {
            0x14c => "x86 (32-bit)",
            0x8664 => "x86-64 (64-bit)",
            0x1c0 => "ARM",
            0xaa64 => "ARM64",
            _ => "Unknown",
        };
        output.push_str(&format!("Architecture: {} (0x{:x})\n", arch, pe.header.coff_header.machine));

        // エントリポイント
        if let Some(optional_header) = &pe.header.optional_header {
            let entry = optional_header.standard_fields.address_of_entry_point;
            let image_base = optional_header.windows_fields.image_base;
            output.push_str(&format!("Entry Point: 0x{:x}\n", entry));
            output.push_str(&format!("Image Base: 0x{:x}\n", image_base));
        }

        // セクション
        output.push_str(&format!("\nSections: {}\n", pe.sections.len()));
        for (i, section) in pe.sections.iter().enumerate() {
            let name = String::from_utf8_lossy(&section.name);
            output.push_str(&format!(
                "  [{}] {} (0x{:x}, size: {} bytes)\n",
                i,
                name.trim_end_matches('\0'),
                section.virtual_address,
                section.virtual_size
            ));
        }

        // インポート
        output.push_str(&format!("\nImports: {}\n", pe.imports.len()));
        for (i, import) in pe.imports.iter().take(10).enumerate() {
            output.push_str(&format!("  [{}] {} ({})\n", i, import.name, import.dll));
        }

        // エクスポート
        if let Some(exports) = &pe.exports {
            output.push_str(&format!("\nExports: {}\n", exports.len()));
            for (i, export) in exports.iter().take(10).enumerate() {
                if let Some(name) = &export.name {
                    output.push_str(&format!("  [{}] {}\n", i, name));
                }
            }
        }

        Ok(output)
    }

    fn analyze_mach(&self, mach: &Mach) -> Result<String> {
        let mut output = String::new();
        
        output.push_str("Format: Mach-O (macOS/iOS)\n");

        match mach {
            Mach::Binary(macho) => {
                // アーキテクチャ
                let arch = match macho.header.cputype {
                    0x7 => "x86 (32-bit)",
                    0x1000007 => "x86-64 (64-bit)",
                    0xc => "ARM",
                    0x100000c => "ARM64",
                    _ => "Unknown",
                };
                output.push_str(&format!("Architecture: {} (0x{:x})\n", arch, macho.header.cputype));

                // エントリポイント
                if let Some(entry_point) = macho.entry {
                    output.push_str(&format!("Entry Point: 0x{:x}\n", entry_point));
                }

                // セグメント
                output.push_str(&format!("\nSegments: {}\n", macho.segments.len()));
                for (i, segment) in macho.segments.iter().take(10).enumerate() {
                    if let Ok(name) = segment.name() {
                        output.push_str(&format!(
                            "  [{}] {} (0x{:x})\n",
                            i, name, segment.vmaddr
                        ));
                    }
                }
            }
            Mach::Fat(_) => {
                output.push_str("Type: Universal Binary (Fat Mach-O)\n");
            }
        }

        Ok(output)
    }

    /// 逆アセンブル実行
    pub async fn disassemble(&self, path: &str, address: &str, count: usize) -> Result<String> {
        use crate::disassembler::Disassembler;
        
        let disasm = Disassembler::new(path)?;
        let addr = if address.starts_with("0x") {
            u64::from_str_radix(&address[2..], 16)?
        } else {
            address.parse()?
        };
        
        disasm.disassemble(addr, count)
    }

    /// 関数検出
    pub async fn find_functions(&self, path: &str) -> Result<String> {
        let path = Path::new(path);
        let buffer = fs::read(path)?;
        let object = Object::parse(&buffer)?;

        let mut output = String::new();
        output.push_str("=== Functions ===\n\n");

        match object {
            Object::Elf(elf) => {
                for sym in &elf.syms {
                    if sym.st_type() == 2 {  // STT_FUNC
                        if let Some(name) = elf.strtab.get_at(sym.st_name) {
                            if !name.is_empty() {
                                output.push_str(&format!(
                                    "0x{:016x}  {}  (size: {} bytes)\n",
                                    sym.st_value, name, sym.st_size
                                ));
                            }
                        }
                    }
                }
            }
            Object::PE(pe) => {
                if let Some(exports) = &pe.exports {
                    for export in exports {
                        if let Some(name) = &export.name {
                            output.push_str(&format!(
                                "0x{:08x}  {}\n",
                                export.rva, name
                            ));
                        }
                    }
                }
            }
            _ => {
                output.push_str("Function detection not yet implemented for this format\n");
            }
        }

        Ok(output)
    }

    /// 簡易デコンパイル
    pub async fn decompile_function(&self, path: &str, function_name: &str) -> Result<String> {
        use crate::decompiler::Decompiler;
        
        let decompiler = Decompiler::new(path)?;
        decompiler.decompile(function_name)
    }

    /// 文字列抽出
    pub async fn find_strings(&self, path: &str, min_length: usize) -> Result<String> {
        let buffer = fs::read(path)?;
        let mut output = String::new();
        output.push_str("=== Strings ===\n\n");

        let mut current_string = Vec::new();
        let mut offset = 0;

        for (i, &byte) in buffer.iter().enumerate() {
            if byte >= 0x20 && byte <= 0x7E {
                if current_string.is_empty() {
                    offset = i;
                }
                current_string.push(byte);
            } else {
                if current_string.len() >= min_length {
                    let s = String::from_utf8_lossy(&current_string);
                    output.push_str(&format!("0x{:08x}: {}\n", offset, s));
                }
                current_string.clear();
            }
        }

        Ok(output)
    }

    /// インポート解析
    pub async fn analyze_imports(&self, path: &str) -> Result<String> {
        let buffer = fs::read(path)?;
        let object = Object::parse(&buffer)?;

        let mut output = String::new();
        output.push_str("=== Imports ===\n\n");

        match object {
            Object::Elf(elf) => {
                for sym in &elf.dynsyms {
                    if sym.st_bind() == 1 && sym.st_shndx == 0 {  // Global undefined
                        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                            if !name.is_empty() {
                                output.push_str(&format!("{}\n", name));
                            }
                        }
                    }
                }
            }
            Object::PE(pe) => {
                for import in &pe.imports {
                    output.push_str(&format!("{} (from {})\n", import.name, import.dll));
                }
            }
            _ => {
                output.push_str("Import analysis not yet implemented for this format\n");
            }
        }

        Ok(output)
    }
}
