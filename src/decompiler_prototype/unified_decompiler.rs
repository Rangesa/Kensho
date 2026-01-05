/// Unified decompiler combining caching, detail levels, and automatic offset calculation
/// Consolidates decompile_function_native, decompile_function_cached, and analyze_function_detail

use super::parallel_analyzer::*;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Detail level for decompilation output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailLevel {
    /// Basic statistics only (lightweight, fast)
    Basic,
    /// Full details including type inference and optional disassembly (detailed, slower)
    Full,
}

/// Disassembly line information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyLine {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
}

/// Type inference binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeBinding {
    pub varnode: String,
    pub inferred_type: String,
}

/// Unified decompilation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedDecompileResult {
    // Always included (basic level)
    pub function_address: u64,
    pub pcode_count: usize,
    pub block_count: usize,
    pub loop_count: usize,
    pub control_structure: String,

    // detail_level=full only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly: Option<Vec<DisassemblyLine>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_inference: Option<Vec<TypeBinding>>,

    // Cache information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_at: Option<u64>,
}

/// Unified decompiler
pub struct UnifiedDecompiler {
    parallel_decompiler: Arc<ParallelDecompiler>,
}

impl UnifiedDecompiler {
    /// Create new unified decompiler
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        let parallel_decompiler = ParallelDecompiler::new(cache_dir)?;
        Ok(Self {
            parallel_decompiler: Arc::new(parallel_decompiler),
        })
    }

    /// Decompile function with unified interface
    pub fn decompile(
        &self,
        binary_path: &Path,
        function_address: u64,
        file_offset: Option<usize>,
        max_instructions: usize,
        cache: bool,
        detail_level: DetailLevel,
        include_disassembly: bool,
    ) -> Result<UnifiedDecompileResult> {
        // 1. Calculate file offset if not provided
        let offset = if let Some(o) = file_offset {
            o
        } else {
            Self::calculate_file_offset(binary_path, function_address)
                .context("Failed to calculate file offset automatically")?
        };

        // 2. Read binary data
        let binary_data = std::fs::read(binary_path)
            .context("Failed to read binary file")?;

        // 3. Decompile with cache control
        let cached_result = if cache {
            self.parallel_decompiler.decompile_function_cached(
                Some(binary_path),
                &binary_data,
                function_address,
                offset,
                max_instructions,
            )?
        } else {
            self.parallel_decompiler.decompile_function_uncached(
                &binary_data,
                function_address,
                offset,
                max_instructions,
            )?
        };

        // 4. Process detail level
        let (disassembly, type_inference) = match detail_level {
            DetailLevel::Basic => (None, None),
            DetailLevel::Full => {
                // TODO: Extract type inference details from TypeInference
                let types = None; // Placeholder

                // TODO: Extract disassembly from CapstoneTranslator
                // This requires extending CapstoneTranslator to preserve disassembly info
                let disasm = if include_disassembly {
                    None // Placeholder
                } else {
                    None
                };

                (disasm, types)
            }
        };

        Ok(UnifiedDecompileResult {
            function_address: cached_result.address,
            pcode_count: cached_result.pcode_count,
            block_count: cached_result.block_count,
            loop_count: cached_result.loop_count,
            control_structure: cached_result.control_structure,
            disassembly,
            type_inference,
            cached_at: Some(cached_result.cached_at),
        })
    }

    /// Calculate file offset from virtual address (PE/ELF support)
    fn calculate_file_offset(binary_path: &Path, address: u64) -> Result<usize> {
        use goblin::Object;

        let buffer = std::fs::read(binary_path)?;
        let object = Object::parse(&buffer)?;

        match object {
            Object::PE(pe) => {
                // VA → RVA → File Offset
                let image_base = pe.image_base as u64;
                let rva = address.checked_sub(image_base)
                    .ok_or_else(|| anyhow!("Address 0x{:X} is below image base 0x{:X}", address, image_base))?;

                for section in pe.sections {
                    let section_va = section.virtual_address as u64;
                    let section_size = section.virtual_size as u64;

                    if rva >= section_va && rva < section_va + section_size {
                        let offset_in_section = rva - section_va;
                        let file_offset = section.pointer_to_raw_data as u64 + offset_in_section;
                        return Ok(file_offset as usize);
                    }
                }

                Err(anyhow!("Address 0x{:X} (RVA 0x{:X}) not found in any PE section", address, rva))
            }
            Object::Elf(elf) => {
                // VA → File Offset (Program Header based)
                for ph in elf.program_headers {
                    if address >= ph.p_vaddr && address < ph.p_vaddr + ph.p_memsz {
                        let offset_in_segment = address - ph.p_vaddr;
                        let file_offset = ph.p_offset + offset_in_segment;
                        return Ok(file_offset as usize);
                    }
                }

                Err(anyhow!("Address 0x{:X} not found in any ELF segment", address))
            }
            _ => Err(anyhow!("Unsupported binary format (only PE and ELF are supported)")),
        }
    }
}
