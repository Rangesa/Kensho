/// Memory dump management for dynamic analysis
///
/// This module provides functionality to save and load memory dumps from running processes.
/// It supports metadata tracking and validation to ensure dump integrity.

use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use std::path::{Path, PathBuf};
use std::fs;

/// Memory dump metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDumpMetadata {
    /// Original process name
    pub process_name: String,
    /// Process ID at dump time
    pub pid: u32,
    /// Base address in process memory
    pub base_address: u64,
    /// Total size of dumped memory
    pub size: usize,
    /// Timestamp when dump was created (Unix timestamp)
    pub timestamp: u64,
    /// Regions included in the dump
    pub regions: Vec<DumpedRegion>,
}

/// Information about a dumped memory region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpedRegion {
    /// Start address in original process
    pub original_address: u64,
    /// Offset in dump file
    pub dump_offset: usize,
    /// Size of region
    pub size: usize,
    /// Memory protection flags
    pub protection: u32,
}

/// Memory dump file format
/// Structure: [Metadata JSON File][Binary Data File]
///
/// Files are saved as:
/// - {base_path}.dump.json: Metadata
/// - {base_path}.dump.bin: Raw binary data
pub struct MemoryDumpFile {
    metadata_path: PathBuf,
    data_path: PathBuf,
}

impl MemoryDumpFile {
    /// Create new dump file paths
    ///
    /// # Arguments
    /// * `base_path` - Base path without extension (e.g., "C:\\dumps\\region_00")
    ///
    /// # Returns
    /// A MemoryDumpFile with .dump.json and .dump.bin paths
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        let base = base_path.as_ref();
        Self {
            metadata_path: base.with_extension("dump.json"),
            data_path: base.with_extension("dump.bin"),
        }
    }

    /// Save memory dump to disk
    ///
    /// # Arguments
    /// * `metadata` - Metadata about the dump
    /// * `data` - Raw binary data
    ///
    /// # Errors
    /// Returns error if file write fails or serialization fails
    pub fn save(
        &self,
        metadata: &MemoryDumpMetadata,
        data: &[u8],
    ) -> Result<()> {
        // Validate size matches
        if data.len() != metadata.size {
            bail!(
                "Data size mismatch: metadata says {}, but data is {}",
                metadata.size,
                data.len()
            );
        }

        // Save metadata as pretty JSON for human readability
        let json = serde_json::to_string_pretty(metadata)
            .context("Failed to serialize metadata")?;
        fs::write(&self.metadata_path, json)
            .with_context(|| format!("Failed to write metadata file: {:?}", self.metadata_path))?;

        // Save binary data
        fs::write(&self.data_path, data)
            .with_context(|| format!("Failed to write data file: {:?}", self.data_path))?;

        Ok(())
    }

    /// Load memory dump from disk
    ///
    /// # Returns
    /// Tuple of (metadata, binary_data)
    ///
    /// # Errors
    /// Returns error if files don't exist, can't be read, or sizes don't match
    pub fn load(&self) -> Result<(MemoryDumpMetadata, Vec<u8>)> {
        // Load metadata
        let json = fs::read_to_string(&self.metadata_path)
            .with_context(|| format!("Failed to read metadata file: {:?}", self.metadata_path))?;
        let metadata: MemoryDumpMetadata = serde_json::from_str(&json)
            .context("Failed to parse metadata JSON")?;

        // Load binary data
        let data = fs::read(&self.data_path)
            .with_context(|| format!("Failed to read data file: {:?}", self.data_path))?;

        // Validate size
        if data.len() != metadata.size {
            bail!(
                "Data size mismatch: expected {} (from metadata), got {}",
                metadata.size,
                data.len()
            );
        }

        Ok((metadata, data))
    }

    /// Check if both dump files exist
    pub fn exists(&self) -> bool {
        self.metadata_path.exists() && self.data_path.exists()
    }

    /// Delete both dump files
    ///
    /// # Errors
    /// Returns error if deletion fails
    pub fn delete(&self) -> Result<()> {
        if self.metadata_path.exists() {
            fs::remove_file(&self.metadata_path)
                .with_context(|| format!("Failed to delete metadata file: {:?}", self.metadata_path))?;
        }
        if self.data_path.exists() {
            fs::remove_file(&self.data_path)
                .with_context(|| format!("Failed to delete data file: {:?}", self.data_path))?;
        }
        Ok(())
    }

    /// Get metadata file path
    pub fn metadata_path(&self) -> &Path {
        &self.metadata_path
    }

    /// Get data file path
    pub fn data_path(&self) -> &Path {
        &self.data_path
    }
}

/// Helper function to create dump from memory scanner
///
/// This function is only available on Windows
#[cfg(windows)]
pub fn create_dump_from_scanner(
    scanner: &super::super::memory_scanner::MemoryScanner,
    address: u64,
    size: usize,
) -> Result<(MemoryDumpMetadata, Vec<u8>)> {
    use std::time::SystemTime;

    // Read memory from process
    let data = scanner.read_memory(address as usize, size)
        .context("Failed to read process memory")?;

    // Create metadata
    let metadata = MemoryDumpMetadata {
        process_name: scanner.process_info.name.clone(),
        pid: scanner.process_info.pid,
        base_address: address,
        size: data.len(),
        timestamp: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        regions: vec![DumpedRegion {
            original_address: address,
            dump_offset: 0,
            size: data.len(),
            protection: 0, // TODO: Get actual protection flags from VirtualQueryEx
        }],
    };

    Ok((metadata, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_dump_save_and_load() {
        let temp_dir = env::temp_dir();
        let dump_path = temp_dir.join("test_dump");
        let dump_file = MemoryDumpFile::new(&dump_path);

        // Create test data
        let test_data = vec![0x90, 0x90, 0x90, 0xC3]; // NOP NOP NOP RET
        let metadata = MemoryDumpMetadata {
            process_name: "test.exe".to_string(),
            pid: 12345,
            base_address: 0x140000000,
            size: test_data.len(),
            timestamp: 1234567890,
            regions: vec![DumpedRegion {
                original_address: 0x140000000,
                dump_offset: 0,
                size: test_data.len(),
                protection: 0x20, // PAGE_EXECUTE_READ
            }],
        };

        // Save
        dump_file.save(&metadata, &test_data).unwrap();
        assert!(dump_file.exists());

        // Load
        let (loaded_metadata, loaded_data) = dump_file.load().unwrap();
        assert_eq!(loaded_metadata.process_name, metadata.process_name);
        assert_eq!(loaded_metadata.pid, metadata.pid);
        assert_eq!(loaded_metadata.base_address, metadata.base_address);
        assert_eq!(loaded_data, test_data);

        // Cleanup
        dump_file.delete().unwrap();
        assert!(!dump_file.exists());
    }

    #[test]
    fn test_size_validation() {
        let temp_dir = env::temp_dir();
        let dump_path = temp_dir.join("test_dump_invalid");
        let dump_file = MemoryDumpFile::new(&dump_path);

        let test_data = vec![0x90; 100];
        let mut metadata = MemoryDumpMetadata {
            process_name: "test.exe".to_string(),
            pid: 12345,
            base_address: 0x140000000,
            size: 50, // Wrong size!
            timestamp: 1234567890,
            regions: vec![],
        };

        // Save should fail due to size mismatch
        let result = dump_file.save(&metadata, &test_data);
        assert!(result.is_err());

        // Fix size and save
        metadata.size = test_data.len();
        dump_file.save(&metadata, &test_data).unwrap();

        // Cleanup
        dump_file.delete().ok();
    }
}
