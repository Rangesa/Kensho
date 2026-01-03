/// Parallel decompiler with caching support
/// Supports multi-core decompilation and intelligent caching

use super::cfg::*;
use super::ssa::*;
use super::optimizer::*;
use super::type_inference::*;
use super::control_flow::*;
use super::capstone_translator::*;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::Xxh3;

/// Hash strategy for cache keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashStrategy {
    /// Metadata-based hash (fast, uses file size + mtime + path)
    Metadata,
    /// Sampling-based hash (header + tail sampling)
    Sampling,
    /// Full file hash (slowest, most accurate)
    Full,
}

/// Decompilation cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileCache {
    /// File hash for cache validation
    pub file_hash: String,
    /// Cached results per function
    pub results: HashMap<u64, CachedFunctionResult>,
}

/// Cached function decompilation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFunctionResult {
    /// Function address
    pub address: u64,
    /// Number of P-code operations
    pub pcode_count: usize,
    /// Number of basic blocks
    pub block_count: usize,
    /// Number of inferred types
    pub type_count: usize,
    /// Number of loops detected
    pub loop_count: usize,
    /// Control structure representation
    pub control_structure: String,
    /// Timestamp when cached
    pub cached_at: u64,
}

/// Parallel decompiler with caching
pub struct ParallelDecompiler {
    /// Cache directory path
    cache_dir: PathBuf,
    /// In-memory cache
    memory_cache: Arc<Mutex<HashMap<String, DecompileCache>>>,
    /// Hash computation strategy
    hash_strategy: HashStrategy,
}

impl ParallelDecompiler {
    /// Create new decompiler with default hash strategy
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        Self::with_strategy(cache_dir, HashStrategy::Metadata)
    }

    /// Create new decompiler with custom hash strategy
    pub fn with_strategy<P: AsRef<Path>>(cache_dir: P, strategy: HashStrategy) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&cache_dir)?;

        Ok(Self {
            cache_dir,
            memory_cache: Arc::new(Mutex::new(HashMap::new())),
            hash_strategy: strategy,
        })
    }

    /// Compute file hash based on strategy
    fn compute_file_hash(&self, binary_path: Option<&Path>, binary_data: &[u8]) -> String {
        match self.hash_strategy {
            HashStrategy::Metadata => {
                if let Some(path) = binary_path {
                    if let Ok(metadata) = std::fs::metadata(path) {
                        let mut hasher = Xxh3::new();

                        hasher.update(&metadata.len().to_le_bytes());

                        if let Ok(modified) = metadata.modified() {
                            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                                hasher.update(&duration.as_secs().to_le_bytes());
                            }
                        }

                        if let Ok(abs_path) = path.canonicalize() {
                            hasher.update(abs_path.to_string_lossy().as_bytes());
                        }

                        return format!("{:x}", hasher.digest());
                    }
                }

                self.compute_file_hash_sampling(binary_data)
            }

            HashStrategy::Sampling => {
                self.compute_file_hash_sampling(binary_data)
            }

            HashStrategy::Full => {
                let mut hasher = Xxh3::new();
                hasher.update(binary_data);
                format!("{:x}", hasher.digest())
            }
        }
    }

    /// Compute hash from file sampling
    fn compute_file_hash_sampling(&self, binary_data: &[u8]) -> String {
        const SAMPLE_SIZE: usize = 4096;
        let mut hasher = Xxh3::new();

        hasher.update(&binary_data.len().to_le_bytes());

        let head_size = std::cmp::min(SAMPLE_SIZE, binary_data.len());
        hasher.update(&binary_data[..head_size]);

        if binary_data.len() > SAMPLE_SIZE * 2 {
            let tail_start = binary_data.len() - SAMPLE_SIZE;
            hasher.update(&binary_data[tail_start..]);
        }

        format!("{:x}", hasher.digest())
    }

    /// Get cache file path for a hash
    fn get_cache_path(&self, file_hash: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", file_hash))
    }

    /// Load cache from disk/memory
    fn load_cache(&self, file_hash: &str) -> Option<DecompileCache> {
        if let Ok(cache) = self.memory_cache.lock() {
            if let Some(cached) = cache.get(file_hash) {
                return Some(cached.clone());
            }
        }

        let cache_path = self.get_cache_path(file_hash);
        if let Ok(data) = std::fs::read_to_string(&cache_path) {
            if let Ok(cache) = serde_json::from_str::<DecompileCache>(&data) {
                if let Ok(mut mem_cache) = self.memory_cache.lock() {
                    mem_cache.insert(file_hash.to_string(), cache.clone());
                }
                return Some(cache);
            }
        }

        None
    }

    /// Save cache to disk/memory
    fn save_cache(&self, file_hash: &str, cache: &DecompileCache) -> Result<()> {
        if let Ok(mut mem_cache) = self.memory_cache.lock() {
            mem_cache.insert(file_hash.to_string(), cache.clone());
        }

        let cache_path = self.get_cache_path(file_hash);
        let json = serde_json::to_string_pretty(cache)?;
        std::fs::write(&cache_path, json)?;

        Ok(())
    }

    /// Decompile function with caching
    pub fn decompile_function_cached(
        &self,
        binary_path: Option<&Path>,
        binary_data: &[u8],
        function_address: u64,
        file_offset: usize,
        max_instructions: usize,
    ) -> Result<CachedFunctionResult> {
        let file_hash = self.compute_file_hash(binary_path, binary_data);

        if let Some(cache) = self.load_cache(&file_hash) {
            if let Some(result) = cache.results.get(&function_address) {
                return Ok(result.clone());
            }
        }

        let result = self.decompile_function_uncached(
            binary_data,
            function_address,
            file_offset,
            max_instructions,
        )?;

        let mut cache = self.load_cache(&file_hash).unwrap_or(DecompileCache {
            file_hash: file_hash.clone(),
            results: HashMap::new(),
        });

        cache.results.insert(function_address, result.clone());
        self.save_cache(&file_hash, &cache)?;

        Ok(result)
    }

    /// Decompile function without caching
    fn decompile_function_uncached(
        &self,
        binary_data: &[u8],
        function_address: u64,
        file_offset: usize,
        max_instructions: usize,
    ) -> Result<CachedFunctionResult> {
        let code_slice = if file_offset < binary_data.len() {
            let end = std::cmp::min(file_offset + max_instructions * 15, binary_data.len());
            &binary_data[file_offset..end]
        } else {
            &[]
        };

        let mut translator = CapstoneTranslator::new()?;
        let mut pcodes = translator.translate(code_slice, function_address, max_instructions)?;

        let optimizer = Optimizer::new();
        let _opt_stats = optimizer.optimize(&mut pcodes);

        let mut cfg = ControlFlowGraph::from_pcodes(pcodes.clone());

        let mut ssa = SSATransform::new();
        ssa.transform(&mut cfg);

        let mut type_inference = TypeInference::new();
        type_inference.run(&pcodes);

        let mut analyzer = ControlFlowAnalyzer::new();
        let structure = analyzer.analyze(&cfg);

        let mut printer = ControlStructurePrinter::new();
        let structure_str = printer.print(&structure);

        let result = CachedFunctionResult {
            address: function_address,
            pcode_count: pcodes.len(),
            block_count: cfg.blocks.len(),
            type_count: type_inference.get_all_types().len(),
            loop_count: analyzer.get_loops().len(),
            control_structure: structure_str,
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        Ok(result)
    }

    /// Decompile multiple functions in parallel (requires parallel feature)
    #[cfg(feature = "parallel")]
    pub fn decompile_functions_parallel(
        &self,
        binary_path: Option<&Path>,
        binary_data: Arc<Vec<u8>>,
        function_addresses: Vec<(u64, usize)>,
        max_instructions: usize,
    ) -> Result<Vec<CachedFunctionResult>> {
        use rayon::prelude::*;

        let results: Vec<Result<CachedFunctionResult>> = function_addresses
            .par_iter()
            .map(|&(address, offset)| {
                self.decompile_function_cached(binary_path, &binary_data, address, offset, max_instructions)
            })
            .collect();

        results.into_iter().collect()
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> CacheStatistics {
        let mem_size = if let Ok(cache) = self.memory_cache.lock() {
            cache.len()
        } else {
            0
        };

        let disk_files = std::fs::read_dir(&self.cache_dir)
            .map(|entries| entries.count())
            .unwrap_or(0);

        CacheStatistics {
            memory_cached_binaries: mem_size,
            disk_cached_binaries: disk_files,
            cache_directory: self.cache_dir.display().to_string(),
        }
    }

    /// Clear all caches
    pub fn clear_cache(&self) -> Result<()> {
        if let Ok(mut cache) = self.memory_cache.lock() {
            cache.clear();
        }

        for entry in std::fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                std::fs::remove_file(entry.path())?;
            }
        }

        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStatistics {
    pub memory_cached_binaries: usize,
    pub disk_cached_binaries: usize,
    pub cache_directory: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_parallel_decompiler_cache() -> Result<()> {
        let temp_dir = env::temp_dir().join("kensho_mcp_cache_test");
        let decompiler = ParallelDecompiler::new(&temp_dir)?;

        let binary_data = vec![0u8; 1024];
        let file_hash = decompiler.compute_file_hash(None, &binary_data);

        assert!(decompiler.load_cache(&file_hash).is_none());

        let cache = DecompileCache {
            file_hash: file_hash.clone(),
            results: HashMap::new(),
        };

        decompiler.save_cache(&file_hash, &cache)?;

        assert!(decompiler.load_cache(&file_hash).is_some());

        decompiler.clear_cache()?;

        Ok(())
    }
}
