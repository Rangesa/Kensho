/// 並列解析とキャッシュ機構
/// 大規模バイナリの高速解析を実現

use super::cfg::*;
use super::ssa::*;
use super::ssa_advanced::*;
use super::nzmask::*;
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

/// ハッシュ計算戦略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashStrategy {
    /// メタデータベース（最速）: ファイルサイズ + 更新日時 + パス
    /// 計算時間: ~0ms（ファイルI/O不要）
    /// 用途: 内部キャッシュ、信頼できるバイナリ
    Metadata,

    /// サンプリング（実用的）: 先頭4KB + 末尾4KB + サイズ
    /// 計算時間: ~1-5ms（数KBのみ読み込み）
    /// 用途: 大規模バイナリの高速ハッシュ化
    Sampling,

    /// フルハッシュ（完全）: ファイル全体をハッシュ化
    /// 計算時間: ファイルサイズ依存（247MBで約490ms）
    /// 用途: 外部バイナリの完全性検証
    Full,
}

/// デコンパイル結果のキャッシュ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileCache {
    /// バイナリファイルのハッシュ
    pub file_hash: String,
    /// キャッシュされたデコンパイル結果
    pub results: HashMap<u64, CachedFunctionResult>,
}

/// 個別の関数のキャッシュ結果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFunctionResult {
    /// 関数アドレス
    pub address: u64,
    /// P-code命令数
    pub pcode_count: usize,
    /// 基本ブロック数
    pub block_count: usize,
    /// 型推論結果の数
    pub type_count: usize,
    /// ループ数
    pub loop_count: usize,
    /// 制御構造の文字列表現
    pub control_structure: String,
    /// キャッシュ作成時刻（UNIX timestamp）
    pub cached_at: u64,
}

/// 並列デコンパイラ
pub struct ParallelDecompiler {
    /// キャッシュディレクトリ
    cache_dir: PathBuf,
    /// メモリ内キャッシュ
    memory_cache: Arc<Mutex<HashMap<String, DecompileCache>>>,
    /// ハッシュ計算戦略
    hash_strategy: HashStrategy,
}

impl ParallelDecompiler {
    /// デフォルトのハッシュ戦略（Metadata）でデコンパイラを作成
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        Self::with_strategy(cache_dir, HashStrategy::Metadata)
    }

    /// 指定したハッシュ戦略でデコンパイラを作成
    pub fn with_strategy<P: AsRef<Path>>(cache_dir: P, strategy: HashStrategy) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&cache_dir)?;

        Ok(Self {
            cache_dir,
            memory_cache: Arc::new(Mutex::new(HashMap::new())),
            hash_strategy: strategy,
        })
    }

    /// バイナリファイルのハッシュを計算
    fn compute_file_hash(&self, binary_path: Option<&Path>, binary_data: &[u8]) -> String {
        match self.hash_strategy {
            HashStrategy::Metadata => {
                // メタデータベース: ファイルサイズ + 更新日時 + パス
                if let Some(path) = binary_path {
                    if let Ok(metadata) = std::fs::metadata(path) {
                        let mut hasher = Xxh3::new();

                        // ファイルサイズ
                        hasher.update(&metadata.len().to_le_bytes());

                        // 更新日時（mtimeがあれば）
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                                hasher.update(&duration.as_secs().to_le_bytes());
                            }
                        }

                        // ファイルパス（絶対パス）
                        if let Ok(abs_path) = path.canonicalize() {
                            hasher.update(abs_path.to_string_lossy().as_bytes());
                        }

                        return format!("{:x}", hasher.digest());
                    }
                }

                // メタデータ取得失敗時はサンプリングにフォールバック
                self.compute_file_hash_sampling(binary_data)
            }

            HashStrategy::Sampling => {
                self.compute_file_hash_sampling(binary_data)
            }

            HashStrategy::Full => {
                // フルハッシュ: ファイル全体
                let mut hasher = Xxh3::new();
                hasher.update(binary_data);
                format!("{:x}", hasher.digest())
            }
        }
    }

    /// サンプリングハッシュ: 先頭4KB + 末尾4KB + サイズ
    fn compute_file_hash_sampling(&self, binary_data: &[u8]) -> String {
        const SAMPLE_SIZE: usize = 4096;
        let mut hasher = Xxh3::new();

        // ファイルサイズ
        hasher.update(&binary_data.len().to_le_bytes());

        // 先頭4KB
        let head_size = std::cmp::min(SAMPLE_SIZE, binary_data.len());
        hasher.update(&binary_data[..head_size]);

        // 末尾4KB（ファイルが8KBより大きい場合のみ）
        if binary_data.len() > SAMPLE_SIZE * 2 {
            let tail_start = binary_data.len() - SAMPLE_SIZE;
            hasher.update(&binary_data[tail_start..]);
        }

        format!("{:x}", hasher.digest())
    }

    /// キャッシュファイルのパスを取得
    fn get_cache_path(&self, file_hash: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", file_hash))
    }

    /// キャッシュをロード
    pub fn load_cache(&self, file_hash: &str) -> Option<DecompileCache> {
        // メモリキャッシュを確認
        if let Ok(cache) = self.memory_cache.lock() {
            if let Some(cached) = cache.get(file_hash) {
                return Some(cached.clone());
            }
        }

        // ディスクキャッシュを確認
        let cache_path = self.get_cache_path(file_hash);
        if let Ok(data) = std::fs::read_to_string(&cache_path) {
            if let Ok(cache) = serde_json::from_str::<DecompileCache>(&data) {
                // メモリキャッシュに格納
                if let Ok(mut mem_cache) = self.memory_cache.lock() {
                    mem_cache.insert(file_hash.to_string(), cache.clone());
                }
                return Some(cache);
            }
        }

        None
    }

    /// キャッシュを保存
    pub fn save_cache(&self, file_hash: &str, cache: &DecompileCache) -> Result<()> {
        // メモリキャッシュに格納
        if let Ok(mut mem_cache) = self.memory_cache.lock() {
            mem_cache.insert(file_hash.to_string(), cache.clone());
        }

        // ディスクに保存
        let cache_path = self.get_cache_path(file_hash);
        let json = serde_json::to_string_pretty(cache)?;
        std::fs::write(&cache_path, json)?;

        Ok(())
    }

    /// 関数をデコンパイル（キャッシュあり）
    pub fn decompile_function_cached(
        &self,
        binary_path: Option<&Path>,
        binary_data: &[u8],
        function_address: u64,
        file_offset: usize,
        max_instructions: usize,
    ) -> Result<CachedFunctionResult> {
        let file_hash = self.compute_file_hash(binary_path, binary_data);

        // キャッシュを確認
        if let Some(cache) = self.load_cache(&file_hash) {
            if let Some(result) = cache.results.get(&function_address) {
                return Ok(result.clone());
            }
        }

        // キャッシュがなければデコンパイル実行
        let result = self.decompile_function_uncached(
            binary_data,
            function_address,
            file_offset,
            max_instructions,
        )?;

        // キャッシュに保存
        let mut cache = self.load_cache(&file_hash).unwrap_or(DecompileCache {
            file_hash: file_hash.clone(),
            results: HashMap::new(),
        });

        cache.results.insert(function_address, result.clone());
        self.save_cache(&file_hash, &cache)?;

        Ok(result)
    }

    /// 関数をデコンパイル（キャッシュなし）
    fn decompile_function_uncached(
        &self,
        binary_data: &[u8],
        function_address: u64,
        file_offset: usize,
        max_instructions: usize,
    ) -> Result<CachedFunctionResult> {
        // コードスライスを抽出
        let code_slice = if file_offset < binary_data.len() {
            let end = std::cmp::min(file_offset + max_instructions * 15, binary_data.len());
            &binary_data[file_offset..end]
        } else {
            &[]
        };

        // P-codeに変換
        let mut translator = CapstoneTranslator::new()?;
        let mut pcodes = translator.translate(code_slice, function_address, max_instructions)?;

        // Phase 7: P-code最適化パス
        let optimizer = Optimizer::new();
        let _opt_stats = optimizer.optimize(&mut pcodes);

        // CFG構築
        let mut cfg = ControlFlowGraph::from_pcodes(pcodes.clone());

        // SSA変換（基本）
        let mut ssa = SSATransform::new();
        ssa.transform(&mut cfg);

        // Phase 7: 高度なSSA変換（VariableStack方式）
        // let dom_tree = DominanceTree::compute(&cfg);
        // let mut advanced_ssa = AdvancedSSATransform::new();
        // advanced_ssa.transform(&mut cfg, &dom_tree);

        // 型推論
        let mut type_inference = TypeInference::new();
        type_inference.run(&pcodes);

        // 制御構造検出
        let mut analyzer = ControlFlowAnalyzer::new();
        let structure = analyzer.analyze(&cfg);

        // 結果整形
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

    /// 複数の関数を並列にデコンパイル
    #[cfg(feature = "parallel")]
    pub fn decompile_functions_parallel(
        &self,
        binary_path: Option<&Path>,
        binary_data: Arc<Vec<u8>>,
        function_addresses: Vec<(u64, usize)>, // (VA, file_offset)
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

    /// キャッシュ統計情報
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

    /// キャッシュをクリア
    pub fn clear_cache(&self) -> Result<()> {
        // メモリキャッシュをクリア
        if let Ok(mut cache) = self.memory_cache.lock() {
            cache.clear();
        }

        // ディスクキャッシュをクリア
        for entry in std::fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                std::fs::remove_file(entry.path())?;
            }
        }

        Ok(())
    }
}

/// キャッシュ統計情報
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
        let temp_dir = env::temp_dir().join("ghidra_mcp_cache_test");
        let decompiler = ParallelDecompiler::new(&temp_dir)?;

        let binary_data = vec![0u8; 1024];
        let file_hash = decompiler.compute_file_hash(None, &binary_data);

        // キャッシュが空であることを確認
        assert!(decompiler.load_cache(&file_hash).is_none());

        // キャッシュを作成
        let cache = DecompileCache {
            file_hash: file_hash.clone(),
            results: HashMap::new(),
        };

        decompiler.save_cache(&file_hash, &cache)?;

        // キャッシュがロードできることを確認
        assert!(decompiler.load_cache(&file_hash).is_some());

        // クリーンアップ
        decompiler.clear_cache()?;

        Ok(())
    }
}
