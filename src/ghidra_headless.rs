use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashMap;
use std::sync::Mutex;

/// Ghidra Headless連携モジュール
///
/// Ghidraの高品質デコンパイラをサブプロセスで呼び出す
/// キャッシュ機構により2回目以降は即座に結果を返す
pub struct GhidraHeadless {
    ghidra_path: PathBuf,
    cache_dir: PathBuf,
    cache: Mutex<HashMap<String, CachedDecompilation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedDecompilation {
    binary_path: String,
    function_address: u64,
    decompiled_code: String,
    timestamp: u64,
}

impl GhidraHeadless {
    /// 新しいGhidraHeadlessインスタンスを作成
    ///
    /// # Arguments
    /// * `ghidra_path` - Ghidraのインストールディレクトリ（例: C:/ghidra_11.0）
    pub fn new(ghidra_path: impl AsRef<Path>) -> Result<Self> {
        let ghidra_path = ghidra_path.as_ref().to_path_buf();

        // Ghidraの存在確認
        if !ghidra_path.exists() {
            return Err(anyhow::anyhow!(
                "Ghidra not found at: {}. Please install Ghidra or set correct path",
                ghidra_path.display()
            ));
        }

        // キャッシュディレクトリ作成
        let cache_dir = PathBuf::from(".ghidra_cache");
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
        }

        Ok(Self {
            ghidra_path,
            cache_dir,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// 関数をデコンパイル（キャッシュ優先）
    ///
    /// # Arguments
    /// * `binary_path` - 解析対象バイナリのパス
    /// * `function_address` - 関数のアドレス
    ///
    /// # Returns
    /// デコンパイルされたC疑似コード
    pub fn decompile(&self, binary_path: &str, function_address: u64) -> Result<String> {
        let cache_key = format!("{}_{:x}", binary_path, function_address);

        // キャッシュチェック
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                tracing::info!("Cache hit for {}@0x{:x}", binary_path, function_address);
                return Ok(cached.decompiled_code.clone());
            }
        }

        tracing::info!("Cache miss, calling Ghidra Headless...");

        // Ghidra Headlessで実際にデコンパイル
        let decompiled = self.decompile_with_ghidra(binary_path, function_address)?;

        // キャッシュに保存
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(cache_key.clone(), CachedDecompilation {
                binary_path: binary_path.to_string(),
                function_address,
                decompiled_code: decompiled.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            });
        }

        // ディスクにもキャッシュ
        self.save_cache_to_disk(&cache_key, binary_path, function_address, &decompiled)?;

        Ok(decompiled)
    }

    /// Ghidra Headlessで実際にデコンパイル実行
    fn decompile_with_ghidra(&self, binary_path: &str, function_address: u64) -> Result<String> {
        // 一時プロジェクトディレクトリ
        let temp_project_dir = self.cache_dir.join("temp_projects");
        fs::create_dir_all(&temp_project_dir)?;

        let project_name = format!("temp_{}", std::process::id());

        // Ghidra解析スクリプト作成
        let script_path = self.cache_dir.join("decompile.py");
        let script_content = format!(r#"
# Ghidra Headless Decompilation Script
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# 対象アドレス
target_address = toAddr(0x{:x})

# 関数取得
func = getFunctionAt(target_address)
if func is None:
    print("ERROR: Function not found at address 0x{:x}")
    exit(1)

# デコンパイラ初期化
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

# デコンパイル実行（タイムアウト30秒）
result = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())

if result.decompileCompleted():
    decomp_func = result.getDecompiledFunction()
    if decomp_func is not None:
        print("===DECOMPILED_START===")
        print(decomp_func.getC())
        print("===DECOMPILED_END===")
    else:
        print("ERROR: Decompilation returned null")
        exit(1)
else:
    print("ERROR: Decompilation failed or timed out")
    exit(1)
"#, function_address, function_address);

        fs::write(&script_path, script_content)?;

        // analyzeHeadless実行
        let analyze_headless = self.ghidra_path.join("support").join("analyzeHeadless.bat");

        if !analyze_headless.exists() {
            return Err(anyhow::anyhow!(
                "analyzeHeadless not found. Expected at: {}",
                analyze_headless.display()
            ));
        }

        tracing::info!("Running Ghidra Headless analysis...");

        let output = Command::new(&analyze_headless)
            .arg(&temp_project_dir)
            .arg(&project_name)
            .arg("-import")
            .arg(binary_path)
            .arg("-postScript")
            .arg(&script_path)
            .arg("-deleteProject") // 解析後にプロジェクト削除
            .output()
            .context("Failed to execute Ghidra analyzeHeadless")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // デバッグ出力
        tracing::debug!("Ghidra stdout: {}", stdout);
        if !stderr.is_empty() {
            tracing::warn!("Ghidra stderr: {}", stderr);
        }

        // デコンパイル結果を抽出
        if let Some(start) = stdout.find("===DECOMPILED_START===") {
            if let Some(end) = stdout.find("===DECOMPILED_END===") {
                let decompiled = stdout[start + "===DECOMPILED_START===".len()..end].trim();
                return Ok(decompiled.to_string());
            }
        }

        // エラーチェック
        if stdout.contains("ERROR:") {
            return Err(anyhow::anyhow!("Ghidra decompilation error: {}", stdout));
        }

        Err(anyhow::anyhow!("Failed to extract decompiled code from Ghidra output"))
    }

    /// キャッシュをディスクに保存
    fn save_cache_to_disk(
        &self,
        cache_key: &str,
        binary_path: &str,
        function_address: u64,
        decompiled_code: &str,
    ) -> Result<()> {
        let cache_file = self.cache_dir.join(format!("{}.json", cache_key));

        let cached_data = CachedDecompilation {
            binary_path: binary_path.to_string(),
            function_address,
            decompiled_code: decompiled_code.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let json = serde_json::to_string_pretty(&cached_data)?;
        fs::write(cache_file, json)?;

        Ok(())
    }

    /// ディスクからキャッシュをロード
    pub fn load_cache_from_disk(&self) -> Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }

        let mut cache = self.cache.lock().unwrap();

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(cached_data) = serde_json::from_str::<CachedDecompilation>(&content) {
                        let cache_key = format!("{}_{:x}",
                            cached_data.binary_path,
                            cached_data.function_address
                        );
                        cache.insert(cache_key, cached_data);
                    }
                }
            }
        }

        tracing::info!("Loaded {} cached decompilations from disk", cache.len());
        Ok(())
    }

    /// キャッシュクリア
    pub fn clear_cache(&self) -> Result<()> {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();

        // ディスクキャッシュも削除
        if self.cache_dir.exists() {
            for entry in fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    fs::remove_file(path)?;
                }
            }
        }

        tracing::info!("Cache cleared");
        Ok(())
    }

    /// キャッシュ統計取得
    pub fn cache_stats(&self) -> HashMap<String, usize> {
        let cache = self.cache.lock().unwrap();
        let mut stats = HashMap::new();
        stats.insert("total_entries".to_string(), cache.len());
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_headless_creation() {
        // Ghidraがインストールされていない環境でもテストが通るように
        let result = GhidraHeadless::new("C:/nonexistent_ghidra");
        assert!(result.is_err());
    }
}
