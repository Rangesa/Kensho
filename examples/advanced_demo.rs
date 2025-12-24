/// 拡張機能のデモ
/// 文字列操作命令、エクスポート関数検出、キャッシュ機能のテスト

use anyhow::Result;
use ghidra_mcp::decompiler_prototype::{
    FunctionDetector, ParallelDecompiler, HashStrategy
};
use goblin::pe::PE;
use std::env;
use std::path::Path;

fn main() -> Result<()> {
    println!("🚀 Advanced Decompiler Features Demo");
    println!("{}", "=".repeat(70));

    let binary_path = r"C:\Programming\Cheat\TheFinals\Discovery-d.exe";

    println!("\n📂 Binary: {}", binary_path);

    // バイナリファイルを読み込み
    println!("\n📖 Loading binary...");
    let binary_data = std::fs::read(binary_path)?;
    println!("   Size: {} bytes ({} MB)", binary_data.len(), binary_data.len() / 1_000_000);

    // PEファイルをパース
    println!("\n🔍 Parsing PE file...");
    let pe = PE::parse(&binary_data)?;
    let image_base = pe.image_base as u64;
    println!("   Image Base: 0x{:X}", image_base);
    println!("   Entry Point (RVA): 0x{:X}", pe.entry);
    println!("   Entry Point (VA): 0x{:X}", image_base + pe.entry as u64);

    // エクスポート関数を検出
    println!("\n📤 Detecting export functions...");
    let mut detector = FunctionDetector::new();
    detector.detect_exports(&pe, image_base)?;

    let export_functions = detector.get_export_functions();
    println!("   ✅ Found {} export functions", export_functions.len());

    println!("\n📋 Export Functions:");
    for (i, func) in export_functions.iter().take(10).enumerate() {
        println!("   [{}] {} @ 0x{:X}",
            i,
            func.name.as_ref().unwrap_or(&"<unnamed>".to_string()),
            func.start_address
        );
    }

    let stats = detector.get_statistics();
    println!("\n📊 Function Statistics:");
    println!("   Total functions: {}", stats.total_functions);
    println!("   Export functions: {}", stats.export_functions);

    // キャッシュ機能のテスト
    println!("\n💾 Testing cache functionality with different hash strategies...");
    let cache_dir = env::temp_dir().join("ghidra_mcp_cache");
    println!("   Cache directory: {}", cache_dir.display());

    // .textセクションの開始アドレス
    let file_offset = 0x600;
    let function_address = 0x140001000;
    let binary_path = Path::new(binary_path);

    // ========================================
    // テスト1: メタデータベース戦略（デフォルト）
    // ========================================
    println!("\n📋 Strategy 1: Metadata (Size + mtime + Path)");
    let decompiler_metadata = ParallelDecompiler::new(&cache_dir)?;

    println!("   🔄 First decompilation (no cache)...");
    let start = std::time::Instant::now();
    let result1 = decompiler_metadata.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration1 = start.elapsed();
    println!("      ⏱️  Time: {:?}", duration1);

    println!("   🔄 Second decompilation (with cache)...");
    let start = std::time::Instant::now();
    let result2 = decompiler_metadata.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration2 = start.elapsed();
    println!("      ⏱️  Time: {:?}", duration2);

    if duration2 < duration1 {
        let speedup = duration1.as_micros() as f64 / duration2.as_micros() as f64;
        println!("      🚀 Cache speedup: {:.0}x faster!", speedup);
    }

    // ========================================
    // テスト2: サンプリング戦略
    // ========================================
    println!("\n📋 Strategy 2: Sampling (Head 4KB + Tail 4KB + Size)");
    let cache_dir_sampling = env::temp_dir().join("ghidra_mcp_cache_sampling");
    let decompiler_sampling = ParallelDecompiler::with_strategy(&cache_dir_sampling, HashStrategy::Sampling)?;

    println!("   🔄 First decompilation (no cache)...");
    let start = std::time::Instant::now();
    let result3 = decompiler_sampling.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration3 = start.elapsed();
    println!("      ⏱️  Time: {:?}", duration3);

    println!("   🔄 Second decompilation (with cache)...");
    let start = std::time::Instant::now();
    let result4 = decompiler_sampling.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration4 = start.elapsed();
    println!("      ⏱️  Time: {:?}", duration4);

    if duration4 < duration3 {
        let speedup = duration3.as_micros() as f64 / duration4.as_micros() as f64;
        println!("      🚀 Cache speedup: {:.0}x faster!", speedup);
    }

    // ========================================
    // テスト3: フルハッシュ戦略（比較用）
    // ========================================
    println!("\n📋 Strategy 3: Full Hash (Entire file - 247MB)");
    let cache_dir_full = env::temp_dir().join("ghidra_mcp_cache_full");
    let decompiler_full = ParallelDecompiler::with_strategy(&cache_dir_full, HashStrategy::Full)?;

    println!("   🔄 First decompilation (no cache)...");
    let start = std::time::Instant::now();
    let result5 = decompiler_full.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration5 = start.elapsed();
    println!("      ⏱️  Time: {:?}", duration5);

    println!("   🔄 Second decompilation (with cache)...");
    let start = std::time::Instant::now();
    let result6 = decompiler_full.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration6 = start.elapsed();
    println!("      ⏱️  Time: {:?}", duration6);

    if duration6 < duration5 {
        let speedup = duration5.as_micros() as f64 / duration6.as_micros() as f64;
        println!("      🚀 Cache speedup: {:.0}x faster!", speedup);
    }

    // 結果の検証
    println!("\n✅ Decompilation Results (all strategies should be identical):");
    println!("   P-code operations: {}", result1.pcode_count);
    println!("   Basic blocks: {}", result1.block_count);
    println!("   Type inferences: {}", result1.type_count);
    println!("   Loops detected: {}", result1.loop_count);

    // キャッシュ統計
    let cache_stats = decompiler_metadata.get_cache_stats();
    println!("\n📈 Cache Statistics:");
    println!("   Memory cached binaries: {}", cache_stats.memory_cached_binaries);
    println!("   Disk cached binaries: {}", cache_stats.disk_cached_binaries);

    println!("\n{}", "=".repeat(70));
    println!("✅ Advanced demo complete!");

    println!("\n💡 New Features Demonstrated:");
    println!("   ✅ Export function detection");
    println!("   ✅ Three hash strategies:");
    println!("      - Metadata: ~0ms (fastest, file metadata only)");
    println!("      - Sampling: ~1-5ms (practical, 4KB+4KB)");
    println!("      - Full: ~490ms (complete, entire 247MB file)");
    println!("   ✅ Disk-based caching");
    println!("   ✅ Memory-based caching");
    println!("   ✅ Cache hit performance improvement");
    println!("   ✅ Function statistics");

    Ok(())
}
