/// 諡｡蠑ｵ讖溯・縺ｮ繝・Δ
/// 譁・ｭ怜・謫堺ｽ懷多莉､縲√お繧ｯ繧ｹ繝昴・繝磯未謨ｰ讀懷・縲√く繝｣繝・す繝･讖溯・縺ｮ繝・せ繝・
use anyhow::Result;
use kensho_mcp::decompiler_prototype::{
    FunctionDetector, ParallelDecompiler, HashStrategy
};
use goblin::pe::PE;
use std::env;
use std::path::Path;

fn main() -> Result<()> {
    println!("噫 Advanced Decompiler Features Demo");
    println!("{}", "=".repeat(70));

    let binary_path = r"C:\Programming\Cheat\TheFinals\Discovery-d.exe";

    println!("\n唐 Binary: {}", binary_path);

    // 繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繧定ｪｭ縺ｿ霎ｼ縺ｿ
    println!("\n当 Loading binary...");
    let binary_data = std::fs::read(binary_path)?;
    println!("   Size: {} bytes ({} MB)", binary_data.len(), binary_data.len() / 1_000_000);

    // PE繝輔ぃ繧､繝ｫ繧偵ヱ繝ｼ繧ｹ
    println!("\n剥 Parsing PE file...");
    let pe = PE::parse(&binary_data)?;
    let image_base = pe.image_base as u64;
    println!("   Image Base: 0x{:X}", image_base);
    println!("   Entry Point (RVA): 0x{:X}", pe.entry);
    println!("   Entry Point (VA): 0x{:X}", image_base + pe.entry as u64);

    // 繧ｨ繧ｯ繧ｹ繝昴・繝磯未謨ｰ繧呈､懷・
    println!("\n豆 Detecting export functions...");
    let mut detector = FunctionDetector::new();
    detector.detect_exports(&pe, image_base)?;

    let export_functions = detector.get_export_functions();
    println!("   笨・Found {} export functions", export_functions.len());

    println!("\n搭 Export Functions:");
    for (i, func) in export_functions.iter().take(10).enumerate() {
        println!("   [{}] {} @ 0x{:X}",
            i,
            func.name.as_ref().unwrap_or(&"<unnamed>".to_string()),
            func.start_address
        );
    }

    let stats = detector.get_statistics();
    println!("\n投 Function Statistics:");
    println!("   Total functions: {}", stats.total_functions);
    println!("   Export functions: {}", stats.export_functions);

    // 繧ｭ繝｣繝・す繝･讖溯・縺ｮ繝・せ繝・    println!("\n沈 Testing cache functionality with different hash strategies...");
    let cache_dir = env::temp_dir().join("kensho_mcp_cache");
    println!("   Cache directory: {}", cache_dir.display());

    // .text繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｮ髢句ｧ九い繝峨Ξ繧ｹ
    let file_offset = 0x600;
    let function_address = 0x140001000;
    let binary_path = Path::new(binary_path);

    // ========================================
    // 繝・せ繝・: 繝｡繧ｿ繝・・繧ｿ繝吶・繧ｹ謌ｦ逡･・医ョ繝輔か繝ｫ繝茨ｼ・    // ========================================
    println!("\n搭 Strategy 1: Metadata (Size + mtime + Path)");
    let decompiler_metadata = ParallelDecompiler::new(&cache_dir)?;

    println!("   売 First decompilation (no cache)...");
    let start = std::time::Instant::now();
    let result1 = decompiler_metadata.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration1 = start.elapsed();
    println!("      竢ｱ・・ Time: {:?}", duration1);

    println!("   売 Second decompilation (with cache)...");
    let start = std::time::Instant::now();
    let result2 = decompiler_metadata.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration2 = start.elapsed();
    println!("      竢ｱ・・ Time: {:?}", duration2);

    if duration2 < duration1 {
        let speedup = duration1.as_micros() as f64 / duration2.as_micros() as f64;
        println!("      噫 Cache speedup: {:.0}x faster!", speedup);
    }

    // ========================================
    // 繝・せ繝・: 繧ｵ繝ｳ繝励Μ繝ｳ繧ｰ謌ｦ逡･
    // ========================================
    println!("\n搭 Strategy 2: Sampling (Head 4KB + Tail 4KB + Size)");
    let cache_dir_sampling = env::temp_dir().join("kensho_mcp_cache_sampling");
    let decompiler_sampling = ParallelDecompiler::with_strategy(&cache_dir_sampling, HashStrategy::Sampling)?;

    println!("   売 First decompilation (no cache)...");
    let start = std::time::Instant::now();
    let result3 = decompiler_sampling.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration3 = start.elapsed();
    println!("      竢ｱ・・ Time: {:?}", duration3);

    println!("   売 Second decompilation (with cache)...");
    let start = std::time::Instant::now();
    let result4 = decompiler_sampling.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration4 = start.elapsed();
    println!("      竢ｱ・・ Time: {:?}", duration4);

    if duration4 < duration3 {
        let speedup = duration3.as_micros() as f64 / duration4.as_micros() as f64;
        println!("      噫 Cache speedup: {:.0}x faster!", speedup);
    }

    // ========================================
    // 繝・せ繝・: 繝輔Ν繝上ャ繧ｷ繝･謌ｦ逡･・域ｯ碑ｼ・畑・・    // ========================================
    println!("\n搭 Strategy 3: Full Hash (Entire file - 247MB)");
    let cache_dir_full = env::temp_dir().join("kensho_mcp_cache_full");
    let decompiler_full = ParallelDecompiler::with_strategy(&cache_dir_full, HashStrategy::Full)?;

    println!("   売 First decompilation (no cache)...");
    let start = std::time::Instant::now();
    let result5 = decompiler_full.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration5 = start.elapsed();
    println!("      竢ｱ・・ Time: {:?}", duration5);

    println!("   売 Second decompilation (with cache)...");
    let start = std::time::Instant::now();
    let result6 = decompiler_full.decompile_function_cached(
        Some(binary_path),
        &binary_data,
        function_address,
        file_offset,
        100,
    )?;
    let duration6 = start.elapsed();
    println!("      竢ｱ・・ Time: {:?}", duration6);

    if duration6 < duration5 {
        let speedup = duration5.as_micros() as f64 / duration6.as_micros() as f64;
        println!("      噫 Cache speedup: {:.0}x faster!", speedup);
    }

    // 邨先棡縺ｮ讀懆ｨｼ
    println!("\n笨・Decompilation Results (all strategies should be identical):");
    println!("   P-code operations: {}", result1.pcode_count);
    println!("   Basic blocks: {}", result1.block_count);
    println!("   Type inferences: {}", result1.type_count);
    println!("   Loops detected: {}", result1.loop_count);

    // 繧ｭ繝｣繝・す繝･邨ｱ險・    let cache_stats = decompiler_metadata.get_cache_stats();
    println!("\n嶋 Cache Statistics:");
    println!("   Memory cached binaries: {}", cache_stats.memory_cached_binaries);
    println!("   Disk cached binaries: {}", cache_stats.disk_cached_binaries);

    println!("\n{}", "=".repeat(70));
    println!("笨・Advanced demo complete!");

    println!("\n庁 New Features Demonstrated:");
    println!("   笨・Export function detection");
    println!("   笨・Three hash strategies:");
    println!("      - Metadata: ~0ms (fastest, file metadata only)");
    println!("      - Sampling: ~1-5ms (practical, 4KB+4KB)");
    println!("      - Full: ~490ms (complete, entire 247MB file)");
    println!("   笨・Disk-based caching");
    println!("   笨・Memory-based caching");
    println!("   笨・Cache hit performance improvement");
    println!("   笨・Function statistics");

    Ok(())
}
