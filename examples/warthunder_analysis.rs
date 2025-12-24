/// War Thunder aces.exe解析デモ
/// エクスポート関数検出、デコンパイル、キャッシュ機能のテスト

use anyhow::Result;
use ghidra_mcp::decompiler_prototype::{
    FunctionDetector, ParallelDecompiler, HashStrategy
};
use goblin::pe::PE;
use std::env;
use std::path::Path;

fn main() -> Result<()> {
    println!("🎮 War Thunder aces.exe Analysis");
    println!("{}", "=".repeat(70));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";

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

    // セクション情報
    println!("\n📋 Sections: {}", pe.sections.len());
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name);
        let name = name.trim_end_matches('\0');
        println!("   - {} @ 0x{:X} (size: 0x{:X})",
            name, section.virtual_address, section.virtual_size);
    }

    // エクスポート関数を検出
    println!("\n📤 Detecting export functions...");
    let mut detector = FunctionDetector::new();
    detector.detect_exports(&pe, image_base)?;

    let export_functions = detector.get_export_functions();
    println!("   ✅ Found {} export functions", export_functions.len());

    println!("\n📋 Export Functions:");
    for (i, func) in export_functions.iter().take(20).enumerate() {
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

    // .textセクションを探す
    let text_section = pe.sections.iter().find(|s| {
        let name = String::from_utf8_lossy(&s.name);
        name.starts_with(".text")
    });

    if let Some(section) = text_section {
        let file_offset = section.pointer_to_raw_data as usize;
        let function_address = image_base + section.virtual_address as u64;

        println!("\n💾 Testing cache functionality...");
        let cache_dir = env::temp_dir().join("ghidra_mcp_cache_warthunder");
        let binary_path_obj = Path::new(binary_path);

        // Metadata戦略でテスト
        println!("\n📋 Hash Strategy: Metadata (デフォルト)");
        let decompiler = ParallelDecompiler::new(&cache_dir)?;
        println!("   Cache directory: {}", cache_dir.display());

        println!("\n🔄 First decompilation (no cache)...");
        let start = std::time::Instant::now();
        let result1 = decompiler.decompile_function_cached(
            Some(binary_path_obj),
            &binary_data,
            function_address,
            file_offset,
            100,
        )?;
        let duration1 = start.elapsed();
        println!("   ⏱️  Time: {:?}", duration1);
        println!("   ✅ P-code operations: {}", result1.pcode_count);
        println!("   ✅ Basic blocks: {}", result1.block_count);
        println!("   ✅ Type inferences: {}", result1.type_count);
        println!("   ✅ Loops detected: {}", result1.loop_count);

        println!("\n🔄 Second decompilation (with cache)...");
        let start = std::time::Instant::now();
        let result2 = decompiler.decompile_function_cached(
            Some(binary_path_obj),
            &binary_data,
            function_address,
            file_offset,
            100,
        )?;
        let duration2 = start.elapsed();
        println!("   ⏱️  Time: {:?}", duration2);

        if duration2 < duration1 {
            let speedup = duration1.as_micros() as f64 / duration2.as_micros() as f64;
            println!("   🚀 Cache speedup: {:.0}x faster!", speedup);
        }

        // キャッシュ統計
        let cache_stats = decompiler.get_cache_stats();
        println!("\n📈 Cache Statistics:");
        println!("   Memory cached binaries: {}", cache_stats.memory_cached_binaries);
        println!("   Disk cached binaries: {}", cache_stats.disk_cached_binaries);
    } else {
        println!("\n⚠️  .text section not found!");
    }

    println!("\n{}", "=".repeat(70));
    println!("✅ War Thunder analysis complete!");

    Ok(())
}
