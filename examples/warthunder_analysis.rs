/// War Thunder aces.exe隗｣譫舌ョ繝｢
/// 繧ｨ繧ｯ繧ｹ繝昴・繝磯未謨ｰ讀懷・縲√ョ繧ｳ繝ｳ繝代う繝ｫ縲√く繝｣繝・す繝･讖溯・縺ｮ繝・せ繝・
use anyhow::Result;
use kensho_mcp::decompiler_prototype::{
    FunctionDetector, ParallelDecompiler, HashStrategy
};
use goblin::pe::PE;
use std::env;
use std::path::Path;

fn main() -> Result<()> {
    println!("式 War Thunder aces.exe Analysis");
    println!("{}", "=".repeat(70));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";

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

    // 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ諠・ｱ
    println!("\n搭 Sections: {}", pe.sections.len());
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name);
        let name = name.trim_end_matches('\0');
        println!("   - {} @ 0x{:X} (size: 0x{:X})",
            name, section.virtual_address, section.virtual_size);
    }

    // 繧ｨ繧ｯ繧ｹ繝昴・繝磯未謨ｰ繧呈､懷・
    println!("\n豆 Detecting export functions...");
    let mut detector = FunctionDetector::new();
    detector.detect_exports(&pe, image_base)?;

    let export_functions = detector.get_export_functions();
    println!("   笨・Found {} export functions", export_functions.len());

    println!("\n搭 Export Functions:");
    for (i, func) in export_functions.iter().take(20).enumerate() {
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

    // .text繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ繧呈爾縺・    let text_section = pe.sections.iter().find(|s| {
        let name = String::from_utf8_lossy(&s.name);
        name.starts_with(".text")
    });

    if let Some(section) = text_section {
        let file_offset = section.pointer_to_raw_data as usize;
        let function_address = image_base + section.virtual_address as u64;

        println!("\n沈 Testing cache functionality...");
        let cache_dir = env::temp_dir().join("kensho_mcp_cache_warthunder");
        let binary_path_obj = Path::new(binary_path);

        // Metadata謌ｦ逡･縺ｧ繝・せ繝・        println!("\n搭 Hash Strategy: Metadata (繝・ヵ繧ｩ繝ｫ繝・");
        let decompiler = ParallelDecompiler::new(&cache_dir)?;
        println!("   Cache directory: {}", cache_dir.display());

        println!("\n売 First decompilation (no cache)...");
        let start = std::time::Instant::now();
        let result1 = decompiler.decompile_function_cached(
            Some(binary_path_obj),
            &binary_data,
            function_address,
            file_offset,
            100,
        )?;
        let duration1 = start.elapsed();
        println!("   竢ｱ・・ Time: {:?}", duration1);
        println!("   笨・P-code operations: {}", result1.pcode_count);
        println!("   笨・Basic blocks: {}", result1.block_count);
        println!("   笨・Type inferences: {}", result1.type_count);
        println!("   笨・Loops detected: {}", result1.loop_count);

        println!("\n売 Second decompilation (with cache)...");
        let start = std::time::Instant::now();
        let result2 = decompiler.decompile_function_cached(
            Some(binary_path_obj),
            &binary_data,
            function_address,
            file_offset,
            100,
        )?;
        let duration2 = start.elapsed();
        println!("   竢ｱ・・ Time: {:?}", duration2);

        if duration2 < duration1 {
            let speedup = duration1.as_micros() as f64 / duration2.as_micros() as f64;
            println!("   噫 Cache speedup: {:.0}x faster!", speedup);
        }

        // 繧ｭ繝｣繝・す繝･邨ｱ險・        let cache_stats = decompiler.get_cache_stats();
        println!("\n嶋 Cache Statistics:");
        println!("   Memory cached binaries: {}", cache_stats.memory_cached_binaries);
        println!("   Disk cached binaries: {}", cache_stats.disk_cached_binaries);
    } else {
        println!("\n笞・・ .text section not found!");
    }

    println!("\n{}", "=".repeat(70));
    println!("笨・War Thunder analysis complete!");

    Ok(())
}
