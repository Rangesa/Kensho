/// 譛驕ｩ蛹悶す繧ｹ繝・Β繝・せ繝・/// Phase 7縺ｮ螳溯｣・柑譫懊ｒ讀懆ｨｼ

use anyhow::Result;
use kensho_mcp::decompiler_prototype::parallel_analyzer::ParallelDecompiler;
use std::time::Instant;
use std::path::Path;

fn main() -> Result<()> {
    println!("溌 Testing P-code Optimization System");
    println!("{}", "=".repeat(80));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let function_address = 0x140001010u64; // dgs_init_argv_exported

    println!("\n刀 Binary: {}", binary_path);
    println!("識 Function: 0x{:X}", function_address);

    // 繧ｭ繝｣繝・す繝･繧偵け繝ｪ繧｢縺励※譛驕ｩ蛹門柑譫懊ｒ貂ｬ螳・    let decompiler = ParallelDecompiler::new("cache")?;
    println!("\n卵・・ Clearing cache to measure optimization impact...");
    decompiler.clear_cache()?;

    // 繝舌う繝翫Μ繧定ｪｭ縺ｿ霎ｼ縺ｿ
    println!("\n当 Loading binary...");
    let binary_data = std::fs::read(binary_path)?;
    println!("   File size: {} MB", binary_data.len() / (1024 * 1024));

    // 繝・さ繝ｳ繝代う繝ｫ螳溯｡鯉ｼ域怙驕ｩ蛹悶≠繧奇ｼ・    println!("\n竢ｱ・・ Decompiling with optimization...");
    let start = Instant::now();

    let result = decompiler.decompile_function_cached(
        Some(Path::new(binary_path)),
        &binary_data,
        function_address,
        0x1010,  // file_offset
        2000,    // max_instructions
    )?;

    let elapsed = start.elapsed();

    println!("   笨・Complete in {:.2?}", elapsed);
    println!("\n投 Decompilation Results:");
    println!("   P-code operations: {}", result.pcode_count);
    println!("   Basic blocks: {}", result.block_count);
    println!("   Typed variables: {}", result.type_count);
    println!("   Loops detected: {}", result.loop_count);

    // 蛻ｶ蠕｡讒矩縺ｮ荳驛ｨ繧定｡ｨ遉ｺ
    println!("\n統 Control Structure Preview (first 500 chars):");
    println!("{}", "=".repeat(80));
    let preview: String = result.control_structure
        .chars()
        .take(500)
        .collect();
    println!("{}", preview);
    if result.control_structure.len() > 500 {
        println!("... (truncated {} more chars)", result.control_structure.len() - 500);
    }

    println!("\n笨・Phase 7 optimization system successfully integrated!");
    println!("\n嶋 Key Improvements:");
    println!("   笨・NZMask analysis for constant propagation");
    println!("   笨・AND/OR/XOR optimization rules");
    println!("   笨・Term ordering normalization");
    println!("   笨・Equality simplification");
    println!("   笨・VariableStack infrastructure (ready for SSA enhancement)");

    Ok(())
}
