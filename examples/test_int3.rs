/// int3蜻ｽ莉､蟇ｾ蠢懊ユ繧ｹ繝・/// War Thunder dgs_init_argv_exported髢｢謨ｰ繧貞・蠎ｦ繝・さ繝ｳ繝代う繝ｫ

use anyhow::Result;
use kensho_mcp::decompiler_prototype::parallel_analyzer::ParallelDecompiler;
use std::time::Instant;
use std::path::Path;

fn main() -> Result<()> {
    println!("剥 Testing int3 Instruction Support");
    println!("{}", "=".repeat(80));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let function_address = 0x140001010u64; // dgs_init_argv_exported

    println!("\n刀 Binary: {}", binary_path);
    println!("識 Function: 0x{:X}", function_address);

    // 繝舌う繝翫Μ繧定ｪｭ縺ｿ霎ｼ縺ｿ
    println!("\n当 Loading binary...");
    let binary_data = std::fs::read(binary_path)?;
    println!("   File size: {} MB", binary_data.len() / (1024 * 1024));

    // 繝・さ繝ｳ繝代う繝ｫ螳溯｡・    println!("\n竢ｱ・・ Decompiling...");
    let start = Instant::now();

    let decompiler = ParallelDecompiler::new("cache")?;
    let result = decompiler.decompile_function_cached(
        Some(Path::new(binary_path)),
        &binary_data,
        function_address,
        0x1010,  // file_offset
        2000,    // max_instructions
    )?;

    let elapsed = start.elapsed();

    println!("   笨・Complete in {:.2?}", elapsed);
    println!("\n投 Statistics:");
    println!("   P-code operations: {}", result.pcode_count);
    println!("   Basic blocks: {}", result.block_count);
    println!("   Typed variables: {}", result.type_count);
    println!("   Loops detected: {}", result.loop_count);

    // 繝・さ繝ｳ繝代う繝ｫ邨先棡繧定｡ｨ遉ｺ
    println!("\n統 Control Structure:");
    println!("{}", "=".repeat(80));
    println!("{}", result.control_structure);

    // 隴ｦ蜻翫Γ繝・そ繝ｼ繧ｸ繧偵メ繧ｧ繝・け
    if result.control_structure.contains("Unsupported instruction: int3") {
        println!("\n笶・FAIL: int3 warnings still present!");
    } else if result.control_structure.contains("int3") {
        println!("\n笞・・ WARNING: int3 mentioned but not as unsupported");
    } else {
        println!("\n笨・SUCCESS: No int3 warnings detected!");
    }

    Ok(())
}
