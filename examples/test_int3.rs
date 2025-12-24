/// int3命令対応テスト
/// War Thunder dgs_init_argv_exported関数を再度デコンパイル

use anyhow::Result;
use ghidra_mcp::decompiler_prototype::parallel_analyzer::ParallelDecompiler;
use std::time::Instant;
use std::path::Path;

fn main() -> Result<()> {
    println!("🔍 Testing int3 Instruction Support");
    println!("{}", "=".repeat(80));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let function_address = 0x140001010u64; // dgs_init_argv_exported

    println!("\n📁 Binary: {}", binary_path);
    println!("🎯 Function: 0x{:X}", function_address);

    // バイナリを読み込み
    println!("\n📖 Loading binary...");
    let binary_data = std::fs::read(binary_path)?;
    println!("   File size: {} MB", binary_data.len() / (1024 * 1024));

    // デコンパイル実行
    println!("\n⏱️  Decompiling...");
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

    println!("   ✅ Complete in {:.2?}", elapsed);
    println!("\n📊 Statistics:");
    println!("   P-code operations: {}", result.pcode_count);
    println!("   Basic blocks: {}", result.block_count);
    println!("   Typed variables: {}", result.type_count);
    println!("   Loops detected: {}", result.loop_count);

    // デコンパイル結果を表示
    println!("\n📝 Control Structure:");
    println!("{}", "=".repeat(80));
    println!("{}", result.control_structure);

    // 警告メッセージをチェック
    if result.control_structure.contains("Unsupported instruction: int3") {
        println!("\n❌ FAIL: int3 warnings still present!");
    } else if result.control_structure.contains("int3") {
        println!("\n⚠️  WARNING: int3 mentioned but not as unsupported");
    } else {
        println!("\n✅ SUCCESS: No int3 warnings detected!");
    }

    Ok(())
}
