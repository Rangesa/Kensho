/// Phase 10統合テスト
/// Def-Use Chain、Copy Propagation、Switch文復元のフルテスト

use anyhow::Result;
use ghidra_mcp::decompiler_prototype::{
    CapstoneTranslator, CopyPropagation, DefUseChain, JumpTableDetector, SwitchPrinter,
};
use std::fs;
use std::time::Instant;

fn main() -> Result<()> {
    println!("🚀 Phase 10 Integration Test");
    println!("{}", "=".repeat(80));
    println!("Def-Use Chain & Switch Statement Recovery");
    println!();

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let function_address = 0x140001010u64;

    println!("📁 Binary: {}", binary_path);
    println!("🎯 Function: 0x{:X}", function_address);

    // バイナリを読み込み
    println!("\n📖 Loading binary...");
    let binary_data = fs::read(binary_path)?;
    println!("   File size: {} MB", binary_data.len() / (1024 * 1024));

    // P-code生成
    println!("\n⚙️  Phase 1: P-code Generation");
    println!("{}", "-".repeat(80));

    let file_offset = 0x1010usize;
    let max_instructions = 2000;

    let code_slice = if file_offset < binary_data.len() {
        let end = std::cmp::min(file_offset + max_instructions * 15, binary_data.len());
        &binary_data[file_offset..end]
    } else {
        &[]
    };

    let start = Instant::now();
    let mut translator = CapstoneTranslator::new()?;
    let pcodes = translator.translate(code_slice, function_address, max_instructions)?;
    let translate_time = start.elapsed();

    println!(
        "   ✅ Generated {} P-code operations in {:.2?}",
        pcodes.len(),
        translate_time
    );

    // Def-Use Chain構築
    println!("\n🔗 Phase 2: Def-Use Chain Construction");
    println!("{}", "-".repeat(80));

    let start = Instant::now();
    let mut du_chain = DefUseChain::new();
    du_chain.build(&pcodes);
    let du_time = start.elapsed();

    let stats = du_chain.stats();
    println!("   ✅ Built Def-Use Chain in {:.2?}", du_time);
    println!("\n   📊 Data Flow Statistics:");
    println!("      Total operations: {}", stats.total_ops);
    println!("      Total definitions: {}", stats.total_defs);
    println!("      Total uses: {}", stats.total_uses);
    println!("      Unused definitions: {} ({:.1}%)",
        stats.unused_defs,
        (stats.unused_defs as f64 / stats.total_defs as f64) * 100.0
    );
    println!("      Single-use definitions: {} ({:.1}%)",
        stats.single_use_defs,
        (stats.single_use_defs as f64 / stats.total_defs as f64) * 100.0
    );

    // Copy Propagation
    println!("\n📋 Phase 3: Copy Propagation");
    println!("{}", "-".repeat(80));

    let start = Instant::now();
    let mut pcodes_copy = pcodes.clone();
    let mut copy_prop = CopyPropagation::new(du_chain.clone());
    let propagations = copy_prop.apply(&mut pcodes_copy);
    let copy_time = start.elapsed();

    println!("   ✅ Copy propagation complete in {:.2?}", copy_time);
    println!("      Propagations performed: {}", propagations);

    if propagations > 0 {
        let reduction = (propagations as f64 / pcodes.len() as f64) * 100.0;
        println!("      Instruction reduction potential: {:.1}%", reduction);
    }

    // ジャンプテーブル検出
    println!("\n🎯 Phase 4: Jump Table Detection");
    println!("{}", "-".repeat(80));

    let start = Instant::now();
    let detector = JumpTableDetector::new(du_chain.clone());
    let jump_tables = detector.detect(&pcodes);
    let detect_time = start.elapsed();

    println!(
        "   ✅ Jump table detection complete in {:.2?}",
        detect_time
    );
    println!("      Jump tables found: {}", jump_tables.len());

    if !jump_tables.is_empty() {
        println!("\n      Jump Table Details:");
        for (i, table) in jump_tables.iter().enumerate() {
            println!("      Table {}: ", i + 1);
            println!("        Address: 0x{:X}", table.table_address);
            println!("        Entries: {}", table.num_entries);
            println!("        Entry size: {} bytes", table.entry_size);
        }
    }

    // Switch文復元
    if !jump_tables.is_empty() {
        println!("\n💻 Phase 5: Switch Statement Recovery");
        println!("{}", "-".repeat(80));

        let start = Instant::now();
        let mut printer = SwitchPrinter::new();

        for (i, table) in jump_tables.iter().enumerate() {
            let switch = detector.recover_switch(table);
            let code = printer.print(&switch);

            println!("\n   Switch Statement {}:", i + 1);
            println!("{}", "-".repeat(60));
            for (line_no, line) in code.lines().enumerate() {
                println!("   {:3} | {}", line_no + 1, line);
            }
        }

        let switch_time = start.elapsed();
        println!("\n   ✅ Switch recovery complete in {:.2?}", switch_time);
    } else {
        println!("\n   ℹ️  No switch statements detected in this function");
    }

    // パフォーマンスサマリー
    println!("\n{}", "=".repeat(80));
    println!("✅ Phase 10 Integration Test Complete!");
    println!("\n📈 Performance Summary:");
    println!("   P-code generation: {:.2?}", translate_time);
    println!("   Def-Use Chain: {:.2?}", du_time);
    println!("   Copy propagation: {:.2?}", copy_time);
    println!("   Jump table detection: {:.2?}", detect_time);
    println!(
        "   Total: {:.2?}",
        translate_time + du_time + copy_time + detect_time
    );

    println!("\n🎯 New Capabilities:");
    println!("   ✓ Def-Use Chain construction (definition-use tracking)");
    println!("   ✓ Data flow analysis (reachability, single-use detection)");
    println!("   ✓ Copy propagation optimization");
    println!("   ✓ Jump table pattern detection");
    println!("   ✓ Switch-case structure recovery");
    println!("   ✓ Switch statement C pseudo-code generation");

    Ok(())
}
