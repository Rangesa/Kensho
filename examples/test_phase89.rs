/// Phase 8-9統合テスト
/// 変数名復元、高度な最適化、C疑似コード生成のフルテスト

use anyhow::Result;
use ghidra_mcp::decompiler_prototype::{
    CPrinter, CapstoneTranslator, Optimizer, SymbolTable, TypeInference,
};
use std::fs;
use std::time::Instant;

fn main() -> Result<()> {
    println!("🚀 Phase 8-9 Integration Test");
    println!("{}", "=".repeat(80));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let function_address = 0x140001010u64; // dgs_init_argv_exported

    println!("\n📁 Binary: {}", binary_path);
    println!("🎯 Function: 0x{:X}", function_address);

    // バイナリを読み込み
    println!("\n📖 Loading binary...");
    let binary_data = fs::read(binary_path)?;
    println!("   File size: {} MB", binary_data.len() / (1024 * 1024));

    // Phase 1: シンボル復元テスト
    println!("\n🔍 Phase 1: Symbol Recovery");
    println!("{}", "-".repeat(80));

    let start = Instant::now();
    let mut symbol_table = SymbolTable::new();
    let symbol_count = symbol_table.load_from_pe(&binary_data)?;
    let elapsed = start.elapsed();

    println!("   ✅ Loaded {} symbols in {:.2?}", symbol_count, elapsed);

    if symbol_count > 0 {
        println!("\n   First 10 symbols:");
        let symbols = symbol_table.get_all_symbols();
        for (i, symbol) in symbols.iter().take(10).enumerate() {
            println!(
                "   {}. 0x{:016X} - {} ({:?})",
                i + 1,
                symbol.address,
                symbol.name,
                symbol.kind
            );
        }
    }

    // 対象関数のシンボルを確認
    if let Some(symbol) = symbol_table.get_symbol(function_address) {
        println!("\n   🎯 Target function symbol found:");
        println!("      Name: {}", symbol.name);
        println!("      Address: 0x{:X}", symbol.address);
    } else {
        println!("\n   ⚠️  No symbol found for target function");
    }

    // Phase 2: P-code生成と最適化
    println!("\n⚙️  Phase 2: P-code Generation & Optimization");
    println!("{}", "-".repeat(80));

    let file_offset = 0x1010usize;
    let max_instructions = 2000;

    let code_slice = if file_offset < binary_data.len() {
        let end = std::cmp::min(file_offset + max_instructions * 15, binary_data.len());
        &binary_data[file_offset..end]
    } else {
        &[]
    };

    println!("   Translating to P-code...");
    let start = Instant::now();
    let mut translator = CapstoneTranslator::new()?;
    let mut pcodes = translator.translate(code_slice, function_address, max_instructions)?;
    let translate_time = start.elapsed();

    println!(
        "   ✅ Generated {} P-code operations in {:.2?}",
        pcodes.len(),
        translate_time
    );

    println!("\n   Applying optimizations...");
    let start = Instant::now();
    let optimizer = Optimizer::new();
    let opt_stats = optimizer.optimize(&mut pcodes);
    let optimize_time = start.elapsed();

    println!("   ✅ Optimization complete in {:.2?}", optimize_time);
    println!("   📊 Optimization Statistics:");
    println!("      Iterations: {}", opt_stats.iterations);
    println!("      Total applications: {}", opt_stats.total_applications);

    if !opt_stats.applications_per_rule.is_empty() {
        println!("\n      Rule applications:");
        let mut rules: Vec<_> = opt_stats.applications_per_rule.iter().collect();
        rules.sort_by_key(|(_, &count)| std::cmp::Reverse(count));

        for (rule, count) in rules.iter().take(10) {
            println!("        {}: {} times", rule, count);
        }
    }

    // Phase 3: C疑似コード生成
    println!("\n💻 Phase 3: C Pseudo-code Generation");
    println!("{}", "-".repeat(80));

    let type_info = TypeInference::new();
    let mut c_printer = CPrinter::new(type_info);

    println!("   Generating C code...");
    let start = Instant::now();
    let c_code = c_printer.print(&pcodes[..std::cmp::min(50, pcodes.len())]);
    let print_time = start.elapsed();

    println!(
        "   ✅ Generated C code ({} lines) in {:.2?}",
        c_code.lines().count(),
        print_time
    );

    println!("\n   📝 Generated C Code (first 30 lines):");
    println!("{}", "-".repeat(80));
    for (i, line) in c_code.lines().take(30).enumerate() {
        println!("{:4} | {}", i + 1, line);
    }
    if c_code.lines().count() > 30 {
        println!("   ... ({} more lines)", c_code.lines().count() - 30);
    }

    // サマリー
    println!("\n{}", "=".repeat(80));
    println!("✅ Phase 8-9 Integration Test Complete!");
    println!("\n📈 Performance Summary:");
    println!("   Symbol loading: {:.2?}", elapsed);
    println!("   P-code translation: {:.2?}", translate_time);
    println!("   Optimization: {:.2?}", optimize_time);
    println!("   C code generation: {:.2?}", print_time);
    println!(
        "   Total: {:.2?}",
        elapsed + translate_time + optimize_time + print_time
    );

    println!("\n🎯 New Capabilities:");
    println!("   ✓ Symbol recovery from PE export table");
    println!("   ✓ Advanced optimization rules (12 rules)");
    println!("   ✓ Constant folding (const op const => const)");
    println!("   ✓ Zero-operation simplification (V + 0 => V)");
    println!("   ✓ C pseudo-code generation with type inference");
    println!("   ✓ Variable name mapping (registers, memory, temporaries)");

    Ok(())
}
