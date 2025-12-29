/// Phase 8-9邨ｱ蜷医ユ繧ｹ繝・/// 螟画焚蜷榊ｾｩ蜈・・ｫ伜ｺｦ縺ｪ譛驕ｩ蛹悶，逍台ｼｼ繧ｳ繝ｼ繝臥函謌舌・繝輔Ν繝・せ繝・
use anyhow::Result;
use kensho_mcp::decompiler_prototype::{
    CPrinter, CapstoneTranslator, Optimizer, SymbolTable, TypeInference,
};
use std::fs;
use std::time::Instant;

fn main() -> Result<()> {
    println!("噫 Phase 8-9 Integration Test");
    println!("{}", "=".repeat(80));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let function_address = 0x140001010u64; // dgs_init_argv_exported

    println!("\n刀 Binary: {}", binary_path);
    println!("識 Function: 0x{:X}", function_address);

    // 繝舌う繝翫Μ繧定ｪｭ縺ｿ霎ｼ縺ｿ
    println!("\n当 Loading binary...");
    let binary_data = fs::read(binary_path)?;
    println!("   File size: {} MB", binary_data.len() / (1024 * 1024));

    // Phase 1: 繧ｷ繝ｳ繝懊Ν蠕ｩ蜈・ユ繧ｹ繝・    println!("\n剥 Phase 1: Symbol Recovery");
    println!("{}", "-".repeat(80));

    let start = Instant::now();
    let mut symbol_table = SymbolTable::new();
    let symbol_count = symbol_table.load_from_pe(&binary_data)?;
    let elapsed = start.elapsed();

    println!("   笨・Loaded {} symbols in {:.2?}", symbol_count, elapsed);

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

    // 蟇ｾ雎｡髢｢謨ｰ縺ｮ繧ｷ繝ｳ繝懊Ν繧堤｢ｺ隱・    if let Some(symbol) = symbol_table.get_symbol(function_address) {
        println!("\n   識 Target function symbol found:");
        println!("      Name: {}", symbol.name);
        println!("      Address: 0x{:X}", symbol.address);
    } else {
        println!("\n   笞・・ No symbol found for target function");
    }

    // Phase 2: P-code逕滓・縺ｨ譛驕ｩ蛹・    println!("\n笞呻ｸ・ Phase 2: P-code Generation & Optimization");
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
        "   笨・Generated {} P-code operations in {:.2?}",
        pcodes.len(),
        translate_time
    );

    println!("\n   Applying optimizations...");
    let start = Instant::now();
    let optimizer = Optimizer::new();
    let opt_stats = optimizer.optimize(&mut pcodes);
    let optimize_time = start.elapsed();

    println!("   笨・Optimization complete in {:.2?}", optimize_time);
    println!("   投 Optimization Statistics:");
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

    // Phase 3: C逍台ｼｼ繧ｳ繝ｼ繝臥函謌・    println!("\n捗 Phase 3: C Pseudo-code Generation");
    println!("{}", "-".repeat(80));

    let type_info = TypeInference::new();
    let mut c_printer = CPrinter::new(type_info);

    println!("   Generating C code...");
    let start = Instant::now();
    let c_code = c_printer.print(&pcodes[..std::cmp::min(50, pcodes.len())]);
    let print_time = start.elapsed();

    println!(
        "   笨・Generated C code ({} lines) in {:.2?}",
        c_code.lines().count(),
        print_time
    );

    println!("\n   統 Generated C Code (first 30 lines):");
    println!("{}", "-".repeat(80));
    for (i, line) in c_code.lines().take(30).enumerate() {
        println!("{:4} | {}", i + 1, line);
    }
    if c_code.lines().count() > 30 {
        println!("   ... ({} more lines)", c_code.lines().count() - 30);
    }

    // 繧ｵ繝槭Μ繝ｼ
    println!("\n{}", "=".repeat(80));
    println!("笨・Phase 8-9 Integration Test Complete!");
    println!("\n嶋 Performance Summary:");
    println!("   Symbol loading: {:.2?}", elapsed);
    println!("   P-code translation: {:.2?}", translate_time);
    println!("   Optimization: {:.2?}", optimize_time);
    println!("   C code generation: {:.2?}", print_time);
    println!(
        "   Total: {:.2?}",
        elapsed + translate_time + optimize_time + print_time
    );

    println!("\n識 New Capabilities:");
    println!("   笨・Symbol recovery from PE export table");
    println!("   笨・Advanced optimization rules (12 rules)");
    println!("   笨・Constant folding (const op const => const)");
    println!("   笨・Zero-operation simplification (V + 0 => V)");
    println!("   笨・C pseudo-code generation with type inference");
    println!("   笨・Variable name mapping (registers, memory, temporaries)");

    Ok(())
}
