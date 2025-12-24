/// デコンパイラのデモプログラム
/// Discovery-d.exeの特定の関数をデコンパイルする

use anyhow::Result;
use ghidra_mcp::decompiler_prototype::{
    CapstoneTranslator, SSATransform, TypeInference,
    ControlFlowAnalyzer, ControlStructurePrinter, ControlFlowGraph
};

fn main() -> Result<()> {
    println!("🦀 Ghidra Native Decompiler - Demo");
    println!("{}", "=".repeat(60));

    // バイナリファイルのパス
    let binary_path = r"C:\Programming\Cheat\TheFinals\Discovery-d.exe";

    // デコンパイル対象のアドレス
    // .textセクションの開始: ファイルオフセット 0x600, VA 0x140001000
    let target_file_offset = 0x600; // .textセクションの開始
    let target_address = 0x140001000; // 仮想アドレス
    let max_instructions = 100; // 命令数を増やす

    println!("\n📂 Binary: {}", binary_path);
    println!("🎯 Target File Offset: 0x{:X}", target_file_offset);
    println!("🎯 Target Virtual Address: 0x{:X}", target_address);
    println!("📊 Max Instructions: {}", max_instructions);
    println!();

    // バイナリファイルを読み込み
    println!("📖 Loading binary...");
    let binary_data = std::fs::read(binary_path)?;
    println!("   Size: {} bytes ({} MB)", binary_data.len(), binary_data.len() / 1_000_000);

    // Capstone Translatorを初期化
    println!("\n🔧 Initializing Capstone Translator...");
    let mut translator = CapstoneTranslator::new()?;

    // 関数のコードを抽出（ファイルオフセットを使用）
    let offset = target_file_offset;
    let code_slice = if offset < binary_data.len() {
        let end = std::cmp::min(offset + max_instructions * 15, binary_data.len());
        println!("   Extracting code from file offset 0x{:X} to 0x{:X}", offset, end);
        &binary_data[offset..end]
    } else {
        println!("   ⚠️ File offset out of bounds!");
        &[]
    };

    if code_slice.is_empty() {
        println!("❌ No code to analyze");
        return Ok(());
    }

    // P-codeに変換
    println!("\n🔄 Translating to P-code...");
    let pcodes = match translator.translate(code_slice, target_address, max_instructions) {
        Ok(p) => {
            println!("   ✅ Generated {} P-code operations", p.len());
            p
        }
        Err(e) => {
            println!("   ❌ Translation failed: {}", e);
            return Err(e);
        }
    };

    if pcodes.is_empty() {
        println!("   ⚠️ No P-code generated");
        return Ok(());
    }

    // 最初のいくつかのP-code命令を表示
    println!("\n📝 First 10 P-code operations:");
    for (i, op) in pcodes.iter().take(10).enumerate() {
        println!("   [{}] {:?}", i, op);
    }

    // CFGを構築
    println!("\n🌐 Building Control Flow Graph...");
    let mut cfg = ControlFlowGraph::from_pcodes(pcodes.clone());
    println!("   ✅ CFG built with {} basic blocks", cfg.blocks.len());

    // SSA変換
    println!("\n🔀 Performing SSA transformation...");
    let mut ssa = SSATransform::new();
    ssa.transform(&mut cfg);
    println!("   ✅ SSA transformation complete");

    // 型推論
    println!("\n🔍 Running type inference...");
    let mut type_inference = TypeInference::new();
    type_inference.run(&pcodes);
    let type_count = type_inference.get_all_types().len();
    println!("   ✅ Inferred types for {} varnodes", type_count);

    // 型情報を表示（最初の10個）
    println!("\n📊 Type inference results (first 10):");
    for (i, (varnode, ty)) in type_inference.get_all_types().iter().enumerate().take(10) {
        println!("   [{}] {:?} :: {}", i, varnode, ty.to_c_string());
    }

    // 制御構造検出
    println!("\n🏗️ Detecting control structures...");
    let mut analyzer = ControlFlowAnalyzer::new();
    let structure = analyzer.analyze(&cfg);
    let loops_detected = analyzer.get_loops().len();
    println!("   ✅ Detected {} loops", loops_detected);

    // 制御構造を表示
    println!("\n📐 Control structure:");
    let mut printer = ControlStructurePrinter::new();
    let structure_str = printer.print(&structure);
    println!("{}", structure_str);

    println!("\n{}", "=".repeat(60));
    println!("✅ Decompilation complete!");
    println!("\n📈 Summary:");
    println!("   - P-code operations: {}", pcodes.len());
    println!("   - Basic blocks: {}", cfg.blocks.len());
    println!("   - Type inferences: {}", type_count);
    println!("   - Loops detected: {}", loops_detected);

    Ok(())
}
