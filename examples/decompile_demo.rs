/// 繝・さ繝ｳ繝代う繝ｩ縺ｮ繝・Δ繝励Ο繧ｰ繝ｩ繝
/// Discovery-d.exe縺ｮ迚ｹ螳壹・髢｢謨ｰ繧偵ョ繧ｳ繝ｳ繝代う繝ｫ縺吶ｋ

use anyhow::Result;
use kensho_mcp::decompiler_prototype::{
    CapstoneTranslator, SSATransform, TypeInference,
    ControlFlowAnalyzer, ControlStructurePrinter, ControlFlowGraph
};

fn main() -> Result<()> {
    println!("ｦ Ghidra Native Decompiler - Demo");
    println!("{}", "=".repeat(60));

    // 繝舌う繝翫Μ繝輔ぃ繧､繝ｫ縺ｮ繝代せ
    let binary_path = r"C:\Programming\Cheat\TheFinals\Discovery-d.exe";

    // 繝・さ繝ｳ繝代う繝ｫ蟇ｾ雎｡縺ｮ繧｢繝峨Ξ繧ｹ
    // .text繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｮ髢句ｧ・ 繝輔ぃ繧､繝ｫ繧ｪ繝輔そ繝・ヨ 0x600, VA 0x140001000
    let target_file_offset = 0x600; // .text繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｮ髢句ｧ・    let target_address = 0x140001000; // 莉ｮ諠ｳ繧｢繝峨Ξ繧ｹ
    let max_instructions = 100; // 蜻ｽ莉､謨ｰ繧貞｢励ｄ縺・
    println!("\n唐 Binary: {}", binary_path);
    println!("識 Target File Offset: 0x{:X}", target_file_offset);
    println!("識 Target Virtual Address: 0x{:X}", target_address);
    println!("投 Max Instructions: {}", max_instructions);
    println!();

    // 繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繧定ｪｭ縺ｿ霎ｼ縺ｿ
    println!("当 Loading binary...");
    let binary_data = std::fs::read(binary_path)?;
    println!("   Size: {} bytes ({} MB)", binary_data.len(), binary_data.len() / 1_000_000);

    // Capstone Translator繧貞・譛溷喧
    println!("\n肌 Initializing Capstone Translator...");
    let mut translator = CapstoneTranslator::new()?;

    // 髢｢謨ｰ縺ｮ繧ｳ繝ｼ繝峨ｒ謚ｽ蜃ｺ・医ヵ繧｡繧､繝ｫ繧ｪ繝輔そ繝・ヨ繧剃ｽｿ逕ｨ・・    let offset = target_file_offset;
    let code_slice = if offset < binary_data.len() {
        let end = std::cmp::min(offset + max_instructions * 15, binary_data.len());
        println!("   Extracting code from file offset 0x{:X} to 0x{:X}", offset, end);
        &binary_data[offset..end]
    } else {
        println!("   笞・・File offset out of bounds!");
        &[]
    };

    if code_slice.is_empty() {
        println!("笶・No code to analyze");
        return Ok(());
    }

    // P-code縺ｫ螟画鋤
    println!("\n売 Translating to P-code...");
    let pcodes = match translator.translate(code_slice, target_address, max_instructions) {
        Ok(p) => {
            println!("   笨・Generated {} P-code operations", p.len());
            p
        }
        Err(e) => {
            println!("   笶・Translation failed: {}", e);
            return Err(e);
        }
    };

    if pcodes.is_empty() {
        println!("   笞・・No P-code generated");
        return Ok(());
    }

    // 譛蛻昴・縺・￥縺､縺九・P-code蜻ｽ莉､繧定｡ｨ遉ｺ
    println!("\n統 First 10 P-code operations:");
    for (i, op) in pcodes.iter().take(10).enumerate() {
        println!("   [{}] {:?}", i, op);
    }

    // CFG繧呈ｧ狗ｯ・    println!("\n倹 Building Control Flow Graph...");
    let mut cfg = ControlFlowGraph::from_pcodes(pcodes.clone());
    println!("   笨・CFG built with {} basic blocks", cfg.blocks.len());

    // SSA螟画鋤
    println!("\n楳 Performing SSA transformation...");
    let mut ssa = SSATransform::new();
    ssa.transform(&mut cfg);
    println!("   笨・SSA transformation complete");

    // 蝙区耳隲・    println!("\n剥 Running type inference...");
    let mut type_inference = TypeInference::new();
    type_inference.run(&pcodes);
    let type_count = type_inference.get_all_types().len();
    println!("   笨・Inferred types for {} varnodes", type_count);

    // 蝙区ュ蝣ｱ繧定｡ｨ遉ｺ・域怙蛻昴・10蛟具ｼ・    println!("\n投 Type inference results (first 10):");
    for (i, (varnode, ty)) in type_inference.get_all_types().iter().enumerate().take(10) {
        println!("   [{}] {:?} :: {}", i, varnode, ty.to_c_string());
    }

    // 蛻ｶ蠕｡讒矩讀懷・
    println!("\n女・・Detecting control structures...");
    let mut analyzer = ControlFlowAnalyzer::new();
    let structure = analyzer.analyze(&cfg);
    let loops_detected = analyzer.get_loops().len();
    println!("   笨・Detected {} loops", loops_detected);

    // 蛻ｶ蠕｡讒矩繧定｡ｨ遉ｺ
    println!("\n盗 Control structure:");
    let mut printer = ControlStructurePrinter::new();
    let structure_str = printer.print(&structure);
    println!("{}", structure_str);

    println!("\n{}", "=".repeat(60));
    println!("笨・Decompilation complete!");
    println!("\n嶋 Summary:");
    println!("   - P-code operations: {}", pcodes.len());
    println!("   - Basic blocks: {}", cfg.blocks.len());
    println!("   - Type inferences: {}", type_count);
    println!("   - Loops detected: {}", loops_detected);

    Ok(())
}
