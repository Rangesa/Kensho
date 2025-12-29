/// 繧ｷ繝ｳ繝励Ν縺ｪ騾・い繧ｻ繝ｳ繝悶Ν繝・せ繝・/// 繝輔ぃ繧､繝ｫ縺ｮ隍・焚縺ｮ繧ｪ繝輔そ繝・ヨ繧定ｩｦ縺励※繧ｳ繝ｼ繝峨▲縺ｽ縺・伜沺繧定ｦ九▽縺代ｋ

use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("菴ｿ逕ｨ譁ｹ豕・ cargo run --example simple_disasm -- <binary_path>");
        return;
    }

    let binary_path = &args[1];

    match scan_for_code(binary_path) {
        Ok(_) => println!("\n螳御ｺ・ｼ・),
        Err(e) => eprintln!("繧ｨ繝ｩ繝ｼ: {}", e),
    }
}

/// 繝輔ぃ繧､繝ｫ蜀・〒繧ｳ繝ｼ繝峨▲縺ｽ縺・そ繧ｯ繧ｷ繝ｧ繝ｳ繧呈爾邏｢
fn scan_for_code(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);

    println!("=== Code Section Scanner ===\n");
    println!("繝輔ぃ繧､繝ｫ: {}\n", path.display());

    let binary = fs::read(path)?;
    println!("繝輔ぃ繧､繝ｫ繧ｵ繧､繧ｺ: {} bytes\n", binary.len());

    use capstone::prelude::*;

    // Capstone繧ｨ繝ｳ繧ｸ繝ｳ繧貞・譛溷喧・・86-64・・    let cs = Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()?;

    // 縺・￥縺､縺九・繧ｪ繝輔そ繝・ヨ繧定ｩｦ縺・    let offsets_to_try = vec![
        0x1000, 0x2000, 0x4000, 0x10000, 0x400000, // 繝倥ャ繝繝ｼ蠕後・荳闊ｬ逧・↑繧ｪ繝輔そ繝・ヨ
        1024 * 1024,                                  // 1MB
        512,                                          // 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ髢句ｧ狗峩蠕・    ];

    println!("隍・焚縺ｮ繧ｪ繝輔そ繝・ヨ繧偵せ繧ｭ繝｣繝ｳ荳ｭ...\n");

    let mut found_any = false;

    for offset in offsets_to_try {
        if offset >= binary.len() {
            continue;
        }

        let code = &binary[offset..];

        // 譛螟ｧ30蜻ｽ莉､繧定ｩｦ縺・        if let Ok(insns) = cs.disasm_count(code, offset as u64, 30) {
            let count = insns.iter().count();

            if count > 5 {
                // 5蜻ｽ莉､莉･荳企・い繧ｻ繝ｳ繝悶Ν縺ｧ縺阪◆繧芽｡ｨ遉ｺ
                found_any = true;
                println!("笨・繧ｪ繝輔そ繝・ヨ 0x{:08x} - {} 蜻ｽ莉､騾・い繧ｻ繝ｳ繝悶Ν謌仙粥", offset, count);
                println!("  譛蛻昴・5蜻ｽ莉､:");

                for (i, insn) in insns.iter().take(5).enumerate() {
                    let mnemonic = insn.mnemonic().unwrap_or("???");
                    let op_str = insn.op_str().unwrap_or("");
                    println!("    [{}] 0x{:x}: {} {}", i, insn.address(), mnemonic, op_str);
                }
                println!();
            }
        }
    }

    if !found_any {
        println!("笞・・ 繧ｳ繝ｼ繝峨そ繧ｯ繧ｷ繝ｧ繝ｳ縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ縺ｧ縺励◆");
        println!("\n縺薙・繝輔ぃ繧､繝ｫ縺ｯ莉･荳九・蜿ｯ閭ｽ諤ｧ縺後≠繧翫∪縺・");
        println!("  - 繝代ャ繧ｭ繝ｳ繧ｰ/蝨ｧ邵ｮ縺輔ｌ縺ｦ縺・ｋ");
        println!("  - 髮｣隱ｭ蛹悶＆繧後※縺・ｋ");
        println!("  - 繝阪う繝・ぅ繝悶さ繝ｼ繝峨ｒ蜷ｫ縺ｾ縺ｪ縺・ｼ医せ繧ｯ繝ｪ繝励ヨ縺ｪ縺ｩ・・);
    }

    Ok(())
}
