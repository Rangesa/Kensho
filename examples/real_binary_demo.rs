/// 螳滄圀縺ｮ繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繧偵ョ繧ｳ繝ｳ繝代う繝ｫ縺吶ｋ繝・Δ
///
/// 菴ｿ逕ｨ譁ｹ豕・
/// cargo run --example real_binary_demo -- <binary_path> <address> <count>
///
/// 萓・
/// cargo run --example real_binary_demo -- "C:\Programming\Cheat\TheFinals\Discovery-d.exe" 0x1000 50

use kensho_mcp::decompiler_prototype::printer::SimplePrinter;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("菴ｿ逕ｨ譁ｹ豕・ cargo run --example real_binary_demo -- <binary_path> [address] [count]");
        println!("\n繝・ヵ繧ｩ繝ｫ繝郁ｨｭ螳・");
        println!("  address: 0x1000");
        println!("  count: 20");
        println!("\n萓・");
        println!("  cargo run --example real_binary_demo -- \"C:\\\\Programming\\\\Cheat\\\\TheFinals\\\\Discovery-d.exe\"");
        return;
    }

    let binary_path = &args[1];
    let address = if args.len() > 2 {
        parse_hex(&args[2]).unwrap_or(0x1000)
    } else {
        0x1000
    };
    let count = if args.len() > 3 {
        args[3].parse().unwrap_or(20)
    } else {
        20
    };

    match analyze_binary(binary_path, address, count) {
        Ok(_) => println!("\n隗｣譫仙ｮ御ｺ・ｼ・),
        Err(e) => eprintln!("繧ｨ繝ｩ繝ｼ: {}", e),
    }
}

/// 繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繧定ｧ｣譫・fn analyze_binary(path: &str, start_addr: u64, instr_count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);

    println!("=== Binary Decompiler Demo ===\n");
    println!("繝輔ぃ繧､繝ｫ: {}", path.display());

    // 繝輔ぃ繧､繝ｫ縺悟ｭ伜惠縺吶ｋ縺狗｢ｺ隱・    if !path.exists() {
        return Err(format!("繝輔ぃ繧､繝ｫ縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ: {}", path.display()).into());
    }

    // 繝輔ぃ繧､繝ｫ繧ｵ繧､繧ｺ繧定｡ｨ遉ｺ
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();
    println!("繝輔ぃ繧､繝ｫ繧ｵ繧､繧ｺ: {} bytes ({} MB)", file_size, file_size / 1_000_000);

    // 繝舌う繝翫Μ繧定ｪｭ縺ｿ霎ｼ繧
    println!("\n繝舌う繝翫Μ繧定ｪｭ縺ｿ霎ｼ縺ｿ荳ｭ...");
    let binary = fs::read(path)?;

    // 繧｢繝峨Ξ繧ｹ縺後ヰ繧､繝翫Μ遽・峇蜀・°遒ｺ隱・    if start_addr as usize >= binary.len() {
        return Err(format!(
            "繧｢繝峨Ξ繧ｹ 0x{:x} 縺後ヰ繧､繝翫Μ遽・峇螟悶〒縺呻ｼ医ヰ繧､繝翫Μ繧ｵ繧､繧ｺ: 0x{:x}・・,
            start_addr,
            binary.len()
        )
        .into());
    }

    // 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ諠・ｱ繧定｡ｨ遉ｺ
    println!("\n=== Binary Format Detection ===");
    detect_format(&binary);

    // 騾・い繧ｻ繝ｳ繝悶Ν・・apstone菴ｿ逕ｨ・・    println!("\n=== Disassembly ===");
    println!("繧｢繝峨Ξ繧ｹ: 0x{:x}", start_addr);
    println!("蜻ｽ莉､謨ｰ: {}\n", instr_count);

    disassemble_section(&binary, start_addr, instr_count)?;

    Ok(())
}

/// 繝舌う繝翫Μ繝輔か繝ｼ繝槭ャ繝医ｒ讀懷・
fn detect_format(binary: &[u8]) {
    if binary.len() < 4 {
        println!("繝輔ぃ繧､繝ｫ縺悟ｰ上＆縺吶℃縺ｾ縺・);
        return;
    }

    // PE 繝輔か繝ｼ繝槭ャ繝・    if binary[0] == 0x4D && binary[1] == 0x5A {
        // MZ signature
        println!("Format: PE (Windows executable)");
        if binary.len() >= 0x3C + 4 {
            let pe_offset = u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
            if pe_offset < binary.len() && binary[pe_offset] == 0x50 && binary[pe_offset + 1] == 0x45 {
                println!("PE Signature found at offset 0x{:x}", pe_offset);
            }
        }
        return;
    }

    // ELF 繝輔か繝ｼ繝槭ャ繝・    if binary.len() >= 4 && binary[0] == 0x7F && binary[1] == 0x45 && binary[2] == 0x4C && binary[3] == 0x46 {
        println!("Format: ELF (Linux executable)");
        return;
    }

    // Mach-O 繝輔か繝ｼ繝槭ャ繝・    if binary.len() >= 4 {
        let magic = u32::from_le_bytes([binary[0], binary[1], binary[2], binary[3]]);
        if magic == 0xFEEDFACF || magic == 0xFEEDFACE {
            println!("Format: Mach-O (macOS executable)");
            return;
        }
    }

    println!("Format: Unknown or Raw binary");
}

/// 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ繧帝・い繧ｻ繝ｳ繝悶Ν
fn disassemble_section(binary: &[u8], start_addr: u64, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    use capstone::prelude::*;

    // Capstone繧ｨ繝ｳ繧ｸ繝ｳ繧貞・譛溷喧・・86-64・・    let cs = Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()?;

    // 繧｢繝峨Ξ繧ｹ縺後ヰ繧､繝翫Μ遽・峇蜀・°遒ｺ隱・    if start_addr as usize >= binary.len() {
        return Err("Address out of bounds".into());
    }

    // 騾・い繧ｻ繝ｳ繝悶Ν
    let code = &binary[start_addr as usize..];
    let insns = cs.disasm_count(code, start_addr, count)?;

    let mut total_disassembled = 0;
    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("???");
        let op_str = insn.op_str().unwrap_or("");

        println!("0x{:x}: {} {}", insn.address(), mnemonic, op_str);
        total_disassembled += 1;
    }

    println!("\n騾・い繧ｻ繝ｳ繝悶Ν縺輔ｌ縺溷多莉､謨ｰ: {}", total_disassembled);

    Ok(())
}

/// 16騾ｲ謨ｰ譁・ｭ怜・繧偵ヱ繝ｼ繧ｹ
fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}
