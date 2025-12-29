/// PE螳溯｡悟庄閭ｽ繝輔ぃ繧､繝ｫ縺ｮ讒矩繧呈爾邏｢
///
/// 菴ｿ逕ｨ譁ｹ豕・
/// cargo run --example pe_explorer -- <binary_path>

use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("菴ｿ逕ｨ譁ｹ豕・ cargo run --example pe_explorer -- <binary_path>");
        println!("\n萓・");
        println!("  cargo run --example pe_explorer -- \"C:\\\\Programming\\\\Cheat\\\\TheFinals\\\\Discovery-d.exe\"");
        return;
    }

    let binary_path = &args[1];

    match explore_pe(binary_path) {
        Ok(_) => println!("\n謗｢邏｢螳御ｺ・ｼ・),
        Err(e) => eprintln!("繧ｨ繝ｩ繝ｼ: {}", e),
    }
}

/// PE 繝輔ぃ繧､繝ｫ繧呈爾邏｢
fn explore_pe(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);

    println!("=== PE Explorer ===\n");
    println!("繝輔ぃ繧､繝ｫ: {}", path.display());

    if !path.exists() {
        return Err(format!("繝輔ぃ繧､繝ｫ縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ: {}", path.display()).into());
    }

    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();
    println!("繝輔ぃ繧､繝ｫ繧ｵ繧､繧ｺ: {} bytes ({} MB)\n", file_size, file_size / 1_000_000);

    let binary = fs::read(path)?;

    // MZ signature 繧堤｢ｺ隱・    if binary.len() < 2 || binary[0] != 0x4D || binary[1] != 0x5A {
        return Err("MZ signature not found - not a PE file".into());
    }

    println!("笨・MZ signature found (PE header)\n");

    // PE header offset 繧貞叙蠕・    if binary.len() < 0x40 {
        return Err("File too small for PE header".into());
    }

    let pe_offset = u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
    println!("PE header offset: 0x{:x}", pe_offset);

    if pe_offset + 4 > binary.len() {
        return Err("PE offset out of range".into());
    }

    // PE signature 繧堤｢ｺ隱・    if binary[pe_offset] != 0x50 || binary[pe_offset + 1] != 0x45 {
        return Err("PE signature not found".into());
    }

    println!("笨・PE signature found at 0x{:x}\n", pe_offset);

    // COFF header 繧定ｧ｣譫・    let coff_offset = pe_offset + 4;
    if coff_offset + 20 > binary.len() {
        return Err("COFF header out of range".into());
    }

    let machine = u16::from_le_bytes([binary[coff_offset], binary[coff_offset + 1]]);
    let num_sections = u16::from_le_bytes([binary[coff_offset + 6], binary[coff_offset + 7]]);

    println!("=== COFF Header ===");
    println!("Machine: 0x{:04x} ({})", machine, machine_to_string(machine));
    println!("Number of sections: {}\n", num_sections);

    // Section headers 繧定ｧ｣譫・    let section_offset = coff_offset + 20 + u16::from_le_bytes([binary[coff_offset + 16], binary[coff_offset + 17]]) as usize;

    println!("=== Sections ===");

    for i in 0..num_sections as usize {
        let offset = section_offset + i * 40;

        if offset + 40 > binary.len() {
            break;
        }

        let name = String::from_utf8_lossy(&binary[offset..offset + 8]).trim_end_matches('\0').to_string();
        let virtual_size = u32::from_le_bytes([binary[offset + 8], binary[offset + 9], binary[offset + 10], binary[offset + 11]]);
        let virtual_address = u32::from_le_bytes([binary[offset + 12], binary[offset + 13], binary[offset + 14], binary[offset + 15]]);
        let size_of_raw_data = u32::from_le_bytes([binary[offset + 16], binary[offset + 17], binary[offset + 18], binary[offset + 19]]);
        let pointer_to_raw_data = u32::from_le_bytes([binary[offset + 20], binary[offset + 21], binary[offset + 22], binary[offset + 23]]);

        println!("{}:", name);
        println!("  Virtual Address: 0x{:08x}", virtual_address);
        println!("  Virtual Size: 0x{:08x} bytes", virtual_size);
        println!("  Raw Size: 0x{:08x} bytes", size_of_raw_data);
        println!("  File Offset: 0x{:08x}", pointer_to_raw_data);

        // .text 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｮ蝣ｴ蜷医√さ繝ｼ繝画ュ蝣ｱ繧定｡ｨ遉ｺ
        if name == ".text" {
            println!("  箝・This is the CODE section!");
            println!("    Suggested address to disassemble: 0x{:x}", virtual_address);

            // 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｮ譛蛻昴・16繝舌う繝医ｒ陦ｨ遉ｺ
            if pointer_to_raw_data as usize + 16 < binary.len() {
                print!("    First bytes: ");
                for j in 0..16 {
                    print!("{:02x} ", binary[pointer_to_raw_data as usize + j]);
                }
                println!();
            }
        }

        println!();
    }

    Ok(())
}

/// 繝槭す繝ｳ繧ｿ繧､繝励ｒ譁・ｭ怜・縺ｫ螟画鋤
fn machine_to_string(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86 (32-bit)",
        0x8664 => "x86-64 (64-bit)",
        0x01c0 => "ARM",
        0xaa64 => "ARM64",
        _ => "Unknown",
    }
}
