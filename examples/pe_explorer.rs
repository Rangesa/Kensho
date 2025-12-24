/// PE実行可能ファイルの構造を探索
///
/// 使用方法:
/// cargo run --example pe_explorer -- <binary_path>

use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("使用方法: cargo run --example pe_explorer -- <binary_path>");
        println!("\n例:");
        println!("  cargo run --example pe_explorer -- \"C:\\\\Programming\\\\Cheat\\\\TheFinals\\\\Discovery-d.exe\"");
        return;
    }

    let binary_path = &args[1];

    match explore_pe(binary_path) {
        Ok(_) => println!("\n探索完了！"),
        Err(e) => eprintln!("エラー: {}", e),
    }
}

/// PE ファイルを探索
fn explore_pe(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);

    println!("=== PE Explorer ===\n");
    println!("ファイル: {}", path.display());

    if !path.exists() {
        return Err(format!("ファイルが見つかりません: {}", path.display()).into());
    }

    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();
    println!("ファイルサイズ: {} bytes ({} MB)\n", file_size, file_size / 1_000_000);

    let binary = fs::read(path)?;

    // MZ signature を確認
    if binary.len() < 2 || binary[0] != 0x4D || binary[1] != 0x5A {
        return Err("MZ signature not found - not a PE file".into());
    }

    println!("✓ MZ signature found (PE header)\n");

    // PE header offset を取得
    if binary.len() < 0x40 {
        return Err("File too small for PE header".into());
    }

    let pe_offset = u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
    println!("PE header offset: 0x{:x}", pe_offset);

    if pe_offset + 4 > binary.len() {
        return Err("PE offset out of range".into());
    }

    // PE signature を確認
    if binary[pe_offset] != 0x50 || binary[pe_offset + 1] != 0x45 {
        return Err("PE signature not found".into());
    }

    println!("✓ PE signature found at 0x{:x}\n", pe_offset);

    // COFF header を解析
    let coff_offset = pe_offset + 4;
    if coff_offset + 20 > binary.len() {
        return Err("COFF header out of range".into());
    }

    let machine = u16::from_le_bytes([binary[coff_offset], binary[coff_offset + 1]]);
    let num_sections = u16::from_le_bytes([binary[coff_offset + 6], binary[coff_offset + 7]]);

    println!("=== COFF Header ===");
    println!("Machine: 0x{:04x} ({})", machine, machine_to_string(machine));
    println!("Number of sections: {}\n", num_sections);

    // Section headers を解析
    let section_offset = coff_offset + 20 + u16::from_le_bytes([binary[coff_offset + 16], binary[coff_offset + 17]]) as usize;

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

        // .text セクションの場合、コード情報を表示
        if name == ".text" {
            println!("  ⭐ This is the CODE section!");
            println!("    Suggested address to disassemble: 0x{:x}", virtual_address);

            // セクションの最初の16バイトを表示
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

/// マシンタイプを文字列に変換
fn machine_to_string(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86 (32-bit)",
        0x8664 => "x86-64 (64-bit)",
        0x01c0 => "ARM",
        0xaa64 => "ARM64",
        _ => "Unknown",
    }
}
