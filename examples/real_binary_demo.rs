/// 実際のバイナリファイルをデコンパイルするデモ
///
/// 使用方法:
/// cargo run --example real_binary_demo -- <binary_path> <address> <count>
///
/// 例:
/// cargo run --example real_binary_demo -- "C:\Programming\Cheat\TheFinals\Discovery-d.exe" 0x1000 50

use ghidra_mcp::decompiler_prototype::printer::SimplePrinter;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("使用方法: cargo run --example real_binary_demo -- <binary_path> [address] [count]");
        println!("\nデフォルト設定:");
        println!("  address: 0x1000");
        println!("  count: 20");
        println!("\n例:");
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
        Ok(_) => println!("\n解析完了！"),
        Err(e) => eprintln!("エラー: {}", e),
    }
}

/// バイナリファイルを解析
fn analyze_binary(path: &str, start_addr: u64, instr_count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);

    println!("=== Binary Decompiler Demo ===\n");
    println!("ファイル: {}", path.display());

    // ファイルが存在するか確認
    if !path.exists() {
        return Err(format!("ファイルが見つかりません: {}", path.display()).into());
    }

    // ファイルサイズを表示
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();
    println!("ファイルサイズ: {} bytes ({} MB)", file_size, file_size / 1_000_000);

    // バイナリを読み込む
    println!("\nバイナリを読み込み中...");
    let binary = fs::read(path)?;

    // アドレスがバイナリ範囲内か確認
    if start_addr as usize >= binary.len() {
        return Err(format!(
            "アドレス 0x{:x} がバイナリ範囲外です（バイナリサイズ: 0x{:x}）",
            start_addr,
            binary.len()
        )
        .into());
    }

    // セクション情報を表示
    println!("\n=== Binary Format Detection ===");
    detect_format(&binary);

    // 逆アセンブル（Capstone使用）
    println!("\n=== Disassembly ===");
    println!("アドレス: 0x{:x}", start_addr);
    println!("命令数: {}\n", instr_count);

    disassemble_section(&binary, start_addr, instr_count)?;

    Ok(())
}

/// バイナリフォーマットを検出
fn detect_format(binary: &[u8]) {
    if binary.len() < 4 {
        println!("ファイルが小さすぎます");
        return;
    }

    // PE フォーマット
    if binary[0] == 0x4D && binary[1] == 0x5A {
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

    // ELF フォーマット
    if binary.len() >= 4 && binary[0] == 0x7F && binary[1] == 0x45 && binary[2] == 0x4C && binary[3] == 0x46 {
        println!("Format: ELF (Linux executable)");
        return;
    }

    // Mach-O フォーマット
    if binary.len() >= 4 {
        let magic = u32::from_le_bytes([binary[0], binary[1], binary[2], binary[3]]);
        if magic == 0xFEEDFACF || magic == 0xFEEDFACE {
            println!("Format: Mach-O (macOS executable)");
            return;
        }
    }

    println!("Format: Unknown or Raw binary");
}

/// セクションを逆アセンブル
fn disassemble_section(binary: &[u8], start_addr: u64, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    use capstone::prelude::*;

    // Capstoneエンジンを初期化（x86-64）
    let cs = Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()?;

    // アドレスがバイナリ範囲内か確認
    if start_addr as usize >= binary.len() {
        return Err("Address out of bounds".into());
    }

    // 逆アセンブル
    let code = &binary[start_addr as usize..];
    let insns = cs.disasm_count(code, start_addr, count)?;

    let mut total_disassembled = 0;
    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("???");
        let op_str = insn.op_str().unwrap_or("");

        println!("0x{:x}: {} {}", insn.address(), mnemonic, op_str);
        total_disassembled += 1;
    }

    println!("\n逆アセンブルされた命令数: {}", total_disassembled);

    Ok(())
}

/// 16進数文字列をパース
fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}
