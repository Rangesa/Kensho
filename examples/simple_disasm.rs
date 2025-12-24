/// シンプルな逆アセンブルテスト
/// ファイルの複数のオフセットを試してコードっぽい領域を見つける

use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("使用方法: cargo run --example simple_disasm -- <binary_path>");
        return;
    }

    let binary_path = &args[1];

    match scan_for_code(binary_path) {
        Ok(_) => println!("\n完了！"),
        Err(e) => eprintln!("エラー: {}", e),
    }
}

/// ファイル内でコードっぽいセクションを探索
fn scan_for_code(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);

    println!("=== Code Section Scanner ===\n");
    println!("ファイル: {}\n", path.display());

    let binary = fs::read(path)?;
    println!("ファイルサイズ: {} bytes\n", binary.len());

    use capstone::prelude::*;

    // Capstoneエンジンを初期化（x86-64）
    let cs = Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()?;

    // いくつかのオフセットを試す
    let offsets_to_try = vec![
        0x1000, 0x2000, 0x4000, 0x10000, 0x400000, // ヘッダー後の一般的なオフセット
        1024 * 1024,                                  // 1MB
        512,                                          // セクション開始直後
    ];

    println!("複数のオフセットをスキャン中...\n");

    let mut found_any = false;

    for offset in offsets_to_try {
        if offset >= binary.len() {
            continue;
        }

        let code = &binary[offset..];

        // 最大30命令を試す
        if let Ok(insns) = cs.disasm_count(code, offset as u64, 30) {
            let count = insns.iter().count();

            if count > 5 {
                // 5命令以上逆アセンブルできたら表示
                found_any = true;
                println!("✓ オフセット 0x{:08x} - {} 命令逆アセンブル成功", offset, count);
                println!("  最初の5命令:");

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
        println!("⚠️  コードセクションが見つかりませんでした");
        println!("\nこのファイルは以下の可能性があります:");
        println!("  - パッキング/圧縮されている");
        println!("  - 難読化されている");
        println!("  - ネイティブコードを含まない（スクリプトなど）");
    }

    Ok(())
}
