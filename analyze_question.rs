// question.exe簡易解析プログラム
use std::fs;
use goblin::pe::PE;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("   Question.exe 解析");
    println!("========================================\n");

    let binary_path = r"D:\Programming\MCP\question.exe";

    // バイナリ読み込み
    let binary_data = fs::read(binary_path)?;
    println!("📁 ファイルサイズ: {} bytes ({:.2} KB)\n",
        binary_data.len(),
        binary_data.len() as f64 / 1024.0
    );

    // PE解析
    let pe = PE::parse(&binary_data)?;

    println!("🔍 PE ヘッダ情報:");
    println!("  アーキテクチャ: {:?}", pe.header.coff_header.machine);
    println!("  セクション数: {}", pe.sections.len());
    println!("  エントリポイント (RVA): 0x{:X}", pe.entry);

    let image_base = pe.image_base as u64;
    println!("  イメージベース: 0x{:X}", image_base);
    println!("  エントリポイント (VA): 0x{:X}\n", image_base + pe.entry as u64);

    // セクション一覧
    println!("📂 セクション一覧:");
    println!("  {:<15} {:<12} {:<12} {:<12}",
        "名前", "仮想アドレス", "仮想サイズ", "特性");
    println!("  {}", "-".repeat(60));

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        let perms = if (section.characteristics & 0x20000000) != 0 { "R" } else { "" }.to_string()
            + if (section.characteristics & 0x40000000) != 0 { "W" } else { "" }
            + if (section.characteristics & 0x80000000) != 0 { "X" } else { "" };

        println!("  {:<15} 0x{:<10X} 0x{:<10X} {}",
            name,
            section.virtual_address,
            section.virtual_size,
            perms
        );
    }

    // インポート
    println!("\n🔗 インポート DLL ({} 個):", pe.imports.len());
    for (i, import) in pe.imports.iter().take(10).enumerate() {
        println!("  [{}] {}", i + 1, import.name);
    }
    if pe.imports.len() > 10 {
        println!("  ... 他 {} 個", pe.imports.len() - 10);
    }

    // エクスポート
    println!("\n📤 エクスポート関数 ({} 個):", pe.exports.len());
    for (i, export) in pe.exports.iter().take(20).enumerate() {
        if let Some(name) = export.name {
            println!("  [{}] {} @ 0x{:X}", i + 1, name, export.rva);
        }
    }

    // 文字列検索
    println!("\n🔤 興味深い文字列を検索:");
    let interesting_keywords = vec![
        "flag", "key", "password", "secret", "correct", "wrong",
        "success", "fail", "check", "verify", "input", "enter"
    ];

    let mut found_count = 0;
    for (offset, window) in binary_data.windows(4).enumerate() {
        // ASCIIプリント可能文字列を探す
        if window.iter().all(|&b| (b >= 0x20 && b <= 0x7E) || b == 0) {
            // 文字列の終端を探す
            let mut end = offset;
            while end < binary_data.len() && binary_data[end] != 0 {
                if binary_data[end] < 0x20 || binary_data[end] > 0x7E {
                    break;
                }
                end += 1;
            }

            if end > offset + 3 {
                let string = String::from_utf8_lossy(&binary_data[offset..end]);
                let lower = string.to_lowercase();

                for keyword in &interesting_keywords {
                    if lower.contains(keyword) && found_count < 30 {
                        println!("  [0x{:08X}] \"{}\"", offset, string);
                        found_count += 1;
                        break;
                    }
                }
            }
        }
    }

    // .textセクションの詳細
    println!("\n⚙️ コードセクション (.text) 詳細:");
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        if name.starts_with(".text") || (section.characteristics & 0x20) != 0 {
            println!("  セクション名: {}", name);
            println!("  仮想アドレス (RVA): 0x{:X}", section.virtual_address);
            println!("  仮想アドレス (VA): 0x{:X}", image_base + section.virtual_address as u64);
            println!("  サイズ: 0x{:X} ({} bytes)", section.virtual_size, section.virtual_size);
            println!("  ファイルオフセット: 0x{:X}", section.pointer_to_raw_data);

            // エントリポイントがこのセクションにあるか確認
            if pe.entry as u32 >= section.virtual_address
                && (pe.entry as u32) < section.virtual_address + section.virtual_size {
                println!("  ⭐ このセクションにエントリポイントが含まれています！");

                let entry_offset = pe.entry as u32 - section.virtual_address;
                let file_offset = section.pointer_to_raw_data + entry_offset;
                println!("  エントリポイントのファイルオフセット: 0x{:X}", file_offset);

                // 最初の数バイトを表示
                if (file_offset as usize + 16) < binary_data.len() {
                    print!("  最初の16バイト: ");
                    for i in 0..16 {
                        print!("{:02X} ", binary_data[file_offset as usize + i]);
                    }
                    println!();
                }
            }
        }
    }

    println!("\n========================================");
    println!("解析完了！");
    println!("========================================");

    Ok(())
}
