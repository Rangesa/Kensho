/// War Thunder aces.exe - 文字列抽出
/// ゲーム内部構造の手がかりを探す

use anyhow::Result;
use goblin::pe::PE;
use std::collections::HashSet;

fn main() -> Result<()> {
    println!("🔍 War Thunder String Analysis");
    println!("{}", "=".repeat(80));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let binary_data = std::fs::read(binary_path)?;

    println!("\n📂 Binary: {} ({} MB)", binary_path, binary_data.len() / 1_000_000);

    // PEファイルをパース
    let pe = PE::parse(&binary_data)?;

    // .rdataセクションを探す（文字列が格納されている可能性が高い）
    let rdata_section = pe.sections.iter().find(|s| {
        let name = String::from_utf8_lossy(&s.name);
        name.starts_with(".rdata") || name.starts_with(".rodata")
    });

    if let Some(section) = rdata_section {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = std::cmp::min(start + size, binary_data.len());

        println!("\n📋 .rdata section found:");
        println!("   Offset: 0x{:X}", start);
        println!("   Size: 0x{:X} ({} MB)", size, size / 1_000_000);

        // 文字列を抽出
        let mut strings = Vec::new();
        extract_strings(&binary_data[start..end], 8, &mut strings);

        println!("\n🔤 Found {} strings (min length: 8)", strings.len());

        // 興味深いキーワードでフィルタリング
        let keywords = [
            "player", "vehicle", "tank", "aircraft", "weapon", "damage",
            "engine", "module", "crew", "ammo", "armor", "penetration",
            "health", "speed", "position", "rotation", "camera",
            "network", "server", "client", "socket", "http",
            "render", "graphics", "d3d", "directx", "vulkan",
            "physics", "collision", "raycast", "hit",
            "class", "struct", "type", "object",
            "error", "warning", "debug", "log", "trace",
            "config", "settings", "data", "save", "load"
        ];

        println!("\n🎯 Interesting strings:");
        let mut found_count = 0;
        let mut categories: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

        for s in &strings {
            let lower = s.to_lowercase();
            for &keyword in &keywords {
                if lower.contains(keyword) {
                    categories.entry(keyword.to_string())
                        .or_insert_with(Vec::new)
                        .push(s.clone());
                    found_count += 1;
                    break;
                }
            }
        }

        // カテゴリごとに表示
        let mut sorted_categories: Vec<_> = categories.iter().collect();
        sorted_categories.sort_by_key(|(k, v)| (-(v.len() as i32), k.as_str()));

        for (keyword, strs) in sorted_categories.iter().take(15) {
            println!("\n   [{} related] ({} strings)", keyword, strs.len());
            for s in strs.iter().take(10) {
                println!("      - {}", s);
            }
            if strs.len() > 10 {
                println!("      ... and {} more", strs.len() - 10);
            }
        }

        println!("\n📊 Summary:");
        println!("   Total strings: {}", strings.len());
        println!("   Interesting strings: {}", found_count);
        println!("   Categories found: {}", categories.len());

        // クラス名っぽいものを探す（大文字始まり、CamelCase）
        println!("\n🏗️  Potential class/struct names:");
        let mut class_names = HashSet::new();
        for s in &strings {
            if is_likely_class_name(s) {
                class_names.insert(s.clone());
            }
        }

        for (i, name) in class_names.iter().take(50).enumerate() {
            if i % 3 == 0 {
                println!();
                print!("   ");
            }
            print!("{:<30}", name);
        }
        println!();
        println!("\n   Found {} potential class names", class_names.len());

    } else {
        println!("\n⚠️  .rdata section not found!");
    }

    // .dataセクションも確認
    let data_section = pe.sections.iter().find(|s| {
        let name = String::from_utf8_lossy(&s.name);
        name.starts_with(".data")
    });

    if let Some(section) = data_section {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = std::cmp::min(start + size, binary_data.len());

        println!("\n📋 .data section:");
        let mut strings = Vec::new();
        extract_strings(&binary_data[start..end], 10, &mut strings);
        println!("   Found {} strings (min length: 10)", strings.len());

        for s in strings.iter().take(20) {
            println!("   - {}", s);
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("✅ String analysis complete!");

    Ok(())
}

fn extract_strings(data: &[u8], min_len: usize, output: &mut Vec<String>) {
    let mut current = Vec::new();

    for &byte in data {
        if byte >= 0x20 && byte <= 0x7E {
            current.push(byte);
        } else if byte == 0 && current.len() >= min_len {
            if let Ok(s) = String::from_utf8(current.clone()) {
                output.push(s);
            }
            current.clear();
        } else {
            current.clear();
        }
    }
}

fn is_likely_class_name(s: &str) -> bool {
    if s.len() < 4 || s.len() > 50 {
        return false;
    }

    // 最初の文字が大文字
    let first_char = s.chars().next().unwrap();
    if !first_char.is_uppercase() {
        return false;
    }

    // CamelCaseっぽい（大文字が2個以上）
    let uppercase_count = s.chars().filter(|c| c.is_uppercase()).count();
    if uppercase_count < 2 {
        return false;
    }

    // 英数字とアンダースコアのみ
    s.chars().all(|c| c.is_alphanumeric() || c == '_')
}
