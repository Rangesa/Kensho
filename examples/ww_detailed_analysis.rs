/// WW.exe隧ｳ邏ｰ隗｣譫・- 繝代ャ繧ｫ繝ｼ讀懷・縺ｨ繝｡繧ｿ繝・・繧ｿ謚ｽ蜃ｺ
use anyhow::Result;
use std::fs;
use goblin::pe::PE;

fn main() -> Result<()> {
    println!("剥 WW.exe 隧ｳ邏ｰ隗｣譫申n");

    let binary_path = "C:/Programming/MCP/WW.exe";
    let binary_data = fs::read(binary_path)?;

    println!("唐 Basic Info:");
    println!("  Size: {} bytes ({:.2} MB)", binary_data.len(), binary_data.len() as f64 / 1024.0 / 1024.0);

    let pe = PE::parse(&binary_data)?;

    // 繧､繝ｳ繝昴・繝域ュ蝣ｱ
    println!("\n逃 Imports:");
    let imports = pe.imports;
    if imports.is_empty() {
        println!("  笞・・ No imports found - likely packed!");
    } else {
        let mut dll_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for import in &imports {
            *dll_counts.entry(import.dll.to_string()).or_insert(0) += 1;
        }

        for (dll, count) in dll_counts.iter().take(10) {
            println!("  - {}: {} functions", dll, count);
        }

        if dll_counts.len() > 10 {
            println!("  ... and {} more DLLs", dll_counts.len() - 10);
        }
    }

    // 繧ｨ繧ｯ繧ｹ繝昴・繝域ュ蝣ｱ
    println!("\n豆 Exports:");
    if pe.exports.is_empty() {
        println!("  No exports");
    } else {
        println!("  Export count: {}", pe.exports.len());
        for (i, export) in pe.exports.iter().take(10).enumerate() {
            if let Some(name) = export.name {
                println!("    {}. {} (RVA: 0x{:x})", i + 1, name, export.rva);
            }
        }
    }

    // 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｮ隧ｳ邏ｰ
    println!("\n搭 Section Details:");
    for (i, section) in pe.sections.iter().enumerate() {
        let name = String::from_utf8_lossy(&section.name);
        let characteristics = section.characteristics;

        let mut flags = Vec::new();
        if characteristics & 0x20 != 0 { flags.push("CODE"); }
        if characteristics & 0x40 != 0 { flags.push("INIT_DATA"); }
        if characteristics & 0x80 != 0 { flags.push("UNINIT_DATA"); }
        if characteristics & 0x20000000 != 0 { flags.push("EXEC"); }
        if characteristics & 0x40000000 != 0 { flags.push("READ"); }
        if characteristics & 0x80000000 != 0 { flags.push("WRITE"); }

        println!("  {}. {} - VA:0x{:x} Size:{} bytes Flags:[{}]",
                 i,
                 name.trim_end_matches('\0'),
                 section.virtual_address,
                 section.virtual_size,
                 flags.join(", "));
    }

    // 繧ｨ繝ｳ繝医Ο繝斐・險育ｮ暦ｼ医ヱ繝・き繝ｼ讀懷・・・    println!("\n溌 Entropy Analysis:");
    for (i, section) in pe.sections.iter().enumerate().take(3) {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data.min(section.virtual_size) as usize;

        if start + size <= binary_data.len() && size > 0 {
            let section_data = &binary_data[start..start + size.min(binary_data.len() - start)];
            let entropy = calculate_entropy(section_data);

            let name = String::from_utf8_lossy(&section.name);
            println!("  Section {}: {} - Entropy: {:.4}", i, name.trim_end_matches('\0'), entropy);

            if entropy > 7.0 {
                println!("    笞・・ HIGH ENTROPY - Likely compressed/encrypted!");
            } else if entropy < 2.0 {
                println!("    邃ｹ・・ Low entropy - Mostly padding/zeros");
            }
        }
    }

    // PE繝倥ャ繝繝ｼ迚ｹ蠕ｴ
    println!("\n女・・ PE Header Analysis:");
    println!("  Machine: {:?}", pe.header.coff_header.machine);
    println!("  Timestamp: {}", pe.header.coff_header.time_date_stamp);
    println!("  Characteristics: 0x{:x}", pe.header.coff_header.characteristics);

    if let Some(opt_header) = &pe.header.optional_header {
        println!("  Subsystem: {:?}", opt_header.windows_fields.subsystem);
        println!("  DLL Characteristics: 0x{:x}", opt_header.windows_fields.dll_characteristics);
        println!("  Size of Image: {} bytes", opt_header.windows_fields.size_of_image);
        println!("  Size of Headers: {} bytes", opt_header.windows_fields.size_of_headers);
    }

    // 繝代ャ繧ｫ繝ｼ謗ｨ貂ｬ
    println!("\n鹿 Packer Detection:");
    detect_packer(&pe, &binary_data);

    Ok(())
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn detect_packer(pe: &PE, binary_data: &[u8]) {
    let mut indicators = Vec::new();

    // 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ蜷阪メ繧ｧ繝・け
    let all_std = pe.sections.iter().all(|s| {
        String::from_utf8_lossy(&s.name).trim_end_matches('\0') == ".std"
    });

    if all_std {
        indicators.push("All sections named '.std' - HIGHLY SUSPICIOUS");
    }

    // 繧､繝ｳ繝昴・繝医′蟆代↑縺・    if pe.imports.len() < 5 {
        indicators.push("Very few imports - likely packed");
    }

    // 繧ｨ繝ｳ繝医Ο繝斐・繝√ぉ繝・け・域怙蛻昴・繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ・・    if let Some(first_section) = pe.sections.first() {
        let start = first_section.pointer_to_raw_data as usize;
        let size = first_section.size_of_raw_data.min(first_section.virtual_size) as usize;

        if start + size <= binary_data.len() && size > 0 {
            let section_data = &binary_data[start..start + size.min(binary_data.len() - start)];
            let entropy = calculate_entropy(section_data);

            if entropy > 7.0 {
                indicators.push("High entropy in code section - likely compressed");
            }
        }
    }

    // 譌｢遏･縺ｮ繝代ャ繧ｫ繝ｼ繧ｷ繧ｰ繝阪メ繝｣
    let first_bytes = &binary_data[0..256.min(binary_data.len())];
    if let Some(packer) = detect_known_packer(first_bytes) {
        indicators.push(packer);
    }

    if indicators.is_empty() {
        println!("  笨・No obvious packer signatures detected");
    } else {
        println!("  笞・・ Packer indicators found:");
        for indicator in indicators {
            println!("    - {}", indicator);
        }
    }
}

fn detect_known_packer(data: &[u8]) -> Option<&'static str> {
    // UPX 繧ｷ繧ｰ繝阪メ繝｣
    if data.windows(3).any(|w| w == b"UPX") {
        return Some("UPX packer detected");
    }

    // Themida/WinLicense
    if data.windows(7).any(|w| w == b"Themida" || w == b"WinLice") {
        return Some("Themida/WinLicense detected");
    }

    // VMProtect
    if data.windows(9).any(|w| w == b"VMProtect") {
        return Some("VMProtect detected");
    }

    None
}
