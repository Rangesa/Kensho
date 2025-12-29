/// PE繝輔ぃ繧､繝ｫ繧｢繝翫Λ繧､繧ｶ繝ｼ
/// Discovery-d.exe縺ｮ讒矩繧定ｧ｣譫舌＠縺ｦ繧ｳ繝ｼ繝峨そ繧ｯ繧ｷ繝ｧ繝ｳ繧定ｦ九▽縺代ｋ

use anyhow::Result;
use goblin::pe::PE;

fn main() -> Result<()> {
    println!("剥 PE File Analyzer");
    println!("{}", "=".repeat(60));

    let binary_path = r"C:\Programming\Cheat\TheFinals\Discovery-d.exe";

    println!("\n唐 Analyzing: {}", binary_path);

    // 繝舌う繝翫Μ繝輔ぃ繧､繝ｫ繧定ｪｭ縺ｿ霎ｼ縺ｿ
    let binary_data = std::fs::read(binary_path)?;
    println!("   Size: {} bytes ({} MB)", binary_data.len(), binary_data.len() / 1_000_000);

    // PE繝輔ぃ繧､繝ｫ繧偵ヱ繝ｼ繧ｹ
    let pe = PE::parse(&binary_data)?;

    println!("\n投 PE Header Information:");
    println!("   Machine: {:?}", pe.header.coff_header.machine);
    println!("   Sections: {}", pe.sections.len());
    println!("   Entry Point (RVA): 0x{:X}", pe.entry);

    // 繧､繝｡繝ｼ繧ｸ繝吶・繧ｹ繧｢繝峨Ξ繧ｹ繧貞叙蠕・    let image_base = pe.image_base as u64;
    println!("   Image Base: 0x{:X}", image_base);
    println!("   Entry Point (VA): 0x{:X}", image_base + pe.entry as u64);

    println!("\n搭 Sections:");
    println!("{}", "-".repeat(100));
    println!("{:<15} {:<12} {:<12} {:<12} {:<12} {:<20}",
        "Name", "Virtual Addr", "Virtual Size", "Raw Offset", "Raw Size", "Characteristics");
    println!("{}", "-".repeat(100));

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        println!("{:<15} 0x{:<10X} 0x{:<10X} 0x{:<10X} 0x{:<10X} 0x{:08X}",
            name,
            section.virtual_address,
            section.virtual_size,
            section.pointer_to_raw_data,
            section.size_of_raw_data,
            section.characteristics,
        );
    }

    // .text繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ繧呈爾縺・    println!("\n剥 Looking for code sections (.text):");
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        // IMAGE_SCN_CNT_CODE (0x00000020) 縺ｾ縺溘・ .text 繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ
        if name.starts_with(".text") || (section.characteristics & 0x20) != 0 {
            println!("\n笨・Found code section: {}", name);
            println!("   Virtual Address (RVA): 0x{:X}", section.virtual_address);
            println!("   Virtual Address (VA):  0x{:X}", image_base + section.virtual_address as u64);
            println!("   Virtual Size: 0x{:X} ({} bytes)", section.virtual_size, section.virtual_size);
            println!("   Raw Offset in File: 0x{:X}", section.pointer_to_raw_data);
            println!("   Raw Size: 0x{:X} ({} bytes)", section.size_of_raw_data, section.size_of_raw_data);

            // 繧ｨ繝ｳ繝医Μ繝ｼ繝昴う繝ｳ繝医′縺薙・繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｫ縺ゅｋ縺狗｢ｺ隱・            if pe.entry as u32 >= section.virtual_address
                && (pe.entry as u32) < section.virtual_address + section.virtual_size {
                println!("   箝・This section contains the entry point!");

                let entry_offset_in_section = pe.entry as u32 - section.virtual_address;
                let entry_file_offset = section.pointer_to_raw_data + entry_offset_in_section;

                println!("   Entry point offset in section: 0x{:X}", entry_offset_in_section);
                println!("   Entry point file offset: 0x{:X}", entry_file_offset);
            }
        }
    }

    // 繧､繝ｳ繝昴・繝医ユ繝ｼ繝悶Ν諠・ｱ
    let imports = &pe.imports;
    println!("\n逃 Imported DLLs: {}", imports.len());
    for (i, import) in imports.iter().take(10).enumerate() {
        println!("   [{}] {}", i, import.name);
    }
    if imports.len() > 10 {
        println!("   ... and {} more", imports.len() - 10);
    }

    // 繧ｨ繧ｯ繧ｹ繝昴・繝医ユ繝ｼ繝悶Ν諠・ｱ
    let exports = &pe.exports;
    println!("\n豆 Exported functions: {}", exports.len());
    for (i, export) in exports.iter().take(10).enumerate() {
        if let Some(name) = export.name {
            println!("   [{}] {} @ 0x{:X}", i, name, export.rva);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("笨・Analysis complete!");

    println!("\n庁 Suggested decompilation address:");
    println!("   VA (Virtual Address): 0x{:X}", image_base + pe.entry as u64);

    // .text繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｮ譛蛻昴・繧｢繝峨Ξ繧ｹ繧よ署譯・    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        if name.starts_with(".text") {
            let file_offset = section.pointer_to_raw_data;
            println!("   File Offset for .text section: 0x{:X}", file_offset);
            break;
        }
    }

    Ok(())
}
