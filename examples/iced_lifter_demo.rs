/// IcedLifter縺ｮ繝・Δ - 螳滄圀縺ｫWW.exe繧定ｧ｣譫・use kensho_mcp::decompiler_prototype::lifter::IcedLifter;
use anyhow::Result;
use std::fs;

fn main() -> Result<()> {
    println!("ｦ IcedLifter Demo - WW.exe Analysis\n");

    // WW.exe繧定ｪｭ縺ｿ霎ｼ縺ｿ
    let binary_path = "C:/Programming/MCP/WW.exe";
    println!("唐 Loading: {}", binary_path);

    let binary_data = fs::read(binary_path)?;
    println!("笨・Loaded {} bytes ({:.2} MB)\n", binary_data.len(), binary_data.len() as f64 / 1024.0 / 1024.0);

    // goblin縺ｧPE繧偵ヱ繝ｼ繧ｹ
    use goblin::pe::PE;
    let pe = PE::parse(&binary_data)?;

    println!("投 PE Information:");
    println!("  Entry Point: 0x{:x}", pe.entry);
    println!("  Sections: {}", pe.sections.len());
    println!("  Image Base: 0x{:x}\n", pe.image_base);

    // 蜈ｨ繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ繧定｡ｨ遉ｺ
    println!("搭 Sections:");
    for (i, section) in pe.sections.iter().enumerate() {
        let name = String::from_utf8_lossy(&section.name);
        println!("  {}: {} (VA: 0x{:x}, Size: {} bytes)",
                 i, name.trim_end_matches('\0'), section.virtual_address, section.virtual_size);
    }
    println!();

    // .text繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ繧定ｦ九▽縺代ｋ・亥ｮ溯｡悟庄閭ｽ縺ｪ繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ繧呈爾縺呻ｼ・    let text_section = pe.sections.iter()
        .find(|s| {
            let name = String::from_utf8_lossy(&s.name);
            name.trim_end_matches('\0').starts_with(".text") ||
            (s.characteristics & 0x20000000 != 0) // IMAGE_SCN_MEM_EXECUTE
        })
        .ok_or_else(|| anyhow::anyhow!("No executable section found"))?;

    let section_name = String::from_utf8_lossy(&text_section.name);
    let section_start = text_section.pointer_to_raw_data as usize;
    let section_size = if text_section.size_of_raw_data > 0 {
        text_section.size_of_raw_data as usize
    } else {
        text_section.virtual_size as usize
    };
    let section_va = text_section.virtual_address as u64;

    println!("剥 Code Section:");
    println!("  Name: {}", section_name.trim_end_matches('\0'));
    println!("  Virtual Address: 0x{:x}", section_va);
    println!("  Size: {} bytes ({:.2} KB)", section_size, section_size as f64 / 1024.0);
    println!("  File Offset: 0x{:x}\n", section_start);

    // 譛蛻昴・繧ｻ繧ｯ繧ｷ繝ｧ繝ｳ縺ｮ蜈磯ｭ縺九ｉ蟆代＠繝ｪ繝輔ヨ・医お繝ｳ繝医Μ繝昴う繝ｳ繝郁ｨ育ｮ励′隍・尅縺ｪ縺ｮ縺ｧ・・    let start_offset = section_start;
    let code_end = (start_offset + section_size).min(binary_data.len()).min(start_offset + 4096);
    let code_slice = &binary_data[start_offset..code_end];

    println!("笞｡ Lifting first 50 instructions from section start (0x{:x})...\n", section_va);

    let mut lifter = IcedLifter::new();
    let base_address = pe.image_base as u64 + section_va;

    match lifter.lift(code_slice, base_address, 50) {
        Ok(pcodes) => {
            println!("笨・Successfully lifted {} P-code operations!\n", pcodes.len());

            // 譛蛻昴・20蛟九ｒ陦ｨ遉ｺ
            println!("搭 First 20 P-code operations:");
            for (i, op) in pcodes.iter().take(20).enumerate() {
                println!("  {:3}. 0x{:x}: {}", i + 1, op.address, op);
            }

            if pcodes.len() > 20 {
                println!("\n  ... ({} more operations)", pcodes.len() - 20);
            }

            // 邨ｱ險域ュ蝣ｱ
            println!("\n嶋 Statistics:");
            let mut opcode_counts = std::collections::HashMap::new();
            for op in &pcodes {
                *opcode_counts.entry(format!("{:?}", op.opcode)).or_insert(0) += 1;
            }

            let mut counts: Vec<_> = opcode_counts.iter().collect();
            counts.sort_by(|a, b| b.1.cmp(a.1));

            println!("  Top 10 P-code opcodes:");
            for (i, (opcode, count)) in counts.iter().take(10).enumerate() {
                println!("    {:2}. {:20} : {} times", i + 1, opcode, count);
            }
        }
        Err(e) => {
            eprintln!("笶・Lifting failed: {}", e);
        }
    }

    Ok(())
}
