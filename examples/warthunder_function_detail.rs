/// War Thunder - 迚ｹ螳夐未謨ｰ縺ｮ隧ｳ邏ｰ隗｣譫・/// 繧ｨ繧ｯ繧ｹ繝昴・繝磯未謨ｰ dgs_init_argv_exported 繧定ｩｳ邏ｰ縺ｫ繝・さ繝ｳ繝代う繝ｫ

use anyhow::Result;
use kensho_mcp::decompiler_prototype::{
    CapstoneTranslator, ControlFlowGraph, SSATransform, TypeInference,
    ControlFlowAnalyzer, ControlStructurePrinter
};
use goblin::pe::PE;
use std::path::Path;

fn main() -> Result<()> {
    println!("剥 War Thunder Function Detail Analysis");
    println!("{}", "=".repeat(80));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let binary_data = std::fs::read(binary_path)?;

    println!("\n唐 Binary: {} ({} MB)", binary_path, binary_data.len() / 1_000_000);

    // PE繝輔ぃ繧､繝ｫ繧偵ヱ繝ｼ繧ｹ
    let pe = PE::parse(&binary_data)?;
    let image_base = pe.image_base as u64;

    println!("\n豆 Export Functions:");
    for (i, export) in pe.exports.iter().enumerate() {
        if let Some(name) = export.name {
            let va = image_base + export.rva as u64;
            println!("   [{}] {} @ 0x{:X}", i, name, va);
        }
    }

    // dgs_init_argv_exported 繧呈爾縺・    let target_export = pe.exports.iter().find(|e| {
        e.name.map(|n| n == "dgs_init_argv_exported").unwrap_or(false)
    });

    if let Some(export) = target_export {
        let function_va = image_base + export.rva as u64;
        let function_rva = export.rva as u64;

        println!("\n識 Analyzing: dgs_init_argv_exported");
        println!("   RVA: 0x{:X}", function_rva);
        println!("   VA:  0x{:X}", function_va);

        // RVA縺九ｉ繝輔ぃ繧､繝ｫ繧ｪ繝輔そ繝・ヨ繧定ｨ育ｮ・        let mut file_offset = None;
        for section in &pe.sections {
            let section_start = section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;

            if function_rva >= section_start && function_rva < section_end {
                let offset_in_section = function_rva - section_start;
                file_offset = Some(section.pointer_to_raw_data as usize + offset_in_section as usize);

                let section_name = String::from_utf8_lossy(&section.name);
                println!("\n   Found in section: {}", section_name.trim_end_matches('\0'));
                println!("   File offset: 0x{:X}", file_offset.unwrap());
                break;
            }
        }

        if let Some(offset) = file_offset {
            // 譛螟ｧ500蜻ｽ莉､繧定ｧ｣譫・            let max_instructions = 500;
            let code_size = max_instructions * 15;
            let end_offset = std::cmp::min(offset + code_size, binary_data.len());
            let code_slice = &binary_data[offset..end_offset];

            println!("\n売 Decompiling...");
            println!("   Code slice: {} bytes", code_slice.len());

            // P-code縺ｫ螟画鋤
            let mut translator = CapstoneTranslator::new()?;
            let pcodes = translator.translate(code_slice, function_va, max_instructions)?;
            println!("   笨・Generated {} P-code operations", pcodes.len());

            // CFG讒狗ｯ・            let mut cfg = ControlFlowGraph::from_pcodes(pcodes.clone());
            println!("   笨・CFG: {} basic blocks", cfg.blocks.len());

            // SSA螟画鋤
            let mut ssa = SSATransform::new();
            ssa.transform(&mut cfg);
            println!("   笨・SSA transformation complete");

            // 蝙区耳隲・            let mut type_inference = TypeInference::new();
            type_inference.run(&pcodes);
            let typed_varnodes = type_inference.get_all_types();
            println!("   笨・Type inference: {} variables typed", typed_varnodes.len());

            // 蛻ｶ蠕｡讒矩讀懷・
            let mut analyzer = ControlFlowAnalyzer::new();
            let structure = analyzer.analyze(&cfg);
            println!("   笨・Control flow analysis complete");

            // 邨先棡繧定｡ｨ遉ｺ
            println!("\n投 Analysis Results:");
            println!("   P-code operations: {}", pcodes.len());
            println!("   Basic blocks: {}", cfg.blocks.len());
            println!("   Typed variables: {}", typed_varnodes.len());
            println!("   Loops detected: {}", analyzer.get_loops().len());

            // 蛻ｶ蠕｡讒矩繧定｡ｨ遉ｺ
            println!("\n女・・ Control Structure:");
            let mut printer = ControlStructurePrinter::new();
            let structure_str = printer.print(&structure);
            println!("{}", structure_str);

            // 譛蛻昴・50蛟九・P-code謫堺ｽ懊ｒ陦ｨ遉ｺ
            println!("\n統 First 50 P-code Operations:");
            for (i, op) in pcodes.iter().take(50).enumerate() {
                println!("   {:3}: 0x{:X}  {:?}", i, op.address, op.opcode);
                if !op.inputs.is_empty() {
                    println!("        Inputs:  {:?}", op.inputs);
                }
                if let Some(output) = &op.output {
                    println!("        Output:  {:?}", output);
                }
            }

            // 蝙区耳隲也ｵ先棡繧定｡ｨ遉ｺ
            println!("\n筈 Type Inference Results (first 30):");
            for (i, (varnode, typ)) in typed_varnodes.iter().take(30).enumerate() {
                println!("   {:2}: {:?} : {:?}", i, varnode, typ);
            }

        } else {
            println!("\n笶・Could not find file offset for function");
        }
    } else {
        println!("\n笶・dgs_init_argv_exported not found in exports");
    }

    println!("\n{}", "=".repeat(80));
    println!("笨・Analysis complete!");

    Ok(())
}
