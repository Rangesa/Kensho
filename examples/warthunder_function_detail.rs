/// War Thunder - 特定関数の詳細解析
/// エクスポート関数 dgs_init_argv_exported を詳細にデコンパイル

use anyhow::Result;
use ghidra_mcp::decompiler_prototype::{
    CapstoneTranslator, ControlFlowGraph, SSATransform, TypeInference,
    ControlFlowAnalyzer, ControlStructurePrinter
};
use goblin::pe::PE;
use std::path::Path;

fn main() -> Result<()> {
    println!("🔍 War Thunder Function Detail Analysis");
    println!("{}", "=".repeat(80));

    let binary_path = r"C:\Users\asdas\AppData\Local\WarThunder\win64\aces.exe";
    let binary_data = std::fs::read(binary_path)?;

    println!("\n📂 Binary: {} ({} MB)", binary_path, binary_data.len() / 1_000_000);

    // PEファイルをパース
    let pe = PE::parse(&binary_data)?;
    let image_base = pe.image_base as u64;

    println!("\n📤 Export Functions:");
    for (i, export) in pe.exports.iter().enumerate() {
        if let Some(name) = export.name {
            let va = image_base + export.rva as u64;
            println!("   [{}] {} @ 0x{:X}", i, name, va);
        }
    }

    // dgs_init_argv_exported を探す
    let target_export = pe.exports.iter().find(|e| {
        e.name.map(|n| n == "dgs_init_argv_exported").unwrap_or(false)
    });

    if let Some(export) = target_export {
        let function_va = image_base + export.rva as u64;
        let function_rva = export.rva as u64;

        println!("\n🎯 Analyzing: dgs_init_argv_exported");
        println!("   RVA: 0x{:X}", function_rva);
        println!("   VA:  0x{:X}", function_va);

        // RVAからファイルオフセットを計算
        let mut file_offset = None;
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
            // 最大500命令を解析
            let max_instructions = 500;
            let code_size = max_instructions * 15;
            let end_offset = std::cmp::min(offset + code_size, binary_data.len());
            let code_slice = &binary_data[offset..end_offset];

            println!("\n🔄 Decompiling...");
            println!("   Code slice: {} bytes", code_slice.len());

            // P-codeに変換
            let mut translator = CapstoneTranslator::new()?;
            let pcodes = translator.translate(code_slice, function_va, max_instructions)?;
            println!("   ✅ Generated {} P-code operations", pcodes.len());

            // CFG構築
            let mut cfg = ControlFlowGraph::from_pcodes(pcodes.clone());
            println!("   ✅ CFG: {} basic blocks", cfg.blocks.len());

            // SSA変換
            let mut ssa = SSATransform::new();
            ssa.transform(&mut cfg);
            println!("   ✅ SSA transformation complete");

            // 型推論
            let mut type_inference = TypeInference::new();
            type_inference.run(&pcodes);
            let typed_varnodes = type_inference.get_all_types();
            println!("   ✅ Type inference: {} variables typed", typed_varnodes.len());

            // 制御構造検出
            let mut analyzer = ControlFlowAnalyzer::new();
            let structure = analyzer.analyze(&cfg);
            println!("   ✅ Control flow analysis complete");

            // 結果を表示
            println!("\n📊 Analysis Results:");
            println!("   P-code operations: {}", pcodes.len());
            println!("   Basic blocks: {}", cfg.blocks.len());
            println!("   Typed variables: {}", typed_varnodes.len());
            println!("   Loops detected: {}", analyzer.get_loops().len());

            // 制御構造を表示
            println!("\n🏗️  Control Structure:");
            let mut printer = ControlStructurePrinter::new();
            let structure_str = printer.print(&structure);
            println!("{}", structure_str);

            // 最初の50個のP-code操作を表示
            println!("\n📝 First 50 P-code Operations:");
            for (i, op) in pcodes.iter().take(50).enumerate() {
                println!("   {:3}: 0x{:X}  {:?}", i, op.address, op.opcode);
                if !op.inputs.is_empty() {
                    println!("        Inputs:  {:?}", op.inputs);
                }
                if let Some(output) = &op.output {
                    println!("        Output:  {:?}", output);
                }
            }

            // 型推論結果を表示
            println!("\n🔤 Type Inference Results (first 30):");
            for (i, (varnode, typ)) in typed_varnodes.iter().take(30).enumerate() {
                println!("   {:2}: {:?} : {:?}", i, varnode, typ);
            }

        } else {
            println!("\n❌ Could not find file offset for function");
        }
    } else {
        println!("\n❌ dgs_init_argv_exported not found in exports");
    }

    println!("\n{}", "=".repeat(80));
    println!("✅ Analysis complete!");

    Ok(())
}
