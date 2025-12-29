// DWARF/PDB デバッグシンボル統合デモ
//
// gimli（DWARF）とpdbクレートを使用した
// 内部関数名・変数名・型情報・ソースロケーションの完全復元デモ

use kensho_mcp::decompiler_prototype::debug_symbols::{
    DwarfSymbolParser, PdbSymbolParser
};
use std::path::Path;
use std::fs;

fn main() {
    println!("=== DWARF/PDB デバッグシンボル統合デモ ===\n");

    // Demo 1: DWARF解析（Linux ELFバイナリ）
    demo_dwarf_analysis();

    // Demo 2: PDB解析（Windows PEバイナリ）
    demo_pdb_analysis();

    println!("\n=== 全デモ完了 ===");
    println!("\nDWARF/PDB本格統合により以下が実現：");
    println!("  ✓ 内部関数名の復元");
    println!("  ✓ 変数名の復元");
    println!("  ✓ ソースファイルと行番号のマッピング");
    println!("  ✓ 型情報の取得（構造体、共用体、ポインタ、配列）");
}

fn demo_dwarf_analysis() {
    println!("Demo 1: DWARF解析（ELF + DWARFデバッグ情報）");
    println!("  DWARF（Debugging With Attributed Record Formats）");
    println!("  - Linux/Unix系バイナリ（ELF形式）で使用");
    println!("  - gcc/clangが生成する標準的なデバッグ情報形式");
    println!("  - gimliクレートでフル解析");
    println!();

    // テスト用のバイナリパスを確認
    let test_binary = "D:/Programming/MCP/target/release/kensho-mcp.exe";

    if !Path::new(test_binary).exists() {
        println!("  ℹ テストバイナリが見つかりません: {}", test_binary);
        println!("  ℹ DWARFデモをスキップします");
        println!();
        return;
    }

    match fs::read(test_binary) {
        Ok(binary_data) => {
            println!("  バイナリ読み込み: {} ({} bytes)", test_binary, binary_data.len());

            match DwarfSymbolParser::parse_from_elf(&binary_data) {
                Ok(parser) => {
                    println!("  ✓ DWARF解析成功");
                    println!();

                    // 統計情報
                    println!("  検出されたシンボル:");
                    println!("    関数: {} 個", parser.functions().len());
                    println!("    変数: {} 個", parser.variables().len());
                    println!("    型: {} 個", parser.types().len());
                    println!();

                    // 関数名の例
                    if !parser.functions().is_empty() {
                        println!("  関数名の例（最初の5個）:");
                        for (addr, name) in parser.functions().iter().take(5) {
                            println!("    0x{:08X}: {}", addr, name);
                        }
                        println!();
                    }

                    // 型情報の例
                    if !parser.types().is_empty() {
                        println!("  型情報の例（最初の5個）:");
                        for (id, type_info) in parser.types().iter().take(5) {
                            println!("    ID {}: {} ({} bytes, {:?})",
                                id, type_info.name, type_info.size, type_info.kind);
                        }
                        println!();
                    }

                    // DebugSymbolProvider traitを使用した例
                    println!("  DebugSymbolProvider trait使用例:");
                    if let Some(first_addr) = parser.functions().keys().next() {
                        if let Some(name) = parser.get_function_name(*first_addr) {
                            println!("    get_function_name(0x{:X}) = {}", first_addr, name);
                        }
                        if let Some(location) = parser.get_source_location(*first_addr) {
                            println!("    get_source_location(0x{:X}) = {}:{}",
                                first_addr, location.0, location.1);
                        }
                    }
                }
                Err(e) => {
                    println!("  ℹ DWARF解析エラー: {}", e);
                    println!("  ℹ このバイナリにはDWARF情報が含まれていない可能性があります");
                }
            }
        }
        Err(e) => {
            println!("  ✗ バイナリ読み込みエラー: {}", e);
        }
    }
    println!();
}

fn demo_pdb_analysis() {
    println!("Demo 2: PDB解析（PE + PDBデバッグ情報）");
    println!("  PDB（Program Database）");
    println!("  - Windowsバイナリ（PE形式）で使用");
    println!("  - MSVCが生成する独自のデバッグ情報形式");
    println!("  - pdbクレートでフル解析");
    println!();

    // テスト用のPDBファイルパスを確認
    let test_pdb = "D:/Programming/MCP/target/release/kensho-mcp.pdb";

    if !Path::new(test_pdb).exists() {
        println!("  ℹ テストPDBが見つかりません: {}", test_pdb);
        println!("  ℹ PDBデモをスキップします");
        println!("  ℹ PDBファイルを生成するには、MSVCでビルドしてください");
        println!();
        return;
    }

    match fs::read(test_pdb) {
        Ok(pdb_data) => {
            println!("  PDB読み込み: {} ({} bytes)", test_pdb, pdb_data.len());

            match PdbSymbolParser::parse_from_pdb_data(&pdb_data) {
                Ok(parser) => {
                    println!("  ✓ PDB解析成功");
                    println!();

                    // 統計情報
                    println!("  検出されたシンボル:");
                    println!("    関数: {} 個", parser.functions().len());
                    println!("    変数: {} 個", parser.variables().len());
                    println!("    型: {} 個", parser.types().len());
                    println!();

                    // 関数名の例
                    if !parser.functions().is_empty() {
                        println!("  関数名の例（最初の5個）:");
                        for (addr, name) in parser.functions().iter().take(5) {
                            println!("    0x{:08X}: {}", addr, name);
                        }
                        println!();
                    }

                    // 型情報の例
                    if !parser.types().is_empty() {
                        println!("  型情報の例（最初の5個）:");
                        for (id, type_info) in parser.types().iter().take(5) {
                            println!("    ID {}: {} ({} bytes, {:?})",
                                id, type_info.name, type_info.size, type_info.kind);
                        }
                        println!();
                    }

                    // DebugSymbolProvider traitを使用した例
                    println!("  DebugSymbolProvider trait使用例:");
                    if let Some(first_addr) = parser.functions().keys().next() {
                        if let Some(name) = parser.get_function_name(*first_addr) {
                            println!("    get_function_name(0x{:X}) = {}", first_addr, name);
                        }
                        if let Some(location) = parser.get_source_location(*first_addr) {
                            println!("    get_source_location(0x{:X}) = {}:{}",
                                first_addr, location.0, location.1);
                        }
                    }
                }
                Err(e) => {
                    println!("  ✗ PDB解析エラー: {}", e);
                }
            }
        }
        Err(e) => {
            println!("  ✗ PDB読み込みエラー: {}", e);
        }
    }
    println!();
}
