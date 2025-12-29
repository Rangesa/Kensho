// 高度な型推論デモ
// 構造体フィールド推論、vtable検出、関数シグネチャ推論を統合実演

use kensho_mcp::decompiler_prototype::{
    StructAnalyzer, VTableDetector, SignatureInferenceEngine, Architecture,
    PcodeOp, OpCode, Varnode, AddressSpace, ControlFlowGraph,
};
use std::fs;

fn main() {
    println!("=== 高度な型推論デモ ===\n");

    // Demo 1: 構造体フィールド推論
    demo_struct_field_inference();

    // Demo 2: vtable検出（C++オブジェクト解析）
    demo_vtable_detection();

    // Demo 3: 関数シグネチャ推論
    demo_function_signature_inference();

    println!("\n=== 全デモ完了 ===");
    println!("\n実装された高度な型推論機能:");
    println!("  ✓ 構造体フィールド自動推論 - メモリアクセスパターンから構造");
    println!("  ✓ vtable検出 - C++仮想関数テーブルの自動識別");
    println!("  ✓ 関数シグネチャ推論 - 引数と戻り値の型の自動推定");
    println!("  ✓ ポインタ解析 - 指す先の型の推論");
    println!("  ✓ 配列検出 - サイズと要素型の推定");
    println!("  ✓ 入れ子構造体 - 構造体内の構造体ポインタ検出");
}

fn demo_struct_field_inference() {
    println!("Demo 1: 構造体フィールド推論");
    println!("  メモリアクセスパターンから構造体のフィールド構成を自動推論");
    println!();

    // 模擬的なP-code命令列を作成
    // struct Point { int x; int y; } のようなアクセスパターン
    let base_reg = Varnode::register(0, 8); // rax = struct pointer

    let ops = vec![
        // Load x field (offset 0, size 4)
        PcodeOp {
            opcode: OpCode::Load,
            inputs: vec![
                Varnode::constant(0, 8), // address space
                base_reg.clone(),
            ],
            output: Some(Varnode::register(8, 4)),
            address: 0x1000,
        },
        // Load y field (offset 4, size 4)
        PcodeOp {
            opcode: OpCode::Load,
            inputs: vec![
                Varnode::constant(0, 8),
                base_reg.clone(),
            ],
            output: Some(Varnode::register(12, 4)),
            address: 0x1008,
        },
        // Store to x field
        PcodeOp {
            opcode: OpCode::Store,
            inputs: vec![
                Varnode::constant(0, 8),
                base_reg.clone(),
                Varnode::constant(42, 4),
            ],
            output: None,
            address: 0x1010,
        },
    ];

    let cfg = ControlFlowGraph::new();
    let mut analyzer = StructAnalyzer::new();

    match analyzer.analyze_struct_fields(&ops, &cfg) {
        Ok(()) => {
            println!("  ✓ 構造体解析成功\n");
            println!("{}", analyzer.generate_summary());

            // 推論された構造体の詳細表示
            if let Some(layout) = analyzer.get_inferred_structs().values().next() {
                println!("\n  推論されたC構造体:");
                println!("  struct {} {{", layout.name.as_ref().unwrap_or(&"unknown".to_string()));
                for field in &layout.fields {
                    println!("    {:?} {}; // offset: 0x{:x}, access: {:?}, count: {}",
                        field.field_type,
                        field.name.as_ref().unwrap_or(&"unknown".to_string()),
                        field.offset,
                        field.access_type,
                        field.access_count);
                }
                println!("  }}; // total size: {} bytes", layout.total_size);
            }
        }
        Err(e) => {
            println!("  ✗ 構造体解析エラー: {}", e);
        }
    }

    println!();
}

fn demo_vtable_detection() {
    println!("Demo 2: vtable検出（C++オブジェクト解析）");
    println!("  C++仮想関数テーブルを自動検出し、継承関係を推論");
    println!();

    // テスト用のバイナリを読み込み
    let test_binary = "D:/Programming/MCP/target/release/kensho-mcp.exe";

    match fs::read(test_binary) {
        Ok(binary_data) => {
            println!("  バイナリ読み込み: {} ({} bytes)", test_binary, binary_data.len());

            let mut detector = VTableDetector::new(binary_data);

            // 模擬的なP-code命令列
            let ops = vec![
                // 間接呼び出し（仮想関数呼び出し）
                PcodeOp {
                    opcode: OpCode::CallInd,
                    inputs: vec![Varnode::register(0, 8)],
                    output: None,
                    address: 0x2000,
                },
            ];

            let cfg = ControlFlowGraph::new();

            match detector.detect_vtables(&ops, &cfg) {
                Ok(()) => {
                    println!("  ✓ vtable検出完了\n");
                    println!("{}", detector.generate_summary());

                    if detector.get_vtables().is_empty() {
                        println!("  ℹ このバイナリからはvtableが検出されませんでした");
                        println!("  ℹ C++バイナリまたはデバッグシンボル付きバイナリで再試行してください");
                    } else {
                        // 検出されたvtableの詳細
                        for (addr, vtable) in detector.get_vtables() {
                            println!("\n  クラス: {} @ 0x{:x}",
                                vtable.class_name.as_ref().unwrap_or(&"unknown".to_string()),
                                addr);

                            if let Some(parent) = vtable.parent_vtable {
                                println!("    継承: 親クラスのvtable @ 0x{:x}", parent);
                            }

                            println!("    仮想関数:");
                            for vfunc in &vtable.virtual_functions {
                                println!("      virtual func_{:x}() @ 0x{:x} (vtable+0x{:x})",
                                    vfunc.function_address,
                                    vfunc.function_address,
                                    vfunc.vtable_offset);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("  ✗ vtable検出エラー: {}", e);
                }
            }
        }
        Err(e) => {
            println!("  ✗ バイナリ読み込みエラー: {}", e);
        }
    }

    println!();
}

fn demo_function_signature_inference() {
    println!("Demo 3: 関数シグネチャ推論");
    println!("  関数の引数、戻り値、呼び出し規約を自動推論");
    println!();

    // 関数の模擬的なP-code命令列
    // int add(int a, int b) { return a + b; }
    let ops = vec![
        // 引数をレジスタから読み取り（Windows x64: rcx, rdx）
        PcodeOp {
            opcode: OpCode::Copy,
            inputs: vec![Varnode::register(1, 4)], // rcx (arg0)
            output: Some(Varnode::unique(0, 4)),
            address: 0x3000,
        },
        PcodeOp {
            opcode: OpCode::Copy,
            inputs: vec![Varnode::register(2, 4)], // rdx (arg1)
            output: Some(Varnode::unique(1, 4)),
            address: 0x3004,
        },
        // 加算
        PcodeOp {
            opcode: OpCode::IntAdd,
            inputs: vec![
                Varnode::unique(0, 4),
                Varnode::unique(1, 4),
            ],
            output: Some(Varnode::unique(2, 4)),
            address: 0x3008,
        },
        // 結果をraxに設定（戻り値）
        PcodeOp {
            opcode: OpCode::Copy,
            inputs: vec![Varnode::unique(2, 4)],
            output: Some(Varnode::register(0, 4)), // rax
            address: 0x300c,
        },
        // return
        PcodeOp {
            opcode: OpCode::Return,
            inputs: vec![],
            output: None,
            address: 0x3010,
        },
    ];

    let cfg = ControlFlowGraph::new();
    let mut engine = SignatureInferenceEngine::new(Architecture::X86_64);

    match engine.infer_signature(0x3000, &ops, &cfg) {
        Ok(signature) => {
            println!("  ✓ シグネチャ推論成功\n");
            println!("{}", engine.generate_summary());

            // 推論された関数シグネチャの詳細
            println!("\n  推論されたC関数シグネチャ:");

            // 戻り値の型
            let ret_type = if let Some(ret) = &signature.return_value {
                format!("{:?}", ret.return_type)
            } else {
                "void".to_string()
            };

            // パラメータリスト
            let params: Vec<String> = signature.parameters.iter()
                .map(|p| format!("{:?} {}", p.param_type, p.name.as_ref().unwrap_or(&"unknown".to_string())))
                .collect();

            println!("  {} {}({}) {{",
                ret_type,
                signature.name.as_ref().unwrap_or(&"unknown".to_string()),
                params.join(", "));
            println!("    // 呼び出し規約: {:?}", signature.calling_convention);
            println!("    // スタックフレームサイズ: {} bytes", signature.stack_frame_size);
            println!("    // パラメータ数: {}", signature.parameters.len());

            for param in &signature.parameters {
                println!("    //   [{}] {:?} @ {:?}",
                    param.index, param.param_type, param.location);
            }

            println!("  }}");
        }
        Err(e) => {
            println!("  ✗ シグネチャ推論エラー: {}", e);
        }
    }

    println!();
}
