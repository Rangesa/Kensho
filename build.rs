use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=instructions.toml");

    // Rust出力ディレクトリを取得
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("x86_64_lifter.rs");

    // 擬似的な命令定義ファイルを生成（本来はTOML等から読み込む）
    let instructions = vec![
        ("MOV", "Standard Move"),
        ("ADD", "Addition"),
        ("SUB", "Subtraction"),
        ("JMP", "Unconditional Jump"),
        // ... 他の命令
    ];

    // 生成コードの作成
    let mut code = String::new();
    code.push_str("/// 自動生成されたx86_64リフター\n");
    code.push_str("pub fn lift_instruction(mnemonic: &str) -> Option<&'static str> {\n");
    code.push_str("    match mnemonic {\n");

    for (mnem, desc) in &instructions {
        code.push_str(&format!("        {:?} => Some({:?}),\n", mnem, desc));
    }

    code.push_str("        _ => None,\n");
    code.push_str("    }\n");
    code.push_str("}\n");

    // ファイルに書き出し
    fs::write(&dest_path, code).expect("Failed to write generated code");

    println!("cargo:warning=Kensho-MCP: x86_64_lifter.rsを生成しました（{} 命令）", instructions.len());
}
