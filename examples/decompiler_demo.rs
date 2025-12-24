/// Ghidraデコンパイラコア プロトタイプのデモ
///
/// 実行方法:
/// cargo run --example decompiler_demo

use ghidra_mcp::decompiler_prototype::{
    x86_64::{X86Decoder, X86Register},
    cfg::ControlFlowGraph,
    printer::SimplePrinter,
};

fn main() {
    println!("=== Ghidra Decompiler Core Prototype Demo ===\n");

    // デモ1: 簡単な関数
    demo_simple_function();

    // デモ2: より複雑な関数
    demo_complex_function();

    println!("\n=== Demo Complete ===");
}

/// デモ1: 簡単な関数
/// C疑似コード:
/// ```c
/// int simple_add() {
///     int a = 0;
///     int b = 10;
///     return a + b;
/// }
/// ```
fn demo_simple_function() {
    println!("Demo 1: Simple Function");
    println!("------------------------");

    let mut decoder = X86Decoder::new();
    let mut pcodes = Vec::new();

    // mov rax, 0
    pcodes.extend(decoder.decode_mov_imm(X86Register::RAX, 0, 0x1000));
    // mov rbx, 10
    pcodes.extend(decoder.decode_mov_imm(X86Register::RBX, 10, 0x1003));
    // add rax, rbx
    pcodes.extend(decoder.decode_add(X86Register::RAX, X86Register::RBX, 0x1006));
    // ret
    pcodes.extend(decoder.decode_ret(0x1009));

    println!("P-code:");
    for (i, op) in pcodes.iter().enumerate() {
        println!("  [{}] 0x{:x}: {}", i, op.address, op);
    }

    println!("\nC Output:");
    let mut printer = SimplePrinter::new();
    let c_code = printer.print_pcodes(&pcodes);
    println!("{}", c_code);
}

/// デモ2: より複雑な関数
/// C疑似コード:
/// ```c
/// int complex_function(int x, int y) {
///     int sum = x + y;
///     int diff = x - y;
///     return sum + diff;
/// }
/// ```
fn demo_complex_function() {
    println!("\nDemo 2: Complex Function");
    println!("------------------------");

    let mut decoder = X86Decoder::new();
    let mut pcodes = Vec::new();

    // 引数をレジスタに設定（x = rdi, y = rsi）
    // mov rax, rdi
    pcodes.extend(decoder.decode_mov(X86Register::RAX, X86Register::RDI, 0x2000));
    // add rax, rsi (sum = x + y)
    pcodes.extend(decoder.decode_add(X86Register::RAX, X86Register::RSI, 0x2003));
    // mov rcx, rdi
    pcodes.extend(decoder.decode_mov(X86Register::RCX, X86Register::RDI, 0x2006));
    // sub rcx, rsi (diff = x - y)
    pcodes.extend(decoder.decode_sub(X86Register::RCX, X86Register::RSI, 0x2009));
    // add rax, rcx (result = sum + diff)
    pcodes.extend(decoder.decode_add(X86Register::RAX, X86Register::RCX, 0x200c));
    // ret
    pcodes.extend(decoder.decode_ret(0x200f));

    println!("P-code:");
    for (i, op) in pcodes.iter().enumerate() {
        println!("  [{}] 0x{:x}: {}", i, op.address, op);
    }

    // 制御フローグラフを構築
    let cfg = ControlFlowGraph::from_pcodes(pcodes.clone());
    println!("\n{}", cfg);

    // C言語出力
    println!("C Output:");
    let mut printer = SimplePrinter::new();
    let c_code = printer.print_cfg(&cfg);
    println!("{}", c_code);
}
