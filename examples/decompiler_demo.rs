/// Ghidra繝・さ繝ｳ繝代う繝ｩ繧ｳ繧｢ 繝励Ο繝医ち繧､繝励・繝・Δ
///
/// 螳溯｡梧婿豕・
/// cargo run --example decompiler_demo

use kensho_mcp::decompiler_prototype::{
    x86_64::{X86Decoder, X86Register},
    cfg::ControlFlowGraph,
    printer::SimplePrinter,
};

fn main() {
    println!("=== Ghidra Decompiler Core Prototype Demo ===\n");

    // 繝・Δ1: 邁｡蜊倥↑髢｢謨ｰ
    demo_simple_function();

    // 繝・Δ2: 繧医ｊ隍・尅縺ｪ髢｢謨ｰ
    demo_complex_function();

    println!("\n=== Demo Complete ===");
}

/// 繝・Δ1: 邁｡蜊倥↑髢｢謨ｰ
/// C逍台ｼｼ繧ｳ繝ｼ繝・
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

/// 繝・Δ2: 繧医ｊ隍・尅縺ｪ髢｢謨ｰ
/// C逍台ｼｼ繧ｳ繝ｼ繝・
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

    // 蠑墓焚繧偵Ξ繧ｸ繧ｹ繧ｿ縺ｫ險ｭ螳夲ｼ・ = rdi, y = rsi・・    // mov rax, rdi
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

    // 蛻ｶ蠕｡繝輔Ο繝ｼ繧ｰ繝ｩ繝輔ｒ讒狗ｯ・    let cfg = ControlFlowGraph::from_pcodes(pcodes.clone());
    println!("\n{}", cfg);

    // C險隱槫・蜉・    println!("C Output:");
    let mut printer = SimplePrinter::new();
    let c_code = printer.print_cfg(&cfg);
    println!("{}", c_code);
}
