/// War Thunder 動的解析デモ
/// ゲームプロセスにアタッチしてメモリをスキャン

use anyhow::Result;
use ghidra_mcp::memory_scanner::MemoryScanner;

fn main() -> Result<()> {
    println!("🎮 War Thunder Dynamic Analysis");
    println!("{}", "=".repeat(80));

    // War Thunderプロセスを検索
    println!("\n🔍 Searching for War Thunder process (aces.exe)...");

    let scanner = match MemoryScanner::from_process_name("aces.exe") {
        Ok(s) => {
            println!("   ✅ Process found!");
            println!("   PID: {}", s.process_info.pid);
            println!("   Base Address: 0x{:X}", s.process_info.base_address);
            s
        },
        Err(e) => {
            println!("   ❌ War Thunder is not running!");
            println!("   Error: {}", e);
            println!("\n💡 Please start War Thunder and try again.");
            return Ok(());
        }
    };

    // メモリリージョンを列挙
    println!("\n📊 Enumerating memory regions...");
    let regions = scanner.enumerate_regions()?;
    println!("   Found {} memory regions", regions.len());

    // 読み取り可能なリージョンの統計
    let total_size: usize = regions.iter().map(|r| r.size).sum();
    let readable_regions = regions.iter()
        .filter(|r| r.protection & 0x04 != 0) // PAGE_READWRITE
        .count();

    println!("   Total memory: {} MB", total_size / (1024 * 1024));
    println!("   Readable regions: {}", readable_regions);

    // 文字列をスキャン（デバッグ用）
    println!("\n🔤 Scanning for debug strings...");
    let debug_strings = [
        "Player",
        "Vehicle",
        "Damage",
        "Health",
        "Position",
        "Rotation",
    ];

    for debug_str in &debug_strings {
        match scanner.scan_string(debug_str) {
            Ok(results) if !results.is_empty() => {
                println!("   ✅ '{}' found at {} locations", debug_str, results.len());
                // 最初の5個のアドレスを表示
                for (i, addr) in results.iter().take(5).enumerate() {
                    println!("      [{}] 0x{:X}", i, addr);
                }
                if results.len() > 5 {
                    println!("      ... and {} more", results.len() - 5);
                }
            },
            Ok(_) => {
                println!("   ⚠️  '{}' not found", debug_str);
            },
            Err(e) => {
                println!("   ❌ Error scanning '{}': {}", debug_str, e);
            }
        }
    }

    // 典型的なゲーム値をスキャン
    println!("\n🎯 Scanning for game values...");

    // 体力値（0〜100の整数）
    println!("\n   Scanning for health values (0-100)...");
    for health in [100, 75, 50, 25].iter() {
        match scanner.scan_int32(*health) {
            Ok(results) if !results.is_empty() => {
                println!("   ✅ Health={} found at {} locations (too many, need refinement)", health, results.len());
            },
            _ => {}
        }
    }

    // 浮動小数点値（座標など）
    println!("\n   Scanning for floating point values...");
    let test_floats = [0.0f32, 1.0f32, 100.0f32, 1000.0f32];
    for value in &test_floats {
        match scanner.scan_float(*value) {
            Ok(results) if !results.is_empty() => {
                println!("   ✅ Float={} found at {} locations", value, results.len());
            },
            _ => {}
        }
    }

    // パターンマッチング（AOB: Array of Bytes）
    println!("\n🔍 Scanning for code patterns...");

    // 典型的なx86-64プロローグパターン
    let prologue_patterns = [
        (vec![0x40, 0x53], "push rbx"),
        (vec![0x48, 0x89, 0x5C, 0x24], "mov [rsp+??], rbx"),
        (vec![0x48, 0x83, 0xEC], "sub rsp, ??"),
    ];

    for (pattern, desc) in &prologue_patterns {
        match scanner.scan_pattern(pattern, None) {
            Ok(results) if !results.is_empty() => {
                println!("   ✅ Pattern '{}' found at {} locations", desc, results.len());
            },
            _ => {}
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("✅ Dynamic analysis complete!");

    println!("\n💡 Next steps for SDK development:");
    println!("   1. Identify player structure by scanning known values (health, ammo)");
    println!("   2. Use pointer scanning to find base addresses");
    println!("   3. Reverse engineer data structure layouts");
    println!("   4. Create offset signatures for auto-updating");
    println!("   5. Build SDK with safe memory read/write wrappers");

    Ok(())
}
