/// War Thunder 蜍慕噪隗｣譫舌ョ繝｢
/// 繧ｲ繝ｼ繝繝励Ο繧ｻ繧ｹ縺ｫ繧｢繧ｿ繝・メ縺励※繝｡繝｢繝ｪ繧偵せ繧ｭ繝｣繝ｳ

use anyhow::Result;
use kensho_mcp::memory_scanner::MemoryScanner;

fn main() -> Result<()> {
    println!("式 War Thunder Dynamic Analysis");
    println!("{}", "=".repeat(80));

    // War Thunder繝励Ο繧ｻ繧ｹ繧呈､懃ｴ｢
    println!("\n剥 Searching for War Thunder process (aces.exe)...");

    let scanner = match MemoryScanner::from_process_name("aces.exe") {
        Ok(s) => {
            println!("   笨・Process found!");
            println!("   PID: {}", s.process_info.pid);
            println!("   Base Address: 0x{:X}", s.process_info.base_address);
            s
        },
        Err(e) => {
            println!("   笶・War Thunder is not running!");
            println!("   Error: {}", e);
            println!("\n庁 Please start War Thunder and try again.");
            return Ok(());
        }
    };

    // 繝｡繝｢繝ｪ繝ｪ繝ｼ繧ｸ繝ｧ繝ｳ繧貞・謖・    println!("\n投 Enumerating memory regions...");
    let regions = scanner.enumerate_regions()?;
    println!("   Found {} memory regions", regions.len());

    // 隱ｭ縺ｿ蜿悶ｊ蜿ｯ閭ｽ縺ｪ繝ｪ繝ｼ繧ｸ繝ｧ繝ｳ縺ｮ邨ｱ險・    let total_size: usize = regions.iter().map(|r| r.size).sum();
    let readable_regions = regions.iter()
        .filter(|r| r.protection & 0x04 != 0) // PAGE_READWRITE
        .count();

    println!("   Total memory: {} MB", total_size / (1024 * 1024));
    println!("   Readable regions: {}", readable_regions);

    // 譁・ｭ怜・繧偵せ繧ｭ繝｣繝ｳ・医ョ繝舌ャ繧ｰ逕ｨ・・    println!("\n筈 Scanning for debug strings...");
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
                println!("   笨・'{}' found at {} locations", debug_str, results.len());
                // 譛蛻昴・5蛟九・繧｢繝峨Ξ繧ｹ繧定｡ｨ遉ｺ
                for (i, addr) in results.iter().take(5).enumerate() {
                    println!("      [{}] 0x{:X}", i, addr);
                }
                if results.len() > 5 {
                    println!("      ... and {} more", results.len() - 5);
                }
            },
            Ok(_) => {
                println!("   笞・・ '{}' not found", debug_str);
            },
            Err(e) => {
                println!("   笶・Error scanning '{}': {}", debug_str, e);
            }
        }
    }

    // 蜈ｸ蝙狗噪縺ｪ繧ｲ繝ｼ繝蛟､繧偵せ繧ｭ繝｣繝ｳ
    println!("\n識 Scanning for game values...");

    // 菴灘鴨蛟､・・縲・00縺ｮ謨ｴ謨ｰ・・    println!("\n   Scanning for health values (0-100)...");
    for health in [100, 75, 50, 25].iter() {
        match scanner.scan_int32(*health) {
            Ok(results) if !results.is_empty() => {
                println!("   笨・Health={} found at {} locations (too many, need refinement)", health, results.len());
            },
            _ => {}
        }
    }

    // 豬ｮ蜍募ｰ乗焚轤ｹ蛟､・亥ｺｧ讓吶↑縺ｩ・・    println!("\n   Scanning for floating point values...");
    let test_floats = [0.0f32, 1.0f32, 100.0f32, 1000.0f32];
    for value in &test_floats {
        match scanner.scan_float(*value) {
            Ok(results) if !results.is_empty() => {
                println!("   笨・Float={} found at {} locations", value, results.len());
            },
            _ => {}
        }
    }

    // 繝代ち繝ｼ繝ｳ繝槭ャ繝√Φ繧ｰ・・OB: Array of Bytes・・    println!("\n剥 Scanning for code patterns...");

    // 蜈ｸ蝙狗噪縺ｪx86-64繝励Ο繝ｭ繝ｼ繧ｰ繝代ち繝ｼ繝ｳ
    let prologue_patterns = [
        (vec![0x40, 0x53], "push rbx"),
        (vec![0x48, 0x89, 0x5C, 0x24], "mov [rsp+??], rbx"),
        (vec![0x48, 0x83, 0xEC], "sub rsp, ??"),
    ];

    for (pattern, desc) in &prologue_patterns {
        match scanner.scan_pattern(pattern, None) {
            Ok(results) if !results.is_empty() => {
                println!("   笨・Pattern '{}' found at {} locations", desc, results.len());
            },
            _ => {}
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("笨・Dynamic analysis complete!");

    println!("\n庁 Next steps for SDK development:");
    println!("   1. Identify player structure by scanning known values (health, ammo)");
    println!("   2. Use pointer scanning to find base addresses");
    println!("   3. Reverse engineer data structure layouts");
    println!("   4. Create offset signatures for auto-updating");
    println!("   5. Build SDK with safe memory read/write wrappers");

    Ok(())
}
