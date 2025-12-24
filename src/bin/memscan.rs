/// 汎用メモリスキャナー - あらゆるプロセスに対応
///
/// Usage:
///   memscan --process <name or PID>
///   memscan -p aces.exe --string "Player"
///   memscan -p 1234 --int 100 --float 1.5

use anyhow::Result;
use clap::{Parser, Subcommand};
use ghidra_mcp::memory_scanner::MemoryScanner;

#[derive(Parser)]
#[command(name = "memscan")]
#[command(about = "Universal memory scanner for game hacking and reverse engineering", long_about = None)]
struct Cli {
    /// Target process name or PID
    #[arg(short, long, value_name = "PROCESS")]
    process: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List all memory regions
    Regions,

    /// Scan for integer value
    Int {
        /// Value to search for
        value: i64,

        /// Size in bytes (1, 2, 4, or 8)
        #[arg(short, long, default_value = "4")]
        size: u8,
    },

    /// Scan for float value
    Float {
        /// Value to search for
        value: f32,
    },

    /// Scan for string
    String {
        /// String to search for
        text: String,

        /// Case sensitive
        #[arg(short, long)]
        case_sensitive: bool,
    },

    /// Scan for byte pattern (hex)
    Pattern {
        /// Pattern in hex format (e.g., "48 8B 5C 24 ?? 48 83 C4")
        /// Use ?? for wildcards
        pattern: String,
    },

    /// Interactive mode (multiple scans)
    Interactive,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("🔍 Universal Memory Scanner");
    println!("{}", "=".repeat(80));

    // プロセスをアタッチ
    println!("\n📌 Attaching to process: {}", cli.process);
    let scanner = if let Ok(pid) = cli.process.parse::<u32>() {
        MemoryScanner::from_pid(pid)?
    } else {
        MemoryScanner::from_process_name(&cli.process)?
    };

    println!("   ✅ Attached successfully!");
    println!("   PID: {}", scanner.process_info.pid);
    println!("   Base Address: 0x{:X}", scanner.process_info.base_address);

    match cli.command {
        Some(Commands::Regions) => {
            cmd_regions(&scanner)?;
        },
        Some(Commands::Int { value, size }) => {
            cmd_int(&scanner, value, size)?;
        },
        Some(Commands::Float { value }) => {
            cmd_float(&scanner, value)?;
        },
        Some(Commands::String { text, case_sensitive }) => {
            cmd_string(&scanner, &text, case_sensitive)?;
        },
        Some(Commands::Pattern { pattern }) => {
            cmd_pattern(&scanner, &pattern)?;
        },
        Some(Commands::Interactive) => {
            cmd_interactive(&scanner)?;
        },
        None => {
            // デフォルト: プロセス情報と統計を表示
            cmd_info(&scanner)?;
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("✅ Scan complete!");

    Ok(())
}

fn cmd_regions(scanner: &MemoryScanner) -> Result<()> {
    println!("\n📊 Memory Regions:");
    let regions = scanner.enumerate_regions()?;

    println!("   Total regions: {}", regions.len());

    let total_size: usize = regions.iter().map(|r| r.size).sum();
    println!("   Total memory: {} MB", total_size / (1024 * 1024));

    println!("\n   Top 20 regions:");
    for (i, region) in regions.iter().take(20).enumerate() {
        println!(
            "   [{:3}] 0x{:016X} - 0x{:016X}  ({:8} KB)  Protection: 0x{:X}",
            i,
            region.base_address,
            region.base_address + region.size,
            region.size / 1024,
            region.protection
        );
    }

    if regions.len() > 20 {
        println!("   ... and {} more regions", regions.len() - 20);
    }

    Ok(())
}

fn cmd_int(scanner: &MemoryScanner, value: i64, size: u8) -> Result<()> {
    println!("\n🔢 Scanning for integer: {} (size: {} bytes)", value, size);

    let results = match size {
        4 => scanner.scan_int32(value as i32)?,
        8 => scanner.scan_int64(value)?,
        _ => {
            eprintln!("   ❌ Unsupported size: {} (use 4 or 8)", size);
            return Ok(());
        }
    };

    println!("   ✅ Found {} matches", results.len());

    for (i, addr) in results.iter().take(50).enumerate() {
        println!("   [{:4}] 0x{:016X}", i, addr);
    }

    if results.len() > 50 {
        println!("   ... and {} more matches", results.len() - 50);
    }

    Ok(())
}

fn cmd_float(scanner: &MemoryScanner, value: f32) -> Result<()> {
    println!("\n🔢 Scanning for float: {}", value);

    let results = scanner.scan_float(value)?;
    println!("   ✅ Found {} matches", results.len());

    for (i, addr) in results.iter().take(50).enumerate() {
        println!("   [{:4}] 0x{:016X}", i, addr);
    }

    if results.len() > 50 {
        println!("   ... and {} more matches", results.len() - 50);
    }

    Ok(())
}

fn cmd_string(scanner: &MemoryScanner, text: &str, case_sensitive: bool) -> Result<()> {
    println!("\n🔤 Scanning for string: \"{}\"", text);
    println!("   Case sensitive: {}", case_sensitive);

    let search_text = if case_sensitive {
        text.to_string()
    } else {
        text.to_lowercase()
    };

    let results = scanner.scan_string(&search_text)?;
    println!("   ✅ Found {} matches", results.len());

    for (i, addr) in results.iter().take(50).enumerate() {
        println!("   [{:4}] 0x{:016X}", i, addr);
    }

    if results.len() > 50 {
        println!("   ... and {} more matches", results.len() - 50);
    }

    Ok(())
}

fn cmd_pattern(scanner: &MemoryScanner, pattern_str: &str) -> Result<()> {
    println!("\n🔍 Scanning for pattern: {}", pattern_str);

    // パターンをパース（例: "48 8B 5C 24 ?? 48 83 C4"）
    let parts: Vec<&str> = pattern_str.split_whitespace().collect();
    let mut pattern = Vec::new();
    let mut mask = Vec::new();

    for part in parts {
        if part == "??" {
            pattern.push(0);
            mask.push(false);
        } else {
            match u8::from_str_radix(part, 16) {
                Ok(byte) => {
                    pattern.push(byte);
                    mask.push(true);
                },
                Err(_) => {
                    eprintln!("   ❌ Invalid hex byte: {}", part);
                    return Ok(());
                }
            }
        }
    }

    println!("   Pattern bytes: {}", pattern.len());
    println!("   Wildcards: {}", mask.iter().filter(|&&m| !m).count());

    let results = scanner.scan_pattern(&pattern, Some(&mask))?;
    println!("   ✅ Found {} matches", results.len());

    for (i, addr) in results.iter().take(50).enumerate() {
        println!("   [{:4}] 0x{:016X}", i, addr);
    }

    if results.len() > 50 {
        println!("   ... and {} more matches", results.len() - 50);
    }

    Ok(())
}

fn cmd_interactive(scanner: &MemoryScanner) -> Result<()> {
    println!("\n🎮 Interactive Mode");
    println!("   Commands:");
    println!("     int <value>        - Scan for integer");
    println!("     float <value>      - Scan for float");
    println!("     string <text>      - Scan for string");
    println!("     pattern <hex>      - Scan for byte pattern");
    println!("     regions            - List memory regions");
    println!("     quit               - Exit");

    use std::io::{self, Write};

    loop {
        print!("\nmemscan> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        match parts.get(0) {
            Some(&"quit") | Some(&"exit") => break,
            Some(&"regions") => cmd_regions(scanner)?,
            Some(&"int") if parts.len() >= 2 => {
                if let Ok(value) = parts[1].parse::<i64>() {
                    cmd_int(scanner, value, 4)?;
                }
            },
            Some(&"float") if parts.len() >= 2 => {
                if let Ok(value) = parts[1].parse::<f32>() {
                    cmd_float(scanner, value)?;
                }
            },
            Some(&"string") if parts.len() >= 2 => {
                let text = parts[1..].join(" ");
                cmd_string(scanner, &text, true)?;
            },
            Some(&"pattern") if parts.len() >= 2 => {
                let pattern = parts[1..].join(" ");
                cmd_pattern(scanner, &pattern)?;
            },
            _ => {
                println!("   ❌ Unknown command");
            }
        }
    }

    Ok(())
}

fn cmd_info(scanner: &MemoryScanner) -> Result<()> {
    println!("\n📊 Process Information:");

    let regions = scanner.enumerate_regions()?;
    let total_size: usize = regions.iter().map(|r| r.size).sum();
    let readable_regions = regions.iter()
        .filter(|r| r.protection & 0x04 != 0)
        .count();

    println!("   Total memory regions: {}", regions.len());
    println!("   Readable regions: {}", readable_regions);
    println!("   Total memory size: {} MB", total_size / (1024 * 1024));

    println!("\n💡 Usage examples:");
    println!("   memscan -p {} regions", scanner.process_info.pid);
    println!("   memscan -p {} int 100", scanner.process_info.pid);
    println!("   memscan -p {} float 1.5", scanner.process_info.pid);
    println!("   memscan -p {} string Player", scanner.process_info.pid);
    println!("   memscan -p {} pattern \"48 8B ?? 24\"", scanner.process_info.pid);
    println!("   memscan -p {} interactive", scanner.process_info.pid);

    Ok(())
}
