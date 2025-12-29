use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

fn main() -> std::io::Result<()> {
    // .std繝輔ぃ繧､繝ｫ繧定ｪｭ縺ｿ霎ｼ繧
    let std_path = "WW_extracted/.std";
    let mut file = File::open(std_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    println!("File size: {} bytes", buffer.len());
    
    // 譛蛻昴・256繝舌う繝医ｒHEX繝繝ｳ繝・
    println!("\n=== First 256 bytes (HEX) ===");
    for (i, chunk) in buffer.iter().take(256).enumerate() {
        if i % 16 == 0 {
            print!("\n{:08x}: ", i);
        }
        print!("{:02x} ", chunk);
    }
    println!("\n");

    // ASCII譁・ｭ怜・繧呈歓蜃ｺ・・譁・ｭ嶺ｻ･荳奇ｼ・
    println!("=== Extracted ASCII strings (min length: 4) ===");
    let mut current_string = String::new();
    for &byte in &buffer {
        if byte >= 0x20 && byte <= 0x7E {
            current_string.push(byte as char);
        } else {
            if current_string.len() >= 4 {
                println!("{}", current_string);
            }
            current_string.clear();
        }
    }
    
    // Unicode譁・ｭ怜・繧呈歓蜃ｺ・・TF-16LE・・
    println!("\n=== Extracted Unicode strings (UTF-16LE, min length: 4) ===");
    let mut i = 0;
    while i + 1 < buffer.len() {
        let mut unicode_string = Vec::new();
        let mut j = i;
        
        while j + 1 < buffer.len() {
            let low = buffer[j];
            let high = buffer[j + 1];
            
            if high == 0 && low >= 0x20 && low <= 0x7E {
                unicode_string.push(low as u16);
                j += 2;
            } else {
                break;
            }
        }
        
        if unicode_string.len() >= 4 {
            let s: String = unicode_string.iter()
                .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                .collect();
            println!("{}", s);
        }
        
        i += 2;
    }

    // 繝舌う繝磯ｻ蠎ｦ蛻・梵
    println!("\n=== Byte frequency analysis ===");
    let mut freq = vec![0u32; 256];
    for &byte in &buffer {
        freq[byte as usize] += 1;
    }
    
    let mut sorted_freq: Vec<(u8, u32)> = freq.iter()
        .enumerate()
        .map(|(i, &count)| (i as u8, count))
        .filter(|(_, count)| *count > 0)
        .collect();
    sorted_freq.sort_by(|a, b| b.1.cmp(&a.1));
    
    println!("Top 20 most frequent bytes:");
    for (byte, count) in sorted_freq.iter().take(20) {
        let percentage = (*count as f64 / buffer.len() as f64) * 100.0;
        println!("  0x{:02x} ({:3}): {:6} times ({:5.2}%)", 
                 byte, 
                 if *byte >= 0x20 && *byte <= 0x7E { *byte as char } else { '.' },
                 count, 
                 percentage);
    }

    // 讒矩隗｣譫舌・隧ｦ縺ｿ
    println!("\n=== Structure analysis ===");
    if buffer.len() >= 16 {
        println!("First 16 bytes as different types:");
        
        // u32 (little-endian)
        if buffer.len() >= 4 {
            let val = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
            println!("  u32 [0-3]: {}", val);
        }
        
        // u64 (little-endian)
        if buffer.len() >= 8 {
            let val = u64::from_le_bytes([
                buffer[0], buffer[1], buffer[2], buffer[3],
                buffer[4], buffer[5], buffer[6], buffer[7]
            ]);
            println!("  u64 [0-7]: {}", val);
        }
    }

    Ok(())
}
