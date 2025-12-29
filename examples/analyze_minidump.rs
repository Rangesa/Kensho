use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[repr(C)]
#[derive(Debug)]
struct MinidumpHeader {
    signature: u32,           // 'MDMP' = 0x504D444D
    version: u32,             // 0x0000A793
    stream_count: u32,
    stream_directory_rva: u32,
    checksum: u32,
    time_date_stamp: u32,
    flags: u64,
}

fn main() -> std::io::Result<()> {
    let mut file = File::open("WW.DMP")?;
    let mut buffer = vec![0u8; std::mem::size_of::<MinidumpHeader>()];
    file.read_exact(&mut buffer)?;

    // 繝倥ャ繝繝ｼ繧定ｧ｣譫・
    let signature = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let version = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    let stream_count = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
    let stream_directory_rva = u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);
    let checksum = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
    let time_date_stamp = u32::from_le_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]);
    let flags = u64::from_le_bytes([
        buffer[24], buffer[25], buffer[26], buffer[27],
        buffer[28], buffer[29], buffer[30], buffer[31],
    ]);

    println!("=== Minidump Header ===");
    println!("Signature: 0x{:08X} ({})", signature, 
             String::from_utf8_lossy(&buffer[0..4]));
    println!("Version: 0x{:08X}", version);
    println!("Stream Count: {}", stream_count);
    println!("Stream Directory RVA: 0x{:08X}", stream_directory_rva);
    println!("Checksum: 0x{:08X}", checksum);
    
    // 繧ｿ繧､繝繧ｹ繧ｿ繝ｳ繝励ｒ螟画鋤
    let datetime = chrono::NaiveDateTime::from_timestamp_opt(time_date_stamp as i64, 0);
    if let Some(dt) = datetime {
        println!("Timestamp: {} ({})", time_date_stamp, dt.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("Timestamp: {}", time_date_stamp);
    }
    
    println!("Flags: 0x{:016X}", flags);
    
    // 繝輔Λ繧ｰ縺ｮ隗｣驥・
    println!("\nDump Type:");
    if flags & 0x00000001 != 0 { println!("  - MiniDumpNormal"); }
    if flags & 0x00000002 != 0 { println!("  - MiniDumpWithDataSegs"); }
    if flags & 0x00000004 != 0 { println!("  - MiniDumpWithFullMemory"); }
    if flags & 0x00000008 != 0 { println!("  - MiniDumpWithHandleData"); }
    if flags & 0x00000010 != 0 { println!("  - MiniDumpFilterMemory"); }
    if flags & 0x00000020 != 0 { println!("  - MiniDumpScanMemory"); }
    if flags & 0x00000040 != 0 { println!("  - MiniDumpWithUnloadedModules"); }
    if flags & 0x00000080 != 0 { println!("  - MiniDumpWithIndirectlyReferencedMemory"); }
    if flags & 0x00000100 != 0 { println!("  - MiniDumpFilterModulePaths"); }
    if flags & 0x00000200 != 0 { println!("  - MiniDumpWithProcessThreadData"); }
    if flags & 0x00000400 != 0 { println!("  - MiniDumpWithPrivateReadWriteMemory"); }
    if flags & 0x00000800 != 0 { println!("  - MiniDumpWithoutOptionalData"); }
    if flags & 0x00001000 != 0 { println!("  - MiniDumpWithFullMemoryInfo"); }
    if flags & 0x00002000 != 0 { println!("  - MiniDumpWithThreadInfo"); }
    if flags & 0x00004000 != 0 { println!("  - MiniDumpWithCodeSegs"); }

    // 繧ｹ繝医Μ繝ｼ繝繝・ぅ繝ｬ繧ｯ繝医Μ繧定ｪｭ縺ｿ霎ｼ繧
    println!("\n=== Stream Directory ===");
    file.seek(SeekFrom::Start(stream_directory_rva as u64))?;
    
    for i in 0..stream_count {
        let mut stream_entry = vec![0u8; 12]; // MINIDUMP_DIRECTORY: 12 bytes
        file.read_exact(&mut stream_entry)?;
        
        let stream_type = u32::from_le_bytes([stream_entry[0], stream_entry[1], stream_entry[2], stream_entry[3]]);
        let data_size = u32::from_le_bytes([stream_entry[4], stream_entry[5], stream_entry[6], stream_entry[7]]);
        let rva = u32::from_le_bytes([stream_entry[8], stream_entry[9], stream_entry[10], stream_entry[11]]);
        
        let stream_name = match stream_type {
            0 => "UnusedStream",
            1 => "ReservedStream0",
            2 => "ReservedStream1",
            3 => "ThreadListStream",
            4 => "ModuleListStream",
            5 => "MemoryListStream",
            6 => "ExceptionStream",
            7 => "SystemInfoStream",
            8 => "ThreadExListStream",
            9 => "Memory64ListStream",
            10 => "CommentStreamA",
            11 => "CommentStreamW",
            12 => "HandleDataStream",
            13 => "FunctionTableStream",
            14 => "UnloadedModuleListStream",
            15 => "MiscInfoStream",
            16 => "MemoryInfoListStream",
            17 => "ThreadInfoListStream",
            18 => "HandleOperationListStream",
            _ => "Unknown",
        };
        
        println!("Stream {}: {} (Type: {}, Size: {} bytes, RVA: 0x{:08X})", 
                 i, stream_name, stream_type, data_size, rva);
    }

    // ASCII譁・ｭ怜・繧呈､懃ｴ｢・域怙蛻昴・10MB・・
    println!("\n=== Searching for interesting strings in dump ===");
    file.seek(SeekFrom::Start(0))?;
    let mut search_buffer = vec![0u8; 10 * 1024 * 1024]; // 10MB
    let bytes_read = file.read(&mut search_buffer)?;
    search_buffer.truncate(bytes_read);
    
    // URL繧・ヵ繧｡繧､繝ｫ繝代せ繧呈､懃ｴ｢
    let text = String::from_utf8_lossy(&search_buffer);
    let mut found_strings = Vec::new();
    
    for line in text.lines() {
        if line.contains("http://") || line.contains("https://") || 
           line.contains(".exe") || line.contains(".dll") || 
           line.contains("C:\\") || line.contains("HKEY") {
            if line.len() > 10 && line.len() < 200 {
                found_strings.push(line.to_string());
            }
        }
    }
    
    found_strings.sort();
    found_strings.dedup();
    
    println!("Found {} interesting strings:", found_strings.len());
    for (i, s) in found_strings.iter().take(30).enumerate() {
        println!("  {}: {}", i + 1, s.trim());
    }

    Ok(())
}
