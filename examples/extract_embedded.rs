use std::fs::File;
use std::io::{Read, Write};

fn main() -> std::io::Result<()> {
    // .std繝輔ぃ繧､繝ｫ繧定ｪｭ縺ｿ霎ｼ繧
    let mut file = File::open("WW_extracted/.std")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    println!("Searching for embedded files...\n");

    // PNG繝輔ぃ繧､繝ｫ繧呈､懃ｴ｢繝ｻ謚ｽ蜃ｺ
    let png_signature = b"\x89PNG\r\n\x1a\n";
    let mut png_count = 0;
    
    for (i, window) in buffer.windows(png_signature.len()).enumerate() {
        if window == png_signature {
            println!("Found PNG signature at offset: 0x{:08x}", i);
            
            // IEND繝√Ε繝ｳ繧ｯ繧呈､懃ｴ｢
            let iend_marker = b"IEND\xae\x42\x60\x82";
            if let Some(end_pos) = buffer[i..].windows(iend_marker.len())
                .position(|w| w == iend_marker) {
                let end_offset = i + end_pos + iend_marker.len();
                println!("  PNG ends at offset: 0x{:08x}", end_offset);
                println!("  PNG size: {} bytes", end_offset - i);
                
                // PNG繝輔ぃ繧､繝ｫ繧呈歓蜃ｺ
                let png_data = &buffer[i..end_offset];
                let filename = format!("extracted_image_{}.png", png_count);
                let mut output = File::create(&filename)?;
                output.write_all(png_data)?;
                println!("  Extracted to: {}\n", filename);
                
                png_count += 1;
            }
        }
    }

    // XML繝槭ル繝輔ぉ繧ｹ繝医ｒ讀懃ｴ｢繝ｻ謚ｽ蜃ｺ
    let xml_start = b"<?xml";
    for (i, window) in buffer.windows(xml_start.len()).enumerate() {
        if window == xml_start {
            println!("Found XML at offset: 0x{:08x}", i);
            
            // </assembly>繧呈､懃ｴ｢
            let xml_end = b"</assembly>";
            if let Some(end_pos) = buffer[i..].windows(xml_end.len())
                .position(|w| w == xml_end) {
                let end_offset = i + end_pos + xml_end.len();
                let xml_data = &buffer[i..end_offset];
                
                // XML繧偵ユ繧ｭ繧ｹ繝医→縺励※謚ｽ蜃ｺ
                if let Ok(xml_text) = std::str::from_utf8(xml_data) {
                    let mut output = File::create("extracted_manifest.xml")?;
                    output.write_all(xml_text.as_bytes())?;
                    println!("  Extracted manifest to: extracted_manifest.xml");
                    println!("  Content:\n{}\n", xml_text);
                }
            }
        }
    }

    // 縺昴・莉悶・繝舌う繝翫Μ讒矩繧定ｧ｣譫・
    println!("=== Binary Structure Analysis ===");
    
    // 譛蛻昴・謨ｰ繝舌う繝医ｒ隗｣譫撰ｼ医・繝・ム繝ｼ讒矩縺ｮ蜿ｯ閭ｽ諤ｧ・・
    if buffer.len() >= 64 {
        println!("Potential header structure:");
        for i in (0..64).step_by(16) {
            print!("  {:04x}: ", i);
            for j in 0..16 {
                if i + j < buffer.len() {
                    print!("{:02x} ", buffer[i + j]);
                }
            }
            print!("  |  ");
            for j in 0..16 {
                if i + j < buffer.len() {
                    let byte = buffer[i + j];
                    if byte >= 0x20 && byte <= 0x7E {
                        print!("{}", byte as char);
                    } else {
                        print!(".");
                    }
                }
            }
            println!();
        }
    }

    println!("\nExtraction complete!");
    println!("Total PNGs extracted: {}", png_count);

    Ok(())
}
