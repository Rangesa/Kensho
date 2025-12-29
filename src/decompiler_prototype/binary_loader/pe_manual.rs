//! Manual PE Parser
//!
//! goblinのパースに失敗した場合のフォールバックとして、
//! 手動でPEヘッダーを解析します。
//!
//! 破損したヘッダーや不正な値にも可能な限り対応します。

use anyhow::{Context, Result, anyhow};
use std::convert::TryInto;

/// 手動パース結果
#[derive(Debug)]
pub struct ManualPEInfo {
    pub is_64bit: bool,
    pub entry_point: u64,
    pub image_base: u64,
    pub sections: Vec<ManualSectionInfo>,
}

/// セクション情報
#[derive(Debug)]
pub struct ManualSectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub characteristics: u32,
}

/// 手動PEパーサー
pub struct ManualPEParser;

impl ManualPEParser {
    /// PEファイルを手動でパース
    pub fn parse(data: &[u8]) -> Result<ManualPEInfo> {
        // DOSヘッダーのチェック
        if data.len() < 64 {
            return Err(anyhow!("File too small to be a valid PE"));
        }

        if &data[0..2] != b"MZ" {
            return Err(anyhow!("Invalid DOS signature"));
        }

        // PE署名へのオフセットを取得（オフセット0x3c）
        let pe_offset = Self::read_u32(data, 0x3c)? as usize;

        if data.len() < pe_offset + 4 {
            return Err(anyhow!("PE offset out of bounds"));
        }

        // PE署名のチェック
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(anyhow!("Invalid PE signature"));
        }

        // COFFヘッダー（PE署名の直後）
        let coff_offset = pe_offset + 4;
        if data.len() < coff_offset + 20 {
            return Err(anyhow!("COFF header out of bounds"));
        }

        let machine = Self::read_u16(data, coff_offset)?;
        let number_of_sections = Self::read_u16(data, coff_offset + 2)?;
        let size_of_optional_header = Self::read_u16(data, coff_offset + 16)?;

        // オプショナルヘッダー
        let opt_offset = coff_offset + 20;
        if data.len() < opt_offset + size_of_optional_header as usize {
            return Err(anyhow!("Optional header out of bounds"));
        }

        let magic = Self::read_u16(data, opt_offset)?;
        let is_64bit = magic == 0x20b; // PE32+ (64-bit)

        // エントリーポイントとイメージベース
        let entry_point = Self::read_u32(data, opt_offset + 16)? as u64;
        let image_base = if is_64bit {
            Self::read_u64(data, opt_offset + 24)?
        } else {
            Self::read_u32(data, opt_offset + 28)? as u64
        };

        // セクションヘッダー
        let section_offset = opt_offset + size_of_optional_header as usize;
        let mut sections = Vec::new();

        for i in 0..number_of_sections {
            let sec_off = section_offset + (i as usize * 40);

            if data.len() < sec_off + 40 {
                // セクションヘッダーが範囲外の場合、警告してスキップ
                eprintln!("[ManualPEParser] Warning: Section {} header out of bounds, skipping", i);
                break;
            }

            // セクション名（8バイト）
            let name_bytes = &data[sec_off..sec_off + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();

            let virtual_size = Self::read_u32(data, sec_off + 8)? as u64;
            let virtual_address = Self::read_u32(data, sec_off + 12)? as u64;
            let raw_size = Self::read_u32(data, sec_off + 16)? as u64;
            let raw_offset = Self::read_u32(data, sec_off + 20)? as u64;
            let characteristics = Self::read_u32(data, sec_off + 36)?;

            sections.push(ManualSectionInfo {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                characteristics,
            });
        }

        Ok(ManualPEInfo {
            is_64bit,
            entry_point,
            image_base,
            sections,
        })
    }

    /// u16を読み取る（範囲チェック付き）
    fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
        if data.len() < offset + 2 {
            return Err(anyhow!("Offset {} out of bounds for u16 read", offset));
        }
        Ok(u16::from_le_bytes(
            data[offset..offset + 2]
                .try_into()
                .context("Failed to read u16")?,
        ))
    }

    /// u32を読み取る（範囲チェック付き）
    fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
        if data.len() < offset + 4 {
            return Err(anyhow!("Offset {} out of bounds for u32 read", offset));
        }
        Ok(u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .context("Failed to read u32")?,
        ))
    }

    /// u64を読み取る（範囲チェック付き）
    fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
        if data.len() < offset + 8 {
            return Err(anyhow!("Offset {} out of bounds for u64 read", offset));
        }
        Ok(u64::from_le_bytes(
            data[offset..offset + 8]
                .try_into()
                .context("Failed to read u64")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_primitives() {
        let data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        assert_eq!(ManualPEParser::read_u16(&data, 0).unwrap(), 0x3412);
        assert_eq!(ManualPEParser::read_u32(&data, 0).unwrap(), 0x78563412);
        assert_eq!(ManualPEParser::read_u64(&data, 0).unwrap(), 0xF0DEBC9A78563412);
    }

    #[test]
    fn test_read_out_of_bounds() {
        let data = vec![0x12, 0x34];

        assert!(ManualPEParser::read_u32(&data, 0).is_err());
        assert!(ManualPEParser::read_u64(&data, 0).is_err());
    }
}
