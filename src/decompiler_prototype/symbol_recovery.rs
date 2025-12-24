/// シンボル名復元システム
///
/// PEファイルのエクスポートテーブル、インポートテーブルから
/// 関数名・変数名を抽出して復元

use std::collections::HashMap;
use anyhow::Result;

/// シンボル情報
#[derive(Debug, Clone)]
pub struct Symbol {
    /// シンボル名
    pub name: String,
    /// 仮想アドレス
    pub address: u64,
    /// シンボルの種類
    pub kind: SymbolKind,
}

/// シンボルの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Variable,
    Import,
    Export,
}

/// シンボルテーブル
pub struct SymbolTable {
    /// アドレス → シンボル のマッピング
    symbols: HashMap<u64, Symbol>,
    /// 名前 → アドレス のマッピング（逆引き用）
    names: HashMap<String, u64>,
}

impl SymbolTable {
    /// 新しいシンボルテーブルを作成
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            names: HashMap::new(),
        }
    }

    /// PEファイルからシンボルを抽出
    ///
    /// PEフォーマットのエクスポートテーブルを解析してシンボル情報を取得
    pub fn load_from_pe(&mut self, binary_data: &[u8]) -> Result<usize> {
        // PE署名チェック
        if binary_data.len() < 0x40 {
            return Ok(0);
        }

        // DOSヘッダー確認
        if &binary_data[0..2] != b"MZ" {
            return Ok(0);
        }

        // PE headerオフセット取得
        let pe_offset = u32::from_le_bytes([
            binary_data[0x3C],
            binary_data[0x3D],
            binary_data[0x3E],
            binary_data[0x3F],
        ]) as usize;

        if pe_offset + 4 > binary_data.len() {
            return Ok(0);
        }

        // PE署名確認
        if &binary_data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Ok(0);
        }

        // COFFヘッダーとOptionalヘッダーを解析
        let coff_header_offset = pe_offset + 4;
        let optional_header_offset = coff_header_offset + 20;

        if optional_header_offset + 2 > binary_data.len() {
            return Ok(0);
        }

        // OptionalヘッダーのMagic値で64bit/32bitを判定
        let magic = u16::from_le_bytes([
            binary_data[optional_header_offset],
            binary_data[optional_header_offset + 1],
        ]);

        let is_64bit = magic == 0x020B; // PE32+
        let _is_32bit = magic == 0x010B; // PE32

        // エクスポートテーブルのRVA（相対仮想アドレス）を取得
        let export_table_offset = if is_64bit {
            optional_header_offset + 112
        } else {
            optional_header_offset + 96
        };

        if export_table_offset + 8 > binary_data.len() {
            return Ok(0);
        }

        let export_rva = u32::from_le_bytes([
            binary_data[export_table_offset],
            binary_data[export_table_offset + 1],
            binary_data[export_table_offset + 2],
            binary_data[export_table_offset + 3],
        ]);

        let export_size = u32::from_le_bytes([
            binary_data[export_table_offset + 4],
            binary_data[export_table_offset + 5],
            binary_data[export_table_offset + 6],
            binary_data[export_table_offset + 7],
        ]);

        if export_rva == 0 || export_size == 0 {
            return Ok(0); // エクスポートテーブルなし
        }

        // RVAをファイルオフセットに変換（簡易版）
        let export_offset = self.rva_to_offset(binary_data, export_rva)?;

        // エクスポートディレクトリテーブルを解析
        self.parse_export_directory(binary_data, export_offset as usize)
    }

    /// RVA（相対仮想アドレス）をファイルオフセットに変換
    fn rva_to_offset(&self, binary_data: &[u8], rva: u32) -> Result<u32> {
        // 簡易実装: .textセクションを仮定（実際にはセクションテーブルを解析すべき）
        // 通常.textは0x1000から始まり、ファイルオフセットは0x400
        let text_rva_start = 0x1000u32;
        let text_file_offset = 0x400u32;

        if rva >= text_rva_start {
            Ok(rva - text_rva_start + text_file_offset)
        } else {
            Ok(rva) // ヘッダー領域
        }
    }

    /// エクスポートディレクトリテーブルを解析
    fn parse_export_directory(&mut self, binary_data: &[u8], offset: usize) -> Result<usize> {
        if offset + 40 > binary_data.len() {
            return Ok(0);
        }

        // Number of Functions
        let num_functions = u32::from_le_bytes([
            binary_data[offset + 20],
            binary_data[offset + 21],
            binary_data[offset + 22],
            binary_data[offset + 23],
        ]) as usize;

        // Number of Names
        let num_names = u32::from_le_bytes([
            binary_data[offset + 24],
            binary_data[offset + 25],
            binary_data[offset + 26],
            binary_data[offset + 27],
        ]) as usize;

        // Address of Functions RVA
        let functions_rva = u32::from_le_bytes([
            binary_data[offset + 28],
            binary_data[offset + 29],
            binary_data[offset + 30],
            binary_data[offset + 31],
        ]);

        // Address of Names RVA
        let names_rva = u32::from_le_bytes([
            binary_data[offset + 32],
            binary_data[offset + 33],
            binary_data[offset + 34],
            binary_data[offset + 35],
        ]);

        // Address of Name Ordinals RVA
        let ordinals_rva = u32::from_le_bytes([
            binary_data[offset + 36],
            binary_data[offset + 37],
            binary_data[offset + 38],
            binary_data[offset + 39],
        ]);

        let functions_offset = self.rva_to_offset(binary_data, functions_rva)? as usize;
        let names_offset = self.rva_to_offset(binary_data, names_rva)? as usize;
        let ordinals_offset = self.rva_to_offset(binary_data, ordinals_rva)? as usize;

        let mut count = 0;

        // 各エクスポート関数を処理
        for i in 0..std::cmp::min(num_names, 1000) {
            // 名前RVAを取得
            let name_rva_offset = names_offset + i * 4;
            if name_rva_offset + 4 > binary_data.len() {
                break;
            }

            let name_rva = u32::from_le_bytes([
                binary_data[name_rva_offset],
                binary_data[name_rva_offset + 1],
                binary_data[name_rva_offset + 2],
                binary_data[name_rva_offset + 3],
            ]);

            // 名前文字列を読み取り
            let name_offset = self.rva_to_offset(binary_data, name_rva)? as usize;
            if let Some(name) = self.read_cstring(binary_data, name_offset) {
                // Ordinalを取得
                let ordinal_offset = ordinals_offset + i * 2;
                if ordinal_offset + 2 > binary_data.len() {
                    break;
                }

                let ordinal = u16::from_le_bytes([
                    binary_data[ordinal_offset],
                    binary_data[ordinal_offset + 1],
                ]) as usize;

                // 関数アドレスを取得
                let func_rva_offset = functions_offset + ordinal * 4;
                if func_rva_offset + 4 > binary_data.len() {
                    break;
                }

                let func_rva = u32::from_le_bytes([
                    binary_data[func_rva_offset],
                    binary_data[func_rva_offset + 1],
                    binary_data[func_rva_offset + 2],
                    binary_data[func_rva_offset + 3],
                ]);

                // イメージベースを加算（通常0x140000000 for 64bit）
                let image_base = 0x140000000u64;
                let func_address = image_base + func_rva as u64;

                // シンボルを追加
                self.add_symbol(Symbol {
                    name: name.clone(),
                    address: func_address,
                    kind: SymbolKind::Export,
                });

                count += 1;
            }
        }

        Ok(count)
    }

    /// C文字列を読み取り
    fn read_cstring(&self, data: &[u8], offset: usize) -> Option<String> {
        if offset >= data.len() {
            return None;
        }

        let mut end = offset;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }

        String::from_utf8(data[offset..end].to_vec()).ok()
    }

    /// シンボルを追加
    pub fn add_symbol(&mut self, symbol: Symbol) {
        self.names.insert(symbol.name.clone(), symbol.address);
        self.symbols.insert(symbol.address, symbol);
    }

    /// アドレスからシンボルを取得
    pub fn get_symbol(&self, address: u64) -> Option<&Symbol> {
        self.symbols.get(&address)
    }

    /// 名前からアドレスを取得
    pub fn get_address(&self, name: &str) -> Option<u64> {
        self.names.get(name).copied()
    }

    /// すべてのシンボルを取得
    pub fn get_all_symbols(&self) -> Vec<&Symbol> {
        self.symbols.values().collect()
    }

    /// シンボル数を取得
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// シンボルが空かどうか
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_table() {
        let mut table = SymbolTable::new();

        table.add_symbol(Symbol {
            name: "test_func".to_string(),
            address: 0x1000,
            kind: SymbolKind::Function,
        });

        assert_eq!(table.len(), 1);
        assert_eq!(table.get_address("test_func"), Some(0x1000));
        assert!(table.get_symbol(0x1000).is_some());
    }
}
