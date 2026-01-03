//! Error Recovery for Binary Parsing
//!
//! パース失敗時のエラーリカバリー機能を提供します。
//!
//! 主な機能:
//! - 部分的なデータ抽出
//! - ヒューリスティックによるセクション検出
//! - エントリーポイントの推定
//! - 文字列とAPI呼び出しの抽出

use anyhow::Result;
use std::collections::HashMap;

/// エラーリカバリー結果
#[derive(Debug)]
pub struct RecoveryResult {
    /// 抽出された文字列
    pub strings: Vec<String>,
    /// 検出されたコードパターン
    pub code_patterns: Vec<CodePattern>,
    /// 推定エントリーポイント
    pub estimated_entry_points: Vec<u64>,
    /// リカバリー状態
    pub status: RecoveryStatus,
}

/// コードパターン
#[derive(Debug, Clone)]
pub enum CodePattern {
    /// 関数プロローグ（push ebp; mov ebp, esp）
    FunctionPrologue(u64),
    /// API呼び出し（call [IAT]）
    APICall { address: u64, target: Option<String> },
    /// 文字列参照
    StringReference { address: u64, string: String },
}

/// リカバリー状態
#[derive(Debug)]
pub enum RecoveryStatus {
    /// 完全リカバリー
    Full,
    /// 部分的リカバリー
    Partial { missing_data: Vec<String> },
    /// 最小限のリカバリー
    Minimal { reason: String },
}

/// エラーリカバリーエンジン
pub struct ErrorRecovery;

impl ErrorRecovery {
    /// バイナリデータからの部分的リカバリー
    pub fn recover_from_data(data: &[u8]) -> Result<RecoveryResult> {
        let mut strings = Vec::new();
        let mut code_patterns = Vec::new();
        let mut estimated_entry_points = Vec::new();

        // 文字列を抽出
        strings.extend(Self::extract_strings(data, 4)); // 最小4文字

        // x86/x64のプロローグパターンを検出
        if let Ok(prologues) = Self::find_function_prologues(data) {
            for addr in prologues {
                code_patterns.push(CodePattern::FunctionPrologue(addr));

                // 最初の数個をエントリーポイント候補とする
                if estimated_entry_points.len() < 10 {
                    estimated_entry_points.push(addr);
                }
            }
        }

        let status = if !code_patterns.is_empty() && !strings.is_empty() {
            RecoveryStatus::Full
        } else if !code_patterns.is_empty() || !strings.is_empty() {
            let mut missing = Vec::new();
            if code_patterns.is_empty() {
                missing.push("Code patterns".to_string());
            }
            if strings.is_empty() {
                missing.push("Strings".to_string());
            }
            RecoveryStatus::Partial { missing_data: missing }
        } else {
            RecoveryStatus::Minimal {
                reason: "No recognizable patterns found".to_string(),
            }
        };

        Ok(RecoveryResult {
            strings,
            code_patterns,
            estimated_entry_points,
            status,
        })
    }

    /// ASCII文字列を抽出
    fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current_string = Vec::new();

        for &byte in data {
            if byte >= 0x20 && byte <= 0x7E {
                // 印字可能なASCII文字
                current_string.push(byte);
            } else if !current_string.is_empty() {
                if current_string.len() >= min_length {
                    if let Ok(s) = String::from_utf8(current_string.clone()) {
                        strings.push(s);
                    }
                }
                current_string.clear();
            }
        }

        // 最後の文字列
        if current_string.len() >= min_length {
            if let Ok(s) = String::from_utf8(current_string) {
                strings.push(s);
            }
        }

        strings
    }

    /// 関数プロローグパターンを検出
    fn find_function_prologues(data: &[u8]) -> Result<Vec<u64>> {
        let mut prologues = Vec::new();

        // x86: push ebp; mov ebp, esp (55 8b ec)
        // x64: push rbp; mov rbp, rsp (55 48 8b ec)
        let patterns = vec![
            vec![0x55, 0x8B, 0xEC],       // x86
            vec![0x55, 0x48, 0x8B, 0xEC], // x64
            vec![0x48, 0x83, 0xEC],       // sub rsp, imm8
            vec![0x48, 0x81, 0xEC],       // sub rsp, imm32
        ];

        for (i, window) in data.windows(4).enumerate() {
            for pattern in &patterns {
                if window.starts_with(pattern) {
                    prologues.push(i as u64);
                    break;
                }
            }
        }

        Ok(prologues)
    }

    /// IATからAPI呼び出しを抽出（実装簡略化）
    pub fn extract_api_calls(_data: &[u8]) -> Vec<String> {
        // TODO: IATテーブルのパースとAPI名の抽出
        Vec::new()
    }

    /// ヒューリスティックによるセクション境界の推定
    pub fn estimate_sections(data: &[u8]) -> Vec<(u64, u64, &'static str)> {
        let mut sections = Vec::new();

        // エントロピー分析でコード/データセクションを推定
        const SECTION_SIZE: usize = 0x1000; // 4KB
        let num_sections = (data.len() + SECTION_SIZE - 1) / SECTION_SIZE;

        for i in 0..num_sections {
            let start = i * SECTION_SIZE;
            let end = ((i + 1) * SECTION_SIZE).min(data.len());
            let section_data = &data[start..end];

            let entropy = Self::calculate_entropy(section_data);

            let section_type = if entropy > 7.0 {
                "compressed/encrypted"
            } else if entropy > 5.5 {
                "code"
            } else {
                "data"
            };

            sections.push((start as u64, end as u64, section_type));
        }

        sections
    }

    /// エントロピーを計算
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        for &byte in data {
            *freq.entry(byte).or_insert(0) += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for count in freq.values() {
            let p = *count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_strings() {
        let data = b"Hello\0World\0Test\x01\x02ABC";
        let strings = ErrorRecovery::extract_strings(data, 3);

        assert!(strings.contains(&"Hello".to_string()));
        assert!(strings.contains(&"World".to_string()));
        assert!(strings.contains(&"Test".to_string()));
        assert!(strings.contains(&"ABC".to_string()));
    }

    #[test]
    fn test_find_prologues() {
        let data = vec![
            0x55, 0x8B, 0xEC, // push ebp; mov ebp, esp
            0x00, 0x00, 0x00,
            0x55, 0x48, 0x8B, 0xEC, // push rbp; mov rbp, rsp
        ];

        let prologues = ErrorRecovery::find_function_prologues(&data).unwrap();
        assert_eq!(prologues.len(), 2);
        assert_eq!(prologues[0], 0);
        assert_eq!(prologues[1], 6);
    }

    #[test]
    fn test_calculate_entropy() {
        // 低エントロピー（すべて同じ値）
        let low_entropy_data = vec![0x00; 256];
        let entropy_low = ErrorRecovery::calculate_entropy(&low_entropy_data);
        assert!(entropy_low < 1.0);

        // 高エントロピー（ランダム風）
        let high_entropy_data: Vec<u8> = (0..=255).collect();
        let entropy_high = ErrorRecovery::calculate_entropy(&high_entropy_data);
        assert!(entropy_high > 7.0);
    }
}
