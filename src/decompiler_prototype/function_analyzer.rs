/// 関数解析機能
/// エクスポート関数の検出、関数境界の特定、関数間制御フローの解析

use super::pcode::*;
use super::cfg::*;
use anyhow::Result;
use goblin::pe::PE;
use std::collections::{HashMap, HashSet};

/// 関数情報
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// 関数名（もしあれば）
    pub name: Option<String>,
    /// 開始アドレス（仮想アドレス）
    pub start_address: u64,
    /// 終了アドレス（推定）
    pub end_address: Option<u64>,
    /// 関数のサイズ（バイト）
    pub size: Option<usize>,
    /// エクスポート関数かどうか
    pub is_export: bool,
    /// 呼び出す関数のリスト
    pub callees: Vec<u64>,
    /// この関数を呼び出す関数のリスト
    pub callers: Vec<u64>,
}

/// 関数検出器
pub struct FunctionDetector {
    /// 検出された関数のマップ（アドレス → 関数情報）
    functions: HashMap<u64, FunctionInfo>,
    /// コール命令のマップ（呼び出し元アドレス → 呼び出し先アドレス）
    call_graph: HashMap<u64, Vec<u64>>,
}

impl FunctionDetector {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            call_graph: HashMap::new(),
        }
    }

    /// PEファイルからエクスポート関数を検出
    pub fn detect_exports(&mut self, pe: &PE, image_base: u64) -> Result<()> {
        // エクスポートテーブルを解析
        for export in &pe.exports {
            if let Some(name) = export.name {
                let va = image_base + export.rva as u64;

                let func = FunctionInfo {
                    name: Some(name.to_string()),
                    start_address: va,
                    end_address: None,
                    size: None,
                    is_export: true,
                    callees: Vec::new(),
                    callers: Vec::new(),
                };

                self.functions.insert(va, func);
            }
        }

        Ok(())
    }

    /// P-code命令列から関数のエントリーポイントを検出
    /// 典型的なプロローグパターンを探す: push rbp; mov rbp, rsp
    pub fn detect_function_prologues(&mut self, pcodes: &[PcodeOp]) {
        let mut i = 0;
        while i < pcodes.len() {
            let op = &pcodes[i];

            // プロローグパターンの検出
            // TODO: より高度なパターンマッチング
            if matches!(op.opcode, OpCode::Call) {
                // Call命令から関数境界を推定
                if !op.inputs.is_empty() {
                    if let Some(target_addr) = self.extract_call_target(&op.inputs[0]) {
                        self.add_function_if_new(target_addr, None, false);
                        self.call_graph.entry(op.address).or_default().push(target_addr);
                    }
                }
            }

            i += 1;
        }
    }

    /// Call命令のターゲットアドレスを抽出
    fn extract_call_target(&self, input: &Varnode) -> Option<u64> {
        if input.space == AddressSpace::Const {
            Some(input.offset)
        } else {
            None
        }
    }

    /// 新しい関数を追加（既に存在しない場合のみ）
    fn add_function_if_new(&mut self, address: u64, name: Option<String>, is_export: bool) {
        self.functions.entry(address).or_insert(FunctionInfo {
            name,
            start_address: address,
            end_address: None,
            size: None,
            is_export,
            callees: Vec::new(),
            callers: Vec::new(),
        });
    }

    /// Return命令から関数の終了アドレスを推定
    pub fn estimate_function_boundaries(&mut self, pcodes: &[PcodeOp]) {
        let mut last_ret_address = 0u64;

        for op in pcodes {
            if matches!(op.opcode, OpCode::Return) {
                last_ret_address = op.address;

                // この関数を含む可能性がある範囲を探す
                for (_, func) in self.functions.iter_mut() {
                    if func.start_address <= op.address && func.end_address.is_none() {
                        func.end_address = Some(op.address);
                        if let Some(size) = op.address.checked_sub(func.start_address) {
                            func.size = Some(size as usize);
                        }
                    }
                }
            }
        }
    }

    /// コールグラフを構築（関数間の呼び出し関係）
    pub fn build_call_graph(&mut self) {
        // callers と callees を更新
        for (&caller_addr, callees) in &self.call_graph {
            // caller が属する関数を見つける
            let caller_func = self.find_function_containing(caller_addr);

            for &callee_addr in callees {
                // callee の関数を取得
                if let Some(callee_func) = self.functions.get_mut(&callee_addr) {
                    if let Some(caller_func_addr) = caller_func {
                        if !callee_func.callers.contains(&caller_func_addr) {
                            callee_func.callers.push(caller_func_addr);
                        }
                    }
                }

                // caller の callees に追加
                if let Some(caller_func_addr) = caller_func {
                    if let Some(caller_func) = self.functions.get_mut(&caller_func_addr) {
                        if !caller_func.callees.contains(&callee_addr) {
                            caller_func.callees.push(callee_addr);
                        }
                    }
                }
            }
        }
    }

    /// 指定されたアドレスを含む関数を見つける
    fn find_function_containing(&self, address: u64) -> Option<u64> {
        for (&func_addr, func) in &self.functions {
            if func.start_address <= address {
                if let Some(end_addr) = func.end_address {
                    if address <= end_addr {
                        return Some(func_addr);
                    }
                } else {
                    // 終了アドレスが不明な場合は、次の関数の開始までとする
                    return Some(func_addr);
                }
            }
        }
        None
    }

    /// 全関数情報を取得
    pub fn get_functions(&self) -> &HashMap<u64, FunctionInfo> {
        &self.functions
    }

    /// 特定の関数情報を取得
    pub fn get_function(&self, address: u64) -> Option<&FunctionInfo> {
        self.functions.get(&address)
    }

    /// エクスポート関数のみを取得
    pub fn get_export_functions(&self) -> Vec<&FunctionInfo> {
        self.functions
            .values()
            .filter(|f| f.is_export)
            .collect()
    }

    /// コールグラフを取得
    pub fn get_call_graph(&self) -> &HashMap<u64, Vec<u64>> {
        &self.call_graph
    }

    /// 関数の統計情報
    pub fn get_statistics(&self) -> FunctionStatistics {
        FunctionStatistics {
            total_functions: self.functions.len(),
            export_functions: self.functions.values().filter(|f| f.is_export).count(),
            total_calls: self.call_graph.values().map(|v| v.len()).sum(),
        }
    }
}

/// 関数統計情報
#[derive(Debug, Clone)]
pub struct FunctionStatistics {
    pub total_functions: usize,
    pub export_functions: usize,
    pub total_calls: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_detector() {
        let mut detector = FunctionDetector::new();

        // テスト用の関数を追加
        detector.add_function_if_new(0x1000, Some("main".to_string()), true);
        detector.add_function_if_new(0x2000, Some("helper".to_string()), false);

        assert_eq!(detector.functions.len(), 2);
        assert_eq!(detector.get_export_functions().len(), 1);
    }
}
