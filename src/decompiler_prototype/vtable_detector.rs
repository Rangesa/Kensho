// vtable検出モジュール
// C++オブジェクトの仮想関数テーブルを自動検出

use super::pcode::{PcodeOp, OpCode, Varnode, AddressSpace};
use super::cfg::ControlFlowGraph;
use std::collections::{HashMap, HashSet};
use anyhow::Result;

/// 仮想関数情報
#[derive(Debug, Clone)]
pub struct VirtualFunction {
    /// vtable内のオフセット（バイト）
    pub vtable_offset: usize,
    /// 関数の実アドレス
    pub function_address: u64,
    /// 推論された関数名
    pub name: Option<String>,
    /// 関数シグネチャ（後で推論）
    pub signature: Option<FunctionSignature>,
}

/// 関数シグネチャ（vtable_detectorでは基本情報のみ）
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// パラメータ数
    pub param_count: usize,
    /// 戻り値があるか
    pub has_return: bool,
}

/// vtable情報
#[derive(Debug, Clone)]
pub struct VTableInfo {
    /// vtableのアドレス
    pub address: u64,
    /// 仮想関数の配列
    pub virtual_functions: Vec<VirtualFunction>,
    /// このvtableを使用しているクラスのサイズ推定
    pub class_size: usize,
    /// 親クラスのvtable（継承の検出）
    pub parent_vtable: Option<u64>,
    /// クラス名（推論または既知）
    pub class_name: Option<String>,
}

/// vtable検出器
pub struct VTableDetector {
    /// 検出されたvtable
    vtables: HashMap<u64, VTableInfo>,
    /// vtableへの参照（オブジェクトアドレス -> vtableアドレス）
    #[allow(dead_code)]
    object_to_vtable: HashMap<u64, u64>,
    /// バイナリデータ（vtableの検証用）
    binary_data: Vec<u8>,
}

impl VTableDetector {
    /// 新しいvtable検出器を作成
    pub fn new(binary_data: Vec<u8>) -> Self {
        Self {
            vtables: HashMap::new(),
            object_to_vtable: HashMap::new(),
            binary_data,
        }
    }

    /// P-code命令列からvtableを検出
    pub fn detect_vtables(&mut self, ops: &[PcodeOp], _cfg: &ControlFlowGraph) -> Result<()> {
        // ステップ1: vtableポインタへのアクセスを検出
        let vtable_candidates = self.find_vtable_pointers(ops)?;

        // ステップ2: 各候補が本当にvtableか検証
        for candidate_addr in vtable_candidates {
            if let Some(vtable_info) = self.verify_and_parse_vtable(candidate_addr)? {
                self.vtables.insert(candidate_addr, vtable_info);
            }
        }

        // ステップ3: 継承関係を解析
        self.analyze_inheritance()?;

        Ok(())
    }

    /// vtableポインタへのアクセスを検出
    fn find_vtable_pointers(&mut self, ops: &[PcodeOp]) -> Result<Vec<u64>> {
        let mut candidates = HashSet::new();

        for op in ops {
            match op.opcode {
                OpCode::Load => {
                    // オブジェクトの最初のフィールド（オフセット0）へのアクセスを検出
                    if op.inputs.len() >= 1 {
                        if let Some(vtable_ptr) = self.extract_vtable_candidate(&op.inputs[0]) {
                            candidates.insert(vtable_ptr);
                        }
                    }
                }
                OpCode::CallInd => {
                    // 間接呼び出しは仮想関数呼び出しの可能性
                    // call *[vtable + offset]
                    if op.inputs.len() >= 1 {
                        if let Some(vtable_ptr) = self.extract_vtable_from_indirect_call(&op.inputs[0]) {
                            candidates.insert(vtable_ptr);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(candidates.into_iter().collect())
    }

    /// vtable候補を抽出
    fn extract_vtable_candidate(&self, varnode: &Varnode) -> Option<u64> {
        // 定数アドレスの場合、それがvtableポインタの可能性
        if varnode.space == AddressSpace::Const {
            Some(varnode.offset)
        } else {
            None
        }
    }

    /// 間接呼び出しからvtableを抽出
    fn extract_vtable_from_indirect_call(&self, _varnode: &Varnode) -> Option<u64> {
        // TODO: より高度な解析
        // [reg + offset] -> reg = vtable, offset = 仮想関数のオフセット
        None
    }

    /// vtableを検証してパース
    fn verify_and_parse_vtable(&self, address: u64) -> Result<Option<VTableInfo>> {
        // vtableは関数ポインタの配列
        let mut virtual_functions = Vec::new();
        let mut offset = 0usize;

        // 最大32個の仮想関数をチェック（実際のvtableはもっと少ないことが多い）
        for _ in 0..32 {
            if let Some(func_addr) = self.read_pointer_at(address + offset as u64) {
                // このアドレスが関数の開始点かチェック
                if self.is_likely_function_start(func_addr) {
                    virtual_functions.push(VirtualFunction {
                        vtable_offset: offset,
                        function_address: func_addr,
                        name: None,
                        signature: None,
                    });
                    offset += 8; // 64bitポインタ
                } else {
                    // 関数ポインタでない場合、vtableの終わり
                    break;
                }
            } else {
                break;
            }
        }

        // 少なくとも1つの仮想関数があればvtableと判定
        if virtual_functions.is_empty() {
            return Ok(None);
        }

        Ok(Some(VTableInfo {
            address,
            virtual_functions,
            class_size: 0, // 後で推論
            parent_vtable: None,
            class_name: Some(format!("Class_{:x}", address)),
        }))
    }

    /// 指定アドレスからポインタを読み取り
    fn read_pointer_at(&self, address: u64) -> Option<u64> {
        let offset = address as usize;
        if offset + 8 <= self.binary_data.len() {
            let bytes = &self.binary_data[offset..offset + 8];
            Some(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        } else {
            None
        }
    }

    /// アドレスが関数の開始点である可能性をチェック
    fn is_likely_function_start(&self, address: u64) -> bool {
        let offset = address as usize;
        if offset >= self.binary_data.len() {
            return false;
        }

        // 一般的な関数プロローグパターンをチェック
        // x64の場合: push rbp (0x55), mov rbp, rsp (0x48 0x89 0xe5)
        if offset + 4 <= self.binary_data.len() {
            let bytes = &self.binary_data[offset..offset + 4];

            // push rbp; mov rbp, rsp
            if bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xe5 {
                return true;
            }

            // sub rsp, imm (0x48 0x83 0xec)
            if bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xec {
                return true;
            }
        }

        // その他のヒューリスティック
        // - アドレスがコードセクション内か
        // - アドレスが関数境界にアライメントされているか

        true // 仮実装：全て関数と仮定
    }

    /// 継承関係を解析
    fn analyze_inheritance(&mut self) -> Result<()> {
        // vtableの先頭部分が共通している場合、継承関係の可能性
        let vtable_addrs: Vec<u64> = self.vtables.keys().copied().collect();

        for i in 0..vtable_addrs.len() {
            for j in (i + 1)..vtable_addrs.len() {
                let addr1 = vtable_addrs[i];
                let addr2 = vtable_addrs[j];

                if self.is_parent_child_relation(addr1, addr2) {
                    // addr1がaddr2の親クラス
                    if let Some(child_vtable) = self.vtables.get_mut(&addr2) {
                        child_vtable.parent_vtable = Some(addr1);
                    }
                }
            }
        }

        Ok(())
    }

    /// 親子関係をチェック
    fn is_parent_child_relation(&self, parent_addr: u64, child_addr: u64) -> bool {
        let parent = self.vtables.get(&parent_addr);
        let child = self.vtables.get(&child_addr);

        if let (Some(parent), Some(child)) = (parent, child) {
            // 子クラスのvtableが親クラスのvtableを含んでいるかチェック
            if child.virtual_functions.len() >= parent.virtual_functions.len() {
                for i in 0..parent.virtual_functions.len() {
                    if child.virtual_functions[i].function_address
                        != parent.virtual_functions[i].function_address {
                        // オーバーライドされている可能性もあるので完全一致は要求しない
                        // ただしオフセットは一致する必要がある
                        if child.virtual_functions[i].vtable_offset
                            != parent.virtual_functions[i].vtable_offset {
                            return false;
                        }
                    }
                }
                return true;
            }
        }

        false
    }

    /// 検出されたvtableを取得
    pub fn get_vtables(&self) -> &HashMap<u64, VTableInfo> {
        &self.vtables
    }

    /// 特定のアドレスのvtable情報を取得
    pub fn get_vtable(&self, address: u64) -> Option<&VTableInfo> {
        self.vtables.get(&address)
    }

    /// vtable検出結果のサマリーを生成
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("検出されたvtable: {} 個\n", self.vtables.len()));

        for (addr, vtable) in &self.vtables {
            summary.push_str(&format!("\nvtable @ 0x{:x}: {} (仮想関数: {} 個)\n",
                addr,
                vtable.class_name.as_ref().unwrap_or(&"unknown".to_string()),
                vtable.virtual_functions.len()));

            if let Some(parent) = vtable.parent_vtable {
                summary.push_str(&format!("  継承元: vtable @ 0x{:x}\n", parent));
            }

            for (i, vfunc) in vtable.virtual_functions.iter().enumerate() {
                summary.push_str(&format!("  [{}] +0x{:x}: 0x{:x}\n",
                    i, vfunc.vtable_offset, vfunc.function_address));
            }
        }

        summary
    }
}
