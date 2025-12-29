//! Symbolic Memory Model with Symbolic Address Support
//!
//! シンボリックアドレスに対応した拡張メモリモデル
//!
//! 機能:
//! - シンボリックアドレスの読み書き
//! - ポインタエイリアシング解析
//! - バッファオーバーフロー検出
//! - Use-after-free検出

use super::symbolic_address::{SymbolicAddress, AddressOverlap, AddressRange};
use crate::decompiler_prototype::pcode::{Varnode, AddressSpace};
use std::collections::HashMap;

/// シンボリックメモリの値
#[derive(Debug, Clone)]
pub enum SymbolicValue {
    /// 具体値
    Concrete(Vec<u8>),

    /// シンボリック式（Z3式の文字列表現）
    Symbolic(String),

    /// 未初期化
    Uninitialized,
}

impl SymbolicValue {
    /// 具体値を作成
    pub fn from_u64(value: u64, size: usize) -> Self {
        let bytes = value.to_le_bytes();
        Self::Concrete(bytes[..size.min(8)].to_vec())
    }

    /// シンボリック値を作成
    pub fn symbolic(expr: String) -> Self {
        Self::Symbolic(expr)
    }

    /// 未初期化値を作成
    pub fn uninitialized() -> Self {
        Self::Uninitialized
    }

    /// 具体値かどうか
    pub fn is_concrete(&self) -> bool {
        matches!(self, SymbolicValue::Concrete(_))
    }

    /// シンボリック値かどうか
    pub fn is_symbolic(&self) -> bool {
        matches!(self, SymbolicValue::Symbolic(_))
    }

    /// 具体値を取得
    pub fn as_concrete(&self) -> Option<&Vec<u8>> {
        match self {
            SymbolicValue::Concrete(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// シンボリック式を取得
    pub fn as_symbolic(&self) -> Option<&String> {
        match self {
            SymbolicValue::Symbolic(expr) => Some(expr),
            _ => None,
        }
    }
}

/// メモリアクセス記録
#[derive(Debug, Clone)]
struct MemoryAccess {
    address: SymbolicAddress,
    value: SymbolicValue,
    size: usize,
    is_write: bool,
}

/// メモリ領域の情報
#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub name: String,
    pub base: SymbolicAddress,
    pub size: usize,
    pub is_allocated: bool,
}

/// 拡張シンボリックメモリモデル
#[derive(Debug, Clone)]
pub struct SymbolicMemoryV2 {
    /// 具体的アドレスへのメモリ（高速アクセス用）
    concrete_memory: HashMap<u64, SymbolicValue>,

    /// シンボリックアドレスへのメモリ
    /// (アドレス, サイズ) → 値
    symbolic_memory: Vec<(SymbolicAddress, usize, SymbolicValue)>,

    /// レジスタ
    registers: HashMap<Varnode, SymbolicValue>,

    /// メモリアクセス履歴（デバッグ・解析用）
    access_history: Vec<MemoryAccess>,

    /// メモリ領域の管理
    memory_regions: Vec<MemoryRegionInfo>,

    /// 統計情報
    stats: MemoryStatistics,
}

/// メモリアクセス統計
#[derive(Debug, Default, Clone)]
pub struct MemoryStatistics {
    pub reads: usize,
    pub writes: usize,
    pub concrete_accesses: usize,
    pub symbolic_accesses: usize,
    pub potential_overflows: usize,
    pub potential_use_after_free: usize,
}

impl SymbolicMemoryV2 {
    pub fn new() -> Self {
        Self {
            concrete_memory: HashMap::new(),
            symbolic_memory: Vec::new(),
            registers: HashMap::new(),
            access_history: Vec::new(),
            memory_regions: Vec::new(),
            stats: MemoryStatistics::default(),
        }
    }

    /// メモリから読み取り（シンボリックアドレス対応）
    pub fn read(&mut self, address: SymbolicAddress, size: usize) -> SymbolicValue {
        self.stats.reads += 1;

        // アドレスを簡約化
        let simplified_addr = address.simplify();

        // 具体的アドレスの場合は高速パスを使用
        if let Some(concrete_addr) = simplified_addr.as_concrete() {
            self.stats.concrete_accesses += 1;
            return self.read_concrete(concrete_addr, size);
        }

        // シンボリックアドレスの場合
        self.stats.symbolic_accesses += 1;
        self.read_symbolic(simplified_addr.clone(), size)
    }

    /// 具体的アドレスからの読み取り
    fn read_concrete(&self, address: u64, size: usize) -> SymbolicValue {
        if let Some(value) = self.concrete_memory.get(&address) {
            value.clone()
        } else {
            SymbolicValue::Uninitialized
        }
    }

    /// シンボリックアドレスからの読み取り
    fn read_symbolic(&mut self, address: SymbolicAddress, size: usize) -> SymbolicValue {
        // 既存のシンボリックメモリエントリを検索
        for (stored_addr, stored_size, value) in &self.symbolic_memory {
            if stored_addr == &address && *stored_size == size {
                return value.clone();
            }
        }

        // 見つからない場合は新しいシンボリック値を作成
        let sym_value = SymbolicValue::Symbolic(format!("mem[{}]", address));

        // アクセス履歴に記録
        self.access_history.push(MemoryAccess {
            address: address.clone(),
            value: sym_value.clone(),
            size,
            is_write: false,
        });

        sym_value
    }

    /// メモリに書き込み（シンボリックアドレス対応）
    pub fn write(&mut self, address: SymbolicAddress, size: usize, value: SymbolicValue) {
        self.stats.writes += 1;

        // バッファオーバーフローチェック
        self.check_buffer_overflow(&address, size);

        // Use-after-freeチェック
        self.check_use_after_free(&address);

        // アドレスを簡約化
        let simplified_addr = address.simplify();

        // アクセス履歴に記録
        self.access_history.push(MemoryAccess {
            address: simplified_addr.clone(),
            value: value.clone(),
            size,
            is_write: true,
        });

        // 具体的アドレスの場合は高速パスを使用
        if let Some(concrete_addr) = simplified_addr.as_concrete() {
            self.stats.concrete_accesses += 1;
            self.concrete_memory.insert(concrete_addr, value);
            return;
        }

        // シンボリックアドレスの場合
        self.stats.symbolic_accesses += 1;

        // 既存エントリを更新
        for (stored_addr, stored_size, stored_value) in &mut self.symbolic_memory {
            if stored_addr == &simplified_addr && *stored_size == size {
                *stored_value = value;
                return;
            }
        }

        // 新しいエントリを追加
        self.symbolic_memory.push((simplified_addr, size, value));
    }

    /// メモリ領域を確保
    pub fn allocate_region(&mut self, name: String, base: SymbolicAddress, size: usize) {
        self.memory_regions.push(MemoryRegionInfo {
            name,
            base,
            size,
            is_allocated: true,
        });
    }

    /// メモリ領域を解放
    pub fn free_region(&mut self, base: &SymbolicAddress) {
        for region in &mut self.memory_regions {
            if &region.base == base {
                region.is_allocated = false;
                break;
            }
        }
    }

    /// バッファオーバーフローをチェック
    fn check_buffer_overflow(&mut self, address: &SymbolicAddress, access_size: usize) {
        for region in &self.memory_regions {
            if !region.is_allocated {
                continue;
            }

            // アドレスが領域内に収まっているかチェック
            let region_range = AddressRange::new(region.base.clone(), region.size);
            let access_range = AddressRange::new(address.clone(), access_size);

            match region_range.may_overlap(&access_range) {
                AddressOverlap::DefinitelyOverlap => {
                    // 完全に重なる場合は範囲チェック
                    // TODO: Z3で範囲外アクセスを検証
                }
                AddressOverlap::MaybeOverlap => {
                    // 可能性がある場合は警告
                    self.stats.potential_overflows += 1;
                }
                AddressOverlap::NoOverlap => {}
            }
        }
    }

    /// Use-after-freeをチェック
    fn check_use_after_free(&mut self, address: &SymbolicAddress) {
        for region in &self.memory_regions {
            if region.is_allocated {
                continue;
            }

            // 解放済み領域へのアクセスをチェック
            if &region.base == address {
                self.stats.potential_use_after_free += 1;
                eprintln!(
                    "[WARNING] Potential use-after-free detected: {} (freed region: {})",
                    address, region.name
                );
            }
        }
    }

    /// エイリアシング解析
    ///
    /// 2つのアドレスが同じメモリ位置を指す可能性を判定
    pub fn check_aliasing(
        &self,
        addr1: &SymbolicAddress,
        addr2: &SymbolicAddress,
        size: usize,
    ) -> AddressOverlap {
        addr1.may_overlap(addr2, size)
    }

    /// レジスタから読み取り
    pub fn read_register(&mut self, reg: &Varnode) -> SymbolicValue {
        self.stats.reads += 1;
        self.stats.concrete_accesses += 1;

        if let Some(value) = self.registers.get(reg) {
            value.clone()
        } else {
            // 未初期化レジスタはシンボリック値として扱う
            let sym_name = format!("reg_{}_{}", reg.offset, reg.size);
            SymbolicValue::symbolic(sym_name)
        }
    }

    /// レジスタに書き込み
    pub fn write_register(&mut self, reg: Varnode, value: SymbolicValue) {
        self.stats.writes += 1;
        self.stats.concrete_accesses += 1;
        self.registers.insert(reg, value);
    }

    /// アクセス履歴を取得
    pub fn get_access_history(&self) -> &[MemoryAccess] {
        &self.access_history
    }

    /// メモリ領域の一覧を取得
    pub fn get_memory_regions(&self) -> &[MemoryRegionInfo] {
        &self.memory_regions
    }

    /// 統計情報を取得
    pub fn stats(&self) -> &MemoryStatistics {
        &self.stats
    }

    /// 統計情報をリセット
    pub fn reset_stats(&mut self) {
        self.stats = MemoryStatistics::default();
    }

    /// メモリをクリア
    pub fn clear(&mut self) {
        self.concrete_memory.clear();
        self.symbolic_memory.clear();
        self.registers.clear();
        self.access_history.clear();
        self.memory_regions.clear();
    }
}

impl Default for SymbolicMemoryV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concrete_read_write() {
        let mut memory = SymbolicMemoryV2::new();

        let addr = SymbolicAddress::concrete(0x1000);
        let value = SymbolicValue::from_u64(0x1234, 4);

        memory.write(addr.clone(), 4, value);

        let read_value = memory.read(addr, 4);
        assert!(read_value.is_concrete());
    }

    #[test]
    fn test_symbolic_read_write() {
        let mut memory = SymbolicMemoryV2::new();

        let addr = SymbolicAddress::symbolic("buffer_base + offset");
        let value = SymbolicValue::symbolic("user_input");

        memory.write(addr.clone(), 4, value.clone());

        let read_value = memory.read(addr, 4);
        assert!(read_value.is_symbolic());
    }

    #[test]
    fn test_buffer_overflow_detection() {
        let mut memory = SymbolicMemoryV2::new();

        // 256バイトのバッファを確保
        let buffer_base = SymbolicAddress::concrete(0x1000);
        memory.allocate_region("test_buffer".to_string(), buffer_base.clone(), 256);

        // 範囲外アクセス（可能性）
        let overflow_addr = SymbolicAddress::base_offset(
            buffer_base,
            SymbolicAddress::symbolic("user_offset"),
        );

        memory.write(overflow_addr, 4, SymbolicValue::from_u64(0x42, 4));

        // 潜在的オーバーフローが検出されるはず
        assert!(memory.stats().potential_overflows > 0);
    }

    #[test]
    fn test_use_after_free_detection() {
        let mut memory = SymbolicMemoryV2::new();

        let ptr = SymbolicAddress::concrete(0x2000);

        // メモリ確保
        memory.allocate_region("heap_block".to_string(), ptr.clone(), 64);

        // メモリ解放
        memory.free_region(&ptr);

        // 解放後のアクセス
        memory.write(ptr, 4, SymbolicValue::from_u64(0x99, 4));

        // Use-after-freeが検出されるはず
        assert!(memory.stats().potential_use_after_free > 0);
    }

    #[test]
    fn test_aliasing_detection() {
        let memory = SymbolicMemoryV2::new();

        let ptr1 = SymbolicAddress::symbolic("ptr1");
        let ptr2 = SymbolicAddress::symbolic("ptr2");

        // 異なるシンボリック変数はエイリアスの可能性あり
        assert_eq!(
            memory.check_aliasing(&ptr1, &ptr2, 4),
            AddressOverlap::MaybeOverlap
        );

        // 同じシンボリック変数は確実にエイリアス
        assert_eq!(
            memory.check_aliasing(&ptr1, &ptr1, 4),
            AddressOverlap::DefinitelyOverlap
        );
    }

    #[test]
    fn test_access_history() {
        let mut memory = SymbolicMemoryV2::new();

        let addr1 = SymbolicAddress::concrete(0x1000);
        let addr2 = SymbolicAddress::symbolic("buffer + i");

        memory.write(addr1, 4, SymbolicValue::from_u64(10, 4));
        memory.read(addr2.clone(), 4);
        memory.write(addr2, 4, SymbolicValue::symbolic("value"));

        let history = memory.get_access_history();
        assert_eq!(history.len(), 3);
        assert!(history[0].is_write);
        assert!(!history[1].is_write);
        assert!(history[2].is_write);
    }
}
