/// Non-Zero Mask解析システム
///
/// Ghidraのcoreactionに基づく実装
/// 各Varnodeで「1になりうるビット」を追跡し、最適化の基盤とする
///
/// 例：
/// - 定数0x0F: NZMask = 0x0F (下位4ビットのみ1になりうる)
/// - V & 0xFF: NZMask = min(nzmask(V), 0xFF)
/// - V | W: NZMask = nzmask(V) | nzmask(W)

use crate::decompiler_prototype::pcode::{OpCode, Varnode, PcodeOp, AddressSpace};
use std::collections::HashMap;

/// Varnodeごとの非ゼロマスク情報
#[derive(Debug, Clone)]
pub struct NZMaskAnalyzer {
    /// VarnodeのハッシュキーからNZMaskへのマッピング
    masks: HashMap<VarnodeKey, u64>,
}

/// Varnodeを一意に識別するキー
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VarnodeKey {
    space: AddressSpace,
    offset: u64,
    size: usize,
}

impl From<&Varnode> for VarnodeKey {
    fn from(vn: &Varnode) -> Self {
        VarnodeKey {
            space: vn.space,
            offset: vn.offset,
            size: vn.size,
        }
    }
}

impl NZMaskAnalyzer {
    /// 新しいNZMask解析器を作成
    pub fn new() -> Self {
        Self {
            masks: HashMap::new(),
        }
    }

    /// 指定されたサイズの全ビットマスクを計算
    #[inline]
    fn calc_mask(size: usize) -> u64 {
        if size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        }
    }

    /// VarnodeのNZMaskを取得（未計算の場合は保守的見積もり）
    pub fn get_nzmask(&self, vn: &Varnode) -> u64 {
        let key = VarnodeKey::from(vn);
        self.masks.get(&key).copied().unwrap_or_else(|| {
            // 定数の場合は値そのもの
            if vn.space == AddressSpace::Const {
                vn.offset & Self::calc_mask(vn.size)
            } else {
                // デフォルトは全ビット有効（保守的）
                Self::calc_mask(vn.size)
            }
        })
    }

    /// VarnodeのNZMaskを設定
    pub fn set_nzmask(&mut self, vn: &Varnode, mask: u64) {
        let key = VarnodeKey::from(vn);
        let bounded_mask = mask & Self::calc_mask(vn.size);
        self.masks.insert(key, bounded_mask);
    }

    /// P-code操作からNZMaskを計算
    pub fn compute_op_nzmask(&mut self, op: &PcodeOp) -> Option<u64> {
        use OpCode::*;

        match op.opcode {
            // 定数: 値そのもの
            Copy => {
                let input_mask = self.get_nzmask(&op.inputs[0]);
                Some(input_mask)
            }

            // ビット演算: AND/OR/XOR
            IntAnd => {
                let mask1 = self.get_nzmask(&op.inputs[0]);
                let mask2 = self.get_nzmask(&op.inputs[1]);
                Some(mask1 & mask2)
            }
            IntOr => {
                let mask1 = self.get_nzmask(&op.inputs[0]);
                let mask2 = self.get_nzmask(&op.inputs[1]);
                Some(mask1 | mask2)
            }
            IntXor => {
                let mask1 = self.get_nzmask(&op.inputs[0]);
                let mask2 = self.get_nzmask(&op.inputs[1]);
                Some(mask1 | mask2)
            }
            IntNegate => {
                let mask = self.get_nzmask(&op.inputs[0]);
                Some(mask) // ~V のマスクはVと同じ
            }

            // シフト演算
            IntLeft => {
                if op.inputs[1].space == AddressSpace::Const {
                    let mask = self.get_nzmask(&op.inputs[0]);
                    let shift = op.inputs[1].offset;
                    let size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
                    Some((mask << shift) & Self::calc_mask(size))
                } else {
                    // シフト量が不定の場合は保守的
                    None
                }
            }
            IntRight | IntSRight => {
                if op.inputs[1].space == AddressSpace::Const {
                    let mask = self.get_nzmask(&op.inputs[0]);
                    let shift = op.inputs[1].offset;
                    Some(mask >> shift)
                } else {
                    None
                }
            }

            // 拡張演算
            IntZExt => {
                let mask = self.get_nzmask(&op.inputs[0]);
                Some(mask) // ゼロ拡張はマスクを保持
            }
            IntSExt => {
                // 符号拡張: 入力の最上位ビットが1なら上位ビットも1
                let input_mask = self.get_nzmask(&op.inputs[0]);
                let input_size = op.inputs[0].size;
                let output_size = op.output.as_ref().map(|v| v.size).unwrap_or(8);

                let sign_bit = 1u64 << (input_size * 8 - 1);
                if (input_mask & sign_bit) != 0 {
                    // 符号ビットが立ちうる場合は上位も1になりうる
                    Some(Self::calc_mask(output_size))
                } else {
                    Some(input_mask)
                }
            }

            // 部分抽出
            SubPiece => {
                if op.inputs.len() >= 2 && op.inputs[1].space == AddressSpace::Const {
                    let mask = self.get_nzmask(&op.inputs[0]);
                    let offset_bytes = op.inputs[1].offset as usize;
                    let output_size = op.output.as_ref().map(|v| v.size).unwrap_or(4);

                    let shifted_mask = mask >> (offset_bytes * 8);
                    Some(shifted_mask & Self::calc_mask(output_size))
                } else {
                    None
                }
            }

            // 加算/減算: 保守的見積もり（全ビット有効の可能性）
            IntAdd | IntSub => {
                let size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
                Some(Self::calc_mask(size))
            }

            // 乗算: より保守的
            IntMult => {
                let size = op.output.as_ref().map(|v| v.size).unwrap_or(8);
                Some(Self::calc_mask(size))
            }

            // 比較演算: 結果は0または1
            IntEqual | IntNotEqual | IntLess | IntLessEqual | IntSLess | IntSLessEqual => {
                Some(1)
            }

            // ブール演算: 結果は0または1
            BoolNegate | BoolAnd | BoolOr | BoolXor => {
                Some(1)
            }

            // その他: 保守的見積もり
            _ => None,
        }
    }

    /// P-code操作列を解析してNZMaskを計算
    pub fn analyze_ops(&mut self, ops: &[PcodeOp]) {
        // 複数回パスして収束させる（最大5回）
        for _iteration in 0..5 {
            let mut changed = false;

            for op in ops {
                if let Some(output) = &op.output {
                    if let Some(new_mask) = self.compute_op_nzmask(op) {
                        let old_mask = self.get_nzmask(output);
                        if old_mask != new_mask {
                            self.set_nzmask(output, new_mask);
                            changed = true;
                        }
                    }
                }
            }

            if !changed {
                break; // 収束した
            }
        }
    }

    /// Consume Mask: Varnodeの使用箇所で実際に参照されるビット
    ///
    /// 例: (V & 0xFF) の場合、Vのconsume maskは0xFF
    pub fn compute_consume_mask(&self, vn: &Varnode, ops: &[PcodeOp]) -> u64 {
        let mut consume = 0u64;

        for op in ops {
            // このVarnodeを入力として使う操作を検索
            for (idx, input) in op.inputs.iter().enumerate() {
                if input == vn {
                    match op.opcode {
                        OpCode::IntAnd if idx == 0 && op.inputs.len() > 1 => {
                            // V & const の場合、constのビットだけが消費される
                            if op.inputs[1].space == AddressSpace::Const {
                                consume |= op.inputs[1].offset;
                            } else {
                                consume = Self::calc_mask(vn.size);
                            }
                        }
                        OpCode::IntOr if idx == 0 && op.inputs.len() > 1 => {
                            // V | const の場合、constで立っていないビットが消費される
                            if op.inputs[1].space == AddressSpace::Const {
                                consume |= !op.inputs[1].offset & Self::calc_mask(vn.size);
                            } else {
                                consume = Self::calc_mask(vn.size);
                            }
                        }
                        OpCode::SubPiece if idx == 0 => {
                            // SubPiece: 切り出される範囲のビットが消費される
                            if op.inputs.len() > 1 && op.inputs[1].space == AddressSpace::Const {
                                let offset = op.inputs[1].offset as usize;
                                let size = op.output.as_ref().map(|v| v.size).unwrap_or(4);
                                let mask = Self::calc_mask(size) << (offset * 8);
                                consume |= mask;
                            } else {
                                consume = Self::calc_mask(vn.size);
                            }
                        }
                        _ => {
                            // デフォルトは全ビット消費
                            consume = Self::calc_mask(vn.size);
                        }
                    }
                }
            }
        }

        consume
    }

    /// 統計情報を取得
    pub fn stats(&self) -> NZMaskStats {
        let mut zero_count = 0;
        let mut partial_count = 0;
        let mut full_count = 0;

        for (key, &mask) in &self.masks {
            let full_mask = Self::calc_mask(key.size);
            if mask == 0 {
                zero_count += 1;
            } else if mask == full_mask {
                full_count += 1;
            } else {
                partial_count += 1;
            }
        }

        NZMaskStats {
            total: self.masks.len(),
            zero_count,
            partial_count,
            full_count,
        }
    }
}

impl Default for NZMaskAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// NZMask解析の統計情報
#[derive(Debug, Clone)]
pub struct NZMaskStats {
    pub total: usize,
    pub zero_count: usize,     // マスクが0（常に0）
    pub partial_count: usize,  // 部分的なマスク
    pub full_count: usize,     // 全ビット有効
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_mask() {
        assert_eq!(NZMaskAnalyzer::calc_mask(1), 0xFF);
        assert_eq!(NZMaskAnalyzer::calc_mask(2), 0xFFFF);
        assert_eq!(NZMaskAnalyzer::calc_mask(4), 0xFFFF_FFFF);
        assert_eq!(NZMaskAnalyzer::calc_mask(8), 0xFFFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn test_constant_nzmask() {
        let analyzer = NZMaskAnalyzer::new();
        let vn = Varnode::constant(0x0F, 1);
        assert_eq!(analyzer.get_nzmask(&vn), 0x0F);
    }

    #[test]
    fn test_and_nzmask() {
        let mut analyzer = NZMaskAnalyzer::new();

        let v1 = Varnode::register(0, 4);
        let v2 = Varnode::constant(0xFF, 4);
        let output = Varnode::unique(100, 4);

        analyzer.set_nzmask(&v1, 0xFFFF_FFFF);

        let op = PcodeOp::binary(OpCode::IntAnd, output.clone(), v1, v2, 0x1000);
        let mask = analyzer.compute_op_nzmask(&op).unwrap();

        assert_eq!(mask, 0xFF);
    }

    #[test]
    fn test_or_nzmask() {
        let mut analyzer = NZMaskAnalyzer::new();

        let v1 = Varnode::register(0, 4);
        let v2 = Varnode::constant(0xF0, 4);
        let output = Varnode::unique(100, 4);

        analyzer.set_nzmask(&v1, 0x0F);

        let op = PcodeOp::binary(OpCode::IntOr, output.clone(), v1, v2, 0x1000);
        let mask = analyzer.compute_op_nzmask(&op).unwrap();

        assert_eq!(mask, 0xFF);
    }
}
