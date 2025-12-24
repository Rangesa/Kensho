/// P-code中間表現
/// Ghidraの中間言語をRustで実装
///
/// P-codeは74種類の汎用命令でアーキテクチャ非依存の解析を実現する

use serde::{Deserialize, Serialize};

/// P-code命令の種類（全74種類）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpCode {
    // 基本操作 (1-3)
    Copy = 1,       // 代入
    Load = 2,       // メモリ読み込み
    Store = 3,      // メモリ書き込み

    // 制御フロー (4-10)
    Branch = 4,     // 無条件分岐
    CBranch = 5,    // 条件分岐
    BranchInd = 6,  // 間接分岐（ジャンプテーブル）
    Call = 7,       // 関数呼び出し（絶対アドレス）
    CallInd = 8,    // 関数呼び出し（間接アドレス）
    CallOther = 9,  // ユーザー定義操作
    Return = 10,    // 関数戻り

    // 整数比較 (11-16)
    IntEqual = 11,       // ==
    IntNotEqual = 12,    // !=
    IntSLess = 13,       // < (符号付き)
    IntSLessEqual = 14,  // <= (符号付き)
    IntLess = 15,        // < (符号なし)
    IntLessEqual = 16,   // <= (符号なし)

    // 整数拡張 (17-18)
    IntZExt = 17,   // ゼロ拡張
    IntSExt = 18,   // 符号拡張

    // 整数算術 (19-36)
    IntAdd = 19,     // +
    IntSub = 20,     // -
    IntCarry = 21,   // 符号なしキャリー
    IntSCarry = 22,  // 符号付きキャリー
    IntSBorrow = 23, // 符号付きボロー
    Int2Comp = 24,   // 2の補数
    IntNegate = 25,  // ビット否定 ~
    IntXor = 26,     // ^
    IntAnd = 27,     // &
    IntOr = 28,      // |
    IntLeft = 29,    // <<
    IntRight = 30,   // >> (論理)
    IntSRight = 31,  // >> (算術)
    IntMult = 32,    // *
    IntDiv = 33,     // / (符号なし)
    IntSDiv = 34,    // / (符号付き)
    IntRem = 35,     // % (符号なし)
    IntSRem = 36,    // % (符号付き)

    // ブール演算 (37-40)
    BoolNegate = 37, // !
    BoolXor = 38,    // ^^
    BoolAnd = 39,    // &&
    BoolOr = 40,     // ||

    // 浮動小数点比較 (41-44, 46)
    FloatEqual = 41,      // ==
    FloatNotEqual = 42,   // !=
    FloatLess = 43,       // <
    FloatLessEqual = 44,  // <=
    FloatNan = 46,        // NaN判定

    // 浮動小数点算術 (47-53)
    FloatAdd = 47,   // +
    FloatDiv = 48,   // /
    FloatMult = 49,  // *
    FloatSub = 50,   // -
    FloatNeg = 51,   // -（単項）
    FloatAbs = 52,   // abs
    FloatSqrt = 53,  // sqrt

    // 浮動小数点変換 (54-59)
    FloatInt2Float = 54,    // int → float
    FloatFloat2Float = 55,  // float → float（サイズ変換）
    FloatTrunc = 56,        // ゼロ方向への丸め
    FloatCeil = 57,         // +∞方向への丸め
    FloatFloor = 58,        // -∞方向への丸め
    FloatRound = 59,        // 最近接への丸め

    // SSA特殊命令 (60-61)
    MultiEqual = 60, // Phi-node（SSA合流点）
    Indirect = 61,   // 間接効果を持つコピー

    // データ操作 (62-73)
    Piece = 62,      // 連結
    SubPiece = 63,   // 切り出し
    Cast = 64,       // 型キャスト
    PtrAdd = 65,     // ポインタ加算（配列インデックス）
    PtrSub = 66,     // ポインタ減算（構造体フィールド）
    SegmentOp = 67,  // セグメントアドレス
    CPoolRef = 68,   // 定数プール参照
    New = 69,        // オブジェクト割り当て
    Insert = 70,     // ビット範囲挿入
    Extract = 71,    // ビット範囲抽出
    PopCount = 72,   // 1ビットカウント
    LzCount = 73,    // 先頭ゼロビットカウント
}

/// アドレス空間の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressSpace {
    Register,   // レジスタ空間
    Ram,        // メモリ空間
    Const,      // 定数空間
    Unique,     // 一時変数空間
    Stack,      // スタック空間
}

/// Varnode - SSA形式の変数ノード
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Varnode {
    pub space: AddressSpace,
    pub offset: u64,
    pub size: usize,
}

impl Varnode {
    /// 新しいVarnodeを作成
    pub fn new(space: AddressSpace, offset: u64, size: usize) -> Self {
        Self { space, offset, size }
    }

    /// レジスタVarnodeを作成
    pub fn register(offset: u64, size: usize) -> Self {
        Self::new(AddressSpace::Register, offset, size)
    }

    /// メモリVarnodeを作成
    pub fn ram(offset: u64, size: usize) -> Self {
        Self::new(AddressSpace::Ram, offset, size)
    }

    /// 定数Varnodeを作成
    pub fn constant(value: u64, size: usize) -> Self {
        Self::new(AddressSpace::Const, value, size)
    }

    /// 一時変数Varnodeを作成
    pub fn unique(offset: u64, size: usize) -> Self {
        Self::new(AddressSpace::Unique, offset, size)
    }
}

/// P-code命令
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeOp {
    pub opcode: OpCode,
    pub output: Option<Varnode>,
    pub inputs: Vec<Varnode>,
    pub address: u64,  // この命令が属する機械語アドレス
}

impl PcodeOp {
    /// 新しいP-code命令を作成
    pub fn new(opcode: OpCode, output: Option<Varnode>, inputs: Vec<Varnode>, address: u64) -> Self {
        Self { opcode, output, inputs, address }
    }

    /// 出力なしの命令を作成
    pub fn no_output(opcode: OpCode, inputs: Vec<Varnode>, address: u64) -> Self {
        Self::new(opcode, None, inputs, address)
    }

    /// 単項演算命令を作成
    pub fn unary(opcode: OpCode, output: Varnode, input: Varnode, address: u64) -> Self {
        Self::new(opcode, Some(output), vec![input], address)
    }

    /// 二項演算命令を作成
    pub fn binary(opcode: OpCode, output: Varnode, lhs: Varnode, rhs: Varnode, address: u64) -> Self {
        Self::new(opcode, Some(output), vec![lhs, rhs], address)
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OpCode::Copy => "COPY",
            OpCode::Load => "LOAD",
            OpCode::Store => "STORE",
            OpCode::Branch => "BRANCH",
            OpCode::CBranch => "CBRANCH",
            OpCode::BranchInd => "BRANCHIND",
            OpCode::Call => "CALL",
            OpCode::CallInd => "CALLIND",
            OpCode::CallOther => "CALLOTHER",
            OpCode::Return => "RETURN",
            OpCode::IntEqual => "INT_EQUAL",
            OpCode::IntNotEqual => "INT_NOTEQUAL",
            OpCode::IntSLess => "INT_SLESS",
            OpCode::IntSLessEqual => "INT_SLESSEQUAL",
            OpCode::IntLess => "INT_LESS",
            OpCode::IntLessEqual => "INT_LESSEQUAL",
            OpCode::IntZExt => "INT_ZEXT",
            OpCode::IntSExt => "INT_SEXT",
            OpCode::IntAdd => "INT_ADD",
            OpCode::IntSub => "INT_SUB",
            OpCode::IntCarry => "INT_CARRY",
            OpCode::IntSCarry => "INT_SCARRY",
            OpCode::IntSBorrow => "INT_SBORROW",
            OpCode::Int2Comp => "INT_2COMP",
            OpCode::IntNegate => "INT_NEGATE",
            OpCode::IntXor => "INT_XOR",
            OpCode::IntAnd => "INT_AND",
            OpCode::IntOr => "INT_OR",
            OpCode::IntLeft => "INT_LEFT",
            OpCode::IntRight => "INT_RIGHT",
            OpCode::IntSRight => "INT_SRIGHT",
            OpCode::IntMult => "INT_MULT",
            OpCode::IntDiv => "INT_DIV",
            OpCode::IntSDiv => "INT_SDIV",
            OpCode::IntRem => "INT_REM",
            OpCode::IntSRem => "INT_SREM",
            OpCode::BoolNegate => "BOOL_NEGATE",
            OpCode::BoolXor => "BOOL_XOR",
            OpCode::BoolAnd => "BOOL_AND",
            OpCode::BoolOr => "BOOL_OR",
            OpCode::FloatEqual => "FLOAT_EQUAL",
            OpCode::FloatNotEqual => "FLOAT_NOTEQUAL",
            OpCode::FloatLess => "FLOAT_LESS",
            OpCode::FloatLessEqual => "FLOAT_LESSEQUAL",
            OpCode::FloatNan => "FLOAT_NAN",
            OpCode::FloatAdd => "FLOAT_ADD",
            OpCode::FloatDiv => "FLOAT_DIV",
            OpCode::FloatMult => "FLOAT_MULT",
            OpCode::FloatSub => "FLOAT_SUB",
            OpCode::FloatNeg => "FLOAT_NEG",
            OpCode::FloatAbs => "FLOAT_ABS",
            OpCode::FloatSqrt => "FLOAT_SQRT",
            OpCode::FloatInt2Float => "FLOAT_INT2FLOAT",
            OpCode::FloatFloat2Float => "FLOAT_FLOAT2FLOAT",
            OpCode::FloatTrunc => "FLOAT_TRUNC",
            OpCode::FloatCeil => "FLOAT_CEIL",
            OpCode::FloatFloor => "FLOAT_FLOOR",
            OpCode::FloatRound => "FLOAT_ROUND",
            OpCode::MultiEqual => "MULTIEQUAL",
            OpCode::Indirect => "INDIRECT",
            OpCode::Piece => "PIECE",
            OpCode::SubPiece => "SUBPIECE",
            OpCode::Cast => "CAST",
            OpCode::PtrAdd => "PTRADD",
            OpCode::PtrSub => "PTRSUB",
            OpCode::SegmentOp => "SEGMENTOP",
            OpCode::CPoolRef => "CPOOLREF",
            OpCode::New => "NEW",
            OpCode::Insert => "INSERT",
            OpCode::Extract => "EXTRACT",
            OpCode::PopCount => "POPCOUNT",
            OpCode::LzCount => "LZCOUNT",
        };
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for Varnode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let space_str = match self.space {
            AddressSpace::Register => "reg",
            AddressSpace::Ram => "ram",
            AddressSpace::Const => "const",
            AddressSpace::Unique => "uniq",
            AddressSpace::Stack => "stack",
        };
        write!(f, "{}:0x{:x}:{}", space_str, self.offset, self.size)
    }
}

impl std::fmt::Display for PcodeOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref output) = self.output {
            write!(f, "{} = {} ", output, self.opcode)?;
        } else {
            write!(f, "{} ", self.opcode)?;
        }

        for (i, input) in self.inputs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", input)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_creation() {
        let v = Varnode::register(0, 8);
        assert_eq!(v.space, AddressSpace::Register);
        assert_eq!(v.offset, 0);
        assert_eq!(v.size, 8);
    }

    #[test]
    fn test_pcode_display() {
        // rax = rbx + rcx (仮想的な表現)
        let rax = Varnode::register(0, 8);
        let rbx = Varnode::register(8, 8);
        let rcx = Varnode::register(16, 8);

        let op = PcodeOp::binary(OpCode::IntAdd, rax, rbx, rcx, 0x1000);
        let display = format!("{}", op);

        assert!(display.contains("INT_ADD"));
        assert!(display.contains("reg"));
    }

    #[test]
    fn test_constant_varnode() {
        let const_val = Varnode::constant(42, 4);
        assert_eq!(const_val.space, AddressSpace::Const);
        assert_eq!(const_val.offset, 42);
        assert_eq!(const_val.size, 4);
    }
}
