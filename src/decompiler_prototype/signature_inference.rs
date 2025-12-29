// 関数シグネチャ推論モジュール
// 関数の引数、戻り値、呼び出し規約を自動推論

use super::pcode::{PcodeOp, OpCode, Varnode, AddressSpace};
use super::cfg::{ControlFlowGraph, BlockId};
use std::collections::{HashMap, HashSet};
use anyhow::Result;

/// 呼び出し規約
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Windows x64 calling convention
    Win64,
    /// System V AMD64 ABI (Linux/Unix)
    SysV,
    /// x86 cdecl
    Cdecl,
    /// x86 stdcall
    Stdcall,
    /// x86 fastcall
    Fastcall,
    /// 不明
    Unknown,
}

/// パラメータの位置
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterLocation {
    /// レジスタ渡し（レジスタ名）
    Register(String),
    /// スタック渡し（オフセット）
    Stack(i64),
    /// 不明
    Unknown,
}

/// 推論された型情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredParamType {
    /// 整数型（ビット幅）
    Integer(usize),
    /// ポインタ（指す先の型）
    Pointer(Box<InferredParamType>),
    /// 浮動小数点
    Float(usize),
    /// 不明
    Unknown,
}

/// 関数パラメータ
#[derive(Debug, Clone)]
pub struct Parameter {
    /// パラメータのインデックス（0始まり）
    pub index: usize,
    /// パラメータの位置
    pub location: ParameterLocation,
    /// 推論された型
    pub param_type: InferredParamType,
    /// パラメータ名（推論または既知）
    pub name: Option<String>,
    /// 読み取り専用か
    pub is_readonly: bool,
}

/// 関数の戻り値情報
#[derive(Debug, Clone)]
pub struct ReturnValue {
    /// 戻り値の型
    pub return_type: InferredParamType,
    /// 戻り値の位置（通常はraxやeax）
    pub location: ParameterLocation,
}

/// 関数シグネチャ
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// 関数アドレス
    pub address: u64,
    /// 関数名
    pub name: Option<String>,
    /// パラメータのリスト
    pub parameters: Vec<Parameter>,
    /// 戻り値
    pub return_value: Option<ReturnValue>,
    /// 呼び出し規約
    pub calling_convention: CallingConvention,
    /// スタックフレームサイズ
    pub stack_frame_size: usize,
}

/// 関数シグネチャ推論器
pub struct SignatureInferenceEngine {
    /// 推論された関数シグネチャ
    signatures: HashMap<u64, FunctionSignature>,
    /// アーキテクチャ（x64, x86など）
    architecture: Architecture,
}

/// ターゲットアーキテクチャ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    X86,
    Unknown,
}

impl SignatureInferenceEngine {
    /// 新しいシグネチャ推論エンジンを作成
    pub fn new(architecture: Architecture) -> Self {
        Self {
            signatures: HashMap::new(),
            architecture,
        }
    }

    /// 関数のシグネチャを推論
    pub fn infer_signature(
        &mut self,
        function_addr: u64,
        ops: &[PcodeOp],
        cfg: &ControlFlowGraph,
    ) -> Result<FunctionSignature> {
        // ステップ1: 呼び出し規約を推論
        let calling_convention = self.infer_calling_convention(ops, cfg);

        // ステップ2: パラメータを推論
        let parameters = self.infer_parameters(ops, cfg, calling_convention)?;

        // ステップ3: 戻り値を推論
        let return_value = self.infer_return_value(ops, cfg)?;

        // ステップ4: スタックフレームサイズを計算
        let stack_frame_size = self.calculate_stack_frame_size(ops)?;

        let signature = FunctionSignature {
            address: function_addr,
            name: Some(format!("func_{:x}", function_addr)),
            parameters,
            return_value,
            calling_convention,
            stack_frame_size,
        };

        self.signatures.insert(function_addr, signature.clone());
        Ok(signature)
    }

    /// 呼び出し規約を推論
    fn infer_calling_convention(&self, ops: &[PcodeOp], cfg: &ControlFlowGraph) -> CallingConvention {
        match self.architecture {
            Architecture::X86_64 => {
                // x64では最初の数個の引数がレジスタ渡し
                // Windows: rcx, rdx, r8, r9
                // System V: rdi, rsi, rdx, rcx, r8, r9

                // 関数の最初の方でどのレジスタが使われているかチェック
                let first_block_ops: Vec<&PcodeOp> = ops.iter().take(20).collect();

                let uses_rcx = first_block_ops.iter().any(|op| self.uses_register(op, "rcx"));
                let uses_rdi = first_block_ops.iter().any(|op| self.uses_register(op, "rdi"));

                if uses_rdi {
                    CallingConvention::SysV
                } else if uses_rcx {
                    CallingConvention::Win64
                } else {
                    CallingConvention::Unknown
                }
            }
            Architecture::X86 => {
                // x86では主にスタック渡し
                CallingConvention::Cdecl
            }
            Architecture::Unknown => CallingConvention::Unknown,
        }
    }

    /// レジスタを使用しているかチェック
    fn uses_register(&self, op: &PcodeOp, reg_name: &str) -> bool {
        // TODO: 実際のレジスタ名とVarnodeのマッピング
        false
    }

    /// パラメータを推論
    fn infer_parameters(
        &self,
        ops: &[PcodeOp],
        cfg: &ControlFlowGraph,
        calling_convention: CallingConvention,
    ) -> Result<Vec<Parameter>> {
        let mut parameters = Vec::new();

        match calling_convention {
            CallingConvention::Win64 => {
                // Windows x64: rcx, rdx, r8, r9, その後スタック
                let register_params = vec!["rcx", "rdx", "r8", "r9"];

                for (i, reg_name) in register_params.iter().enumerate() {
                    if self.is_parameter_used(ops, reg_name) {
                        parameters.push(Parameter {
                            index: i,
                            location: ParameterLocation::Register(reg_name.to_string()),
                            param_type: InferredParamType::Unknown,
                            name: Some(format!("arg{}", i)),
                            is_readonly: false,
                        });
                    } else {
                        break; // 使われていないレジスタが出たら終了
                    }
                }
            }
            CallingConvention::SysV => {
                // System V x64: rdi, rsi, rdx, rcx, r8, r9
                let register_params = vec!["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

                for (i, reg_name) in register_params.iter().enumerate() {
                    if self.is_parameter_used(ops, reg_name) {
                        parameters.push(Parameter {
                            index: i,
                            location: ParameterLocation::Register(reg_name.to_string()),
                            param_type: InferredParamType::Unknown,
                            name: Some(format!("arg{}", i)),
                            is_readonly: false,
                        });
                    } else {
                        break;
                    }
                }
            }
            _ => {
                // その他の呼び出し規約やスタックパラメータ
                // TODO: スタックオフセットからパラメータを推論
            }
        }

        // パラメータの型を推論
        for param in &mut parameters {
            param.param_type = self.infer_parameter_type(ops, &param.location);
        }

        Ok(parameters)
    }

    /// パラメータが使用されているかチェック
    fn is_parameter_used(&self, ops: &[PcodeOp], reg_name: &str) -> bool {
        // 関数の最初のN命令でレジスタが読み取られているかチェック
        for op in ops.iter().take(50) {
            for input in &op.inputs {
                // TODO: Varnodeがレジスタ名と一致するかチェック
                // 現在は仮実装
            }
        }
        true // 仮実装：全て使用されていると仮定
    }

    /// パラメータの型を推論
    fn infer_parameter_type(&self, ops: &[PcodeOp], location: &ParameterLocation) -> InferredParamType {
        // データフロー解析でパラメータの使われ方から型を推論
        // - ポインタ参照として使われている -> Pointer
        // - 算術演算に使われている -> Integer
        // - 浮動小数点演算 -> Float

        // TODO: より詳細な型推論
        InferredParamType::Unknown
    }

    /// 戻り値を推論
    fn infer_return_value(&self, ops: &[PcodeOp], cfg: &ControlFlowGraph) -> Result<Option<ReturnValue>> {
        // return文の直前でrax/eaxに値を設定しているかチェック
        for op in ops.iter().rev().take(20) {
            if op.opcode == OpCode::Return {
                // この前の命令でraxに値が設定されているか
                // TODO: データフロー解析で戻り値を追跡
                return Ok(Some(ReturnValue {
                    return_type: InferredParamType::Unknown,
                    location: ParameterLocation::Register("rax".to_string()),
                }));
            }
        }

        Ok(None)
    }

    /// スタックフレームサイズを計算
    fn calculate_stack_frame_size(&self, ops: &[PcodeOp]) -> Result<usize> {
        // 関数プロローグで "sub rsp, size" を探す
        for op in ops.iter().take(10) {
            if op.opcode == OpCode::IntSub {
                if let Some(output) = &op.output {
                    // rspからの減算を検出
                    if output.space == AddressSpace::Register {
                        // TODO: 実際の減算値を取得
                        return Ok(0); // 仮実装
                    }
                }
            }
        }

        Ok(0)
    }

    /// 推論されたシグネチャを取得
    pub fn get_signatures(&self) -> &HashMap<u64, FunctionSignature> {
        &self.signatures
    }

    /// 特定の関数のシグネチャを取得
    pub fn get_signature(&self, address: u64) -> Option<&FunctionSignature> {
        self.signatures.get(&address)
    }

    /// シグネチャのサマリーを生成
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("推論された関数シグネチャ: {} 個\n", self.signatures.len()));

        for (addr, sig) in &self.signatures {
            summary.push_str(&format!("\n関数 @ 0x{:x}: {:?}\n", addr, sig.calling_convention));
            summary.push_str(&format!("  パラメータ: {} 個\n", sig.parameters.len()));

            for param in &sig.parameters {
                summary.push_str(&format!("    [{}] {:?} @ {:?}\n",
                    param.index, param.param_type, param.location));
            }

            if let Some(ret) = &sig.return_value {
                summary.push_str(&format!("  戻り値: {:?}\n", ret.return_type));
            }
        }

        summary
    }
}
