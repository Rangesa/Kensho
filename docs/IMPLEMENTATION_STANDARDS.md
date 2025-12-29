# kensho-mcp 実装基準書

**作成日**: 2025年12月17日
**対象バージョン**: 0.2.0

## 📋 目次

1. [プロジェクト方針](#1-プロジェクト方針)
2. [x86-64アーキテクチャ](#2-x86-64アーキテクチャ)
3. [JSON出力フォーマット](#3-json出力フォーマット)
4. [DWARF/PDB完全対応](#4-dwarfpdb完全対応)
5. [example_translation関数実装](#5-example_translation関数実装)
6. [実装優先度](#6-実装優先度)
7. [コーディング規約](#7-コーディング規約)
8. [テスト基準](#8-テスト基準)

---

## 1. プロジェクト方針

### 1.1 基本理念

- **高速性**: ミリ秒単位の起動とレスポンス
- **軽量性**: 単一バイナリ、最小限のメモリ消費
- **AI最適化**: Claude Codeなどのエージェントが扱いやすいMCP API
- **実用性**: 大規模バイナリ（数百MB）を実際に解析できること

### 1.2 対応範囲の明確化

**実装する機能:**
- ✅ **x86-64アーキテクチャのみ**（ARM64は排除）
- ✅ PE (Windows), ELF (Linux), Mach-O (macOS)
- ✅ DWARF/PDB完全対応（デバッグシンボル）
- ✅ P-codeベースのネイティブデコンパイラ
- ✅ **JSON構造化データ出力**（C疑似コード廃止）

**実装しない機能:**
- ❌ ARM64, MIPS, RISC-V等の他アーキテクチャ
- ❌ シンボリック実行（angrの領域）
- ❌ GUIフロントエンド
- ❌ Mod生成・ビルド・インジェクション（解析のみに特化）

### 1.3 プロジェクトスコープ

このツールは**バイナリ解析に特化したMCPサーバー**である。

```
[解析対象] → kensho-mcp → [JSON構造化データ]
                                      ↓
                              AIエージェントが利用
                                      ↓
                              別ツールでMod生成等
```

**哲学**: Unix哲学「一つのことをうまくやれ」に従い、解析機能のみに特化する。

---

## 2. x86-64アーキテクチャ (完成度: 80%)

**現在の状態:**
- ✅ 基本命令セット（100以上）
- ✅ SSE/AVX命令（49個）
- ✅ CMOV命令（3個、残り13個実装予定）
- ✅ 文字列操作命令（lods, stos, movs系）

**実装基準:**
```rust
// src/decompiler_prototype/x86_64/instructions/*.rs
// 命令カテゴリごとにファイル分割
//
// - arithmetic.rs      : 算術演算
// - logic.rs           : 論理演算
// - data_transfer.rs   : データ転送
// - control_flow.rs    : 制御フロー（CMOV含む）
// - simd.rs            : SSE/AVX/NEON
// - atomic.rs          : アトミック操作
// - misc.rs            : その他（文字列操作等）
```

**優先実装タスク:**
1. **CMOV完全実装**（残り13種類）
   - cmovle, cmovge, cmovb, cmovbe, cmova, cmovae
   - cmovs, cmovns, cmovo, cmovno, cmovp, cmovnp, cmovg

2. **AVX2拡張**（必要に応じて）
   - vaddps, vsubps, vmulps等のVEXプレフィックス版

**x86-64特化の理由（PHILOSOPHY.mdより）:**
- PCゲームMod開発: 99% x86-64
- Windowsマルウェア解析: 99% x86-64
- サーバーアプリ解析: 99% x86-64
- ARM64対応には膨大なリソースが必要
- **哲学**: 「何でも屋」より「x86-64で世界最高」を目指す

---

## 3. JSON出力フォーマット

### 3.1 C疑似コードの廃止

**従来の出力（廃止）:**
```c
void function_140001000() {
    rax = rax + rbx;
    if (rax > 10) {
        return rax * 2;
    }
}
```

**問題点:**
- 人間向けの可読性を重視（AIには不要）
- 推測が混入（変数名等）
- 構造化されていない（機械学習に投入困難）

### 3.2 新しいJSON出力仕様

**出力例:**
```json
{
  "format_version": "1.0",
  "analysis_timestamp": "2025-12-17T10:30:00Z",
  "binary": {
    "path": "/path/to/binary.exe",
    "architecture": "x86-64",
    "format": "PE"
  },
  "function": {
    "address": "0x140001000",
    "size": 245,
    "entry_point": "0x140001000",
    "exit_points": ["0x140001010", "0x140001018"],
    "name": {
      "known": true,
      "value": "process_player_data",
      "source": "DWARF"
    }
  },
  "cfg": {
    "entry_block": 0,
    "blocks": [
      {
        "id": 0,
        "address": "0x140001000",
        "size": 16,
        "ops": [
          {
            "opcode": "IntAdd",
            "output": {
              "space": "register",
              "offset": 0,
              "size": 8,
              "name": "rax"
            },
            "inputs": [
              {
                "space": "register",
                "offset": 0,
                "size": 8,
                "name": "rax"
              },
              {
                "space": "register",
                "offset": 24,
                "size": 8,
                "name": "rbx"
              }
            ],
            "address": "0x140001000"
          },
          {
            "opcode": "IntSLess",
            "output": {
              "space": "unique",
              "offset": 100,
              "size": 1
            },
            "inputs": [
              {"space": "const", "offset": 10, "size": 4},
              {"space": "register", "offset": 0, "size": 8}
            ],
            "address": "0x140001004"
          }
        ],
        "successors": [1, 2],
        "predecessors": []
      },
      {
        "id": 1,
        "address": "0x14000100C",
        "ops": [
          {
            "opcode": "IntMult",
            "output": {"space": "register", "offset": 0, "size": 8},
            "inputs": [
              {"space": "register", "offset": 0, "size": 8},
              {"space": "const", "offset": 2, "size": 4}
            ],
            "address": "0x14000100C"
          },
          {
            "opcode": "Return",
            "output": null,
            "inputs": [{"space": "register", "offset": 0, "size": 8}],
            "address": "0x140001010"
          }
        ],
        "successors": [],
        "predecessors": [0]
      }
    ]
  },
  "dataflow": {
    "def_use_chains": [
      {
        "definition": {"block": 0, "op": 0},
        "uses": [
          {"block": 0, "op": 1},
          {"block": 1, "op": 0}
        ]
      }
    ]
  },
  "type_inference": {
    "varnodes": [
      {
        "varnode": {"space": "register", "offset": 0},
        "inferred_type": "int64",
        "confidence": 0.85
      }
    ]
  },
  "symbols": {
    "functions": [
      {
        "address": "0x140002000",
        "name": "update_position",
        "source": "DWARF",
        "confidence": 1.0
      }
    ],
    "variables": [
      {
        "address": "0x140010000",
        "name": "g_player_health",
        "type": "int32",
        "source": "DWARF"
      }
    ]
  },
  "confidence": {
    "control_flow": 1.0,
    "data_types": 0.65,
    "variable_names": 0.9,
    "function_purpose": 0.1
  },
  "metadata": {
    "optimizations_applied": [
      "RuleTermOrder",
      "RuleConstantFold",
      "RuleAndMask"
    ],
    "analysis_time_ms": 12.3,
    "cache_hit": false
  }
}
```

### 3.3 JSON Schema定義

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "kensho-mcp Analysis Result",
  "type": "object",
  "required": ["format_version", "function", "cfg"],
  "properties": {
    "format_version": {
      "type": "string",
      "description": "JSONフォーマットのバージョン"
    },
    "function": {
      "type": "object",
      "properties": {
        "address": {"type": "string"},
        "size": {"type": "integer"},
        "name": {
          "type": "object",
          "properties": {
            "known": {"type": "boolean"},
            "value": {"type": "string"},
            "source": {"enum": ["DWARF", "PDB", "export", "inferred"]}
          }
        }
      }
    },
    "cfg": {
      "type": "object",
      "properties": {
        "blocks": {
          "type": "array",
          "items": {"$ref": "#/definitions/BasicBlock"}
        }
      }
    },
    "confidence": {
      "type": "object",
      "description": "各解析結果の確信度（0.0～1.0）"
    }
  },
  "definitions": {
    "BasicBlock": {
      "type": "object",
      "properties": {
        "id": {"type": "integer"},
        "address": {"type": "string"},
        "ops": {"type": "array"}
      }
    }
  }
}
```

### 3.4 実装方針

**現在のC疑似コード生成器を置き換える:**

```rust
// src/decompiler_prototype/json_printer.rs (新規作成)
use serde::{Serialize, Deserialize};
use super::cfg::ControlFlowGraph;
use super::dataflow::DefUseAnalysis;

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisResult {
    pub format_version: String,
    pub function: FunctionInfo,
    pub cfg: CfgData,
    pub dataflow: DataflowData,
    pub confidence: ConfidenceScores,
    pub metadata: AnalysisMetadata,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfidenceScores {
    pub control_flow: f64,
    pub data_types: f64,
    pub variable_names: f64,
    pub function_purpose: f64,
}

pub struct JsonPrinter;

impl JsonPrinter {
    pub fn print_analysis(
        cfg: &ControlFlowGraph,
        dataflow: &DefUseAnalysis,
        symbols: Option<&SymbolTable>,
    ) -> Result<String> {
        let result = AnalysisResult {
            format_version: "1.0".to_string(),
            function: self.build_function_info(cfg, symbols)?,
            cfg: self.build_cfg_data(cfg)?,
            dataflow: self.build_dataflow_data(dataflow)?,
            confidence: self.calculate_confidence(cfg, symbols),
            metadata: self.build_metadata()?,
        };

        serde_json::to_string_pretty(&result)
            .map_err(|e| anyhow!("JSON serialization failed: {}", e))
    }
}
```

**MCPツールの出力を変更:**
```rust
// src/main.rs (MCPハンドラ)
async fn handle_decompile_function(args: DecompileArgs) -> Result<Value> {
    let cfg = decompile(args.address)?;
    let dataflow = analyze_dataflow(&cfg)?;
    let symbols = load_debug_symbols(&args.path)?;

    // JSON出力（C疑似コードではなく）
    let json_result = JsonPrinter::print_analysis(&cfg, &dataflow, symbols.as_ref())?;

    Ok(serde_json::from_str(&json_result)?)
}
```

### 3.5 移行計画

### 3.5 移行計画
> [!NOTE]
> 2025-12-27現在、Phase 1は完了しています。

**Phase 1（完了）:**
- [x] `json_printer.rs`作成
- [x] 基本的なJSON出力実装
- [ ] MCPツールの統合

**Phase 2（未着手）:**
- [ ] confidence score計算ロジック
- [ ] DWARF/PDBシンボル統合
- [ ] スキーマ検証

**Phase 3（未着手）:**
- [ ] `c_printer.rs`を`#[deprecated]`にマーク
- [ ] ドキュメント更新
- [ ] 既存のC疑似コード生成は残す（後方互換性）

---

## 4. DWARF/PDB完全対応

### 4.1 目的

現在のシンボル復元は**PEエクスポートテーブルのみ**に対応。
DWARF（ELF）とPDB（PE）のデバッグシンボルを完全に読み込み、以下を実現する：

1. **関数名の完全復元**（エクスポートされていない内部関数も）
2. **変数名の復元**（ローカル変数、グローバル変数）
3. **型情報の取得**（構造体、共用体、配列等）
4. **ソースファイル名と行番号のマッピング**

### 3.2 DWARF対応（ELF/Mach-O）

**使用ライブラリ: `gimli`**

```toml
[dependencies]
gimli = "0.28"       # DWARF解析ライブラリ
addr2line = "0.21"   # アドレス→行番号変換
```

**実装ファイル:**
```
src/decompiler_prototype/
└── debug_symbols/
    ├── mod.rs          # 共通トレイト定義
    ├── dwarf.rs        # DWARF実装
    └── pdb.rs          # PDB実装
```

**DWARF実装例:**
```rust
// src/decompiler_prototype/debug_symbols/dwarf.rs
use gimli::{
    Dwarf, EndianSlice, RunTimeEndian,
    Unit, DebuggingInformationEntry, AttributeValue
};
use anyhow::{Result, Context};
use std::collections::HashMap;

/// DWARF情報を解析してシンボルテーブルを構築
pub struct DwarfSymbolParser {
    /// 関数名テーブル（アドレス → 名前）
    functions: HashMap<u64, String>,
    /// 変数名テーブル（アドレス → 名前）
    variables: HashMap<u64, String>,
    /// 型情報テーブル（type_offset → 型定義）
    types: HashMap<u64, TypeInfo>,
    /// ソース行情報（アドレス → (ファイル名, 行番号)）
    line_info: HashMap<u64, (String, u32)>,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub size: usize,
    pub kind: TypeKind,
}

#[derive(Debug, Clone)]
pub enum TypeKind {
    Base(BaseType),      // int, float等
    Pointer(Box<TypeInfo>),
    Array { element_type: Box<TypeInfo>, length: usize },
    Struct { fields: Vec<StructField> },
    Union { members: Vec<UnionMember> },
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub offset: usize,
    pub type_info: TypeInfo,
}

impl DwarfSymbolParser {
    /// ELFバイナリからDWARF情報を読み込む
    pub fn parse_from_elf(binary_data: &[u8]) -> Result<Self> {
        use object::{Object, ObjectSection};

        let obj_file = object::File::parse(binary_data)
            .context("Failed to parse ELF file")?;

        // DWARF関連セクションを取得
        let dwarf_sections = gimli::DwarfSections::load(|section_id| {
            obj_file.section_by_name(section_id.name())
                .and_then(|section| section.data().ok())
                .unwrap_or(&[])
        }).context("Failed to load DWARF sections")?;

        let dwarf = dwarf_sections.borrow(|section| {
            gimli::EndianSlice::new(section, gimli::RunTimeEndian::Little)
        });

        let mut parser = Self {
            functions: HashMap::new(),
            variables: HashMap::new(),
            types: HashMap::new(),
            line_info: HashMap::new(),
        };

        // Compilation Unitを走査
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            parser.parse_unit(&dwarf, header)?;
        }

        Ok(parser)
    }

    /// 各Compilation Unitを解析
    fn parse_unit<R: gimli::Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        header: gimli::UnitHeader<R>
    ) -> Result<()> {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();

        while let Some((_, entry)) = entries.next_dfs()? {
            match entry.tag() {
                gimli::DW_TAG_subprogram => {
                    self.parse_function(dwarf, &unit, entry)?;
                }
                gimli::DW_TAG_variable => {
                    self.parse_variable(dwarf, &unit, entry)?;
                }
                gimli::DW_TAG_base_type | gimli::DW_TAG_structure_type => {
                    self.parse_type(dwarf, &unit, entry)?;
                }
                _ => {}
            }
        }

        // 行番号情報を解析
        if let Some(program) = unit.line_program.clone() {
            self.parse_line_info(dwarf, program)?;
        }

        Ok(())
    }

    /// 関数情報を抽出
    fn parse_function<R: gimli::Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>
    ) -> Result<()> {
        // DW_AT_name: 関数名
        let name = entry.attr_value(gimli::DW_AT_name)?
            .and_then(|attr| {
                if let AttributeValue::DebugStrRef(offset) = attr {
                    dwarf.debug_str.get_str(offset).ok()
                        .map(|s| s.to_string_lossy().into_owned())
                } else {
                    None
                }
            });

        // DW_AT_low_pc: 関数の開始アドレス
        let address = entry.attr_value(gimli::DW_AT_low_pc)?
            .and_then(|attr| {
                if let AttributeValue::Addr(addr) = attr {
                    Some(addr)
                } else {
                    None
                }
            });

        if let (Some(name), Some(address)) = (name, address) {
            self.functions.insert(address, name);
        }

        Ok(())
    }

    /// 変数情報を抽出
    fn parse_variable<R: gimli::Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>
    ) -> Result<()> {
        // 実装省略（parse_functionと同様）
        Ok(())
    }

    /// 型情報を抽出
    fn parse_type<R: gimli::Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>
    ) -> Result<()> {
        // 実装省略
        Ok(())
    }

    /// 行番号情報を解析
    fn parse_line_info<R: gimli::Reader>(
        &mut self,
        dwarf: &Dwarf<R>,
        program: gimli::IncompleteLineProgram<R>
    ) -> Result<()> {
        let (program, sequences) = program.sequences()?;

        for sequence in sequences {
            let mut rows = program.resume_from(sequence);
            while let Some((header, row)) = rows.next_row()? {
                if let Some(file) = row.file(header) {
                    let file_name = dwarf.attr_string(&program.header(), file.path_name())?
                        .to_string_lossy()
                        .into_owned();

                    if let Some(line) = row.line() {
                        self.line_info.insert(
                            row.address(),
                            (file_name, line.get())
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// アドレスから関数名を取得
    pub fn get_function_name(&self, address: u64) -> Option<&str> {
        self.functions.get(&address).map(|s| s.as_str())
    }

    /// アドレスからソース行情報を取得
    pub fn get_source_location(&self, address: u64) -> Option<&(String, u32)> {
        self.line_info.get(&address)
    }
}
```

### 3.3 PDB対応（Windows PE）

**使用ライブラリ: `pdb`**

```toml
[dependencies]
pdb = "0.8"  # PDBファイル解析ライブラリ
```

**PDB実装例:**
```rust
// src/decompiler_prototype/debug_symbols/pdb.rs
use pdb::{PDB, FallibleIterator, SymbolData, TypeData};
use anyhow::{Result, Context};
use std::collections::HashMap;
use std::fs::File;

/// PDB情報を解析してシンボルテーブルを構築
pub struct PdbSymbolParser {
    functions: HashMap<u64, String>,
    variables: HashMap<u64, String>,
    types: HashMap<u32, TypeInfo>, // type_index → 型定義
}

impl PdbSymbolParser {
    /// PDBファイルを読み込む
    pub fn parse_from_file(pdb_path: &str) -> Result<Self> {
        let file = File::open(pdb_path)
            .context("Failed to open PDB file")?;

        let mut pdb = PDB::open(file)
            .context("Failed to parse PDB file")?;

        let mut parser = Self {
            functions: HashMap::new(),
            variables: HashMap::new(),
            types: HashMap::new(),
        };

        // シンボル情報を取得
        let symbol_table = pdb.global_symbols()
            .context("Failed to get global symbols")?;

        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            parser.parse_symbol(&symbol)?;
        }

        // 型情報を取得
        let type_information = pdb.type_information()
            .context("Failed to get type information")?;

        let mut type_iter = type_information.iter();
        while let Some(item) = type_iter.next()? {
            if let Ok(type_data) = item.parse() {
                parser.parse_type(item.index(), &type_data)?;
            }
        }

        Ok(parser)
    }

    /// シンボル情報を解析
    fn parse_symbol(&mut self, symbol: &pdb::Symbol) -> Result<()> {
        match symbol.parse() {
            Ok(SymbolData::Procedure(proc)) => {
                let name = proc.name.to_string().into_owned();
                // RVA (Relative Virtual Address) からVA計算が必要
                // 実際のアドレス = ImageBase + RVA
                let address = proc.offset.offset as u64; // 簡略化
                self.functions.insert(address, name);
            }
            Ok(SymbolData::Data(data)) => {
                let name = data.name.to_string().into_owned();
                let address = data.offset.offset as u64;
                self.variables.insert(address, name);
            }
            _ => {}
        }
        Ok(())
    }

    /// 型情報を解析
    fn parse_type(&mut self, index: pdb::TypeIndex, type_data: &TypeData) -> Result<()> {
        // 実装省略
        Ok(())
    }

    pub fn get_function_name(&self, address: u64) -> Option<&str> {
        self.functions.get(&address).map(|s| s.as_str())
    }
}
```

### 3.4 統合インターフェース

```rust
// src/decompiler_prototype/debug_symbols/mod.rs
mod dwarf;
mod pdb;

pub use dwarf::DwarfSymbolParser;
pub use pdb::PdbSymbolParser;

/// 統一されたデバッグシンボルインターフェース
pub trait DebugSymbolProvider {
    /// アドレスから関数名を取得
    fn get_function_name(&self, address: u64) -> Option<&str>;

    /// アドレスから変数名を取得
    fn get_variable_name(&self, address: u64) -> Option<&str>;

    /// アドレスからソースコード位置を取得
    fn get_source_location(&self, address: u64) -> Option<SourceLocation>;

    /// 型情報を取得
    fn get_type_info(&self, type_id: u64) -> Option<&TypeInfo>;
}

#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

impl DebugSymbolProvider for DwarfSymbolParser {
    fn get_function_name(&self, address: u64) -> Option<&str> {
        self.get_function_name(address)
    }

    fn get_source_location(&self, address: u64) -> Option<SourceLocation> {
        self.get_source_location(address).map(|(file, line)| {
            SourceLocation {
                file: file.clone(),
                line: *line,
                column: None,
            }
        })
    }

    // ... 他のメソッド実装
}

impl DebugSymbolProvider for PdbSymbolParser {
    // 同様に実装
}
```

### 3.5 既存システムへの統合

```rust
// src/decompiler_prototype/symbol_recovery.rs に追加
use super::debug_symbols::{DebugSymbolProvider, DwarfSymbolParser, PdbSymbolParser};

impl SymbolTable {
    /// DWARF/PDBからシンボルを読み込む
    pub fn load_debug_symbols(&mut self, binary_path: &str) -> Result<usize> {
        // ファイル形式を判定
        let binary_data = std::fs::read(binary_path)?;

        match detect_format(&binary_data)? {
            BinaryFormat::ELF | BinaryFormat::MachO => {
                let parser = DwarfSymbolParser::parse_from_elf(&binary_data)?;
                self.merge_debug_symbols(&parser)
            }
            BinaryFormat::PE => {
                // PDBファイルパスを推定（同じディレクトリに*.pdb）
                let pdb_path = binary_path.replace(".exe", ".pdb");
                if std::path::Path::new(&pdb_path).exists() {
                    let parser = PdbSymbolParser::parse_from_file(&pdb_path)?;
                    self.merge_debug_symbols(&parser)
                } else {
                    Ok(0) // PDBなし
                }
            }
        }
    }

    fn merge_debug_symbols(&mut self, provider: &impl DebugSymbolProvider) -> Result<usize> {
        // デバッグシンボルを既存のSymbolTableにマージ
        // 実装省略
        Ok(0)
    }
}
```

---

## 5. example_translation関数実装

### 4.1 目的

テストコードで使用される**サンプルP-code生成関数**を実装し、
以下のテストを正常に実行できるようにする：

- `cfg.rs::test_cfg_construction()`
- `cfg.rs::test_block_properties()`
- `printer.rs::test_simple_print()`
- `printer.rs::test_cfg_print()`

### 4.2 実装場所

```
src/decompiler_prototype/x86_64/mod.rs
または
src/decompiler_prototype/test_utils.rs (新規作成推奨)
```

### 4.3 実装例

**オプション1: x86_64/mod.rsに追加**
```rust
// src/decompiler_prototype/x86_64/mod.rs

#[cfg(test)]
pub fn example_translation() -> Vec<PcodeOp> {
    use crate::decompiler_prototype::pcode::{OpCode, PcodeOp, Varnode};

    // シンプルな関数のP-code表現
    // C疑似コード:
    // int example(int a, int b) {
    //     int c = a + b;
    //     if (c > 10) {
    //         return c * 2;
    //     } else {
    //         return c;
    //     }
    // }

    vec![
        // 0x1000: c = a + b
        PcodeOp::binary(
            OpCode::IntAdd,
            Varnode::register(24, 4),  // RBX (c)
            Varnode::register(0, 4),   // RAX (a)
            Varnode::register(8, 4),   // RCX (b)
            0x1000
        ),

        // 0x1004: temp1 = c > 10
        PcodeOp::binary(
            OpCode::IntSLess,
            Varnode::unique(100, 1),
            Varnode::constant(10, 4),
            Varnode::register(24, 4),
            0x1004
        ),

        // 0x1008: if (!temp1) goto 0x1014
        PcodeOp::new(
            OpCode::CBranch,
            None,
            vec![Varnode::constant(0x1014, 8), Varnode::unique(100, 1)],
            0x1008
        ),

        // 0x100C: rax = c * 2 (then分岐)
        PcodeOp::binary(
            OpCode::IntMult,
            Varnode::register(0, 4),
            Varnode::register(24, 4),
            Varnode::constant(2, 4),
            0x100C
        ),

        // 0x1010: return rax
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
            0x1010
        ),

        // 0x1014: rax = c (else分岐)
        PcodeOp::unary(
            OpCode::Copy,
            Varnode::register(0, 4),
            Varnode::register(24, 4),
            0x1014
        ),

        // 0x1018: return rax
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
            0x1018
        ),
    ]
}
```

**オプション2: test_utils.rsに分離（推奨）**
```rust
// src/decompiler_prototype/test_utils.rs
use super::pcode::{OpCode, PcodeOp, Varnode};

/// テスト用のサンプルP-code生成
///
/// 以下のC疑似コードに対応:
/// ```c
/// int example(int a, int b) {
///     int c = a + b;
///     if (c > 10) {
///         return c * 2;
///     } else {
///         return c;
///     }
/// }
/// ```
pub fn example_translation() -> Vec<PcodeOp> {
    vec![
        // [上記と同じコード]
    ]
}

/// より複雑なサンプル（ループを含む）
pub fn example_with_loop() -> Vec<PcodeOp> {
    // while (i < 10) { sum += i; i++; }
    vec![
        // 実装省略
    ]
}

/// Switch文を含むサンプル
pub fn example_with_switch() -> Vec<PcodeOp> {
    // switch (x) { case 0: ... case 1: ... default: ... }
    vec![
        // 実装省略
    ]
}
```

### 4.4 テストファイルの修正

**cfg.rs:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::test_utils::example_translation;

    #[test]
    fn test_cfg_construction() {
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        // ret命令で分割されるので2ブロック以上
        assert!(cfg.block_count() >= 2);
        assert!(cfg.entry().is_some());
    }

    #[test]
    fn test_block_properties() {
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        let entry = cfg.entry().unwrap();
        assert!(!entry.ops.is_empty());

        // 制御フロー命令で終わることを確認
        assert!(entry.is_branch() || entry.is_return());
    }
}
```

**printer.rs:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler_prototype::test_utils::example_translation;

    #[test]
    fn test_simple_print() {
        let pcodes = example_translation();
        let mut printer = SimplePrinter::new();
        let c_code = printer.print_pcodes(&pcodes);

        println!("Generated C code:\n{}", c_code);

        assert!(c_code.contains("rax"));
        assert!(c_code.contains("rbx"));
        assert!(c_code.contains("return"));
    }

    #[test]
    fn test_cfg_print() {
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);
        let mut printer = SimplePrinter::new();
        let c_code = printer.print_cfg(&cfg);

        println!("Generated C code from CFG:\n{}", c_code);

        assert!(c_code.contains("void function"));
        assert!(c_code.contains("Block"));
    }
}
```

### 4.5 mod.rsへの追加

```rust
// src/decompiler_prototype/mod.rs
pub mod pcode;
pub mod x86_64;
pub mod cfg;
// ... 既存のモジュール

#[cfg(test)]
pub mod test_utils;  // 追加
```

---

## 6. 実装優先度

### 5.1 High Priority（1-2週間）

1. **example_translation関数実装** ⭐⭐⭐
   - テストが通るようになる
   - 所要時間: 2時間

2. **CMOV命令完全実装** ⭐⭐⭐
   - x86-64対応の完成度を90%に
   - 所要時間: 4時間

3. **DWARF基本対応** ⭐⭐⭐
   - 関数名・変数名の取得のみ（型情報は後回し）
   - 所要時間: 1週間

### 5.2 Medium Priority（3-4週間）

4. **PDB基本対応** ⭐⭐
   - Windows PE向けシンボル復元
   - 所要時間: 1週間

5. **ARM64基盤実装** ⭐⭐
   - レジスタ定義、基本命令のみ
   - 所要時間: 2週間

### 5.3 Low Priority（1-2ヶ月）

6. **DWARF/PDB型情報対応** ⭐
   - 構造体、共用体の完全対応
   - 所要時間: 2週間

7. **ARM64完全実装** ⭐
   - NEON/SIMD含む全命令
   - 所要時間: 3週間

---

## 7. コーディング規約

### 6.1 命名規則

**関数名:**
```rust
// P-code生成関数
pub fn decode_<instruction_name>(...) -> Vec<PcodeOp>

// 例
pub fn decode_add(...)
pub fn decode_movss(...)
pub fn decode_cmove(...)
```

**型名:**
```rust
// PascalCase
pub struct X86Decoder
pub enum OpCode
pub struct DwarfSymbolParser
```

**変数名:**
```rust
// snake_case
let dest_vn = ...;
let src_vn = ...;
let temp_register = ...;
```

### 6.2 ドキュメント

**最小限のドキュメント:**
```rust
/// ADD命令 - 算術加算
///
/// # P-code生成
/// - `dest = src1 + src2` (IntAdd)
pub fn decode_add(...) -> Vec<PcodeOp> {
    // ...
}
```

**詳細ドキュメント（複雑な命令のみ）:**
```rust
/// CMOVE命令 - 条件付きMOVE（ZF=1で移動）
///
/// # 動作
/// - ZFフラグが1の場合、src → dest
/// - ZFフラグが0の場合、destは変更されない
///
/// # P-code生成
/// 1. old_dest = dest (現在値を保存)
/// 2. dest = MultiEqual(ZF, src, old_dest)
///    - ZF=1 → src を選択
///    - ZF=0 → old_dest を選択
pub fn decode_cmove(...) -> Vec<PcodeOp> {
    // ...
}
```

### 6.3 エラーハンドリング

```rust
// ❌ 悪い例: panicは避ける
pub fn parse_dwarf(data: &[u8]) -> SymbolTable {
    let dwarf = Dwarf::parse(data).unwrap(); // panic!
    // ...
}

// ✅ 良い例: Resultを返す
pub fn parse_dwarf(data: &[u8]) -> Result<SymbolTable> {
    let dwarf = Dwarf::parse(data)
        .context("Failed to parse DWARF data")?;
    // ...
    Ok(symbol_table)
}
```

---

## 8. テスト基準

### 7.1 必須テスト

**各命令デコーダ:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_add() {
        let mut decoder = X86Decoder::new();
        let ops = decode_add(&mut decoder, X86Register::RAX, X86Register::RBX, 8, 0x1000);

        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode, OpCode::IntAdd);
    }
}
```

**デバッグシンボル:**
```rust
#[test]
fn test_dwarf_function_names() {
    let binary = include_bytes!("../../tests/fixtures/sample.elf");
    let parser = DwarfSymbolParser::parse_from_elf(binary).unwrap();

    // main関数が存在することを確認
    assert!(parser.get_function_name(0x1234).is_some());
}
```

### 7.2 テストデータ

**テスト用バイナリの配置:**
```
tests/
└── fixtures/
    ├── sample_x86_64.elf    # DWARFシンボル付きELF
    ├── sample_arm64.elf     # ARM64テスト用
    └── sample_pe.exe        # PDBシンボル付きPE
```

---

## 9. リファレンス

### 8.1 参考資料

**P-code:**
- [Ghidra P-code Reference](https://ghidra.re/courses/languages/html/pcoderef.html)

**DWARF:**
- [DWARF Debugging Standard](https://dwarfstd.org/)
- [gimli Documentation](https://docs.rs/gimli/)

**PDB:**
- [PDB Format Documentation](https://github.com/microsoft/microsoft-pdb)
- [pdb crate](https://docs.rs/pdb/)

**ARM64:**
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [ARM64 Instruction Set](https://developer.arm.com/documentation/ddi0596/)

### 8.2 既存実装の参考

**x86-64命令:**
```
src/decompiler_prototype/x86_64/instructions/
├── arithmetic.rs       # ADD, SUB, MUL, DIV
├── logic.rs            # AND, OR, XOR
├── data_transfer.rs    # MOV, PUSH, POP
├── control_flow.rs     # JMP, CALL, RET, CMOV
├── simd.rs             # SSE/AVX
└── misc.rs             # その他
```

---

## 10. 開発フロー

### 9.1 機能追加の手順

1. **Issue作成** → GitHub Issue で機能を定義
2. **ブランチ作成** → `feature/<feature-name>`
3. **実装** → コーディング規約に従う
4. **テスト** → `cargo test` が通ることを確認
5. **ドキュメント** → README.md を更新
6. **PR作成** → mainブランチへマージ

### 9.2 ビルドコマンド

```bash
# 通常ビルド
cargo build

# リリースビルド
cargo build --release

# テスト実行
cargo test

# 特定のテストのみ
cargo test test_cfg_construction

# ドキュメント生成
cargo doc --open
```

---

## 11. まとめ

このドキュメントで定義された実装基準に従うことで、以下を実現します：

✅ **x86-64完全対応**（ARM64は排除、特化戦略）
✅ **JSON構造化データ出力**（AI-First設計）
✅ **DWARF/PDBによる高度なシンボル復元**
✅ **example_translation関数によるテスト正常化**
✅ **統一されたコーディングスタイル**
✅ **実用的で保守可能なコードベース**

**次のステップ（優先順）:**
1. example_translation関数実装（2時間）
2. CMOV命令完全実装（4時間）
3. JSON出力フォーマット実装（1週間）
4. DWARF基本対応（1週間）

---

**作成者**: Claude Sonnet 4.5
**更新履歴**:
- 2025-12-17: 初版作成
