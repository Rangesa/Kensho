//! MCP ツール定義
//! 
//! 全ツールのJSONスキーマを定義

use serde_json::{json, Value};

/// 全ツール定義を取得
pub fn get_tool_definitions() -> Vec<Value> {
    vec![
        // === 階層1: サマリー ===
        tool_get_binary_summary(),
        
        // === 階層2: 一覧系 ===
        tool_list_sections(),
        tool_list_functions(),
        tool_list_strings(),
        tool_list_imports(),
        
        // === デコンパイラ ===
        tool_decompile_function(),
        
        // === 難読化解析 ===
        tool_detect_obfuscation(),
        tool_detect_vm_protection(),
        tool_analyze_control_flow_flattening(),
        tool_simplify_mba_expression(),
    ]
}

// =============================================================================
// 階層1: サマリー
// =============================================================================

fn tool_get_binary_summary() -> Value {
    json!({
        "name": "get_binary_summary",
        "description": "バイナリの概要情報を取得（超軽量、統計のみ）。最初に必ずこれを呼んで全体像を把握する",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "バイナリファイルパス"
                }
            },
            "required": ["path"]
        }
    })
}

// =============================================================================
// 階層2: 一覧系
// =============================================================================

fn tool_list_sections() -> Value {
    json!({
        "name": "list_sections",
        "description": "セクション一覧を取得（ページネーション対応）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "page": {
                    "type": "integer",
                    "description": "ページ番号（0開始）",
                    "default": 0
                },
                "page_size": {
                    "type": "integer",
                    "description": "1ページあたりの件数",
                    "default": 20
                }
            },
            "required": ["path"]
        }
    })
}

fn tool_list_functions() -> Value {
    json!({
        "name": "list_functions",
        "description": "関数一覧を取得（ページネーション対応、名前フィルタ可能）。大規模バイナリでは必ずフィルタ使用を推奨",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "page": {
                    "type": "integer",
                    "description": "ページ番号",
                    "default": 0
                },
                "page_size": {
                    "type": "integer",
                    "description": "1ページあたりの件数（推奨: 20-100）",
                    "default": 50
                },
                "name_filter": {
                    "type": "string",
                    "description": "関数名フィルタ（部分一致）。例: 'update', 'render', 'network'"
                }
            },
            "required": ["path"]
        }
    })
}

fn tool_list_strings() -> Value {
    json!({
        "name": "list_strings",
        "description": "バイナリ内の文字列を取得（ページネーション対応）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "page": {"type": "integer", "default": 0},
                "page_size": {"type": "integer", "default": 100},
                "min_length": {
                    "type": "integer",
                    "description": "最小文字列長",
                    "default": 4
                }
            },
            "required": ["path"]
        }
    })
}

fn tool_list_imports() -> Value {
    json!({
        "name": "list_imports",
        "description": "インポート関数一覧（通常は数百〜数千件なので全件返す）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            },
            "required": ["path"]
        }
    })
}

// =============================================================================
// デコンパイラ
// =============================================================================

fn tool_decompile_function() -> Value {
    json!({
        "name": "decompile_function",
        "description": "関数をデコンパイル（P-code、SSA、型推論、制御構造解析）。キャッシュと詳細レベルを選択可能",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "バイナリファイルパス"
                },
                "function_address": {
                    "type": "string",
                    "description": "関数アドレス（0x140001000形式）"
                },
                "file_offset": {
                    "type": "string",
                    "description": "ファイルオフセット（0x600形式、省略時は自動計算）"
                },
                "max_instructions": {
                    "type": "integer",
                    "description": "最大命令数（デフォルト: 1000）",
                    "default": 1000
                },
                "cache": {
                    "type": "boolean",
                    "description": "キャッシュ使用（デフォルト: true）",
                    "default": true
                },
                "detail_level": {
                    "type": "string",
                    "enum": ["basic", "full"],
                    "description": "詳細レベル（basic: 統計のみ、full: 型推論+逆アセンブル）",
                    "default": "basic"
                },
                "include_disassembly": {
                    "type": "boolean",
                    "description": "逆アセンブル含有（detail_level=fullのみ有効）",
                    "default": false
                }
            },
            "required": ["path", "function_address"]
        }
    })
}

// =============================================================================
// 難読化解析
// =============================================================================

fn tool_detect_obfuscation() -> Value {
    json!({
        "name": "detect_obfuscation",
        "description": "バイナリから難読化パターンを検出（MBA、制御フロー平坦化、VM保護等）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "バイナリファイルパス"
                },
                "function_address": {
                    "type": "string",
                    "description": "関数のアドレス（16進数: 0x140001000）"
                },
                "max_instructions": {
                    "type": "integer",
                    "description": "最大命令数",
                    "default": 1000
                }
            },
            "required": ["path", "function_address"]
        }
    })
}

fn tool_detect_vm_protection() -> Value {
    json!({
        "name": "detect_vm_protection",
        "description": "仮想化ベース難読化（VMProtect等）のパターンを検出",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "バイナリファイルパス"
                },
                "function_address": {
                    "type": "string",
                    "description": "関数のアドレス（16進数: 0x140001000）"
                },
                "max_instructions": {
                    "type": "integer",
                    "description": "最大命令数",
                    "default": 1000
                }
            },
            "required": ["path", "function_address"]
        }
    })
}

fn tool_analyze_control_flow_flattening() -> Value {
    json!({
        "name": "analyze_control_flow_flattening",
        "description": "制御フロー平坦化（Control Flow Flattening）を検出・解析",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "バイナリファイルパス"
                },
                "function_address": {
                    "type": "string",
                    "description": "関数のアドレス（16進数: 0x140001000）"
                },
                "max_instructions": {
                    "type": "integer",
                    "description": "最大命令数",
                    "default": 1000
                }
            },
            "required": ["path", "function_address"]
        }
    })
}

fn tool_simplify_mba_expression() -> Value {
    json!({
        "name": "simplify_mba_expression",
        "description": "MBA（Mixed Boolean-Arithmetic）式を簡約化して元の式を復元",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "バイナリファイルパス"
                },
                "function_address": {
                    "type": "string",
                    "description": "関数のアドレス（16進数: 0x140001000）"
                },
                "max_instructions": {
                    "type": "integer",
                    "description": "最大命令数",
                    "default": 1000
                }
            },
            "required": ["path", "function_address"]
        }
    })
}
