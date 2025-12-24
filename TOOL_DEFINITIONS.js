// 階層的解析MCPツール定義

/// 階層1: サマリー（常に軽量、最初に呼ぶ）
{
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
}

// 出力例:
{
    "file_path": "/path/to/game.exe",
    "file_size": 204857600,  // 200MB
    "format": "PE",
    "architecture": "x86-64",
    "entry_point": "0x140001000",
    "stats": {
        "section_count": 15,
        "function_count": 45678,    // ← 全部は返さない！
        "import_count": 1234,
        "export_count": 567,
        "string_count_estimate": 125000
    }
}

/// 階層2a: セクション一覧（ページネーション）
{
    "name": "list_sections",
    "description": "セクション一覧を取得（ページネーション対応）",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "page": {
                "type": "integer",
                "description": "ページ番号（0始まり）",
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
}

// 出力例:
{
    "total_count": 15,
    "page": 0,
    "page_size": 20,
    "sections": [
        {
            "index": 0,
            "name": ".text",
            "address": "0x140001000",
            "size": 123456,
            "section_type": "CODE"
        },
        // ... 最大20件まで
    ]
}

/// 階層2b: 関数一覧（ページネーション + フィルタリング）
{
    "name": "list_functions",
    "description": "関数一覧を取得（ページネーション対応、名前フィルタ可能）",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "page": {
                "type": "integer",
                "default": 0
            },
            "page_size": {
                "type": "integer",
                "description": "1ページあたりの件数（推奨: 20-100）",
                "default": 50
            },
            "name_filter": {
                "type": "string",
                "description": "関数名フィルタ（部分一致）。例: 'update', 'render' など",
                "default": null
            }
        },
        "required": ["path"]
    }
}

// 出力例:
{
    "total_count": 45678,  // ← 全体数は教えるけど全部は返さない
    "page": 0,
    "page_size": 50,
    "functions": [
        {
            "address": "0x140001000",
            "name": "main",
            "size": 1234,
            "section": ".text"
        },
        // ... 50件まで
    ]
}

/// 階層2c: 文字列一覧（ページネーション）
{
    "name": "list_strings",
    "description": "バイナリ内の文字列を取得（ページネーション対応）",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "page": { "type": "integer", "default": 0 },
            "page_size": { "type": "integer", "default": 100 },
            "min_length": {
                "type": "integer",
                "description": "最小文字列長",
                "default": 4
            }
        },
        "required": ["path"]
    }
}

// 出力例:
{
    "total_count": 125000,
    "page": 0,
    "page_size": 100,
    "strings": [
        {
            "address": "0x14002000",
            "value": "Hello, World!",
            "length": 13
        },
        // ... 100件まで
    ]
}

/// 階層3: 特定関数の詳細解析（これだけ重い）
{
    "name": "analyze_function_detail",
    "description": "特定の関数を詳細解析（逆アセンブル + デコンパイル）。コンテキスト消費大なので、本当に必要な関数のみ実行",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "function_address": {
                "type": "string",
                "description": "関数のアドレス（16進数: 0x140001000）"
            }
        },
        "required": ["path", "function_address"]
    }
}

// 出力例（これは大きくても OK、1関数のみなので）:
{
    "address": "0x140001000",
    "name": "critical_function",
    "size": 5678,
    "disassembly": [
        {
            "address": "0x140001000",
            "mnemonic": "push",
            "operands": "rbp",
            "bytes": "55"
        },
        // ... 最大100命令
    ],
    "decompiled": "void critical_function() {\n  ...\n}",
    "cross_references": ["0x140002000", "0x140003000"]
}

/// 追加の便利ツール

/// 検索: アドレス範囲指定
{
    "name": "list_functions_in_range",
    "description": "指定アドレス範囲内の関数を取得",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "start_address": { "type": "string" },
            "end_address": { "type": "string" }
        },
        "required": ["path", "start_address", "end_address"]
    }
}

/// 検索: 特定セクション内の関数
{
    "name": "list_functions_in_section",
    "description": "特定セクション内の関数のみ取得",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "section_name": {
                "type": "string",
                "description": "セクション名（例: .text, .data）"
            },
            "page": { "type": "integer", "default": 0 },
            "page_size": { "type": "integer", "default": 50 }
        },
        "required": ["path", "section_name"]
    }
}

/// インポート/エクスポート（これらは通常小規模なので全件返してOK）
{
    "name": "list_imports",
    "description": "インポート関数一覧（通常は数百〜数千件なので全件返す）",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": { "type": "string" }
        },
        "required": ["path"]
    }
}

{
    "name": "list_exports",
    "description": "エクスポート関数一覧",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": { "type": "string" }
        },
        "required": ["path"]
    }
}
