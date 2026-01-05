# MCP モジュール アーキテクチャ

## 概要

`src/mcp/` ディレクトリは、Kensho MCPサーバーのツール定義とハンドラーを管理します。

**設計原則**: 責務分離（Separation of Concerns）
- `tools.rs`: **何ができるか**（ツールのJSONスキーマ）
- `handlers.rs`: **どう実行するか**（ツールの実装ロジック）

## ディレクトリ構造

```
src/mcp/
├── mod.rs          # モジュールエントリーポイント
├── tools.rs        # ツール定義（JSONスキーマ）
└── handlers.rs     # ツールハンドラー（実行ロジック）
```

## ファイル詳細

### `mod.rs`
モジュールの公開インターフェース。

```rust
pub use tools::get_tool_definitions;
pub use handlers::dispatch_tool;
```

### `tools.rs`
各ツールのMCPスキーマを定義。AIエージェントに対して「このツールは何ができるか」を伝えます。

```rust
pub fn get_tool_definitions() -> Vec<Value> {
    vec![
        tool_get_binary_summary(),
        tool_list_sections(),
        // ...
    ]
}

fn tool_get_binary_summary() -> Value {
    json!({
        "name": "get_binary_summary",
        "description": "バイナリの概要情報を取得...",
        "inputSchema": { ... }
    })
}
```

### `handlers.rs`
ツール呼び出しを受けて実際の処理を実行。

```rust
pub async fn dispatch_tool(
    tool_name: &str,
    arguments: &Value,
    analyzer: Arc<Mutex<HierarchicalAnalyzer>>,
) -> Result<Value> {
    match tool_name {
        "get_binary_summary" => handle_get_binary_summary(arguments, analyzer).await,
        // ...
    }
}
```

## 新しいツールの追加方法

### Step 1: `tools.rs` にスキーマを追加

```rust
// 1. get_tool_definitions() に追加
pub fn get_tool_definitions() -> Vec<Value> {
    vec![
        // ... 既存ツール ...
        tool_my_new_tool(),  // 追加
    ]
}

// 2. スキーマ定義関数を作成
fn tool_my_new_tool() -> Value {
    json!({
        "name": "my_new_tool",
        "description": "新しいツールの説明",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "バイナリファイルパス"
                },
                "option": {
                    "type": "integer",
                    "description": "オプションパラメータ",
                    "default": 100
                }
            },
            "required": ["path"]
        }
    })
}
```

### Step 2: `handlers.rs` にハンドラーを追加

```rust
// 1. dispatch_tool() のmatchに追加
pub async fn dispatch_tool(...) -> Result<Value> {
    match tool_name {
        // ... 既存ツール ...
        "my_new_tool" => handle_my_new_tool(arguments).await?,
        // ...
    }
}

// 2. ハンドラー関数を実装
async fn handle_my_new_tool(arguments: &Value) -> Result<Value> {
    let path = arguments["path"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing path"))?;
    let option = arguments["option"].as_u64().unwrap_or(100) as usize;

    // 実際の処理
    let result = do_something(path, option)?;

    Ok(json!({
        "status": "success",
        "result": result
    }))
}
```

## ツール一覧

### 階層1: サマリー
| ツール名 | 説明 |
|----------|------|
| `get_binary_summary` | バイナリ概要（エントロピー、パッキング検知含む） |

### 階層2: 一覧系
| ツール名 | 説明 |
|----------|------|
| `list_sections` | セクション一覧（ページネーション対応） |
| `list_functions` | 関数一覧（フィルタリング対応） |
| `list_strings` | 文字列一覧 |
| `list_imports` | インポート関数一覧 |

### デコンパイラ
| ツール名 | 説明 |
|----------|------|
| `decompile_function` | P-code/SSA/型推論でデコンパイル |

### 難読化解析
| ツール名 | 説明 |
|----------|------|
| `detect_obfuscation` | 難読化パターン検出 |
| `detect_vm_protection` | VMProtect等の検出 |
| `analyze_control_flow_flattening` | 制御フロー平坦化解析 |
| `simplify_mba_expression` | MBA式の簡約化 |

## ヘルパー関数

`handlers.rs` には共通処理のヘルパー関数があります：

```rust
// 16進数アドレスのパース（"0x140001000" -> u64）
fn parse_hex_address(addr_str: &str) -> Result<u64>

// バイナリからCFGをロード
fn load_cfg_from_binary(path, address, max_instructions) -> Result<(CFG, Vec<PcodeOp>)>

// コードスライス取得
fn get_code_slice(binary_data, address, max_instructions) -> &[u8]
```

## テスト

```bash
# 単体テスト
cargo test mcp::

# 統合テスト（MCPプロトコル経由）
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | cargo run
```

## 設計判断

### なぜ分離したか？

**Before (main.rs 755行)**:
- ツール定義とロジックが混在
- 新ツール追加時に大きなファイルを編集
- 全体像が見えにくい

**After (main.rs 170行 + mcp/)**:
- main.rs はMCPループのみ
- ツール追加は tools.rs + handlers.rs のみ
- 責務が明確

### 非同期設計

全ハンドラーは `async fn` ですが、現在の実装はほぼ同期的です。
将来的に以下が可能：
- 並列デコンパイル
- 非同期キャッシュアクセス
- タイムアウト処理

---

**最終更新**: 2026-01-05
