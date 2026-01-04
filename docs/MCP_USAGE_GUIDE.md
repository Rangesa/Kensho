# Kensho MCP 使用ガイド

このガイドでは、Kensho MCPサーバーをClaude CodeとGemini CLIで使用する方法を説明します。

## セットアップ

### 1. ビルド

```bash
cargo build --release
```

ビルド後、実行ファイルは `target/release/kensho-mcp.exe` に生成されます。

### 2. Claude Code設定

プロジェクトルートまたはユーザーディレクトリに `.mcp.json` を配置：

```json
{
  "mcpServers": {
    "kensho-mcp": {
      "type": "stdio",
      "command": "D:\\Programming\\MCP\\target\\release\\kensho-mcp.exe",
      "args": [],
      "env": {}
    }
  }
}
```

### 3. Gemini CLI設定

プロジェクトディレクトリに `.gemini/settings.json` を配置：

```json
{
  "mcpServers": {
    "kensho-mcp": {
      "command": "D:\\Programming\\MCP\\target\\release\\kensho-mcp.exe",
      "args": [],
      "env": {},
      "timeout": 60000,
      "trust": true
    }
  }
}
```

または、グローバル設定（`~/.gemini/settings.json`）に追加可能。

## 基本解析ツール

### バイナリサマリ取得

**ツール**: `get_binary_summary`

```
installer.exeのバイナリサマリを取得して
```

**取得情報**:
- PE/ELF基本情報（アーキテクチャ、エントリポイント）
- セクション数、インポート数
- 全体エントロピー
- パックされているかの推定

### セクション情報取得

**ツール**: `list_sections`

```
installer.exeのセクション情報を教えて
```

**取得情報**:
- セクション名、サイズ、仮想アドレス
- 各セクションのエントロピー（暗号化/パックの検出）
- フラグ（実行可能、書き込み可能等）

### 文字列抽出

**ツール**: `list_strings`

```
installer.exeから文字列を抽出して
```

**取得情報**:
- 抽出された文字列リスト
- オフセット情報
- ASCII/Unicode判定

### インポートテーブル

**ツール**: `list_imports`

```
installer.exeのインポート関数を教えて
```

**取得情報**:
- DLL名
- インポートされた関数リスト
- オーディナル情報

### 関数のデコンパイル

**ツール**: `decompile_function_native`

```
installer.exeのアドレス0x1000の関数をデコンパイルして
```

**取得情報**:
- x86-64ネイティブ命令
- P-code変換結果
- SSA形式
- C疑似コード
- 型推論結果

## 難読化解析ツール（Phase 1）

### 総合的な難読化検出

**ツール**: `detect_obfuscation`

```
installer.exeのアドレス0x1000の関数の難読化を検出して
```

**検出パターン**:
- **MBA Expression**: Mixed Boolean-Arithmetic式
- **Control Flow Flattening**: 制御フロー平坦化
- **VM-based Obfuscation**: VMProtect等のVM保護
- **Opaque Predicates**: 常に真/偽となる条件分岐
- **Bogus Control Flow**: 到達不可能なコード
- **Excessive Jumps**: 過剰な間接ジャンプ

**出力例**:
```json
{
  "function_address": "0x1000",
  "is_obfuscated": true,
  "overall_score": 0.85,
  "patterns_detected": [
    {
      "type": "MBAExpression",
      "confidence": 0.9,
      "locations": [
        {
          "block_id": 5,
          "op_index": 12,
          "address": "0x1045"
        }
      ],
      "description": "MBA expression: complexity 8.5, 15 ops (8 bitwise, 7 arithmetic)"
    },
    {
      "type": "ControlFlowFlattening",
      "confidence": 0.8,
      "locations": [
        {
          "block_id": 0,
          "op_index": null,
          "address": "0x1000"
        }
      ],
      "description": "Suspected dispatcher block with 12 successors (control flow flattening)"
    }
  ],
  "statistics": {
    "total_patterns": 5,
    "mba_count": 3,
    "vm_count": 0,
    "flattening_count": 1
  }
}
```

### VM保護検出

**ツール**: `detect_vm_protection`

```
installer.exeのアドレス0x2000の関数でVM保護を検出して
```

**検出内容**:
- VMディスパッチャーブロック
- VMハンドラー数
- バイトコード命令
- 間接ジャンプパターン

**出力例**:
```json
{
  "function_address": "0x2000",
  "vm_detected": true,
  "vm_pattern": {
    "confidence": 0.92,
    "dispatcher": {
      "block_id": 3,
      "indirect_jumps": 8
    },
    "handlers": [
      {
        "block_id": 10,
        "handler_type": "Unknown"
      }
    ],
    "handler_count": 45,
    "bytecode_instructions": 120
  }
}
```

### 制御フロー平坦化解析

**ツール**: `analyze_control_flow_flattening`

```
installer.exeのアドレス0x3000の関数の制御フロー平坦化を解析して
```

**解析内容**:
- 状態変数の特定
- ディスパッチャーブロック
- 状態遷移の追跡
- カバレッジ計算

**出力例**:
```json
{
  "function_address": "0x3000",
  "flattening_detected": true,
  "flattening_info": {
    "confidence": 0.87,
    "state_variable": {
      "space": "register",
      "offset": 16,
      "size": 8
    },
    "dispatcher_block": 0,
    "transition_count": 25,
    "analysis": {
      "total_blocks": 30,
      "blocks_through_dispatcher": 25,
      "coverage": 0.83,
      "dispatcher_successors": 15
    }
  }
}
```

### MBA式の簡約化

**ツール**: `simplify_mba_expression`

```
MBA式 "((x ^ y) + 2 * (x & y))" を簡約化して
```

**機能**:
- Kensho SMT solverによる等価性検証
- ビットブラスティングベースのSAT求解
- 簡約化されたより単純な式の提示

**出力例**:
```json
{
  "original": "((x ^ y) + 2 * (x & y))",
  "simplified": [
    {
      "expression": "x + y",
      "verification": "Verified",
      "rules_applied": ["mba_add_pattern"]
    }
  ],
  "verification_count": 1
}
```

## 使用例

### 完全に難読化されたバイナリの解析

1. **サマリ取得で概要を把握**
```
installer.exeのバイナリサマリを取得
```

2. **難読化パターンを検出**
```
installer.exeのエントリポイント関数の難読化を検出
```

3. **VM保護の有無を確認**
```
installer.exeのアドレス0x1000でVM保護を検出
```

4. **制御フロー平坦化を解析**
```
installer.exeのアドレス0x1000の制御フロー平坦化を解析
```

5. **検出されたMBA式を簡約化**
```
検出されたMBA式 "((x | y) - (x ^ y))" を簡約化
```

### プロセスメモリダンプ

**ツール**: `dump_process_memory`

```
PID 1234のメモリをダンプして
```

## トラブルシューティング

### MCPサーバーが認識されない

1. ビルドが完了しているか確認:
```bash
ls target/release/kensho-mcp.exe
```

2. 設定ファイルのパスが正しいか確認

3. Claude Code / Gemini CLIを再起動

### タイムアウトエラー

大きなバイナリや複雑な関数の解析には時間がかかります。
Gemini CLIの設定で `timeout` を増やしてください:

```json
{
  "timeout": 120000
}
```

### パーミッションエラー

実行ファイルに実行権限があるか確認:
```bash
chmod +x target/release/kensho-mcp.exe  # Unix系
```

## 参考情報

- **Gemini CLI MCP対応**: [MCP servers with the Gemini CLI](https://geminicli.com/docs/tools/mcp-server/)
- **Google MCP公式サポート**: [Announcing official MCP support for Google services](https://cloud.google.com/blog/products/ai-machine-learning/announcing-official-mcp-support-for-google-services)
- **Claude MCP統合**: Claude Code公式ドキュメント
