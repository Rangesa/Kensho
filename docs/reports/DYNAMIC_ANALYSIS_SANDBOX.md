# 動的解析サンドボックス機能 実装レポート

実装日: 2026-01-08
更新日: 2026-01-08（analyze_with_trace追加）

## 概要

Windows専用の動的解析機能として、Job Objectsを使用したサンドボックス実行環境を実装した。外部依存なし（純粋FFI）で、Windows Home環境でも動作する。管理者権限不要。

## 設計方針

### 選択した手法: Job Objects + Restricted Token

検討した選択肢:
1. **Docker**: クロスプラットフォームだが、Windows環境では複雑すぎる
2. **Windows Sandbox**: 優秀だがWindows Pro必須
3. **Job Objects + Restricted Token**: Windows Home対応、外部依存なし

Job Objects + Restricted Tokenを選択した理由:
- Windows標準APIのみで実装可能
- 外部依存ゼロ（windows-rsクレートも不使用）
- Windows Homeでも完全動作
- メモリ/CPU/プロセス数の制限が可能
- 特権剥奪による安全性確保

### 技術的詳細

#### Job Object
Windowsカーネルがプロセスを「グループ化」して管理する機能。以下の制限を適用可能:
- メモリ使用量上限
- CPU時間制限
- 同時実行プロセス数制限
- 親プロセス終了時の子プロセス強制終了

#### Restricted Token
プロセスのセキュリティトークンから特権を剥奪:
- DISABLE_MAX_PRIVILEGE: 全特権を無効化
- UI制限: クリップボード、デスクトップ、グローバルアトム等へのアクセス禁止

## ファイル構成

```
src/dynamic_analysis/
├── mod.rs              # モジュール定義・エクスポート
├── ffi/
│   ├── mod.rs          # FFIサブモジュール定義
│   ├── types.rs        # Windows API基本型
│   ├── kernel32.rs     # デバッグAPI (ReadProcessMemory等)
│   └── security.rs     # Job Object/Token API
├── debugger.rs         # ProcessDebugger実装
├── tracer.rs           # FunctionTracer実装
└── sandbox.rs          # SandboxedProcess実装
```

## 実装詳細

### FFI型定義 (ffi/security.rs)

#### Job Object関連
```rust
pub struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    pub per_process_user_time_limit: i64,
    pub per_job_user_time_limit: i64,
    pub limit_flags: DWORD,
    pub minimum_working_set_size: SIZE_T,
    pub maximum_working_set_size: SIZE_T,
    pub active_process_limit: DWORD,
    pub affinity: ULONG_PTR,
    pub priority_class: DWORD,
    pub scheduling_class: DWORD,
}

pub struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    pub basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    pub io_info: IO_COUNTERS,
    pub process_memory_limit: SIZE_T,
    pub job_memory_limit: SIZE_T,
    pub peak_process_memory_used: SIZE_T,
    pub peak_job_memory_used: SIZE_T,
}
```

#### Token関連
```rust
pub struct TOKEN_PRIVILEGES {
    pub privilege_count: DWORD,
    pub privileges: [LUID_AND_ATTRIBUTES; 1],
}

pub struct SID_AND_ATTRIBUTES {
    pub sid: PSID,
    pub attributes: DWORD,
}
```

### サンドボックス設定 (sandbox.rs)

```rust
pub struct SandboxConfig {
    /// メモリ制限（バイト単位、0で無制限）
    pub memory_limit: usize,           // デフォルト: 512MB
    /// CPU時間制限（100ナノ秒単位、0で無制限）
    pub cpu_time_limit: i64,           // デフォルト: 0（無制限）
    /// 同時プロセス数制限（0で無制限）
    pub process_limit: u32,            // デフォルト: 1
    /// UIアクセス制限
    pub restrict_ui: bool,             // デフォルト: true
    /// ネットワーク制限（ファイアウォール連携必要）
    pub restrict_network: bool,        // デフォルト: false
    /// 低整合性レベルで実行
    pub low_integrity: bool,           // デフォルト: true
    /// 親プロセス終了時に子も終了
    pub kill_on_close: bool,           // デフォルト: true
}
```

### SandboxedProcess実装

```rust
pub struct SandboxedProcess {
    job_handle: HANDLE,
    process_handle: HANDLE,
    thread_handle: HANDLE,
    process_id: u32,
    thread_id: u32,
    config: SandboxConfig,
}

impl SandboxedProcess {
    /// サンドボックス内でプロセスを起動
    pub fn spawn(exe_path: &str, args: Option<&str>, config: SandboxConfig) -> Result<Self>;

    /// プロセス完了を待機
    pub fn wait(&self, timeout_ms: u32) -> Result<SandboxResult>;

    /// プロセスを強制終了
    pub fn terminate(&self) -> Result<()>;

    /// プロセスIDを取得
    pub fn process_id(&self) -> u32;

    /// プロセスが実行中か確認
    pub fn is_running(&self) -> bool;
}
```

### 起動フロー

1. Job Object作成 (`CreateJobObjectW`)
2. 制限情報設定 (`SetInformationJobObject`)
3. プロセス起動（一時停止状態）(`CreateProcessW`, `CREATE_SUSPENDED`)
4. プロセスをJob Objectに割り当て (`AssignProcessToJobObject`)
5. プロセス実行開始 (`ResumeThread`)

注: 管理者権限不要のため `CreateProcessW` を使用。`CreateProcessAsUserW` は管理者権限が必要。

## MCPツール

### run_in_sandbox

サンドボックス環境でバイナリを実行。

```json
{
  "name": "run_in_sandbox",
  "inputSchema": {
    "type": "object",
    "properties": {
      "exe_path": { "type": "string", "description": "実行するバイナリのパス" },
      "args": { "type": "string", "description": "コマンドライン引数" },
      "memory_limit_mb": { "type": "integer", "default": 512 },
      "timeout_ms": { "type": "integer", "default": 30000 }
    },
    "required": ["exe_path"]
  }
}
```

出力例:
```json
{
  "success": true,
  "process_id": 12345,
  "exit_code": 0,
  "memory_peak": 0,
  "terminated_by_limit": false,
  "sandbox_config": {
    "memory_limit_mb": 512,
    "timeout_ms": 30000,
    "restricted_privileges": true,
    "ui_restricted": true
  }
}
```

### sandbox_trace

サンドボックス内でプロセスを起動し、指定関数をトレース。

```json
{
  "name": "sandbox_trace",
  "inputSchema": {
    "type": "object",
    "properties": {
      "exe_path": { "type": "string" },
      "function_address": { "type": "string", "description": "0x140001000形式" },
      "args": { "type": "string" },
      "max_instructions": { "type": "integer", "default": 1000 },
      "memory_limit_mb": { "type": "integer", "default": 512 }
    },
    "required": ["exe_path", "function_address"]
  }
}
```

### analyze_with_trace（統合解析）

動的解析と静的解析を統合したワンストップ解析ツール。サンドボックスでプロセスを実行し、トレースと静的解析（デコンパイル、難読化検出）を同時に実行する。

```json
{
  "name": "analyze_with_trace",
  "inputSchema": {
    "type": "object",
    "properties": {
      "exe_path": { "type": "string", "description": "解析対象バイナリのパス" },
      "function_address": { "type": "string", "description": "解析開始アドレス（0x140001000形式）" },
      "args": { "type": "string", "description": "コマンドライン引数" },
      "max_instructions": { "type": "integer", "default": 500 },
      "memory_limit_mb": { "type": "integer", "default": 256 },
      "detect_obfuscation": { "type": "boolean", "default": true }
    },
    "required": ["exe_path", "function_address"]
  }
}
```

出力例:
```json
{
  "success": true,
  "function_address": "0x140017950",
  "dynamic_analysis": {
    "sandbox": {
      "process_id": 12345,
      "memory_limit_mb": 256,
      "exit_code": 0
    },
    "trace": {
      "success": true,
      "total_instructions": 150,
      "unique_addresses": 45,
      "execution_path": ["0x140017950", "0x140017955", "..."],
      "register_samples": [
        {"address": "0x140017950", "rax": "0x0", "rcx": "0x1", "rdx": "0x0", "rsp": "0x7FF..."}
      ]
    }
  },
  "static_analysis": {
    "success": true,
    "pcode_count": 237,
    "block_count": 8,
    "obfuscation": {
      "detected": true,
      "score": 0.37,
      "patterns": [{"type": "MBAExpression", "confidence": 0.8}],
      "mba_count": 2,
      "vm_count": 0
    }
  },
  "combined_insights": {
    "summary": [
      "実行された命令数: 150 (ユニーク: 45)",
      "検出された分岐: 12 回"
    ],
    "recommendation": "正常に解析完了"
  }
}
```

#### 解析フロー

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Phase 1        │     │  Phase 2        │     │  Phase 3        │
│  サンドボックス │ ──> │  静的解析       │ ──> │  統合インサイト │
│  + トレース     │     │  (P-code, CFG)  │     │  生成           │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

#### 推奨事項（recommendation）の種類

| 状態 | メッセージ |
|------|-----------|
| トレース失敗 | "トレース失敗 - 静的解析結果のみ参照可能" |
| 命令数少 | "トレース命令数が少ない - 開始アドレスまたはタイミングの調整を推奨" |
| 難読化検出 | "難読化検出 - 動的値を参考に手動解析を推奨" |
| 正常 | "正常に解析完了" |

## 制限事項

1. **ネットワーク制限**: Windowsファイアウォールとの連携が必要（未実装）
2. **低整合性レベル**: ConvertStringSidToSid が必要なため簡易実装
3. **メモリピーク取得**: TODO（QueryInformationJobObject実装予定）

## 使用例

### 基本的なサンドボックス実行

```rust
use kensho_mcp::dynamic_analysis::{SandboxConfig, SandboxedProcess};

let config = SandboxConfig {
    memory_limit: 256 * 1024 * 1024,  // 256MB
    process_limit: 1,
    restrict_ui: true,
    kill_on_close: true,
    ..Default::default()
};

let process = SandboxedProcess::spawn("target.exe", Some("--arg1"), config)?;
let result = process.wait(10000)?;  // 10秒待機

println!("Exit code: {}", result.exit_code);
```

### MCPツール経由

```json
{
  "method": "tools/call",
  "params": {
    "name": "run_in_sandbox",
    "arguments": {
      "exe_path": "C:\\path\\to\\suspicious.exe",
      "memory_limit_mb": 256,
      "timeout_ms": 10000
    }
  }
}
```

## セキュリティ考慮事項

- 特権剥奪により、管理者権限が必要な操作は失敗する
- Job Objectによりfork爆弾攻撃を防止
- メモリ制限によりメモリ枯渇攻撃を防止
- タイムアウトにより無限ループを強制終了
- UIアクセス制限によりクリップボード経由の情報漏洩を防止

## 今後の拡張

1. ファイルシステム仮想化（AppContainer連携）
2. ネットワーク隔離（Windows Firewall API連携）
3. レジストリ仮想化
4. プロセスメモリ使用量のリアルタイム監視
5. analyze_with_trace の改善:
   - ブレークポイントベースのトレース（より正確なタイミング制御）
   - 実行パスと静的CFGの比較分析
   - 動的値を使ったMBA式の実行時検証
