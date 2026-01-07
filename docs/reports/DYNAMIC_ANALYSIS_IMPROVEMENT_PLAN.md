# 動的解析強化計画

作成日: 2026-01-08
参照: x64dbg-development (TitanEngine)

## 現状の問題点

1. **アンチデバッグ対策なし** - IsDebuggerPresent等で即検出
2. **INT3ブレークポイントのみ** - 検出されやすい
3. **短命プロセス対応不足** - トレース前に終了
4. **保護バイナリに無力** - パック/VM保護を解除できない

## x64dbgから学んだ改善点

### 1. アンチデバッグ回避 (優先度: 高)

x64dbg/TitanEngine は `HideDebugger()` でPEB偽装を実装。

```rust
// 実装すべき機能
pub fn hide_debugger(process_handle: HANDLE) -> Result<()> {
    // 1. PEB.BeingDebugged を 0 に設定
    // 2. PEB.NtGlobalFlag をクリア (0x70 フラグ)
    // 3. ProcessHeap.Flags/ForceFlags を正常値に
}
```

**PEB構造体オフセット (x64):**
```
+0x002 BeingDebugged      : UChar
+0x0BC NtGlobalFlag       : Uint4B
+0x030 ProcessHeap        : Ptr64
  +0x070 Flags            : Uint4B
  +0x074 ForceFlags       : Uint4B
```

### 2. ハードウェアブレークポイント (優先度: 高)

DR0-DR7レジスタを使用。INT3より検出されにくい。

```rust
pub enum HardwareBreakpointType {
    Execute,     // DR7.R/W = 00
    Write,       // DR7.R/W = 01
    ReadWrite,   // DR7.R/W = 11
}

pub enum HardwareBreakpointSize {
    Byte1,   // DR7.LEN = 00
    Byte2,   // DR7.LEN = 01
    Byte4,   // DR7.LEN = 11
    Byte8,   // DR7.LEN = 10 (x64 only)
}

pub struct HardwareBreakpoint {
    address: u64,
    register: u8,  // 0-3 (DR0-DR3)
    bp_type: HardwareBreakpointType,
    size: HardwareBreakpointSize,
}

impl ProcessDebugger {
    pub fn set_hardware_breakpoint(&mut self, bp: HardwareBreakpoint) -> Result<()>;
    pub fn remove_hardware_breakpoint(&mut self, register: u8) -> Result<()>;
}
```

**DR7レジスタ構造:**
```
Bits 0-7:   L0, G0, L1, G1, L2, G2, L3, G3 (ローカル/グローバル有効化)
Bits 16-17: R/W0, LEN0 (DR0の条件とサイズ)
Bits 20-21: R/W1, LEN1
Bits 24-25: R/W2, LEN2
Bits 28-29: R/W3, LEN3
```

### 3. メモリブレークポイント (優先度: 中)

VirtualProtectで PAGE_GUARD を設定、STATUS_GUARD_PAGE_VIOLATION で検出。

```rust
pub struct MemoryBreakpoint {
    address: u64,
    size: usize,
    bp_type: MemoryBreakpointType,
    original_protection: u32,
}

pub enum MemoryBreakpointType {
    Read,
    Write,
    Execute,
    All,
}

impl ProcessDebugger {
    pub fn set_memory_breakpoint(&mut self, addr: u64, size: usize, bp_type: MemoryBreakpointType) -> Result<()>;
    pub fn remove_memory_breakpoint(&mut self, addr: u64) -> Result<()>;
}
```

### 4. トレース記録の改善 (優先度: 中)

x64dbg TraceRecord.cpp を参考に、効率的なトレース記録を実装。

```rust
pub enum TraceRecordType {
    BitExec,           // 1bit/命令 - 実行有無のみ
    ByteWithCounter,   // 1byte/命令 - 実行回数+タイプ
    FullContext,       // 完全レジスタダンプ
}

pub struct TraceRecordManager {
    pages: HashMap<u64, TraceRecordPage>,
    record_type: TraceRecordType,
}
```

### 5. NtQueryInformationProcess フック (優先度: 高)

ProcessDebugPort (0x7) クエリへの応答を偽装。

```rust
// アプローチ1: ブレークポイント + 戻り値改変
pub fn hook_ntquery_debug_port(&mut self) -> Result<()> {
    let ntdll = get_module_base("ntdll.dll")?;
    let ntquery = get_proc_address(ntdll, "NtQueryInformationProcess")?;
    self.set_breakpoint(ntquery)?;
    // ブレークポイントヒット時に ProcessInformationClass をチェック
    // ProcessDebugPort (7) なら戻り値を 0 に設定
}
```

## 実装優先順位

| 順位 | 機能 | 工数 | 効果 |
|------|------|------|------|
| 1 | PEB偽装 (BeingDebugged) | 小 | 大 |
| 2 | ハードウェアブレークポイント | 中 | 大 |
| 3 | NtGlobalFlag クリア | 小 | 中 |
| 4 | ProcessDebugPort フック | 中 | 大 |
| 5 | メモリブレークポイント | 中 | 中 |
| 6 | トレース記録改善 | 大 | 中 |

## Phase 1 実装計画 (PEB偽装)

### 必要なFFI定義

```rust
// src/dynamic_analysis/ffi/ntdll.rs
#[repr(C)]
pub struct PEB {
    pub inherited_address_space: BOOLEAN,
    pub read_image_file_exec_options: BOOLEAN,
    pub being_debugged: BOOLEAN,           // <- これを0に
    pub bit_field: BOOLEAN,
    pub mutant: HANDLE,
    pub image_base_address: PVOID,
    pub ldr: PVOID,
    pub process_parameters: PVOID,
    // ...
    pub nt_global_flag: ULONG,             // offset 0xBC (x64)
}

extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: PROCESSINFOCLASS,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
}

const ProcessBasicInformation: PROCESSINFOCLASS = 0;
```

### 実装コード

```rust
// src/dynamic_analysis/antidebug.rs

pub struct AntiAntiDebug {
    process_handle: HANDLE,
    peb_address: u64,
    original_being_debugged: u8,
    original_nt_global_flag: u32,
}

impl AntiAntiDebug {
    pub fn new(process_handle: HANDLE) -> Result<Self> {
        let peb_address = get_peb_address(process_handle)?;
        Ok(Self {
            process_handle,
            peb_address,
            original_being_debugged: 0,
            original_nt_global_flag: 0,
        })
    }

    /// デバッガの存在を隠蔽
    pub fn hide(&mut self) -> Result<()> {
        // 1. BeingDebugged を保存して 0 に設定
        let being_debugged_offset = 2u64;
        self.original_being_debugged = read_memory_byte(
            self.process_handle,
            self.peb_address + being_debugged_offset
        )?;
        write_memory_byte(
            self.process_handle,
            self.peb_address + being_debugged_offset,
            0
        )?;

        // 2. NtGlobalFlag をクリア (0x70 = FLG_HEAP_*)
        let nt_global_flag_offset = 0xBCu64; // x64
        self.original_nt_global_flag = read_memory_dword(
            self.process_handle,
            self.peb_address + nt_global_flag_offset
        )?;
        let cleaned_flag = self.original_nt_global_flag & !0x70;
        write_memory_dword(
            self.process_handle,
            self.peb_address + nt_global_flag_offset,
            cleaned_flag
        )?;

        Ok(())
    }

    /// 元の状態に復元
    pub fn restore(&self) -> Result<()> {
        write_memory_byte(
            self.process_handle,
            self.peb_address + 2,
            self.original_being_debugged
        )?;
        write_memory_dword(
            self.process_handle,
            self.peb_address + 0xBC,
            self.original_nt_global_flag
        )?;
        Ok(())
    }
}

fn get_peb_address(process_handle: HANDLE) -> Result<u64> {
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut return_length: ULONG = 0;

    let status = unsafe {
        NtQueryInformationProcess(
            process_handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as PVOID,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            &mut return_length,
        )
    };

    if !NT_SUCCESS(status) {
        return Err(anyhow!("NtQueryInformationProcess failed: {}", status));
    }

    Ok(pbi.peb_base_address as u64)
}
```

## MCPツール拡張

### hide_debugger ツール

```json
{
  "name": "hide_debugger",
  "description": "デバッガの存在を隠蔽（アンチデバッグ回避）",
  "inputSchema": {
    "type": "object",
    "properties": {
      "pid": { "type": "integer", "description": "対象プロセスID" },
      "level": {
        "type": "string",
        "enum": ["basic", "full"],
        "default": "basic",
        "description": "basic=PEB偽装のみ, full=ヒープフラグ等も含む"
      }
    },
    "required": ["pid"]
  }
}
```

### set_hardware_breakpoint ツール

```json
{
  "name": "set_hardware_breakpoint",
  "description": "ハードウェアブレークポイントを設定（INT3より検出されにくい）",
  "inputSchema": {
    "type": "object",
    "properties": {
      "pid": { "type": "integer" },
      "address": { "type": "string", "description": "0x形式のアドレス" },
      "type": {
        "type": "string",
        "enum": ["execute", "write", "readwrite"],
        "default": "execute"
      },
      "size": {
        "type": "integer",
        "enum": [1, 2, 4, 8],
        "default": 1
      },
      "register": {
        "type": "integer",
        "minimum": 0,
        "maximum": 3,
        "description": "使用するデバッグレジスタ (0-3)"
      }
    },
    "required": ["pid", "address"]
  }
}
```

## テスト計画

### アンチデバッグ検出テストバイナリ

```rust
// test_antidebug.rs
fn main() {
    // 1. IsDebuggerPresent
    if unsafe { IsDebuggerPresent() } != 0 {
        println!("Detected: IsDebuggerPresent");
        return;
    }

    // 2. PEB.BeingDebugged
    let peb = get_peb();
    if peb.being_debugged != 0 {
        println!("Detected: PEB.BeingDebugged");
        return;
    }

    // 3. NtGlobalFlag
    if (peb.nt_global_flag & 0x70) != 0 {
        println!("Detected: NtGlobalFlag");
        return;
    }

    // 4. CheckRemoteDebuggerPresent
    let mut debugger_present: BOOL = 0;
    if unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut debugger_present) } != 0 {
        if debugger_present != 0 {
            println!("Detected: CheckRemoteDebuggerPresent");
            return;
        }
    }

    println!("No debugger detected - executing payload");
    // ... 実際の処理
}
```

## 参考資料

- x64dbg TitanEngine: `src/dbg/TitanEngine/TitanEngine.h`
- x64dbg debugger: `src/dbg/debugger.cpp`
- x64dbg breakpoint: `src/dbg/breakpoint.cpp`
- Windows Internals - PEB構造体
- Anti-Debug Tricks: https://anti-debug.checkpoint.com/
