// ntdll.dll FFI定義（PEB操作、アンチデバッグ回避用）

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use super::types::*;
use std::ffi::c_void;

/// PROCESS_BASIC_INFORMATION構造体
/// NtQueryInformationProcess(ProcessBasicInformation)で取得
#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION {
    pub exit_status: i32,
    pub peb_base_address: *mut c_void,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
}

/// ProcessInformationClass定数
pub const PROCESS_BASIC_INFORMATION_CLASS: DWORD = 0;

/// NTSTATUS成功判定マクロ相当
pub fn nt_success(status: i32) -> bool {
    status >= 0
}

#[link(name = "ntdll")]
extern "system" {
    /// プロセス情報を取得
    ///
    /// ProcessBasicInformation (0) でPebBaseAddressを取得可能
    pub fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: DWORD,
        process_information: LPVOID,
        process_information_length: DWORD,
        return_length: *mut DWORD,
    ) -> i32; // NTSTATUS
}

// PEB構造体オフセット（x64）
// 完全な構造体は巨大なため、必要なオフセットのみ定義

/// PEB.BeingDebugged のオフセット（x64: +0x02）
pub const PEB_BEING_DEBUGGED_OFFSET: u64 = 0x02;

/// PEB.NtGlobalFlag のオフセット（x64: +0xBC）
pub const PEB_NT_GLOBAL_FLAG_OFFSET: u64 = 0xBC;

/// NtGlobalFlag のデバッグ関連フラグ
/// FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
pub const NT_GLOBAL_FLAG_DEBUGGER_FLAGS: u32 = 0x70;
