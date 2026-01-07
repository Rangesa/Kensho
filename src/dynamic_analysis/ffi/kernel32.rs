// kernel32.dll FFI宣言（外部依存なし）

use super::types::*;

#[link(name = "kernel32")]
extern "system" {
    // プロセス管理
    pub fn OpenProcess(
        dw_desired_access: DWORD,
        b_inherit_handle: BOOL,
        dw_process_id: DWORD,
    ) -> HANDLE;

    pub fn CloseHandle(h_object: HANDLE) -> BOOL;

    pub fn TerminateProcess(h_process: HANDLE, u_exit_code: u32) -> BOOL;

    // メモリ操作
    pub fn ReadProcessMemory(
        h_process: HANDLE,
        lp_base_address: LPCVOID,
        lp_buffer: LPVOID,
        n_size: SIZE_T,
        lp_number_of_bytes_read: *mut SIZE_T,
    ) -> BOOL;

    pub fn WriteProcessMemory(
        h_process: HANDLE,
        lp_base_address: LPVOID,
        lp_buffer: LPCVOID,
        n_size: SIZE_T,
        lp_number_of_bytes_written: *mut SIZE_T,
    ) -> BOOL;

    pub fn VirtualProtectEx(
        h_process: HANDLE,
        lp_address: LPVOID,
        dw_size: SIZE_T,
        fl_new_protect: DWORD,
        lp_fl_old_protect: *mut DWORD,
    ) -> BOOL;

    pub fn VirtualQueryEx(
        h_process: HANDLE,
        lp_address: LPCVOID,
        lp_buffer: LPVOID,
        dw_length: SIZE_T,
    ) -> SIZE_T;

    // デバッグAPI
    pub fn DebugActiveProcess(dw_process_id: DWORD) -> BOOL;

    pub fn DebugActiveProcessStop(dw_process_id: DWORD) -> BOOL;

    pub fn WaitForDebugEvent(lp_debug_event: *mut DEBUG_EVENT, dw_milliseconds: DWORD) -> BOOL;

    pub fn ContinueDebugEvent(
        dw_process_id: DWORD,
        dw_thread_id: DWORD,
        dw_continue_status: DWORD,
    ) -> BOOL;

    pub fn DebugSetProcessKillOnExit(kill_on_exit: BOOL) -> BOOL;

    // スレッド操作
    pub fn OpenThread(
        dw_desired_access: DWORD,
        b_inherit_handle: BOOL,
        dw_thread_id: DWORD,
    ) -> HANDLE;

    pub fn SuspendThread(h_thread: HANDLE) -> DWORD;

    pub fn ResumeThread(h_thread: HANDLE) -> DWORD;

    pub fn GetThreadContext(h_thread: HANDLE, lp_context: *mut CONTEXT) -> BOOL;

    pub fn SetThreadContext(h_thread: HANDLE, lp_context: *const CONTEXT) -> BOOL;

    // エラー取得
    pub fn GetLastError() -> DWORD;

    pub fn SetLastError(dw_err_code: DWORD);

    // プロセス作成（デバッグモード用）
    pub fn CreateProcessA(
        lp_application_name: LPCSTR,
        lp_command_line: LPSTR,
        lp_process_attributes: LPVOID,
        lp_thread_attributes: LPVOID,
        b_inherit_handles: BOOL,
        dw_creation_flags: DWORD,
        lp_environment: LPVOID,
        lp_current_directory: LPCSTR,
        lp_startup_info: LPVOID,
        lp_process_information: LPVOID,
    ) -> BOOL;
}

// メモリ保護フラグ
pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_WRITECOPY: DWORD = 0x08;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;

// プロセス作成フラグ
pub const DEBUG_PROCESS: DWORD = 0x00000001;
pub const DEBUG_ONLY_THIS_PROCESS: DWORD = 0x00000002;
pub const CREATE_SUSPENDED: DWORD = 0x00000004;

// エラーコード
pub const ERROR_INVALID_HANDLE: DWORD = 6;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_PARTIAL_COPY: DWORD = 299;
