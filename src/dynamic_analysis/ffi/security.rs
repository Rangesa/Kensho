// Windows Security API FFI定義（Job Object, Token関連）

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use super::types::*;

// ============================================================================
// Token関連の型定義
// ============================================================================

pub type PSID = *mut std::ffi::c_void;
pub type LUID = u64;

#[repr(C)]
pub struct TOKEN_PRIVILEGES {
    pub privilege_count: DWORD,
    pub privileges: [LUID_AND_ATTRIBUTES; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LUID_AND_ATTRIBUTES {
    pub luid: LUID,
    pub attributes: DWORD,
}

#[repr(C)]
pub struct SID_AND_ATTRIBUTES {
    pub sid: PSID,
    pub attributes: DWORD,
}

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub n_length: DWORD,
    pub lp_security_descriptor: LPVOID,
    pub b_inherit_handle: BOOL,
}

#[repr(C)]
pub struct STARTUPINFOW {
    pub cb: DWORD,
    pub lp_reserved: *mut u16,
    pub lp_desktop: *mut u16,
    pub lp_title: *mut u16,
    pub dw_x: DWORD,
    pub dw_y: DWORD,
    pub dw_x_size: DWORD,
    pub dw_y_size: DWORD,
    pub dw_x_count_chars: DWORD,
    pub dw_y_count_chars: DWORD,
    pub dw_fill_attribute: DWORD,
    pub dw_flags: DWORD,
    pub w_show_window: u16,
    pub cb_reserved2: u16,
    pub lp_reserved2: *mut u8,
    pub h_std_input: HANDLE,
    pub h_std_output: HANDLE,
    pub h_std_error: HANDLE,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub h_process: HANDLE,
    pub h_thread: HANDLE,
    pub dw_process_id: DWORD,
    pub dw_thread_id: DWORD,
}

// ============================================================================
// Job Object関連の型定義
// ============================================================================

#[repr(C)]
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

#[repr(C)]
pub struct IO_COUNTERS {
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_count: u64,
    pub write_transfer_count: u64,
    pub other_transfer_count: u64,
}

#[repr(C)]
pub struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    pub basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    pub io_info: IO_COUNTERS,
    pub process_memory_limit: SIZE_T,
    pub job_memory_limit: SIZE_T,
    pub peak_process_memory_used: SIZE_T,
    pub peak_job_memory_used: SIZE_T,
}

#[repr(C)]
pub struct JOBOBJECT_BASIC_UI_RESTRICTIONS {
    pub ui_restrictions_class: DWORD,
}

// Job Object Information Class
pub const JOB_OBJECT_INFO_CLASS_BASIC_LIMIT: DWORD = 2;
pub const JOB_OBJECT_INFO_CLASS_EXTENDED_LIMIT: DWORD = 9;
pub const JOB_OBJECT_INFO_CLASS_BASIC_UI_RESTRICTIONS: DWORD = 4;

// Job Object Limit Flags
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x00002000;
pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY: DWORD = 0x00000100;
pub const JOB_OBJECT_LIMIT_JOB_MEMORY: DWORD = 0x00000200;
pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: DWORD = 0x00000008;
pub const JOB_OBJECT_LIMIT_PROCESS_TIME: DWORD = 0x00000002;
pub const JOB_OBJECT_LIMIT_PRIORITY_CLASS: DWORD = 0x00000020;
pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: DWORD = 0x00000400;
pub const JOB_OBJECT_LIMIT_BREAKAWAY_OK: DWORD = 0x00000800;

// UI Restrictions
pub const JOB_OBJECT_UILIMIT_DESKTOP: DWORD = 0x00000040;
pub const JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: DWORD = 0x00000010;
pub const JOB_OBJECT_UILIMIT_EXITWINDOWS: DWORD = 0x00000080;
pub const JOB_OBJECT_UILIMIT_GLOBALATOMS: DWORD = 0x00000020;
pub const JOB_OBJECT_UILIMIT_HANDLES: DWORD = 0x00000001;
pub const JOB_OBJECT_UILIMIT_READCLIPBOARD: DWORD = 0x00000002;
pub const JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: DWORD = 0x00000008;
pub const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: DWORD = 0x00000004;
pub const JOB_OBJECT_UILIMIT_ALL: DWORD = 0x000000FF;

// Token関連定数
pub const TOKEN_DUPLICATE: DWORD = 0x0002;
pub const TOKEN_QUERY: DWORD = 0x0008;
pub const TOKEN_ADJUST_DEFAULT: DWORD = 0x0080;
pub const TOKEN_ADJUST_SESSIONID: DWORD = 0x0100;
pub const TOKEN_ASSIGN_PRIMARY: DWORD = 0x0001;
pub const TOKEN_ALL_ACCESS: DWORD = 0xF01FF;

pub const DISABLE_MAX_PRIVILEGE: DWORD = 0x1;
pub const SANDBOX_INERT: DWORD = 0x2;
pub const LUA_TOKEN: DWORD = 0x4;
pub const WRITE_RESTRICTED: DWORD = 0x8;

pub const SECURITY_MANDATORY_UNTRUSTED_RID: DWORD = 0x00000000;
pub const SECURITY_MANDATORY_LOW_RID: DWORD = 0x00001000;
pub const SECURITY_MANDATORY_MEDIUM_RID: DWORD = 0x00002000;

// Process Creation Flags
pub const CREATE_NEW_CONSOLE: DWORD = 0x00000010;
pub const CREATE_NO_WINDOW: DWORD = 0x08000000;
pub const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x00000400;
pub const EXTENDED_STARTUPINFO_PRESENT: DWORD = 0x00080000;

// ============================================================================
// FFI関数宣言
// ============================================================================

#[link(name = "kernel32")]
extern "system" {
    pub fn CreateJobObjectW(
        lp_job_attributes: *const SECURITY_ATTRIBUTES,
        lp_name: *const u16,
    ) -> HANDLE;

    pub fn SetInformationJobObject(
        h_job: HANDLE,
        job_object_information_class: DWORD,
        lp_job_object_information: LPVOID,
        cb_job_object_information_length: DWORD,
    ) -> BOOL;

    pub fn AssignProcessToJobObject(h_job: HANDLE, h_process: HANDLE) -> BOOL;

    pub fn CreateProcessW(
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *const SECURITY_ATTRIBUTES,
        lp_thread_attributes: *const SECURITY_ATTRIBUTES,
        b_inherit_handles: BOOL,
        dw_creation_flags: DWORD,
        lp_environment: LPVOID,
        lp_current_directory: *const u16,
        lp_startup_info: *const STARTUPINFOW,
        lp_process_information: *mut PROCESS_INFORMATION,
    ) -> BOOL;

    pub fn TerminateJobObject(h_job: HANDLE, u_exit_code: u32) -> BOOL;

    pub fn WaitForSingleObject(h_handle: HANDLE, dw_milliseconds: DWORD) -> DWORD;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn OpenProcessToken(
        process_handle: HANDLE,
        desired_access: DWORD,
        token_handle: *mut HANDLE,
    ) -> BOOL;

    pub fn DuplicateTokenEx(
        h_existing_token: HANDLE,
        dw_desired_access: DWORD,
        lp_token_attributes: *const SECURITY_ATTRIBUTES,
        impersonation_level: DWORD,
        token_type: DWORD,
        ph_new_token: *mut HANDLE,
    ) -> BOOL;

    pub fn CreateRestrictedToken(
        existing_token_handle: HANDLE,
        flags: DWORD,
        disable_sid_count: DWORD,
        sids_to_disable: *const SID_AND_ATTRIBUTES,
        delete_privilege_count: DWORD,
        privileges_to_delete: *const LUID_AND_ATTRIBUTES,
        restricted_sid_count: DWORD,
        sids_to_restrict: *const SID_AND_ATTRIBUTES,
        new_token_handle: *mut HANDLE,
    ) -> BOOL;

    pub fn CreateProcessAsUserW(
        h_token: HANDLE,
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *const SECURITY_ATTRIBUTES,
        lp_thread_attributes: *const SECURITY_ATTRIBUTES,
        b_inherit_handles: BOOL,
        dw_creation_flags: DWORD,
        lp_environment: LPVOID,
        lp_current_directory: *const u16,
        lp_startup_info: *const STARTUPINFOW,
        lp_process_information: *mut PROCESS_INFORMATION,
    ) -> BOOL;

    pub fn SetTokenInformation(
        token_handle: HANDLE,
        token_information_class: DWORD,
        token_information: LPVOID,
        token_information_length: DWORD,
    ) -> BOOL;

    pub fn GetTokenInformation(
        token_handle: HANDLE,
        token_information_class: DWORD,
        token_information: LPVOID,
        token_information_length: DWORD,
        return_length: *mut DWORD,
    ) -> BOOL;
}

// Token Information Class
pub const TOKEN_INFORMATION_CLASS_INTEGRITY_LEVEL: DWORD = 25;

// Security Impersonation Level
pub const SECURITY_IMPERSONATION: DWORD = 2;

// Token Type
pub const TOKEN_PRIMARY: DWORD = 1;

// Wait結果
pub const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_TIMEOUT: DWORD = 258;
pub const WAIT_FAILED: DWORD = 0xFFFFFFFF;

// GetCurrentProcess
#[link(name = "kernel32")]
extern "system" {
    pub fn GetCurrentProcess() -> HANDLE;
}
