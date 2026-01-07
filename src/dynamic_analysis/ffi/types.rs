// Windows API FFI型定義（外部依存なし）

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::c_void;

// 基本型定義
pub type HANDLE = *mut c_void;
pub type DWORD = u32;
pub type WORD = u16;
pub type BYTE = u8;
pub type LPVOID = *mut c_void;
pub type LPCVOID = *const c_void;
pub type SIZE_T = usize;
pub type BOOL = i32;
pub type LPSTR = *mut u8;
pub type LPCSTR = *const u8;
pub type ULONG_PTR = usize;
pub type DWORD64 = u64;

// x86-64 CONTEXT構造体（Windows 64-bit）
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CONTEXT {
    // Register parameter home addresses
    pub p1_home: DWORD64,
    pub p2_home: DWORD64,
    pub p3_home: DWORD64,
    pub p4_home: DWORD64,
    pub p5_home: DWORD64,
    pub p6_home: DWORD64,

    // Control flags
    pub context_flags: DWORD,
    pub mx_csr: DWORD,

    // Segment Registers
    pub seg_cs: WORD,
    pub seg_ds: WORD,
    pub seg_es: WORD,
    pub seg_fs: WORD,
    pub seg_gs: WORD,
    pub seg_ss: WORD,
    pub e_flags: DWORD,

    // Debug registers
    pub dr0: DWORD64,
    pub dr1: DWORD64,
    pub dr2: DWORD64,
    pub dr3: DWORD64,
    pub dr6: DWORD64,
    pub dr7: DWORD64,

    // Integer registers
    pub rax: DWORD64,
    pub rcx: DWORD64,
    pub rdx: DWORD64,
    pub rbx: DWORD64,
    pub rsp: DWORD64,
    pub rbp: DWORD64,
    pub rsi: DWORD64,
    pub rdi: DWORD64,
    pub r8: DWORD64,
    pub r9: DWORD64,
    pub r10: DWORD64,
    pub r11: DWORD64,
    pub r12: DWORD64,
    pub r13: DWORD64,
    pub r14: DWORD64,
    pub r15: DWORD64,

    // Program counter
    pub rip: DWORD64,

    // Floating point state
    pub floating_save: [BYTE; 512],

    // Vector registers
    pub vector_register: [M128A; 26],
    pub vector_control: DWORD64,

    // Special debug control registers
    pub debug_control: DWORD64,
    pub last_branch_to_rip: DWORD64,
    pub last_branch_from_rip: DWORD64,
    pub last_exception_to_rip: DWORD64,
    pub last_exception_from_rip: DWORD64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct M128A {
    pub low: u64,
    pub high: i64,
}

impl Default for CONTEXT {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// デバッグイベント構造体
#[repr(C)]
pub struct DEBUG_EVENT {
    pub dw_debug_event_code: DWORD,
    pub dw_process_id: DWORD,
    pub dw_thread_id: DWORD,
    pub u: DebugEventUnion,
}

#[repr(C)]
pub union DebugEventUnion {
    pub exception: EXCEPTION_DEBUG_INFO,
    pub create_thread: CREATE_THREAD_DEBUG_INFO,
    pub create_process_info: CREATE_PROCESS_DEBUG_INFO,
    pub exit_thread: EXIT_THREAD_DEBUG_INFO,
    pub exit_process: EXIT_PROCESS_DEBUG_INFO,
    pub load_dll: LOAD_DLL_DEBUG_INFO,
    pub unload_dll: UNLOAD_DLL_DEBUG_INFO,
    pub debug_string: OUTPUT_DEBUG_STRING_INFO,
    pub rip_info: RIP_INFO,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXCEPTION_DEBUG_INFO {
    pub exception_record: EXCEPTION_RECORD,
    pub dw_first_chance: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXCEPTION_RECORD {
    pub exception_code: DWORD,
    pub exception_flags: DWORD,
    pub exception_record: *mut EXCEPTION_RECORD,
    pub exception_address: LPVOID,
    pub number_parameters: DWORD,
    pub exception_information: [ULONG_PTR; 15],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CREATE_THREAD_DEBUG_INFO {
    pub h_thread: HANDLE,
    pub lp_thread_local_base: LPVOID,
    pub lp_start_address: LPVOID,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CREATE_PROCESS_DEBUG_INFO {
    pub h_file: HANDLE,
    pub h_process: HANDLE,
    pub h_thread: HANDLE,
    pub lp_base_of_image: LPVOID,
    pub dw_debug_info_file_offset: DWORD,
    pub n_debug_info_size: DWORD,
    pub lp_thread_local_base: LPVOID,
    pub lp_start_address: LPVOID,
    pub lp_image_name: LPVOID,
    pub f_unicode: WORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXIT_THREAD_DEBUG_INFO {
    pub dw_exit_code: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXIT_PROCESS_DEBUG_INFO {
    pub dw_exit_code: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LOAD_DLL_DEBUG_INFO {
    pub h_file: HANDLE,
    pub lp_base_of_dll: LPVOID,
    pub dw_debug_info_file_offset: DWORD,
    pub n_debug_info_size: DWORD,
    pub lp_image_name: LPVOID,
    pub f_unicode: WORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNLOAD_DLL_DEBUG_INFO {
    pub lp_base_of_dll: LPVOID,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OUTPUT_DEBUG_STRING_INFO {
    pub lp_debug_string_data: LPSTR,
    pub f_unicode: WORD,
    pub n_debug_string_length: WORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RIP_INFO {
    pub dw_error: DWORD,
    pub dw_type: DWORD,
}

// 定数定義
pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

// Process access rights
pub const PROCESS_TERMINATE: DWORD = 0x0001;
pub const PROCESS_CREATE_THREAD: DWORD = 0x0002;
pub const PROCESS_VM_OPERATION: DWORD = 0x0008;
pub const PROCESS_VM_READ: DWORD = 0x0010;
pub const PROCESS_VM_WRITE: DWORD = 0x0020;
pub const PROCESS_DUP_HANDLE: DWORD = 0x0040;
pub const PROCESS_CREATE_PROCESS: DWORD = 0x0080;
pub const PROCESS_SET_QUOTA: DWORD = 0x0100;
pub const PROCESS_SET_INFORMATION: DWORD = 0x0200;
pub const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
pub const PROCESS_SUSPEND_RESUME: DWORD = 0x0800;
pub const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
pub const PROCESS_ALL_ACCESS: DWORD = 0x1F0FFF;

// Debug event codes
pub const EXCEPTION_DEBUG_EVENT: DWORD = 1;
pub const CREATE_THREAD_DEBUG_EVENT: DWORD = 2;
pub const CREATE_PROCESS_DEBUG_EVENT: DWORD = 3;
pub const EXIT_THREAD_DEBUG_EVENT: DWORD = 4;
pub const EXIT_PROCESS_DEBUG_EVENT: DWORD = 5;
pub const LOAD_DLL_DEBUG_EVENT: DWORD = 6;
pub const UNLOAD_DLL_DEBUG_EVENT: DWORD = 7;
pub const OUTPUT_DEBUG_STRING_EVENT: DWORD = 8;
pub const RIP_EVENT: DWORD = 9;

// Exception codes
pub const EXCEPTION_ACCESS_VIOLATION: DWORD = 0xC0000005;
pub const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;
pub const EXCEPTION_SINGLE_STEP: DWORD = 0x80000004;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: DWORD = 0xC000001D;

// Debug continue status
pub const DBG_CONTINUE: DWORD = 0x00010002;
pub const DBG_EXCEPTION_NOT_HANDLED: DWORD = 0x80010001;

// Context flags
pub const CONTEXT_AMD64: DWORD = 0x00100000;
pub const CONTEXT_CONTROL: DWORD = CONTEXT_AMD64 | 0x00000001;
pub const CONTEXT_INTEGER: DWORD = CONTEXT_AMD64 | 0x00000002;
pub const CONTEXT_SEGMENTS: DWORD = CONTEXT_AMD64 | 0x00000004;
pub const CONTEXT_FLOATING_POINT: DWORD = CONTEXT_AMD64 | 0x00000008;
pub const CONTEXT_DEBUG_REGISTERS: DWORD = CONTEXT_AMD64 | 0x00000010;
pub const CONTEXT_FULL: DWORD = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
pub const CONTEXT_ALL: DWORD = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

// Thread access rights
pub const THREAD_TERMINATE: DWORD = 0x0001;
pub const THREAD_SUSPEND_RESUME: DWORD = 0x0002;
pub const THREAD_GET_CONTEXT: DWORD = 0x0008;
pub const THREAD_SET_CONTEXT: DWORD = 0x0010;
pub const THREAD_QUERY_INFORMATION: DWORD = 0x0040;
pub const THREAD_SET_INFORMATION: DWORD = 0x0020;
pub const THREAD_SET_THREAD_TOKEN: DWORD = 0x0080;
pub const THREAD_IMPERSONATE: DWORD = 0x0100;
pub const THREAD_DIRECT_IMPERSONATION: DWORD = 0x0200;
pub const THREAD_ALL_ACCESS: DWORD = 0x1F03FF;
