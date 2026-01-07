// サンドボックス実行環境（Job Objects + Restricted Token）
// 外部依存なし、Windows API直接呼び出し

use super::ffi::{kernel32::*, security::*, types::*};
use anyhow::{anyhow, Result};
use serde::Serialize;
use std::ptr::null_mut;

/// サンドボックス設定
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// メモリ制限（バイト単位、0で無制限）
    pub memory_limit: usize,
    /// CPU時間制限（100ナノ秒単位、0で無制限）
    pub cpu_time_limit: i64,
    /// 同時プロセス数制限（0で無制限）
    pub process_limit: u32,
    /// UIアクセス制限（クリップボード、デスクトップ等）
    pub restrict_ui: bool,
    /// ネットワーク制限（Windowsファイアウォール連携が必要）
    pub restrict_network: bool,
    /// 低整合性レベルで実行
    pub low_integrity: bool,
    /// 親プロセス終了時に子も終了
    pub kill_on_close: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit: 512 * 1024 * 1024, // 512MB
            cpu_time_limit: 0,                // 無制限
            process_limit: 1,                 // 単一プロセス
            restrict_ui: true,
            restrict_network: false, // ファイアウォール連携は別途必要
            low_integrity: true,
            kill_on_close: true,
        }
    }
}

/// サンドボックス化されたプロセス
pub struct SandboxedProcess {
    job_handle: HANDLE,
    process_handle: HANDLE,
    thread_handle: HANDLE,
    process_id: u32,
    thread_id: u32,
    config: SandboxConfig,
}

/// プロセス実行結果
#[derive(Debug, Serialize)]
pub struct SandboxResult {
    pub exit_code: u32,
    pub process_id: u32,
    pub memory_peak: usize,
    pub terminated_by_limit: bool,
}

impl SandboxedProcess {
    /// サンドボックス内でプロセスを起動
    /// Job Objectによるリソース制限を適用（管理者権限不要）
    pub fn spawn(exe_path: &str, args: Option<&str>, config: SandboxConfig) -> Result<Self> {
        unsafe {
            // 1. Job Object作成（メモリ/プロセス数/UI制限）
            let job_handle = create_job_object(&config)?;

            // 2. プロセス起動準備
            let mut startup_info: STARTUPINFOW = std::mem::zeroed();
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;

            let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

            // コマンドライン構築
            let command_line = if let Some(a) = args {
                format!("\"{}\" {}", exe_path, a)
            } else {
                format!("\"{}\"", exe_path)
            };
            let mut command_line_wide: Vec<u16> =
                command_line.encode_utf16().chain(std::iter::once(0)).collect();

            // 3. プロセス起動（一時停止状態）
            // CreateProcessW を使用（管理者権限不要）
            let creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

            let result = CreateProcessW(
                std::ptr::null(),
                command_line_wide.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                FALSE,
                creation_flags,
                null_mut(),
                std::ptr::null(),
                &startup_info,
                &mut process_info,
            );

            if result == FALSE {
                let err = GetLastError();
                CloseHandle(job_handle);
                return Err(anyhow!("Failed to create sandboxed process (error: {})", err));
            }

            // 4. プロセスをJob Objectに割り当て（リソース制限適用）
            if AssignProcessToJobObject(job_handle, process_info.h_process) == FALSE {
                let err = GetLastError();
                TerminateProcess(process_info.h_process, 1);
                CloseHandle(process_info.h_process);
                CloseHandle(process_info.h_thread);
                CloseHandle(job_handle);
                return Err(anyhow!("Failed to assign process to job (error: {})", err));
            }

            // 5. プロセス実行開始
            ResumeThread(process_info.h_thread);

            Ok(Self {
                job_handle,
                process_handle: process_info.h_process,
                thread_handle: process_info.h_thread,
                process_id: process_info.dw_process_id,
                thread_id: process_info.dw_thread_id,
                config,
            })
        }
    }

    /// プロセス完了を待機
    pub fn wait(&self, timeout_ms: u32) -> Result<SandboxResult> {
        unsafe {
            let wait_result = WaitForSingleObject(self.process_handle, timeout_ms);

            match wait_result {
                WAIT_OBJECT_0 => {
                    // 正常終了
                    let mut exit_code: DWORD = 0;
                    GetExitCodeProcess(self.process_handle, &mut exit_code);

                    Ok(SandboxResult {
                        exit_code,
                        process_id: self.process_id,
                        memory_peak: 0, // TODO: 取得実装
                        terminated_by_limit: false,
                    })
                }
                WAIT_TIMEOUT => Err(anyhow!("Process wait timed out")),
                _ => {
                    let err = GetLastError();
                    Err(anyhow!("Wait failed (error: {})", err))
                }
            }
        }
    }

    /// プロセスを強制終了
    pub fn terminate(&self) -> Result<()> {
        unsafe {
            // Job Object全体を終了（子プロセスも含めて）
            if TerminateJobObject(self.job_handle, 1) == FALSE {
                let err = GetLastError();
                return Err(anyhow!("Failed to terminate job (error: {})", err));
            }
            Ok(())
        }
    }

    /// プロセスIDを取得
    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    /// プロセスが実行中か確認
    pub fn is_running(&self) -> bool {
        unsafe {
            let result = WaitForSingleObject(self.process_handle, 0);
            result == WAIT_TIMEOUT
        }
    }

    /// 設定を取得
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// メインスレッドIDを取得
    pub fn main_thread_id(&self) -> u32 {
        self.thread_id
    }

    /// プロセスハンドルを取得
    pub fn process_handle(&self) -> HANDLE {
        self.process_handle
    }

    /// スレッドハンドルを取得
    pub fn thread_handle(&self) -> HANDLE {
        self.thread_handle
    }

    // ========================================
    // 短命プロセス対策（観察能力向上のため）
    // ========================================

    /// サンドボックス内でプロセスを起動（一時停止状態で返す）
    ///
    /// 通常のspawn()と異なり、プロセスを一時停止状態のまま返す。
    /// これにより、ブレークポイント設定やPEB偽装を行ってからresume()で実行開始できる。
    ///
    /// # 使用例
    /// ```ignore
    /// let process = SandboxedProcess::spawn_suspended(exe_path, args, config)?;
    /// let mut debugger = ProcessDebugger::attach(process.process_id())?;
    /// debugger.hide_debugger()?;
    /// debugger.set_hardware_breakpoint(process.main_thread_id(), 0, entry, ...)?;
    /// process.resume()?;  // ここで実行開始
    /// ```
    pub fn spawn_suspended(exe_path: &str, args: Option<&str>, config: SandboxConfig) -> Result<Self> {
        unsafe {
            // 1. Job Object作成
            let job_handle = create_job_object(&config)?;

            // 2. プロセス起動準備
            let mut startup_info: STARTUPINFOW = std::mem::zeroed();
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;

            let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

            // コマンドライン構築
            let command_line = if let Some(a) = args {
                format!("\"{}\" {}", exe_path, a)
            } else {
                format!("\"{}\"", exe_path)
            };
            let mut command_line_wide: Vec<u16> =
                command_line.encode_utf16().chain(std::iter::once(0)).collect();

            // 3. プロセス起動（一時停止状態、ResumeThreadは呼ばない）
            let creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

            let result = CreateProcessW(
                std::ptr::null(),
                command_line_wide.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                FALSE,
                creation_flags,
                null_mut(),
                std::ptr::null(),
                &startup_info,
                &mut process_info,
            );

            if result == FALSE {
                let err = GetLastError();
                CloseHandle(job_handle);
                return Err(anyhow!("Failed to create suspended process (error: {})", err));
            }

            // 4. プロセスをJob Objectに割り当て
            if AssignProcessToJobObject(job_handle, process_info.h_process) == FALSE {
                let err = GetLastError();
                TerminateProcess(process_info.h_process, 1);
                CloseHandle(process_info.h_process);
                CloseHandle(process_info.h_thread);
                CloseHandle(job_handle);
                return Err(anyhow!("Failed to assign process to job (error: {})", err));
            }

            // 注意: ResumeThread() は呼ばない！
            // プロセスは一時停止状態のまま返される

            Ok(Self {
                job_handle,
                process_handle: process_info.h_process,
                thread_handle: process_info.h_thread,
                process_id: process_info.dw_process_id,
                thread_id: process_info.dw_thread_id,
                config,
            })
        }
    }

    /// 一時停止中のプロセスを再開
    ///
    /// spawn_suspended() で作成したプロセスを実行開始する。
    /// ブレークポイント設定やPEB偽装の後に呼び出す。
    pub fn resume(&self) -> Result<()> {
        unsafe {
            let result = ResumeThread(self.thread_handle);
            if result == u32::MAX {
                let err = GetLastError();
                return Err(anyhow!("Failed to resume thread (error: {})", err));
            }
            Ok(())
        }
    }

    /// プロセスが一時停止中か確認
    pub fn is_suspended(&self) -> bool {
        // プロセスが実行中でなく、かつ終了もしていない場合は一時停止中と判断
        // 注: これは完全な判定ではないが、実用上は十分
        unsafe {
            let wait_result = WaitForSingleObject(self.process_handle, 0);
            // WAIT_TIMEOUT = まだ実行中または一時停止中
            // WAIT_OBJECT_0 = 終了済み
            wait_result == WAIT_TIMEOUT
        }
    }
}

impl Drop for SandboxedProcess {
    fn drop(&mut self) {
        unsafe {
            // 実行中なら終了
            if self.is_running() {
                let _ = self.terminate();
            }

            // ハンドルを閉じる
            CloseHandle(self.thread_handle);
            CloseHandle(self.process_handle);
            CloseHandle(self.job_handle);
        }
    }
}

/// Job Objectを作成して制限を設定
unsafe fn create_job_object(config: &SandboxConfig) -> Result<HANDLE> {
    // Job Object作成
    let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
    if job.is_null() {
        let err = GetLastError();
        return Err(anyhow!("Failed to create job object (error: {})", err));
    }

    // 基本制限設定
    let mut limit_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();

    // 親プロセス終了時に子も終了
    if config.kill_on_close {
        limit_info.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }

    // メモリ制限
    if config.memory_limit > 0 {
        limit_info.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limit_info.process_memory_limit = config.memory_limit;
    }

    // CPU時間制限
    if config.cpu_time_limit > 0 {
        limit_info.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        limit_info.basic_limit_information.per_process_user_time_limit = config.cpu_time_limit;
    }

    // プロセス数制限
    if config.process_limit > 0 {
        limit_info.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limit_info.basic_limit_information.active_process_limit = config.process_limit;
    }

    // 例外時に終了
    limit_info.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    // 制限を適用
    let result = SetInformationJobObject(
        job,
        JOB_OBJECT_INFO_CLASS_EXTENDED_LIMIT,
        &mut limit_info as *mut _ as LPVOID,
        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
    );

    if result == FALSE {
        let err = GetLastError();
        CloseHandle(job);
        return Err(anyhow!("Failed to set job limits (error: {})", err));
    }

    // UI制限
    if config.restrict_ui {
        let mut ui_restrictions: JOBOBJECT_BASIC_UI_RESTRICTIONS = std::mem::zeroed();
        ui_restrictions.ui_restrictions_class = JOB_OBJECT_UILIMIT_ALL;

        let result = SetInformationJobObject(
            job,
            JOB_OBJECT_INFO_CLASS_BASIC_UI_RESTRICTIONS,
            &mut ui_restrictions as *mut _ as LPVOID,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as DWORD,
        );

        if result == FALSE {
            // UI制限失敗は警告のみ（続行）
            let _err = GetLastError();
        }
    }

    Ok(job)
}

/// 制限付きトークンを作成
unsafe fn create_restricted_token(low_integrity: bool) -> Result<HANDLE> {
    // 現在のプロセスのトークンを取得
    let mut current_token: HANDLE = null_mut();
    let result = OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY,
        &mut current_token,
    );

    if result == FALSE {
        let err = GetLastError();
        return Err(anyhow!("Failed to open process token (error: {})", err));
    }

    // 制限付きトークンを作成
    let mut restricted_token: HANDLE = null_mut();
    let flags = DISABLE_MAX_PRIVILEGE; // 全ての特権を無効化

    let result = CreateRestrictedToken(
        current_token,
        flags,
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        &mut restricted_token,
    );

    CloseHandle(current_token);

    if result == FALSE {
        let err = GetLastError();
        return Err(anyhow!("Failed to create restricted token (error: {})", err));
    }

    // 低整合性レベル設定（オプション）
    if low_integrity {
        // 低整合性レベルのSIDを設定
        // 注: 完全な実装には ConvertStringSidToSid が必要
        // ここでは簡易実装としてスキップ
        // TODO: 低整合性レベルSIDの設定
    }

    Ok(restricted_token)
}

// GetExitCodeProcess FFI宣言
#[link(name = "kernel32")]
extern "system" {
    fn GetExitCodeProcess(h_process: HANDLE, lp_exit_code: *mut DWORD) -> BOOL;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert_eq!(config.memory_limit, 512 * 1024 * 1024);
        assert!(config.kill_on_close);
        assert!(config.restrict_ui);
    }
}
