// プロセスデバッガ（Windows Debug API使用、外部依存なし）

use super::ffi::{kernel32::*, types::*};
use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// ハードウェアブレークポイントの条件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwBreakpointCondition {
    /// 実行時にブレーク (R/W = 00)
    Execute = 0b00,
    /// データ書き込み時にブレーク (R/W = 01)
    DataWrite = 0b01,
    /// データ読み書き時にブレーク (R/W = 11)
    DataReadWrite = 0b11,
}

/// ハードウェアブレークポイントのサイズ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwBreakpointSize {
    /// 1バイト (LEN = 00)
    Byte1 = 0b00,
    /// 2バイト (LEN = 01)
    Byte2 = 0b01,
    /// 4バイト (LEN = 11)
    Byte4 = 0b11,
    /// 8バイト (LEN = 10) - x64専用
    Byte8 = 0b10,
}

pub struct ProcessDebugger {
    process_id: u32,
    process_handle: HANDLE,
    thread_handles: HashMap<u32, HANDLE>,
    attached: bool,
    breakpoints: HashMap<u64, u8>, // address -> original byte
}

impl ProcessDebugger {
    /// 既存プロセスにアタッチ
    pub fn attach(pid: u32) -> Result<Self> {
        unsafe {
            // プロセスハンドルを取得
            let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if handle.is_null() {
                let err = GetLastError();
                return Err(anyhow!(
                    "Failed to open process {} (error code: {})",
                    pid,
                    err
                ));
            }

            // デバッガとしてアタッチ
            if DebugActiveProcess(pid) == FALSE {
                let err = GetLastError();
                CloseHandle(handle);
                return Err(anyhow!(
                    "Failed to attach debugger to PID {} (error code: {})",
                    pid,
                    err
                ));
            }

            // プロセス終了時にデバッギーを殺さない設定
            DebugSetProcessKillOnExit(FALSE);

            Ok(Self {
                process_id: pid,
                process_handle: handle,
                thread_handles: HashMap::new(),
                attached: true,
                breakpoints: HashMap::new(),
            })
        }
    }

    /// デタッチ
    pub fn detach(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }

        unsafe {
            // 全てのブレークポイントを復元
            let breakpoints: Vec<_> = self.breakpoints.drain().collect();
            for (addr, original_byte) in breakpoints {
                let _ = self.write_memory(addr, &[original_byte]);
            }

            // デバッガを切断
            if DebugActiveProcessStop(self.process_id) == FALSE {
                let err = GetLastError();
                return Err(anyhow!(
                    "Failed to detach from PID {} (error code: {})",
                    self.process_id,
                    err
                ));
            }

            self.attached = false;
        }

        Ok(())
    }

    /// メモリ読み込み
    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read: SIZE_T = 0;

        unsafe {
            let success = ReadProcessMemory(
                self.process_handle,
                address as LPCVOID,
                buffer.as_mut_ptr() as LPVOID,
                size,
                &mut bytes_read,
            );

            if success == FALSE {
                let err = GetLastError();
                return Err(anyhow!(
                    "Failed to read memory at 0x{:X} (error code: {})",
                    address,
                    err
                ));
            }
        }

        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    /// メモリ書き込み
    pub fn write_memory(&self, address: u64, data: &[u8]) -> Result<()> {
        let mut bytes_written: SIZE_T = 0;

        unsafe {
            let success = WriteProcessMemory(
                self.process_handle,
                address as LPVOID,
                data.as_ptr() as LPCVOID,
                data.len(),
                &mut bytes_written,
            );

            if success == FALSE || bytes_written != data.len() {
                let err = GetLastError();
                return Err(anyhow!(
                    "Failed to write memory at 0x{:X} (error code: {})",
                    address,
                    err
                ));
            }
        }

        Ok(())
    }

    /// ブレークポイントを設定
    pub fn set_breakpoint(&mut self, address: u64) -> Result<()> {
        if self.breakpoints.contains_key(&address) {
            return Ok(()); // 既に設定済み
        }

        // 元の命令（1バイト）を保存
        let original_byte = self.read_memory(address, 1)?[0];

        // 0xCC（INT3）ブレークポイント命令を書き込み
        self.write_memory(address, &[0xCC])?;

        self.breakpoints.insert(address, original_byte);
        Ok(())
    }

    /// ブレークポイントを削除
    pub fn remove_breakpoint(&mut self, address: u64) -> Result<()> {
        if let Some(original_byte) = self.breakpoints.remove(&address) {
            self.write_memory(address, &[original_byte])?;
        }
        Ok(())
    }

    /// ブレークポイントを一時的に復元（シングルステップ用）
    pub fn restore_breakpoint_temporary(&self, address: u64) -> Result<()> {
        if let Some(&original_byte) = self.breakpoints.get(&address) {
            self.write_memory(address, &[original_byte])?;
        }
        Ok(())
    }

    /// ブレークポイントを再設定
    pub fn reapply_breakpoint(&self, address: u64) -> Result<()> {
        if self.breakpoints.contains_key(&address) {
            self.write_memory(address, &[0xCC])?;
        }
        Ok(())
    }

    /// デバッグイベントを待機
    pub fn wait_for_event(&mut self, timeout_ms: u32) -> Result<DEBUG_EVENT> {
        unsafe {
            let mut event: DEBUG_EVENT = std::mem::zeroed();

            if WaitForDebugEvent(&mut event, timeout_ms) == FALSE {
                let err = GetLastError();
                return Err(anyhow!("WaitForDebugEvent failed (error code: {})", err));
            }

            // スレッドハンドルを記録
            if event.dw_debug_event_code == CREATE_THREAD_DEBUG_EVENT {
                let info = event.u.create_thread;
                self.thread_handles
                    .insert(event.dw_thread_id, info.h_thread);
            } else if event.dw_debug_event_code == CREATE_PROCESS_DEBUG_EVENT {
                let info = event.u.create_process_info;
                self.thread_handles
                    .insert(event.dw_thread_id, info.h_thread);
            }

            Ok(event)
        }
    }

    /// デバッグイベントの処理を継続
    pub fn continue_event(&self, event: &DEBUG_EVENT, status: DWORD) -> Result<()> {
        unsafe {
            if ContinueDebugEvent(event.dw_process_id, event.dw_thread_id, status) == FALSE {
                let err = GetLastError();
                return Err(anyhow!("ContinueDebugEvent failed (error code: {})", err));
            }
        }
        Ok(())
    }

    /// スレッドコンテキストを取得
    pub fn get_thread_context(&self, thread_id: u32) -> Result<CONTEXT> {
        let thread_handle = self
            .thread_handles
            .get(&thread_id)
            .ok_or_else(|| anyhow!("Thread {} not found", thread_id))?;

        unsafe {
            let mut context = CONTEXT::default();
            context.context_flags = CONTEXT_ALL;

            if GetThreadContext(*thread_handle, &mut context) == FALSE {
                let err = GetLastError();
                return Err(anyhow!(
                    "Failed to get thread context (error code: {})",
                    err
                ));
            }

            Ok(context)
        }
    }

    /// スレッドコンテキストを設定
    pub fn set_thread_context(&self, thread_id: u32, context: &CONTEXT) -> Result<()> {
        let thread_handle = self
            .thread_handles
            .get(&thread_id)
            .ok_or_else(|| anyhow!("Thread {} not found", thread_id))?;

        unsafe {
            if SetThreadContext(*thread_handle, context) == FALSE {
                let err = GetLastError();
                return Err(anyhow!(
                    "Failed to set thread context (error code: {})",
                    err
                ));
            }
        }

        Ok(())
    }

    /// シングルステップフラグを有効化
    pub fn enable_single_step(&self, thread_id: u32) -> Result<()> {
        let mut context = self.get_thread_context(thread_id)?;

        // Trap Flag (EFLAGS.TF = bit 8) をセット
        context.e_flags |= 0x100;

        self.set_thread_context(thread_id, &context)?;
        Ok(())
    }

    /// シングルステップフラグを無効化
    pub fn disable_single_step(&self, thread_id: u32) -> Result<()> {
        let mut context = self.get_thread_context(thread_id)?;

        // Trap Flag (EFLAGS.TF) をクリア
        context.e_flags &= !0x100;

        self.set_thread_context(thread_id, &context)?;
        Ok(())
    }

    /// プロセスIDを取得
    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    /// アタッチされているか
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// プロセスハンドルを取得（外部で使用する場合）
    pub fn process_handle(&self) -> HANDLE {
        self.process_handle
    }

    // ========================================
    // ハードウェアブレークポイント (DR0-DR3)
    // ========================================

    /// ハードウェアブレークポイントを設定
    ///
    /// INT3と違いコードを改変しないため、パッカーのコードチェックサム検出を回避できる。
    /// 最大4個（DR0-DR3）まで同時設定可能。
    ///
    /// # Arguments
    /// * `thread_id` - 対象スレッドID
    /// * `slot` - 使用するデバッグレジスタ (0-3 = DR0-DR3)
    /// * `address` - 監視アドレス
    /// * `condition` - ブレーク条件（実行/書込/読書）
    /// * `size` - 監視サイズ（1/2/4/8バイト）
    pub fn set_hardware_breakpoint(
        &mut self,
        thread_id: u32,
        slot: u8,
        address: u64,
        condition: HwBreakpointCondition,
        size: HwBreakpointSize,
    ) -> Result<()> {
        if slot > 3 {
            return Err(anyhow!("Invalid hardware breakpoint slot: {} (must be 0-3)", slot));
        }

        let mut ctx = self.get_thread_context(thread_id)?;

        // DR0-DR3 にアドレスを設定
        match slot {
            0 => ctx.dr0 = address,
            1 => ctx.dr1 = address,
            2 => ctx.dr2 = address,
            3 => ctx.dr3 = address,
            _ => unreachable!(),
        }

        // DR7 の設定
        // ビット構造:
        //   0-7:   L0,G0,L1,G1,L2,G2,L3,G3 (ローカル/グローバル有効化)
        //   16-17: R/W0 (条件), 18-19: LEN0 (サイズ)
        //   20-21: R/W1, 22-23: LEN1
        //   24-25: R/W2, 26-27: LEN2
        //   28-29: R/W3, 30-31: LEN3

        let slot_u64 = slot as u64;

        // Ln ビットを有効化（ローカル有効化、ビット 0, 2, 4, 6）
        let enable_bit = 1u64 << (slot_u64 * 2);

        // R/Wn と LENn のビット位置を計算
        let rw_shift = 16 + slot_u64 * 4;
        let len_shift = 18 + slot_u64 * 4;

        // 既存の設定をクリアしてから新しい値を設定
        let clear_mask = !(0b1111u64 << (16 + slot_u64 * 4));
        ctx.dr7 = (ctx.dr7 & clear_mask) | enable_bit;
        ctx.dr7 |= (condition as u64) << rw_shift;
        ctx.dr7 |= (size as u64) << len_shift;

        self.set_thread_context(thread_id, &ctx)?;
        Ok(())
    }

    /// ハードウェアブレークポイントを削除
    ///
    /// # Arguments
    /// * `thread_id` - 対象スレッドID
    /// * `slot` - 削除するデバッグレジスタ (0-3)
    pub fn remove_hardware_breakpoint(&mut self, thread_id: u32, slot: u8) -> Result<()> {
        if slot > 3 {
            return Err(anyhow!("Invalid hardware breakpoint slot: {} (must be 0-3)", slot));
        }

        let mut ctx = self.get_thread_context(thread_id)?;

        // Ln ビットを無効化
        let disable_mask = !(1u64 << (slot as u64 * 2));
        ctx.dr7 &= disable_mask;

        // DR0-DR3 もクリア
        match slot {
            0 => ctx.dr0 = 0,
            1 => ctx.dr1 = 0,
            2 => ctx.dr2 = 0,
            3 => ctx.dr3 = 0,
            _ => unreachable!(),
        }

        self.set_thread_context(thread_id, &ctx)?;
        Ok(())
    }

    /// 全てのハードウェアブレークポイントを削除
    pub fn clear_all_hardware_breakpoints(&mut self, thread_id: u32) -> Result<()> {
        let mut ctx = self.get_thread_context(thread_id)?;

        ctx.dr0 = 0;
        ctx.dr1 = 0;
        ctx.dr2 = 0;
        ctx.dr3 = 0;
        ctx.dr6 = 0;
        ctx.dr7 = 0;

        self.set_thread_context(thread_id, &ctx)?;
        Ok(())
    }

    // ========================================
    // アンチデバッグ回避（観察能力向上のため）
    // ========================================

    /// デバッガの存在を隠蔽
    ///
    /// PEB.BeingDebugged と PEB.NtGlobalFlag を操作して、
    /// IsDebuggerPresent() 等の基本的なアンチデバッグチェックを回避する。
    ///
    /// 注意: カーネルレベルのアンチデバッグ（NtQueryInformationProcess ProcessDebugPort等）
    /// は回避できない。
    pub fn hide_debugger(&self) -> Result<()> {
        use super::ffi::ntdll::*;

        // 1. PEB のベースアドレスを取得
        let peb_address = self.get_peb_address()?;

        // 2. PEB.BeingDebugged (offset +0x02) を 0 に設定
        self.write_memory(peb_address + PEB_BEING_DEBUGGED_OFFSET, &[0x00])?;

        // 3. PEB.NtGlobalFlag (offset +0xBC) からデバッグフラグをクリア
        let nt_global_flag_addr = peb_address + PEB_NT_GLOBAL_FLAG_OFFSET;
        let current_flag_bytes = self.read_memory(nt_global_flag_addr, 4)?;
        if current_flag_bytes.len() == 4 {
            let current_flag = u32::from_le_bytes([
                current_flag_bytes[0],
                current_flag_bytes[1],
                current_flag_bytes[2],
                current_flag_bytes[3],
            ]);
            let cleaned_flag = current_flag & !NT_GLOBAL_FLAG_DEBUGGER_FLAGS;
            self.write_memory(nt_global_flag_addr, &cleaned_flag.to_le_bytes())?;
        }

        Ok(())
    }

    /// PEB のベースアドレスを取得
    fn get_peb_address(&self) -> Result<u64> {
        use super::ffi::ntdll::*;

        let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mut return_length: DWORD = 0;

        let status = unsafe {
            NtQueryInformationProcess(
                self.process_handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as LPVOID,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as DWORD,
                &mut return_length,
            )
        };

        if !nt_success(status) {
            return Err(anyhow!(
                "NtQueryInformationProcess failed with NTSTATUS: 0x{:08X}",
                status as u32
            ));
        }

        Ok(pbi.peb_base_address as u64)
    }

    /// デバッガ隠蔽状態を確認（デバッグ用）
    pub fn is_debugger_hidden(&self) -> Result<bool> {
        use super::ffi::ntdll::*;

        let peb_address = self.get_peb_address()?;
        let being_debugged = self.read_memory(peb_address + PEB_BEING_DEBUGGED_OFFSET, 1)?;

        Ok(being_debugged.first().copied().unwrap_or(1) == 0)
    }
}

impl Drop for ProcessDebugger {
    fn drop(&mut self) {
        let _ = self.detach();

        unsafe {
            // スレッドハンドルをクローズ
            for (_, handle) in self.thread_handles.drain() {
                CloseHandle(handle);
            }

            // プロセスハンドルをクローズ
            if !self.process_handle.is_null() {
                CloseHandle(self.process_handle);
            }
        }
    }
}
