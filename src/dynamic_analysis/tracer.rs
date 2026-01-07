// 命令トレーサー（シングルステップ実行、外部依存なし）

use super::debugger::ProcessDebugger;
use super::ffi::types::*;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct InstructionTrace {
    pub address: u64,
    pub registers: RegisterSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterSnapshot {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u32,
}

impl From<&CONTEXT> for RegisterSnapshot {
    fn from(ctx: &CONTEXT) -> Self {
        Self {
            rax: ctx.rax,
            rbx: ctx.rbx,
            rcx: ctx.rcx,
            rdx: ctx.rdx,
            rsi: ctx.rsi,
            rdi: ctx.rdi,
            rbp: ctx.rbp,
            rsp: ctx.rsp,
            r8: ctx.r8,
            r9: ctx.r9,
            r10: ctx.r10,
            r11: ctx.r11,
            r12: ctx.r12,
            r13: ctx.r13,
            r14: ctx.r14,
            r15: ctx.r15,
            rip: ctx.rip,
            rflags: ctx.e_flags,
        }
    }
}

pub struct FunctionTracer {
    debugger: ProcessDebugger,
}

impl FunctionTracer {
    /// 新しいトレーサーを作成（プロセスにアタッチ）
    pub fn new(pid: u32) -> Result<Self> {
        Ok(Self {
            debugger: ProcessDebugger::attach(pid)?,
        })
    }

    /// 関数をトレース（シングルステップ実行）
    pub fn trace_function(
        &mut self,
        start_address: u64,
        max_instructions: usize,
    ) -> Result<Vec<InstructionTrace>> {
        let mut traces = Vec::new();
        let mut current_thread_id: Option<u32> = None;
        let mut in_trace = false;
        let mut instruction_count = 0;

        // エントリポイントにブレークポイントを設定
        self.debugger.set_breakpoint(start_address)?;

        loop {
            // デバッグイベント待機（無限タイムアウト）
            let event = self.debugger.wait_for_event(INFINITE)?;

            match event.dw_debug_event_code {
                EXCEPTION_DEBUG_EVENT => unsafe {
                    let exception = event.u.exception;
                    let exception_code = exception.exception_record.exception_code;
                    let exception_address = exception.exception_record.exception_address as u64;

                    if exception_code == EXCEPTION_BREAKPOINT {
                        // ブレークポイントヒット
                        if exception_address == start_address {
                            // 目的の関数のエントリポイント
                            current_thread_id = Some(event.dw_thread_id);
                            in_trace = true;

                            // ブレークポイントを一時的に復元
                            self.debugger.restore_breakpoint_temporary(start_address)?;

                            // シングルステップモードを有効化
                            self.debugger.enable_single_step(event.dw_thread_id)?;

                            // RIPを1命令分戻す（ブレークポイントで止まったので）
                            let mut context = self.debugger.get_thread_context(event.dw_thread_id)?;
                            context.rip = start_address;
                            self.debugger.set_thread_context(event.dw_thread_id, &context)?;

                            // 最初の命令のレジスタ状態を記録
                            let snapshot = RegisterSnapshot::from(&context);
                            traces.push(InstructionTrace {
                                address: context.rip,
                                registers: snapshot,
                            });

                            instruction_count += 1;
                        }

                        self.debugger.continue_event(&event, DBG_CONTINUE)?;
                    } else if exception_code == EXCEPTION_SINGLE_STEP {
                        // シングルステップ実行
                        if in_trace && Some(event.dw_thread_id) == current_thread_id {
                            let context = self.debugger.get_thread_context(event.dw_thread_id)?;

                            // レジスタ状態を記録
                            let snapshot = RegisterSnapshot::from(&context);
                            traces.push(InstructionTrace {
                                address: context.rip,
                                registers: snapshot,
                            });

                            instruction_count += 1;

                            // 最大命令数に達したら終了
                            if instruction_count >= max_instructions {
                                break;
                            }

                            // RET命令検出（関数終了）
                            let code = self.debugger.read_memory(context.rip, 1)?;
                            if !code.is_empty() && (code[0] == 0xC3 || code[0] == 0xC2) {
                                // RET命令なので、次の1ステップで終了
                                self.debugger.enable_single_step(event.dw_thread_id)?;
                                self.debugger.continue_event(&event, DBG_CONTINUE)?;

                                // RET後のアドレスも記録
                                let event2 = self.debugger.wait_for_event(INFINITE)?;
                                if event2.dw_debug_event_code == EXCEPTION_DEBUG_EVENT {
                                    let exc = event2.u.exception;
                                    if exc.exception_record.exception_code == EXCEPTION_SINGLE_STEP {
                                        let final_context = self.debugger.get_thread_context(event2.dw_thread_id)?;
                                        let final_snapshot = RegisterSnapshot::from(&final_context);
                                        traces.push(InstructionTrace {
                                            address: final_context.rip,
                                            registers: final_snapshot,
                                        });
                                    }
                                }
                                break;
                            }
                        }

                        self.debugger.continue_event(&event, DBG_CONTINUE)?;
                    } else {
                        // その他の例外は処理せず続行
                        self.debugger
                            .continue_event(&event, DBG_EXCEPTION_NOT_HANDLED)?;
                    }
                },

                EXIT_PROCESS_DEBUG_EVENT => {
                    // プロセス終了
                    break;
                }

                _ => {
                    // その他のイベントは無視
                    self.debugger.continue_event(&event, DBG_CONTINUE)?;
                }
            }
        }

        // ブレークポイントを削除
        self.debugger.remove_breakpoint(start_address)?;

        Ok(traces)
    }

    /// メモリリージョンをダンプ
    pub fn dump_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        self.debugger.read_memory(address, size)
    }

    /// デバッガへの参照を取得
    pub fn debugger(&self) -> &ProcessDebugger {
        &self.debugger
    }

    /// デバッガへの可変参照を取得
    pub fn debugger_mut(&mut self) -> &mut ProcessDebugger {
        &mut self.debugger
    }
}

#[derive(Debug, Serialize)]
pub struct TraceResult {
    pub function_address: u64,
    pub instruction_count: usize,
    pub traces: Vec<InstructionTrace>,
}

impl TraceResult {
    pub fn new(function_address: u64, traces: Vec<InstructionTrace>) -> Self {
        let instruction_count = traces.len();
        Self {
            function_address,
            instruction_count,
            traces,
        }
    }
}
