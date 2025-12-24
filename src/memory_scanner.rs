/// War Thunder動的解析 - メモリスキャナー
/// プロセスメモリからゲームデータ構造を探索

#[cfg(windows)]
use windows::{
    Win32::Foundation::*,
    Win32::System::Diagnostics::Debug::*,
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::System::Memory::*,
    Win32::System::Threading::*,
};

use anyhow::{Result, Context, bail};
use std::mem;

/// プロセス情報
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub base_address: usize,
}

/// メモリリージョン
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: u32,
}

/// メモリスキャナー
pub struct MemoryScanner {
    #[cfg(windows)]
    process_handle: HANDLE,
    pub process_info: ProcessInfo,
}

impl MemoryScanner {
    /// プロセス名からスキャナーを作成
    #[cfg(windows)]
    pub fn from_process_name(name: &str) -> Result<Self> {
        let pid = Self::find_process_by_name(name)?;
        Self::from_pid(pid)
    }

    /// PIDからスキャナーを作成
    #[cfg(windows)]
    pub fn from_pid(pid: u32) -> Result<Self> {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            ).context("Failed to open process")?
        };

        let base_address = Self::get_module_base_address(process_handle)?;

        Ok(Self {
            process_handle,
            process_info: ProcessInfo {
                pid,
                name: String::new(),
                base_address,
            },
        })
    }

    /// プロセス名からPIDを検索
    #[cfg(windows)]
    fn find_process_by_name(name: &str) -> Result<u32> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

            let mut entry = PROCESSENTRY32W {
                dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_err() {
                let _ = CloseHandle(snapshot);
                bail!("Failed to enumerate processes");
            }

            loop {
                let process_name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_lowercase();

                if process_name.contains(&name.to_lowercase()) {
                    let pid = entry.th32ProcessID;
                    let _ = CloseHandle(snapshot);
                    return Ok(pid);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }

            let _ = CloseHandle(snapshot);
            bail!("Process not found: {}", name);
        }
    }

    /// モジュールのベースアドレスを取得
    #[cfg(windows)]
    fn get_module_base_address(process_handle: HANDLE) -> Result<usize> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0)?;

            let mut entry = MODULEENTRY32W {
                dwSize: mem::size_of::<MODULEENTRY32W>() as u32,
                ..Default::default()
            };

            if Module32FirstW(snapshot, &mut entry).is_ok() {
                let base = entry.modBaseAddr as usize;
                let _ = CloseHandle(snapshot);
                return Ok(base);
            }

            let _ = CloseHandle(snapshot);
            bail!("Failed to get module base address");
        }
    }

    /// メモリリージョンを列挙
    #[cfg(windows)]
    pub fn enumerate_regions(&self) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();
        let mut address: usize = 0;

        unsafe {
            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
                let result = VirtualQueryEx(
                    self.process_handle,
                    Some(address as *const _),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                // 読み取り可能なメモリのみ
                if mbi.State == MEM_COMMIT {
                    let protection = mbi.Protect.0;
                    if protection & PAGE_GUARD.0 == 0 && protection & PAGE_NOACCESS.0 == 0 {
                        regions.push(MemoryRegion {
                            base_address: mbi.BaseAddress as usize,
                            size: mbi.RegionSize,
                            protection,
                        });
                    }
                }

                address = (mbi.BaseAddress as usize) + mbi.RegionSize;
            }
        }

        Ok(regions)
    }

    /// メモリを読み取り
    #[cfg(windows)]
    pub fn read_memory(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;

        unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            )?;
        }

        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    /// パターンマッチング（バイトシーケンス検索）
    #[cfg(windows)]
    pub fn scan_pattern(&self, pattern: &[u8], mask: Option<&[bool]>) -> Result<Vec<usize>> {
        let regions = self.enumerate_regions()?;
        let mut results = Vec::new();

        for region in regions {
            // 大きすぎるリージョンはスキップ（100MB以上）
            if region.size > 100 * 1024 * 1024 {
                continue;
            }

            if let Ok(data) = self.read_memory(region.base_address, region.size) {
                let matches = Self::find_pattern(&data, pattern, mask.unwrap_or(&vec![true; pattern.len()]));
                for offset in matches {
                    results.push(region.base_address + offset);
                }
            }
        }

        Ok(results)
    }

    /// データ内でパターンを検索
    fn find_pattern(data: &[u8], pattern: &[u8], mask: &[bool]) -> Vec<usize> {
        let mut results = Vec::new();

        if pattern.len() > data.len() {
            return results;
        }

        for i in 0..=(data.len() - pattern.len()) {
            let mut matched = true;
            for j in 0..pattern.len() {
                if mask[j] && data[i + j] != pattern[j] {
                    matched = false;
                    break;
                }
            }
            if matched {
                results.push(i);
            }
        }

        results
    }

    /// 4バイト整数値でスキャン
    #[cfg(windows)]
    pub fn scan_int32(&self, value: i32) -> Result<Vec<usize>> {
        let pattern = value.to_le_bytes();
        self.scan_pattern(&pattern, None)
    }

    /// 8バイト整数値でスキャン
    #[cfg(windows)]
    pub fn scan_int64(&self, value: i64) -> Result<Vec<usize>> {
        let pattern = value.to_le_bytes();
        self.scan_pattern(&pattern, None)
    }

    /// 浮動小数点数でスキャン
    #[cfg(windows)]
    pub fn scan_float(&self, value: f32) -> Result<Vec<usize>> {
        let pattern = value.to_le_bytes();
        self.scan_pattern(&pattern, None)
    }

    /// 文字列でスキャン
    #[cfg(windows)]
    pub fn scan_string(&self, text: &str) -> Result<Vec<usize>> {
        self.scan_pattern(text.as_bytes(), None)
    }
}

#[cfg(windows)]
impl Drop for MemoryScanner {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.process_handle);
        }
    }
}

// Windows以外のプラットフォーム用のスタブ実装
#[cfg(not(windows))]
impl MemoryScanner {
    pub fn from_process_name(_name: &str) -> Result<Self> {
        bail!("Memory scanning is only supported on Windows");
    }

    pub fn from_pid(_pid: u32) -> Result<Self> {
        bail!("Memory scanning is only supported on Windows");
    }

    pub fn enumerate_regions(&self) -> Result<Vec<MemoryRegion>> {
        bail!("Memory scanning is only supported on Windows");
    }

    pub fn read_memory(&self, _address: usize, _size: usize) -> Result<Vec<u8>> {
        bail!("Memory scanning is only supported on Windows");
    }

    pub fn scan_pattern(&self, _pattern: &[u8], _mask: Option<&[bool]>) -> Result<Vec<usize>> {
        bail!("Memory scanning is only supported on Windows");
    }

    pub fn scan_int32(&self, _value: i32) -> Result<Vec<usize>> {
        bail!("Memory scanning is only supported on Windows");
    }

    pub fn scan_int64(&self, _value: i64) -> Result<Vec<usize>> {
        bail!("Memory scanning is only supported on Windows");
    }

    pub fn scan_float(&self, _value: f32) -> Result<Vec<usize>> {
        bail!("Memory scanning is only supported on Windows");
    }

    pub fn scan_string(&self, _text: &str) -> Result<Vec<usize>> {
        bail!("Memory scanning is only supported on Windows");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_find() {
        let data = b"Hello World Hello Rust";
        let pattern = b"Hello";
        let mask = vec![true; pattern.len()];

        let results = MemoryScanner::find_pattern(data, pattern, &mask);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], 0);
        assert_eq!(results[1], 12);
    }
}
