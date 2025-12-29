# 🚀 Kensho MCP - AI Onboarding / Context Loading

> **For AI Agents:** Read this first to understand the project in < 30 seconds.

## 1. Core Identity
**Kensho MCP** is a **Rust-native, lightweight binary analysis engine** exposed as an MCP server.
It reimplements Ghidra's core logic (P-code, SSA, Decompilation) in pure Rust to provide millisecond-latency analysis tools for AI agents.

**Goal:** Enable AI agents to analyze binaries (PE/ELF/Mach-O) and scan memory (memscan) without needing external tools like Ghidra or IDA Pro.

## 2. The "Why"
- **Problem:** Ghidra Headless takes 10+ seconds to start. AI agents need instant feedback.
- **Solution:** Kensho MCP starts in milliseconds, uses 5-15MB RAM, and caches generic analysis results.
- **Constraint:** AI context windows are finite. We cannot dump a 200MB binary's full analysis at once.
- **Strategy:** **Hierarchical Analysis**. You must query data in layers (Summary -> List -> Detail).

## 3. Architecture Pipeline
The decompilation pipeline duplicates Ghidra's robust methodology:
1.  **Parser**: `goblin` parses PE/ELF/Mach-O headers.
2.  **Disasm**: `capstone` produces x86-64 assembly.
3.  **Lifter**: Translates assembly to **P-code** (Ghidra's IR).
4.  **Analysis**:
    - **CFG**: Control Flow Graph construction.
    - **SSA**: Static Single Assignment form (Phi-nodes, Dominance).
    - **Optimization**: Constant folding, Dead code elimination, Copy propagation.
    - **Type Inference**: Data type propogation (int, float, ptr).
    - **Control Recovery**: Rebuilds `if`, `while`, `switch` from graphs.
5.  **Output**: C-like pseudo-code.

## 4. How to Use (The "Happy Path")
When analyzing a binary for a user, **DO NOT** ask for everything at once. Follow this flow:

### Step 1: High-Level Recon (Context: ~200 tokens)
Call `get_binary_summary`.
```json
{ "name": "get_binary_summary", "arguments": { "path": "target.exe" } }
```
*Result: Arch, Entry Point, Section counts, Function counts.*

### Step 2: Targeted Search (Context: ~1k tokens)
Call `list_functions` with a `name_filter`.
```json
{ "name": "list_functions", "arguments": { "path": "target.exe", "name_filter": "login" } }
```
*Result: List of functions matching "login".*

### Step 3: Deep Dive (Context: ~5k-50k tokens)
Call `decompile_function_cached` on a specific address found in Step 2.
```json
{ "name": "decompile_function_cached", "arguments": { "path": "target.exe", "function_address": "0x140001234" } }
```
*Result: C-pseudo code, Assembly, and Flow information.*

---

## 5. Critical Tools & Files

### 🛠️ Tools
- **`kensho-mcp`** (`src/main.rs`): The MCP server binary.
- **`memscan`** (`src/bin/memscan.rs`): A standalone memory scanner (Cheat Engine style).

### 📂 Key Source Directories
- `src/decompiler_prototype/`: **THE CORE**.
  - `pcode.rs`: P-code definitions.
  - `ssa.rs` / `ssa_advanced.rs`: SSA transformation logic.
  - `optimizer.rs`: The 12+ optimization rules.
  **Phase 1（完了）:**
  - [x] `json_printer.rs`作成
  - [x] 基本的なJSON出力実装
  - [ ] MCPツールの統合
- `docs/`: Comprehensive documentation.

## 6. Current State (As of Dec 2025)
- **Status**:- ✅ Phase 1-10 Complete
- 🚧 Phase 11 (Advanced Optimization) In Progress
- **Working**: x86-64 P-code lifting, full SSA, Type inference, Control flow recovery, C-code generation.
- **Not Working / Future**: DWARF/PDB full support, ARM/MIPS support, specialized floating-point optimizations.

**Rule of Thumb:** If you need to fix a bug in decompilation, look in `src/decompiler_prototype/`. If you need to add a tool feature, look in `src/`.
