# 動的解析機能の実装と保留判断

**作成日**: 2024-12-24
**ステータス**: 実装完了・保留中

---

## エグゼクティブサマリー

Phase 1（動的解析統合）として、プロセスメモリのダンプ機能を実装したが、**Kensho MCPの主要ターゲット（dll解析）には不適合**と判断し保留。

**理由**:
1. **dllは単独で実行できない** → リアルタイムメモリダンプが困難
2. **EAC等のアンチチート** → カーネルレベル防御により無効化される
3. **プロジェクト哲学との不整合** → "Analysis Tool Only"の範囲を超える

**Phase 2（難読化検出）は有効** → そのまま維持・活用

---

## 実装した内容（Phase 1）

### 1. メモリダンプシステム

**新規ファイル**: `src/decompiler_prototype/memory_dump.rs` (272行)

**機能**:
- プロセスメモリを2ファイル形式で保存
  - `.dump.json`: メタデータ（プロセス名、PID、アドレス、タイムスタンプ）
  - `.dump.bin`: 生のバイナリデータ
- サイズ検証、エラーハンドリング完備

**主要構造体**:
```rust
pub struct MemoryDumpMetadata {
    pub process_name: String,
    pub pid: u32,
    pub base_address: u64,
    pub size: usize,
    pub timestamp: u64,
    pub regions: Vec<DumpedRegion>,
}

pub struct MemoryDumpFile {
    metadata_path: PathBuf,  // xxx.dump.json
    data_path: PathBuf,      // xxx.dump.bin
}
```

### 2. MCPツール追加

#### `dump_process_memory` (Windows専用)
```json
{
  "name": "dump_process_memory",
  "description": "プロセスメモリをダンプしてファイルに保存（パッキング対策、Windows専用）",
  "arguments": {
    "process_name": "game.exe",
    "address": "0x140000000",
    "size": 1048576,
    "output_path": "C:\\dumps\\region_00"
  }
}
```

**使用API**:
- `OpenProcess(PROCESS_VM_READ)`
- `ReadProcessMemory()`
- `CreateToolhelp32Snapshot()` / `Process32FirstW()` / `Process32NextW()`

#### `decompile_memory_dump`
```json
{
  "name": "decompile_memory_dump",
  "description": "メモリダンプから関数をデコンパイル（キャッシュ対応）",
  "arguments": {
    "dump_path": "C:\\dumps\\region_00",
    "function_offset": "0x1000"
  }
}
```

**機能**:
- ダンプファイルからデコンパイル
- `ParallelDecompiler`のキャッシュシステムを完全活用
- 2回目以降は即座に結果返却

### 3. 修正ファイル

- `src/main.rs`: 2つのMCPツール定義・ハンドラー追加
- `src/decompiler_prototype/mod.rs`: memory_dumpモジュールのエクスポート

---

## 保留理由の詳細

### 理由1: dllは単独で実行できない

**問題**:
```
exe: プロセスとして実行可能
  → メモリダンプ可能

dll: ホストプロセスに読み込まれる
  → 単独では実行できない
  → どのプロセスに読み込まれているか不明
  → リアルタイムダンプが困難
```

**具体例**:
```
ターゲット: game_engine.dll
問題: このdllがどのプロセス（game.exe? launcher.exe?）に
      読み込まれているか事前に特定する必要がある
```

**回避策**（実装していない）**:
- モジュール列挙（`CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`）
- 全プロセスを走査してdllを検索
- 複雑度が高く、Kensho MCPの範囲を超える

### 理由2: アンチチート・DRM防御

**現在の実装の限界**:
```rust
OpenProcess(PROCESS_VM_READ, ...)  // Ring 3（ユーザーモード）
ReadProcessMemory(...)
```

**防御例**:
- **EAC/BattlEye**: カーネルドライバ（Ring 0）で`ObRegisterCallbacks`フック
- **Vanguard**: ハイパーバイザレベル（Ring -1）監視
- **自作防御**: `PROCESS_VM_READ`フラグを削除

**結果**: `OpenProcess`は成功するが、読み取り権限が無効化される

**回避手法**（実装していない）:
- カーネルドライバ: `MmCopyVirtualMemory()`を直接呼び出し
- DMAデバイス: 物理メモリに直接アクセス
- ハイパーバイザー: Ring -1からゲストOS監視

**問題**:
- カーネル署名が必要
- PatchGuard対策が必要
- EACが検出・ブロック
- **プロジェクト哲学「Analysis Tool Only」を逸脱**

### 理由3: プロジェクト哲学との不整合

**PHILOSOPHY.md より**:
> "Kensho MCPはバイナリ解析ツール。
> Mod生成、チート作成、アンチチート回避は別ツールの責務。"

**動的解析の位置づけ**:
- アンチチート回避 → 解析ツールの範囲を超える
- カーネルドライバ → インフラレベルの変更が必要
- リアルタイム監視 → デバッガの領域

**判断**:
- 基本的なメモリダンプ実装は「研究・学習」として有効
- しかし、実戦レベル（EAC回避等）は別プロジェクトの領域
- Kensho MCPの本質（静的解析）に集中すべき

---

## 実装の価値（保留でも意味がある理由）

### ✅ 有効なユースケース

1. **マルウェア解析**
   - パッキングされたマルウェアサンプル
   - サンドボックス環境で実行後のメモリダンプ
   - 防御機構なし

2. **CTF/クラックミー**
   - 教育目的のバイナリ
   - アンチデバッグはあっても、カーネルドライバなし

3. **自作ソフトウェアの解析**
   - 自分で開発したexe/dll
   - リバースエンジニアリングの学習

4. **レガシーソフト**
   - Windows XP時代の古いソフト
   - 現代的な保護機構なし

### ✅ 技術的価値

- **P-code統合の実証**: メモリダンプ → P-code変換のフローを確立
- **キャッシュシステム活用**: 既存の`ParallelDecompiler`を再利用
- **将来の拡張ポイント**: カーネルドライバ等を別途実装する際の統合ポイント

### ✅ 学習的価値

- Windows API（`OpenProcess`, `ReadProcessMemory`）の実践
- プロセスメモリ構造の理解
- アンチダンプ技術の理解（限界を知ることで）

---

## Phase 2（難読化検出）は維持

Phase 2の実装は**dllにも有効**なため、そのまま維持：

### 実装内容

**新規ファイル**: `src/decompiler_prototype/obfuscation_detector.rs` (600行以上)

**検出パターン**:
1. **Opaque Predicates** (不透明述語)
   - `x XOR x = 0`
   - `x - x = 0`
   - `x AND 0 = 0`

2. **Control Flow Flattening** (制御フロー平坦化)
   - 5個以上のsuccessorsを持つディスパッチャブロック

3. **Bogus Control Flow** (偽の制御フロー)
   - BFSで到達不可能ブロックを検出

4. **Excessive Jumps** (過剰な間接分岐)
   - `CallInd` / `BranchInd` の数をカウント

**JSON出力強化**:
- 全デコンパイル結果に`obfuscation`フィールド追加
- `overall_score` (0.0-1.0) で難読化レベルを数値化
- Confidence scoreで不確実性を明示

**哲学との整合性**:
- ✅ **Truth Over Beauty**: 難読化を解除せず、現実をそのまま提示
- ✅ **AI-First**: 構造化JSONでLLMが推論可能
- ✅ **Analysis Tool Only**: 解析結果の提供に留まる

**dllへの適用**:
```
dll静的解析 → CFG構築 → 難読化パターン検出 → JSON出力
→ LLMが「このdllは高度に難読化されている（score: 0.85）」と判断可能
```

---

## ファイル構造

### 実装済みファイル（保留中）

```
src/decompiler_prototype/
├── memory_dump.rs              # メモリダンプシステム（保留）
├── obfuscation_detector.rs     # 難読化検出（維持）
├── json_printer.rs             # obfuscationフィールド追加（維持）
└── mod.rs                      # モジュール宣言

src/
├── main.rs                     # MCPツール定義（保留中のツール含む）
└── memory_scanner.rs           # Windowsメモリスキャナ（既存）
```

### ツール定義の扱い

**main.rs内のツール定義**:
```rust
// Phase 1: メモリダンプ（保留中、削除しない）
json!({
    "name": "decompile_memory_dump",
    // ...
}),

#[cfg(windows)]
{
    tools.push(json!({
        "name": "dump_process_memory",
        // ...
    }));
}
```

**判断**: コードは削除せず、このドキュメントで「保留」を明示。

**理由**:
- 将来的に別プロジェクト（カーネルドライバ等）と統合する可能性
- 研究・学習用途では有効
- コード量が少なく、メンテナンスコストが低い

---

## 今後の方向性

### Option A: 現状維持（推奨）

**内容**:
- Phase 1のコードは保留（削除しない）
- Phase 2（難読化検出）を積極活用
- dllの静的解析に集中

**メリット**:
- プロジェクト哲学に整合
- dll解析の価値を最大化
- 難読化情報でLLMの推論を支援

### Option B: 将来の拡張（非推奨）

**内容**:
- 別プロジェクト「kensho-kernel-dumper」を作成
- カーネルドライバでメモリダンプ
- Kensho MCPと統合

**課題**:
- カーネルプログラミングの難易度
- カーネル署名の取得
- PatchGuard対策
- EAC検出回避（ほぼ不可能）
- プロジェクト範囲の肥大化

**見積もり**: 20-40時間（カーネル経験者）

**判断**: 「Analysis Tool Only」哲学に反するため非推奨

### Option C: 削除（非推奨）

**内容**:
- Phase 1のコードを完全削除
- Phase 2のみ維持

**メリット**:
- コードベースのクリーンアップ

**デメリット**:
- 研究・学習用途での価値喪失
- 将来の拡張可能性の放棄

**判断**: コード量が少ないため削除不要

---

## 結論

### ✅ 採用する方針

**Option A: 現状維持**

1. **Phase 1（動的解析）**: 保留・削除しない
   - 研究・学習用途で価値あり
   - 将来の統合ポイントとして保持
   - このドキュメントで「保留」を明示

2. **Phase 2（難読化検出）**: 積極活用
   - dll静的解析に完全適用
   - JSON出力でLLMを支援
   - プロジェクト哲学に整合

3. **今後の開発**: dll静的解析に集中
   - DWARF/PDB統合（計画中）
   - 型推論の強化（計画中）
   - シンボル復元の強化（計画中）

---

## 関連ドキュメント

- `PHILOSOPHY.md`: プロジェクト哲学
- `IMPLEMENTATION_STANDARDS.md`: 実装標準
- `PROJECT_COMPLETE_SUMMARY_20251216.md`: プロジェクト完了サマリー
- `README.md`: プロジェクト概要

---

## 変更履歴

| 日付 | 変更内容 | 担当 |
|------|---------|------|
| 2024-12-24 | Phase 1実装完了・保留判断 | Claude Sonnet 4.5 |
| 2024-12-24 | Phase 2実装完了・維持決定 | Claude Sonnet 4.5 |

---

**最終判断**: Phase 1は保留、Phase 2は維持。Kensho MCPはdll静的解析に集中する。
