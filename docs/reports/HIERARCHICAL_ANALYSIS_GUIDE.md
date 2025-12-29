# 階層的バイナリ解析ガイド 🌲

## 🎯 設計思想

**問題**: 200MBバイナリの全解析結果をJSONで吐くとコンテキストオーバーフロー（Claude: 200K tokens ≒ 150KB）

**解決**: ツリー構造で段階的に掘り下げる（Ghidra/IDAと同じUX）

```
階層1: サマリー（数百バイト）
  ├─ 統計情報のみ（関数数、セクション数など）
  └─ 詳細は返さない
  
階層2: 一覧（ページネーション、数KB〜数十KB）
  ├─ セクション一覧（20件/ページ）
  ├─ 関数一覧（50-100件/ページ、フィルタ可能）
  └─ 文字列一覧（100件/ページ）
  
階層3: 詳細解析（数KB〜数十KB）
  └─ 特定関数のみ（逆アセンブル + デコンパイル）
```

---

## 📖 使用例：War Thunder クライアント解析

### ステップ1: まず全体像を把握（軽量）

**AIエージェント**: "War Thunder.exeを解析して"

**MCPツール呼び出し**:
```json
{
  "name": "get_binary_summary",
  "arguments": {
    "path": "C:\\Games\\WarThunder\\aces.exe"
  }
}
```

**レスポンス（200バイト程度）**:
```json
{
  "file_path": "C:\\Games\\WarThunder\\aces.exe",
  "file_size": 187564032,  // 187MB
  "format": "PE",
  "architecture": "x86-64",
  "entry_point": "0x140001000",
  "stats": {
    "section_count": 8,
    "function_count": 87654,     // ← 8万関数！
    "import_count": 2345,
    "export_count": 123,
    "string_count_estimate": 245000  // 24万文字列！
  }
}
```

**AIの判断**: 「8万関数あるので、全部は見れない。興味のある関数を絞り込む必要がある」

---

### ステップ2: セクションを確認

**AIエージェント**: 「セクション構成を教えて」

**MCPツール呼び出し**:
```json
{
  "name": "list_sections",
  "arguments": {
    "path": "C:\\Games\\WarThunder\\aces.exe",
    "page": 0,
    "page_size": 20
  }
}
```

**レスポンス（1KB程度）**:
```json
{
  "total_count": 8,
  "page": 0,
  "page_size": 20,
  "sections": [
    {
      "index": 0,
      "name": ".text",
      "address": "0x140001000",
      "size": 123456789,
      "section_type": "CODE"
    },
    {
      "index": 1,
      "name": ".rdata",
      "address": "0x148000000",
      "size": 45678901,
      "section_type": "READONLY_DATA"
    },
    // ... 全8セクション
  ]
}
```

**AIの判断**: 「.textセクションが主要なコード、.rdataに文字列がありそう」

---

### ステップ3: 関数を検索（フィルタリング）

**ユーザー**: 「ネットワーク関連の関数を探して」

**AIエージェント**: 「"network", "socket", "packet"で検索」

**MCPツール呼び出し**:
```json
{
  "name": "list_functions",
  "arguments": {
    "path": "C:\\Games\\WarThunder\\aces.exe",
    "page": 0,
    "page_size": 50,
    "name_filter": "network"
  }
}
```

**レスポンス（5KB程度）**:
```json
{
  "total_count": 234,  // network関連は234個
  "page": 0,
  "page_size": 50,
  "functions": [
    {
      "address": "0x140123000",
      "name": "NetworkManager::init",
      "size": 1234,
      "section": ".text"
    },
    {
      "address": "0x140124000",
      "name": "NetworkManager::sendPacket",
      "size": 5678,
      "section": ".text"
    },
    // ... 50件
  ]
}
```

**AIの判断**: 「sendPacketが怪しい。詳細を見よう」

---

### ステップ4: 特定関数を詳細解析

**ユーザー**: 「sendPacket関数を詳しく見て」

**MCPツール呼び出し**:
```json
{
  "name": "analyze_function_detail",
  "arguments": {
    "path": "C:\\Games\\WarThunder\\aces.exe",
    "function_address": "0x140124000"
  }
}
```

**レスポンス（20-50KB程度、これは許容範囲）**:
```json
{
  "address": "0x140124000",
  "name": "NetworkManager::sendPacket",
  "size": 5678,
  "disassembly": [
    {
      "address": "0x140124000",
      "mnemonic": "push",
      "operands": "rbp",
      "bytes": "55"
    },
    {
      "address": "0x140124001",
      "mnemonic": "mov",
      "operands": "rbp, rsp",
      "bytes": "48 89 e5"
    },
    // ... 最大100命令
  ],
  "decompiled": `
void NetworkManager::sendPacket(Packet* packet) {
    if (packet == nullptr) {
        return;
    }
    
    uint64_t rax = encrypt_packet(packet);
    
    if (/* flags */ ==) {
        send_to_server(rax);
    }
    
    return;
}
  `,
  "cross_references": [
    "0x140125000",
    "0x140126000"
  ]
}
```

**AIの判断**: 「encrypt_packet関数を呼んでいる。次はそれを見よう」

---

### ステップ5: 関連関数を追跡

**AIエージェント**: 「encrypt_packetも見てみる」

（同様にanalyze_function_detailを使用）

---

## 🔍 コンテキスト消費量の比較

### ❌ 旧実装（一括取得）
```
全関数リスト: 87,654関数 × 平均100バイト = 8.7MB
→ Claude（200K tokens ≒ 150KB）完全オーバーフロー ☠️
```

### ✅ 新実装（階層的）
```
階層1（サマリー）: 200バイト
階層2（50件/ページ）: 5KB × 必要ページ数
階層3（1関数詳細）: 20-50KB × 解析対象関数数

合計: 数KB〜数百KB（完全制御可能）✨
```

---

## 🤖 AIエージェントの推奨フロー

```python
# 1. まず全体像
summary = mcp.call("get_binary_summary", {"path": target})
print(f"関数数: {summary.stats.function_count}")

# 2. 興味のある領域を絞り込み
if user_interest == "ネットワーク":
    funcs = mcp.call("list_functions", {
        "path": target,
        "name_filter": "network",
        "page": 0,
        "page_size": 50
    })
    
    # 3. 候補をユーザーに提示
    print(f"network関連関数: {funcs.total_count}件見つかりました")
    for func in funcs.functions[:10]:
        print(f"  - {func.name} @ 0x{func.address:x}")
    
    # 4. ユーザーが選択した関数のみ詳細解析
    selected = user_choice()
    detail = mcp.call("analyze_function_detail", {
        "path": target,
        "function_address": selected.address
    })
    
    # 5. デコンパイル結果を表示
    print(detail.decompiled)
```

---

## 📊 ページネーション戦略

### 推奨ページサイズ

| データ種別 | 推奨ページサイズ | 理由 |
|-----------|-----------------|------|
| セクション | 20-50 | 通常10-20個なので1ページで収まる |
| 関数 | 50-100 | バランス（多すぎず少なすぎず） |
| 文字列 | 100-200 | 文字列は小さいので多めでも可 |
| インポート | 全件 | 通常数百〜数千件なので一度に返せる |

### ページング例

```javascript
// 最初のページ
page1 = list_functions(path, page=0, page_size=50)
// total_count: 87654

// 興味深い関数が見つかるまでページング
page2 = list_functions(path, page=1, page_size=50)
page3 = list_functions(path, page=2, page_size=50)

// または名前フィルタで絞り込み
filtered = list_functions(path, name_filter="render", page=0)
// total_count: 234 （元の87654から激減）
```

---

## 🎨 実践Tips

### Tip 1: 最初は統計のみ
```
❌ 「全関数をリストして」
✅ 「関数が何個あるか教えて」（サマリーのみ）
```

### Tip 2: フィルタリングを活用
```
❌ list_functions(page=0~1753) // 87654個を順に見る...
✅ list_functions(name_filter="update") // 数百個に絞る
```

### Tip 3: セクション単位で探索
```
✅ list_functions_in_section(".text") // コードセクションのみ
✅ list_strings_in_section(".rdata") // 読み取り専用データのみ
```

### Tip 4: アドレス範囲指定
```
✅ list_functions_in_range("0x140000000", "0x140100000")
// 特定モジュールのみ解析
```

### Tip 5: 詳細解析は最後
```
階層1: サマリー（必須）
階層2: リスト取得（フィルタ活用）
階層2: リスト取得（さらに絞り込み）
階層3: 詳細解析（1-10関数程度に絞った後）
```

---

## 🚀 War Thunder DMA解析での応用例

```bash
# 1. ゲームクライアント全体像
$ kensho-mcp get_binary_summary aces.exe
→ 関数数: 87,654

# 2. チート検出関連を探す
$ kensho-mcp list_functions --filter "anticheat"
→ 45件ヒット

$ kensho-mcp list_functions --filter "verify"
→ 234件ヒット

# 3. メモリ検証関数を詳細解析
$ kensho-mcp analyze_function_detail 0x140567000
→ デコンパイル結果取得

# 4. DMAで該当関数をフック回避
```

---

## 💡 今後の拡張案

### キャッシュ機構
```rust
// 一度解析した結果をキャッシュ
// 2回目以降は即座に返す
cache: HashMap<String, CachedBinaryData>
```

### インクリメンタル解析
```rust
// 必要な関数だけ段階的に解析
// 全解析は不要
lazy_analysis: bool = true
```

### 並列処理
```rust
// 複数関数を同時に解析
// ページング時のレイテンシ削減
#[tokio::spawn]
async fn analyze_batch(functions: Vec<u64>)
```

---

**結論: この階層的アプローチにより、200MBバイナリでもコンテキストオーバーフローなく、効率的に解析できます！**
