# リバースエンジニアリング学習ガイド

## 学習の進め方

### ステップ1: 基礎（step1_simple.c）
**目標**: 関数呼び出し、スタックフレームを理解する

1. コンパイル:
```bash
gcc -o step1.exe step1_simple.c
```

2. MCPサーバーで解析:
- `get_binary_summary` で概要確認
- `detect_export_functions` でエクスポート確認
- `list_functions` で関数一覧
- `decompile_function_native` でadd関数をデコンパイル

3. 学ぶこと:
- 関数のプロローグ/エピローグ
- レジスタの使い方（RDI, RSI = 引数）
- return値の渡し方（RAX）

### ステップ2: 文字列解析（step2_strings.c）
**目標**: 文字列から手がかりを見つける

1. コンパイル:
```bash
gcc -o step2.exe step2_strings.c
```

2. MCPサーバーで解析:
- `list_strings` でパスワード文字列を探す
- "MySecretPassword123"が見つかるはず
- `decompile_function_native` でcheck_password関数を解析

3. 学ぶこと:
- 文字列はバイナリに平文で残る
- strcmp関数の呼び出しパターン
- 条件分岐の見分け方

### ステップ3: 簡易難読化（step3_obfuscated.c）
**目標**: XOR暗号化を突破する

1. コンパイル:
```bash
gcc -o step3.exe step3_obfuscated.c
```

2. MCPサーバーで解析:
- `list_strings` → パスワードが見つからない！
- `decompile_function_native` でdecrypt_password関数を解析
- XOR演算（OpCode.INT_XOR）を見つける
- encrypted_password配列とxor_keyを特定

3. 学ぶこと:
- 文字列難読化の基本
- XOR暗号の仕組み
- 動的解析が必要な場面

4. 解読方法:
```python
# Pythonで復号
encrypted = [0x5E, 0x7B, 0x48, 0x64, 0x62, 0x73, 0x64, 0x71, 0x45, 0x60, 0x72, 0x72, 0x76, 0x6E, 0x73, 0x63]
key = 0x42
password = ''.join(chr(c ^ key) for c in encrypted)
print(password)  # "HiddenPassword2"
```

## 次のステップ

### レベルアップ課題
1. **アンチデバッグ技術**
   - IsDebuggerPresent()検出
   - タイミングチェック

2. **パッキング/アンパッキング**
   - UPX, Themida, VMProtect

3. **仮想化難読化**
   - VM-based obfuscation
   - Code Flow Flattening

### 推奨リソース
- **書籍**:
  - "Practical Malware Analysis" - 実践的
  - "Reversing: Secrets of Reverse Engineering" - 基礎から

- **オンライン**:
  - https://crackmes.one/ - 練習問題
  - https://begin.re/ - インタラクティブチュートリアル
  - https://pwnable.kr/ - バイナリexploit練習

- **YouTube**:
  - LiveOverflow - CTF解説
  - John Hammond - リバースエンジニアリング
  - OALabs - マルウェア解析

## 倫理的な注意

**やって良いこと:**
- 自分で書いたプログラム
- オープンソースソフトウェア
- 許可されたCTF/Crackmes
- セキュリティ研究（責任ある開示）

**やってはいけないこと:**
- 商用ソフトのクラック
- 不正アクセス
- チート作成・配布
- マルウェア作成

**War Thunderなどの商用ゲーム:**
- 利用規約違反の可能性
- 学習目的でも避けるべき
- 代わりにオープンソースゲームで練習

## 実践例: MCPサーバーを使った解析フロー

```bash
# 1. バイナリの概要を把握
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_binary_summary","arguments":{"path":"./step1.exe"}}}' | ./kensho-mcp.exe

# 2. 文字列を探す
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_strings","arguments":{"path":"./step1.exe","page":0,"page_size":50}}}' | ./kensho-mcp.exe

# 3. 関数一覧
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_functions","arguments":{"path":"./step1.exe"}}}' | ./kensho-mcp.exe

# 4. 特定関数をデコンパイル
echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"decompile_function_native","arguments":{"path":"./step1.exe","function_address":"0x401000"}}}' | ./kensho-mcp.exe
```

## 成長のヒント

1. **毎日少しずつ**: 1日30分でも続ける
2. **手を動かす**: 読むだけでなく実際に解析
3. **コミュニティ**: Discord, Reddit (/r/ReverseEngineering)
4. **ブログを書く**: アウトプットで定着
5. **CTFに参加**: 実戦経験が一番の学習

頑張ってください。
