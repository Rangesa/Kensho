# リバースエンジニアリング クイックスタートガイド

## 今日から始める！実践ロードマップ

### Week 1-2: 基礎固め

#### Day 1-3: アセンブリ入門
**リソース:**
- [x86-64 Assembly Language Programming with Ubuntu](http://www.egr.unlv.edu/~ed/assembly64.pdf) - 無料PDF
- [Godbolt Compiler Explorer](https://godbolt.org/) - C→アセンブリ変換を見る

**実践:**
```c
// Godboltで試す
int add(int a, int b) {
    return a + b;
}
```
→ x86-64アセンブリがどう生成されるか確認

#### Day 4-7: PEフォーマット理解
**学ぶこと:**
- DOS Header, PE Header
- セクション（.text, .data, .rdata）
- Import/Export テーブル

**実践: このMCPサーバーで解析**
```bash
# notepad.exeのセクション構造を見る
cat << 'EOF' | ./target/release/kensho-mcp.exe
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_sections","arguments":{"path":"C:\\Windows\\System32\\notepad.exe"}}}
EOF
```

### Week 3-4: ツール習得

#### Ghidraのインストール
1. [Ghidra公式](https://ghidra-sre.org/)からダウンロード
2. JDK 17+が必要
3. `ghidraRun.bat`で起動

**初めてのプロジェクト:**
1. New Project → Non-Shared Project
2. Import File → notepad.exe
3. CodeBrowser で開く
4. Auto Analyze → すべてチェックしてAnalyze

#### x64dbgのインストール
1. [x64dbg公式](https://x64dbg.com/)からダウンロード
2. 解凍して起動
3. File → Open → notepad.exe
4. F9で実行、F2でブレークポイント

### Week 5-8: 実践演習

#### レベル1: crackmes.one
[https://crackmes.one/](https://crackmes.one/)

**推奨問題（難易度1-2）:**
1. **"Baby's First"** - 文字列比較だけ
2. **"Easy Peasy"** - 簡単なアルゴリズム
3. **"Math Challenge"** - 計算ロジック

**解析フロー:**
```
1. 実行してどんな動作か確認
2. 文字列を探す（このMCPサーバー or Strings2.exe）
3. Ghidraでmain関数を特定
4. 条件分岐を見つける
5. 正解の条件を特定
```

#### レベル2: PicoCTF
[https://picoctf.org/](https://picoctf.org/)

**Binary Exploitation カテゴリ:**
- Reverse Engineering セクションから開始
- 段階的に難易度アップ

### Month 3: 専門分野選択

#### パス1: マルウェア解析
- **書籍**: "Practical Malware Analysis"
- **プラットフォーム**: [Any.run](https://any.run/) (無料枠あり)
- **練習**: [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)

#### パス2: ゲームハッキング（倫理的）
- **注意**: 商用ゲームではなく、自作/オープンソースで練習
- **Cheat Engine** - メモリスキャン学習
- **学習用**: [PwnAdventure3](http://www.pwnadventure.com/) - 練習用ゲーム

#### パス3: CTF競技
- **プラットフォーム**:
  - [HackTheBox](https://www.hackthebox.com/)
  - [TryHackMe](https://tryhackme.com/)
  - [picoCTF](https://picoctf.org/)

### 毎日のルーティン（30分）

```
[10分] アセンブリ読解
  → Godboltで簡単なC関数を見る
  → 何をしているか理解する

[15分] Crackme解析
  → 1問に集中
  → 詰まったら解説を見てもOK

[5分] コミュニティ
  → /r/ReverseEngineering を読む
  → Discord参加（ReverseEngineering, OALabs）
```

## 必須ツールセット

### 静的解析
- **このMCPサーバー** - 概要把握、文字列抽出
- **Ghidra** - デコンパイル、詳細解析
- **IDA Free** - 業界標準（有料版は高額）
- **PEiD** - パッカー検出

### 動的解析
- **x64dbg** - デバッガ
- **Process Monitor** - システムコール監視
- **Process Hacker** - プロセス詳細

### ユーティリティ
- **HxD** - Hexエディタ
- **010 Editor** - バイナリテンプレート（有料）
- **CFF Explorer** - PE詳細ビューア

## 学習のコツ

### 1. 手を動かす
[NG] 「動画を見るだけ」
[推奨] 「実際に解析して手を動かす」

### 2. ブログを書く
- アウトプットで理解が深まる
- 将来の自分への参考資料
- ポートフォリオになる

### 3. コミュニティに参加
**Discord:**
- ReverseEngineering Discord
- OALabs Research
- MalwareTech

**Reddit:**
- /r/ReverseEngineering
- /r/AskReverseEngineering
- /r/netsec

### 4. CTFに参加
**定期開催:**
- Google CTF（年1回、超難関）
- DEFCON CTF Quals（年1回）
- 週末CTF（毎週）

**日本:**
- SECCON（年1回）
- SECCON Beginners（初心者向け）

## 必読書

### 初級
1. **"Hacking: The Art of Exploitation"** - バッファオーバーフロー基礎
2. **"Practical Binary Analysis"** - バイナリ解析全般

### 中級
3. **"Practical Malware Analysis"** - マルウェア解析の定番
4. **"The IDA Pro Book"** - IDA使い方

### 上級
5. **"Reversing: Secrets of Reverse Engineering"** - 難読化対策
6. **"Windows Internals"** - OS内部構造

## 倫理とリスク管理

### やって良いこと
- 自分のプログラム
- オープンソースソフトウェア
- Crackmes, CTF問題
- 許可されたペネトレーションテスト

### 絶対ダメ
- 商用ソフトのクラック・配布
- 不正アクセス
- チート作成・配布（利用規約違反）
- マルウェア作成・配布

### グレーゾーン
**商用ゲームの解析（War Thunderなど）:**
- [NG] チート作成
- [NG] 利用規約違反
- [OK] 個人的な学習（公開しない）
- [OK] セキュリティ脆弱性の報告（責任ある開示）

**推奨:**
- 学習目的でもオープンソースゲームを使う
- 例: [OpenArena](http://www.openarena.ws/), [Xonotic](https://xonotic.org/)

## 3ヶ月後の目標

### 達成すべきこと
- [ ] アセンブリ（x86-64）が読める
- [ ] Ghidraで基本的な解析ができる
- [ ] Crackmes（難易度1-2）を5問以上解いた
- [ ] CTFでBinaryカテゴリ1問以上解いた
- [ ] PEフォーマットを理解している

### ボーナス目標
- [ ] ブログで解析記事を3本書いた
- [ ] CTFチームに参加している
- [ ] 自作ツール（スクリプト）を作った

## よくある失敗

### 1. 「難しすぎる問題から始める」
[NG] いきなりVMProtect解析
[推奨] まずはCrackmes難易度1から

### 2. 「ツールの使い方だけ覚える」
[NG] IDAのボタンを覚える
[推奨] アセンブリの意味を理解する

### 3. 「動画を見るだけ」
[NG] YouTubeで解説を見て満足
[推奨] 自分の手で実際に解析

### 4. 「一人で悩み続ける」
[NG] 3日間同じ場所で詰まる
[推奨] 1時間悩んだら質問 or 解説を見る

## 進捗管理

### Notion / Obsidianで管理
```markdown
# 2025年1月 Week 1

## 学習時間: 3.5時間
- アセンブリ読解: 1時間
- Crackme解析: 2時間
- コミュニティ: 30分

## 達成
- [x] Crackme "baby1" 解決
- [x] x86-64レジスタ暗記
- [ ] Ghidraインストール（週末予定）

## 学んだこと
- cmp命令とjz/jnzの関係
- strcmpの戻り値（0 = 一致）

## Next Week
- Ghidraで初めての解析
- Crackme "easy1" に挑戦
```

## オンラインコース（有料/無料）

### 無料
- **Nightmare (by guyinatuxedo)** - CTF Binary Exploitation
- **ROP Emporium** - ROP入門
- **Microcorruption** - 組み込み系CTF

### 有料（価値あり）
- **Practical Reverse Engineering (Udemy)** - $50-100
- **Malware Analysis Bootcamp (TCM Security)** - $30
- **Binary Exploitation (Pentester Academy)** - サブスク制

## 最後に

**リバースエンジニアリングは時間がかかります。**
- 最初の1ヶ月は何もわからなくて当然
- 3ヶ月で基礎が固まる
- 6ヶ月で中級問題が解ける
- 1年で自信を持って解析できる

**焦らず、毎日少しずつ続けることが大切です。**

頑張ってください。

---

## MCPサーバー活用例

### 基本ワークフロー
```bash
# 1. 概要把握
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_binary_summary","arguments":{"path":"./target.exe"}}}' | ./kensho-mcp.exe

# 2. 文字列から手がかり探し
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_strings","arguments":{"path":"./target.exe","min_length":10}}}' | ./kensho-mcp.exe

# 3. セクション確認
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_sections","arguments":{"path":"./target.exe"}}}' | ./kensho-mcp.exe

# 4. エクスポート関数（DLLの場合）
echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"detect_export_functions","arguments":{"path":"./target.dll"}}}' | ./kensho-mcp.exe
```

### Claude DesktopでGUI操作
設定ファイル（`claude_desktop_config.json`）:
```json
{
  "mcpServers": {
    "kensho-mcp": {
      "command": "D:\\Programming\\MCP\\target\\release\\kensho-mcp.exe"
    }
  }
}
```

これで、Claudeと会話しながらバイナリ解析できます！
