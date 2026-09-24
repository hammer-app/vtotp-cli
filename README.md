[English](README.en.md) | 日本語

# vtotp

Windows 環境での実用性と堅牢性を重視して設計された、高セキュリティな CLI TOTP（時間基準ワンタイムパスワード）認証ツールです。

マスターキーと暗号化データの物理的分離、メモリ・ログへのシークレット完全非露出（Zero Leakage Rule）、そして Windows 特有のパス入力挙動に完全対応した設計で、端末固定かつポータブルな運用を重視しています。

---

## 主な特徴

- **強固な暗号化と鍵分離**: TOTP シークレットは AES-256-GCM で暗号化して保存されます。暗号化データと復号用のマスターキー（32バイト）は別々の安全な場所（外部メディア、OneDrive Vault 等）に分離管理できます。
- **Zero Leakage Rule（秘密情報の完全防衛）**:
  - 生成された 6 桁コードのみを `stdout`（標準出力）へ出力します。クリップボード連携や他コマンドへのパイプ渡し（`vtotp github | clip`）でも安全です。
  - 残り有効時間バーや進捗表示、案内・警告・エラーメッセージはすべて `stderr`（標準エラー出力）へ分離されます。
  - エラー発生時や通常出力時に、マスターキーや平文シークレットが画面・ログへ漏洩することは一切ありません。
- **日本語・英語の完全な多言語対応**: ヘルプ・プロンプト・エラーメッセージ等の全表示文言が日英で切り替え可能です（`-l` / `--lang`、環境変数、設定ファイルで解決）。
- **Windows フレンドリー**:
  - エクスプローラーの「パスのコピー」等で混入する引用符（`"` や `'`）や全角空白混じりのパスを自動正規化。
  - Windows 特有の不正文字による `[WinError 123]` や未処理例外（Traceback）の露出を完全に防ぎます。
- **直感的な操作性**:
  - 頻繁に使うコード生成はサブコマンドを省略可能（`vtotp <service>` のみで即座に発行）。
  - 鍵の安全な世代交代（最大 3 世代までの自動バックアップ）をサポート。
- **耐タンパー性の高いネイティブバイナリ**: 配布用バイナリは、従来の Python バイトコード同梱方式ではなく **Nuitka による C 言語トランスパイル・ネイティブコンパイル方式** でビルドされています。ソースコードを C 言語相当の中間コードへ変換した上でネイティブ機械語へコンパイルするため、一般的な Python バイトコードデコンパイラによる復元が困難で、高い耐タンパー性・リバースエンジニアリング耐性（難読化）を備えています。

---

## 動作環境

- Python 3.11 以上（ソースコード版利用時）
- Windows / macOS / Linux（配布バイナリは現時点で Windows x64 のみ）

---

## インストールと利用形態

vtotp は、利用環境やユースケースに応じて選べる **3 つの配布形態** を提供しています。いずれも機能・動作（Zero Leakage、暗号化処理、終了コード体系等）は完全に同一です。

| 形態 | 配布物 | 起動速度 | セキュリティ特性 | 推奨対象 |
| --- | --- | --- | --- | --- |
| ① **Standalone ZIP 版**（推奨） | `vtotp-windows-x64.zip`（フォルダ一式） | **瞬時**（体感ラグなし、実行時の一時解凍が一切無い） | 一時フォルダへの動的展開（ドロッパー的挙動）を行わないため、AV 誤検知リスクが最も低い | ターミナルから頻繁に呼び出し、PATH を通して快適・爆速で TOTP コードを取得したい常用ユーザー |
| ② **Onefile EXE 版** | `vtotp.exe`（単一ファイル） | 自己展開による待機あり（実行時の一時解凍やセキュリティ製品のスキャン状況により待機時間が発生） | 実行時に一時フォルダへ DLL 群を展開するため、環境や AV 定義によって検知・スキャンの影響を受けやすい | PATH 設定やフォルダ展開を行わず、USB メモリ等に単一の `.exe` のみを手軽に配置・持ち運びたいユーザー |
| ③ **ソースコード版**（Python パッケージ） | `pip install -e .` | 通常（Python ランタイムの起動速度相応） | OS 標準の Python 実行環境に依存 | Linux/macOS 環境のユーザー、コードを直接確認・改変したい開発者 |

### ① Standalone ZIP 版（推奨・高速）

[GitHub Releases](https://github.com/hammer-app/vtotp-cli/releases) から `vtotp-windows-x64.zip` をダウンロードし、任意のフォルダへ展開します。

```powershell
# 例: C:\Tools\vtotp\ へ展開した場合
Expand-Archive vtotp-windows-x64.zip -DestinationPath C:\Tools\vtotp

# 展開したフォルダに PATH を通しておくと、どこからでも vtotp コマンドとして実行できる
C:\Tools\vtotp\vtotp.exe --version
```

フォルダ内には `vtotp.exe` と依存 DLL・Python ランタイムが同梱されており、一時展開を行わないため瞬時かつ低リスクに起動します。

### ② Onefile EXE 版（ポータブル・単体ファイル）

同じく [Releases ページ](https://github.com/hammer-app/vtotp-cli/releases) から単一ファイルの `vtotp.exe` をダウンロードし、任意のフォルダに配置するだけで実行できます。

```powershell
# 例: PATH を通していない場合
C:\Tools\vtotp\vtotp.exe --version
```

実行時の一時解凍やセキュリティ製品のスキャン状況によっては自己展開による待機が発生する場合がありますが、フォルダ管理やインストールが簡単です。

いずれの形態も pip や仮想環境のセットアップは不要です。以降のクイックスタートの `vtotp` コマンドは、そのまま `vtotp.exe` に読み替えて実行できます。

### ③ ソースコード版（Python / pip 経由）

仮想環境を作成し、編集可能（editable）モードまたは通常モードでインストールします。

```powershell
# リポジトリのクローン
git clone https://github.com/hammer-app/vtotp-cli.git
cd vtotp-cli

# 仮想環境の作成と有効化
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# インストール
pip install -e .
```

インストール後、`vtotp` コマンドが使用可能になります。

---

## クイックスタート

### 1. 初期化 (`init`)

マスターキーを作成し、暗号化ストレージを初期化します。`-l` / `--lang` を省略した場合は対話プロンプトで表示言語（`en`/`ja`）を選択できます（未入力の場合は自動解決された既定言語が採用されます）。

```powershell
# 対話プロンプトで保存先パス・表示言語を入力する場合
vtotp init
```

対話プロンプトが表示されたら、鍵の保存先パス（例: `"C:\Users\<user>\OneDrive\個人用 Vault\master.key"`）を指定します。引用符で囲んだまま貼り付けても自動的に除去されます。

```powershell
# 保存先パス・表示言語を引数で直接指定する場合（-k / --key、-l / --lang、対話プロンプトなし）
vtotp init --key "C:\Users\<user>\OneDrive\個人用 Vault\master.key" -l ja
vtotp init -k "D:\USB\master.key" -l en
```

### 2. サービスの登録 (`add`)

Base32 形式の TOTP シークレットを登録します。シークレットは `--secret`（短縮形: `-s`）で直接指定できます。

```powershell
# 対話プロンプトで安全に入力する場合（推奨: ターミナル履歴に残りません）
vtotp add github

# 引数で直接指定する場合（--secret / -s）
vtotp add aws --secret JBSWY3DPEHPK3PXP --issuer Amazon
vtotp add aws -s JBSWY3DPEHPK3PXP --issuer Amazon
```

### 3. TOTP コードの生成 (`generate`、エイリアス: `get` / `-g`、省略形)

サービス名を渡すだけで即座に 6 桁コードを取得できます。`generate` には `get` および `-g` というエイリアスがあります。

```powershell
# サブコマンド省略形（日常利用に最適。サービス名のみでgenerate扱いになる）
vtotp github

# 明示的なサブコマンド指定
vtotp generate github

# エイリアス（generateと完全に同じ動作）
vtotp get github
vtotp -g github

# クリップボードへ直接コピー（PowerShell）
vtotp github | Set-Clipboard
```

### 4. サービス一覧の確認 (`list`、エイリアス: `ls`)

登録されているサービス名と発行者（Issuer）を表示します（シークレットは表示されません）。`ls` は `list` のエイリアスです。

```powershell
vtotp list
vtotp ls
```

### 5. サービスの削除 (`remove`、エイリアス: `rm`)

不要になったサービスを安全に削除します。`rm` は `remove` のエイリアスです。確認プロンプトは `--force`（短縮形: `-f`）でスキップできます。

```powershell
# 確認プロンプトあり
vtotp remove github

# 確認をスキップして即時削除（--force / -f）
vtotp remove github --force
vtotp remove github -f

# rm は remove のエイリアス（動作は同じ）
vtotp rm github --force
```

### 6. マスターキーのローテーション (`rekey`)

ストレージを再暗号化し、新しいマスターキーを発行します（旧鍵は `<key_path>.1` として自動退避されます）。

```powershell
vtotp rekey
```

---

## コマンド構文とオプション配置ルール

vtotp のコマンドラインは、パイプ連携やスクリプト組み込み時の予測可能性を重視し、次の 2 原則に従います。

1. **第一引数の固定**: 第一引数は必ず「予約サブコマンド」または「サービス名（省略形）」であり、`-h` / `--help` / `--version` を除き、オプションは後方に置きます。
2. **オプションの後置**: `SERVICE` を必要とするコマンド（`generate` / `get` / `add` / `remove` / `rm`）では、サブコマンド直後に必ず `SERVICE` を置き、オプションはその後方に指定します。

```powershell
# 正しい例（SERVICEがサブコマンド直後、オプションは後方・順不同）
vtotp get github -l ja
vtotp get github --key "PATH" -l ja

# 非サポート（終了コード 2 で拒否される）
vtotp get -l ja github
vtotp get --key "PATH" github
```

---

## 言語設定 (`-l` / `--lang`)

CLI の表示言語（ヘルプ・プロンプト・エラーメッセージ等）は英語（`en`）・日本語（`ja`）の 2 言語に完全対応しており、以下の優先順位で自動解決されます。

1. コマンドライン引数（`-l` / `--lang <en|ja>`）— 各サブコマンドの `SERVICE`/オプションの後方に指定
2. 環境変数 `VTOTP_LANG`
3. `config.json` の `language` 設定
4. OS ロケール環境（`LANG`, `LC_ALL`, OS 既定ロケール）
5. 既定フォールバック言語（`en`）

```powershell
# 一時的に日本語で表示
vtotp list -l ja
vtotp github -l ja

# 環境変数で恒久的に切り替え（シェルの設定ファイル等に記述）
$env:VTOTP_LANG = "ja"
```

### 言語設定の確認・恒久的な変更 (`config`)

```powershell
# 現在解決されている鍵パス・ストレージパス・表示言語を確認
vtotp config

# 言語設定を config.json へ恒久的に保存（ショートカット構文）
vtotp config -l ja

# 言語設定を config.json へ恒久的に保存（標準構文。上記と完全に同じ動作）
vtotp config set language en
```

`config -l <en|ja>` と `config set language <en|ja>` は完全に等価な動作（保存内容・表示メッセージ・終了コード）をします。日常的な切り替えには短いショートカット構文が便利です。

---

## 設定と優先順位

マスターキーの参照先は以下の優先順位で自動解決されます。

1. コマンドライン引数（`-k PATH` または `--key PATH`）
2. 環境変数 `VTOTP_KEY_PATH`
3. 初期化時に保存された設定ファイル（`~/.vtotp/config.json`）

暗号化データファイルの参照先は `--storage PATH` で一時的に上書きできます（`config.json` には保存されません）。指定が無い場合は `config.json` の `storage_path`、それも無い場合は `config.json` と同じディレクトリの `vtotp-secrets.enc` が既定値として使用されます。

現在の設定状況は以下のコマンドで確認できます。

```powershell
vtotp config
```

---

## 終了コード

スクリプトから呼び出す際は、以下の終了コードで結果を判定できます。

| コード | 意味 |
| --- | --- |
| 0 | 成功 |
| 1 | 一般エラー（ファイル操作の失敗等） |
| 2 | CLI 引数エラー |
| 3 | 鍵ファイルが存在しない・不正 |
| 4 | 暗号化データの破損・復号失敗 |
| 5 | 指定したサービスが未登録 |
| 6 | TOTP シークレットの形式が不正 |
| 7 | ユーザーによるキャンセル |

---

## 開発とビルド

- 開発環境の構築やテスト実行手順: [CONTRIBUTING.md](CONTRIBUTING.md)
- 配布バイナリのビルドやCI仕様: [docs/BUILD.md](docs/BUILD.md)

本プロジェクトは継続的にテスト・静的解析・ビルド検証を整備しており、カバレッジ 100% と警告ゼロを維持する方針です。

---

## ライセンス

MIT License
