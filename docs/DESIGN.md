# Custom CLI TOTP Authenticator 詳細アーキテクチャ設計書

## 1. 設計方針

- CLI名: `vtotp`
- 対応OS: Windows / Linux / macOS
- Python: 3.11以上を推奨
- 暗号化方式: AES-256-GCM
- TOTP: RFC 6238準拠
- 秘密情報は標準出力、ログ、平文ファイルへ出力しない
- 鍵ファイルと暗号化データファイルは分離する
- 復号された平文シークレットおよび秘密鍵はディスクへ永続化せず、必要な処理スコープ内だけで一時的に扱い、処理終了後は速やかに参照を破棄する
- インメモリ秘密情報の扱いは、ディスクへの非永続化と処理スコープの最小化を目的とする。実行中のメモリから秘密情報を完全に消去することは保証しない

> `cryptography.fernet` は内部でAESを使用するが、AES-256-GCMを明示的に要求する場合は `AESGCM` を使用する。

## 2. 推奨プロジェクト構造

```text
vtotp/
├── pyproject.toml
├── README.md
├── src/
│   └── vtotp/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── handler.py
│       │   ├── parser.py
│       │   ├── commands.py
│       │   └── output.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── key_manager.py
│       │   ├── secure_storage.py
│       │   ├── totp_generator.py
│       │   ├── config_manager.py
│       │   └── service_registry.py
│       ├── domain/
│       │   ├── __init__.py
│       │   ├── models.py
│       │   └── exceptions.py
│       └── infrastructure/
│           ├── __init__.py
│           ├── file_system.py
│           └── platform_paths.py
├── tests/
│   ├── unit/
│   │   ├── test_key_manager.py
│   │   ├── test_secure_storage.py
│   │   ├── test_totp_generator.py
│   │   └── test_cli_handler.py
│   └── integration/
│       └── test_cli_commands.py
└── config/
    └── config.example.json
```

### 実行時データの配置例

```text
~/.vtotp/
├── config.json
└── vtotp-secrets.enc
```

`config.json` は鍵ファイルの内容を保存せず、鍵ファイルのパスだけを指定する。鍵ファイルはツールの内部データとして保持せず、`config.json` の `key_path` に指定された外部パスへ保存する。通常の実行では、指定されたパスに鍵ファイルが存在しない場合、ツールは実行を中止する。

```json
{
    "key_path": "C:/Users/example/Personal Vault/master.key",
    "storage_path": "vtotp-secrets.enc"
}
```

### 鍵ファイルの管理方針

```text
- 鍵ファイルの内容はconfig.json、ツール内の内部データ、プロジェクト管理対象ファイルへ保存しない
- config.jsonには鍵の内容ではなく、鍵ファイルのパスだけを保存する
- 通常の実行ではconfig.jsonのkey_pathを必須とし、指定先に鍵が存在することを前提にする
- key_pathのファイルが存在しない、読み込めない、または32バイトでない場合はエラー終了する
- 通常の実行でVTOTP_KEY_PATHや--keyを使用する場合は、指定先に既存の鍵ファイルがあることを必須とする
- initは新しい32バイト鍵を生成し、指定された外部パスへ保存した上で、そのパスをconfig.jsonへ保存する
- rekeyはconfig.jsonのkey_pathで指定された鍵ファイルを更新し、既存データを新鍵で再暗号化する
- initで--keyが指定されない場合は、対話入力で鍵ファイルの出力先を必ず指定させる
- initとrekeyで生成する鍵の保存先は、ツール内の暗黙の既定パスにしない
- config.jsonの更新はinitによる初期設定と、configによるlanguage更新に限定する
- --keyと--storageは、config.jsonへ保存しない一時的な実行時指定とする
- rekeyでは、更新前の鍵ファイルを世代番号付きで退避し、暗号化済みシークレットデータのローテーション保存は行わない
- 鍵ファイルの保持上限は3世代とし、`<key_path>.1` から `<key_path>.3` までを保持する
- 保持上限到達時は専用オプションを使用せず、警告への対話応答で続行または中止を決定する
```

### 復号後の論理データ構造

```json
{
  "version": 1,
  "services": {
    "github": {
      "secret": "JBSWY3DPEHPK3PXP",
      "issuer": "GitHub"
    }
  }
}
```

### 暗号化ファイルの構造

JSON全体を暗号化し、ファイルにはメタデータと暗号文だけを保存する。

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "nonce": "<base64>",
  "ciphertext": "<base64>"
}
```

## 3. CLIライブラリの選定

### 推奨: `argparse`

```text
- Python標準ライブラリで追加依存が不要
- Windows / Linux / macOSで動作差が少ない
- -g、-k、--stdin、--forceなどを明確に定義できる
- サブコマンドとエイリアスを細かく制御できる
- vtotp <service> の独自フォールバック処理を実装しやすい
- CLIの挙動を予測しやすい
```

| ライブラリ | 長所 | 短所 | 評価 |
| --- | --- | --- | --- |
| `argparse` | 標準搭載、依存が少ない、細かい制御が可能 | 定義量がやや多い | 推奨 |
| `click` | サブコマンドや入力処理が書きやすい | 外部依存が増える | 採用候補 |
| `typer` | 型ヒントを利用でき、記述量が少ない | Click依存、抽象化が強い | 将来候補 |

ポータビリティと予測可能性を重視し、初期実装では `argparse` を採用する。

## 4. 主要モジュールの責務

```text
CliHandler
    CLI入力の前処理、予約コマンド判定、引数解析、エラー表示

KeyManager
    鍵の生成、読み込み、存在確認、鍵パス解決、権限確認

SecureStorage
    暗号化ファイルの読み込み、復号、暗号化、atomic保存、再暗号化

TotpGenerator
    Base32シークレットの検証、TOTPコード生成

ConfigManager
    config.jsonの読み込み、CLI・環境変数・既定値の統合、解決済み設定の提供

ServiceRegistry
    サービスの追加、更新、削除、一覧取得

CommandService
    init、generate、add、remove、list、rekey、configのユースケース実行
```

## 5. ドメインモデルと例外

```python
class SecretRecord:
    service_name: str
    secret: str
    issuer: str | None


class AppConfig:
    key_path: Path
    storage_path: Path


class EncryptedPayload:
    version: int
    algorithm: str
    nonce: bytes
    ciphertext: bytes
```

```python
class TotpCliError(Exception):
    """アプリケーション共通例外"""


class KeyNotFoundError(TotpCliError):
    pass


class InvalidKeyError(TotpCliError):
    pass


class KeyStorageError(TotpCliError):
    """鍵ファイルの生成・保存またはアクセス権設定に失敗した場合の例外"""

    exit_code: int = 1


class StorageCorruptedError(TotpCliError):
    pass


class ServiceNotFoundError(TotpCliError):
    pass


class InvalidSecretError(TotpCliError):
    pass


class CommandParseError(TotpCliError):
    pass
```

## 6. KeyManager

### KeyManagerの責務

- AES-256用の32バイト鍵を生成する
- 鍵ファイルを読み込む
- 鍵サイズと形式を検証する
- CLI、環境変数、設定ファイルから鍵パスを解決する
- 通常の読み込み処理では、外部にある鍵ファイルの存在、形式、読み取り可否を検証する
- initとrekeyでは、指定された外部パスへ新規鍵を生成・保存する

### KeyManagerのインターフェース定義

```python
class KeyManager:
    def __init__(
        self,
        file_system: FileSystem,
        path_resolver: PathResolver,
    ) -> None:
        ...

    def generate_key(self) -> bytes:
        """暗号学的に安全な32バイト鍵を生成する"""
        ...

    def create_key_file(self, path: Path, key: bytes | None = None) -> None:
        """鍵を生成または受け取り、安全に一時保存して指定パスへ配置する"""
        ...

    def rotate_key_file(self, path: Path, new_key: bytes) -> Path:
        """
        既存鍵を世代番号付きファイルへ繰り上げ、最古の鍵を必要に応じて削除し、
        新鍵をpathへ保存する。
        上限到達時の削除は、呼び出し元の対話確認後に実行する。
        """
        ...

    def rotated_key_paths(self, path: Path, max_generations: int = 3) -> list[Path]:
        """path.1からpath.Nまでのローテーション対象パスを返す"""
        ...

    def check_existing_key(self, path: Path) -> bool:
        """指定パスに既存の鍵ファイルがあるか確認する"""
        ...

    def verify_key_file(self, path: Path) -> None:
        """外部指定された既存の鍵ファイルを検証する"""
        ...

    def load_key(self, path: Path) -> bytes:
        """鍵を読み込み、32バイトであることを検証する"""
        ...

    def resolve_key_path(
        self,
        cli_path: Path | None,
        config_path: Path | None,
        environment_path: Path | None,
    ) -> Path:
        """
        優先順位:
        1. CLIオプション --key
        2. VTOTP_KEY_PATH
        3. config.json
        4. パス未指定としてエラー
        """
        ...

    def validate_key_file(self, path: Path) -> None:
        """存在、通常ファイル、サイズ、読み取り可否を検証する"""
        ...

    def set_private_permissions(self, path: Path) -> None:
        """鍵ファイルを実行ユーザーだけが読み書きできる状態にする"""
        ...
```

### 鍵ファイル保存とパーミッション制御

鍵の新規作成・更新は、既存ファイルを直接開かず、対象パスと同じディレクトリに
一時ファイルを作成してから `os.replace` で配置する。`create_key_file` と
`rotate_key_file` は次の共通フローを使用する。

```text
1. 親ディレクトリを作成または検証する。
2. 予測困難な名前の一時ファイルを同一ディレクトリに排他的に作成する。
3. 一時ファイルに実行ユーザー専用のパーミッション/ACLを設定する。
4. 鍵を書き込み、flushおよびfsyncを実行する。
5. 32バイトであることを検証し、`os.replace(temp_path, path)` で原子的に配置する。
6. 成功時も失敗時も、一時ファイルが残っていれば削除する。
```

`set_private_permissions` は外部依存パッケージを使用せず、OSごとに次の標準機能を
使う。権限設定は鍵のバイト列を書き込む前に行う。

- **Unix系:** `os.chmod(path, 0o600)` を実行する。所有者以外の読み取り・書き込みを
    許可しない。
- **Windows:** `subprocess.run` で標準コマンド `icacls` を呼び出し、継承を無効化して
    現在のユーザーへ明示的な読み取り・書き込み・削除権限だけを付与する。概念上の実行内容は
    次の通りであり、実装では `shell=True` を使わず引数配列として渡す。

    ```text
    <GetSystemDirectoryW()の戻り値>\icacls.exe <path> /inheritance:r /grant:r "*<現在のユーザーSID>:(R,W,D)"
    ```

    `icacls.exe` のパスは `GetSystemDirectoryW` で取得した System32 の絶対パスから構成し、
    `SystemRoot` 等の環境変数や PATH 検索には依存しない。ACL の付与先は環境変数や
    `getpass.getuser()` から推測せず、`OpenProcessToken` と `GetTokenInformation(TokenUser)`
    で取得したプロセストークンの真のユーザー SID を使用する。SID は `icacls` が受け付ける
    `*S-1-...` 形式で引数配列に渡す。Win32 API の取得失敗も `KeyStorageError` として処理を
    中断する。`subprocess.run(..., check=True, capture_output=True)` で終了コードを検査し、
    標準出力・標準エラーには鍵の内容を含めず、失敗時のコマンド出力もユーザー向け例外へ
    そのまま流さない。

  - `D`（削除）を含めるのは、親フォルダの権限が「変更」のみ（子の削除権限なし）の
    環境で、`(R,W)` だけでは `os.replace` による配置・世代繰り上げ・一時ファイル
    削除が拒否されるためである。付与先は実行ユーザーのみであり、排他性は変わらない。
  - 親フォルダから継承可能な権限がない場合など、OSまたはトークンの既定 DACL から付与
    される `SYSTEM`、`Administrators`、`OWNER RIGHTS` の ACE、および現在のログオン
    セッションを表す Logon SID（`S-1-5-5-...`）の ACE は残存を許容する。これらは
    Windows の管理・所有者・セッションに結び付くエントリであり、任意の一般ユーザーへ
    アクセスを許可するものではない。これらの ACE を除く一般ユーザーのアクセスは遮断
    されていなければならない。

ACLまたは `chmod`、一時ファイル作成、書き込み、atomic replace のいずれかが失敗した
場合は、既存の `pass` で握りつぶさない。`OSError`、`subprocess.CalledProcessError`
等を秘密情報を含まない `KeyStorageError` へ変換して処理を中断する。一時ファイルの
削除を `finally` で試み、削除自体にも失敗した場合は元のエラーを優先しつつ、ログには
鍵の内容を出さない。保存完了前に失敗した場合、既存の正式な鍵ファイルは変更しない。

通常の `load_key` / `verify_key_file` の読み込み経路では、パーミッションやACLの検査を
強制しない。FAT32 / exFAT のUSBメディアではUnixモードビットやWindows ACLが期待通り
に保持されないためであり、読み取り時は存在、通常ファイル、読み取り可否、32バイトの
形式だけを検証する。排他的なパーミッション設定は、鍵ファイルを生成・保存する処理
に限定する。

鍵の内容を例外メッセージ、ログ、サブプロセス出力へ含めない。

## 7. SecureStorage

### SecureStorageの責務

- 暗号化JSONの読み込みと復号
- JSONデータの暗号化
- 一時ファイルを利用したatomic保存
- 再暗号化
- 暗号文の形式・バージョン検証

### SecureStorageのインターフェース定義

```python
class SecureStorage:
    def __init__(
        self,
        file_system: FileSystem,
        serializer: JsonSerializer,
    ) -> None:
        ...

    def initialize(self, path: Path, key: bytes) -> None:
        """空のサービスデータを暗号化して新規作成する"""
        ...

    def load(
        self,
        path: Path,
        key: bytes,
    ) -> dict[str, SecretRecord]:
        """暗号化ファイルを復号してサービス情報を返す"""
        ...

    def save(
        self,
        path: Path,
        key: bytes,
        records: dict[str, SecretRecord],
    ) -> None:
        """サービス情報を暗号化し、atomicに保存する"""
        ...

    def prepare_rekey(
        self,
        path: Path,
        old_key: bytes,
        new_key: bytes,
    ) -> Path:
        """新鍵で再暗号化した一時ファイルを作成し、検証済みパスを返す"""
        ...

    def commit_rekey(self, path: Path, prepared_path: Path) -> None:
        """検証済みの再暗号化データをatomicに正式ファイルへ置き換える"""
        ...

    def encrypt(
        self,
        payload: bytes,
        key: bytes,
    ) -> EncryptedPayload:
        ...

    def decrypt(
        self,
        encrypted_payload: EncryptedPayload,
        key: bytes,
    ) -> bytes:
        ...
```

### 保存処理の擬似フロー

```text
1. サービス情報をJSONへシリアライズ
2. 32バイト鍵をAES-256-GCMへ渡す
3. 暗号学的に安全なnonceを生成
4. JSONを暗号化
5. メタデータと暗号文を一時ファイルへ書き込む
6. ファイル内容を検証
7. atomic renameで正式ファイルへ置き換える
8. 一時ファイルを削除する
```

### セキュリティ要件

```text
- GCMの認証タグ検証に失敗した場合は復号を中止する
- 破損データを空データとして扱わない
- 復号失敗時に別の鍵で再試行しない
- 保存途中のプロセス終了で既存ファイルを破壊しない
- 復号済みJSONを平文ファイルへ書き込まない
```

## 8. TotpGenerator

### TotpGeneratorの責務

- Base32形式のTOTPシークレットを検証する
- RFC 6238準拠のコードを生成する
- 桁数、時間ステップ、アルゴリズムを管理する

### TotpGeneratorのインターフェース定義

```python
class TotpGenerator:
    def __init__(
        self,
        clock: Clock,
        digits: int = 6,
        interval_seconds: int = 30,
        algorithm: str = "SHA1",
    ) -> None:
        ...

    def validate_secret(self, secret: str) -> None:
        """Base32シークレットの形式を検証する"""
        ...

    def generate(self, secret: str) -> str:
        """現在時刻に対応するTOTPコードを生成する"""
        ...

    def remaining_seconds(self) -> int:
        """現在のTOTP有効期間の残り秒数を返す"""
        ...
```

## 9. ConfigManager

```python
class ConfigManager:
    def __init__(
        self,
        file_system: FileSystem,
        environment: Environment,
    ) -> None:
        ...

    def load(self, path: Path) -> AppConfig:
        """config.jsonを読み込む"""
        ...

    def save_key_path(self, path: Path, key_path: Path) -> None:
        """initでのみconfig.jsonのkey_pathを更新する"""
        ...

    def resolve(
        self,
        config_path: Path | None,
        cli_key_path: Path | None,
        cli_storage_path: Path | None,
    ) -> AppConfig:
        """CLI、環境変数、設定ファイル、既定値を統合して解決する"""
        ...
```

### パスの優先順位

```text
鍵パス:
1. --key
2. VTOTP_KEY_PATH
3. config.jsonのkey_path
4. 未指定としてエラー

データファイルパス:
1. --storage
2. config.jsonのstorage_path
3. config.jsonと同じディレクトリのvtotp-secrets.enc
```

`storage_path` が `config.json` に指定されていない場合でもエラーにはせず、
設定ファイルと同じディレクトリ直下の `vtotp-secrets.enc` を既定値として使用する。

## 10. ServiceRegistry

```python
class ServiceRegistry:
    def get(
        self,
        records: dict[str, SecretRecord],
        service_name: str,
    ) -> SecretRecord:
        ...

    def list_names(
        self,
        records: dict[str, SecretRecord],
    ) -> list[str]:
        """サービス名だけを返し、シークレットは返さない"""
        ...

    def add_or_update(
        self,
        records: dict[str, SecretRecord],
        record: SecretRecord,
    ) -> dict[str, SecretRecord]:
        ...

    def remove(
        self,
        records: dict[str, SecretRecord],
        service_name: str,
    ) -> dict[str, SecretRecord]:
        ...
```

## 11. CliHandler

### CliHandlerの責務

- CLI引数の初期取得
- 省略形コマンドの判定
- 予約サブコマンドとの衝突回避
- argparseによる正式な引数解析
- CLI例外のユーザー向けメッセージへの変換

### CliHandlerのインターフェース定義

```python
class CliHandler:
    RESERVED_COMMANDS = {
        "init",
        "generate",
        "get",
        "add",
        "remove",
        "rm",
        "list",
        "ls",
        "rekey",
        "config",
        "-g",
        "-h",
        "--help",
        "--version",
    }

    def __init__(
        self,
        parser_factory: ParserFactory,
        command_dispatcher: CommandDispatcher,
    ) -> None:
        ...

    def run(self, argv: list[str]) -> int:
        """CLI全体のエントリーポイント"""
        ...

    def normalize_argv(self, argv: list[str]) -> list[str]:
        """省略形を正式なgenerateコマンドへ変換する"""
        ...

    def prompt_for_key_output_path(self) -> Path:
        """initで--key未指定時に鍵の出力先を対話入力で取得する"""
        ...

    def confirm_existing_key_warning(self, path: Path) -> bool:
        """既存鍵の上書きに関する第1警告を確認する"""
        ...

    def confirm_decryption_loss_warning(self, path: Path) -> bool:
        """既存シークレットを復号できなくなる第2警告を確認する"""
        ...

    def confirm_rotation_limit_warning(self, path: Path) -> bool:
        """最古の鍵を削除するローテーション上限警告を確認する"""
        ...

    def parse(self, argv: list[str]) -> ParsedCommand:
        """正規化後の引数を解析する"""
        ...

    def reject_deprecated_secret_args(self, argv: list[str]) -> None:
        """addの廃止済みシークレット引数を安全に検知する"""
        ...

    def dispatch(self, command: ParsedCommand) -> int:
        """解析済みコマンドをユースケースへ委譲する"""
        ...

    def handle_error(self, error: Exception) -> int:
        """安全なエラー表示と終了コード変換"""
        ...
```

`run()` は引数を正規化した後、実行されたサブコマンドや引数位置（前置・後置）に
関わらず、CLI引数列全体（`argv`）を `argparse` に渡す前に
`reject_deprecated_secret_args()` で事前検査する。`--secret` / `-s` が指定されていたら、
引数列や該当値を表示・ログ出力・例外コンテキストへ複製せず、固定の
`SECRET_ARG_DEPRECATED` を持つ `CommandParseError` に変換する。これにより、
`argparse` 標準の `unrecognized arguments: ...` が秘密値をエコーバックする経路を遮断する。

## 12. CLIコマンド定義

```text
vtotp init [--key PATH]

vtotp generate SERVICE [--key PATH] [--storage PATH]
vtotp get SERVICE [--key PATH] [--storage PATH]
vtotp -g SERVICE [--key PATH] [--storage PATH]

vtotp add SERVICE [--issuer ISSUER] [--stdin] [--key PATH] [--storage PATH]

vtotp remove SERVICE [--force]
                    [--key PATH] [--storage PATH]
vtotp rm SERVICE [--force]
                 [--key PATH] [--storage PATH]

vtotp list [--key PATH] [--storage PATH]
vtotp ls [--key PATH] [--storage PATH]

vtotp rekey [--key PATH] [--storage PATH]

vtotp config
```

`config` は、現在解決される `config.json` のパス、マスター鍵パス、
暗号化ストレージパスを表示する。鍵の内容やTOTPシークレットは表示しない。

### パスオプションの扱い

`--key` と `--storage` は、暗号鍵ファイルと暗号化済みTOTPシークレットファイルのパスを実行時に一時指定するオプションとして正式に提供する。`--key` を指定しない場合は、`VTOTP_KEY_PATH`、`config.json` の `key_path` の順に解決する。`--storage` を指定しない場合は、`config.json` の `storage_path`、設定ファイルと同じディレクトリの `vtotp-secrets.enc` の順に解決する。これらのオプションによる変更は実行中だけ有効で、`config.json` へ保存しない。

これらのオプションは、サブコマンドまたはサービス名の後方にのみ配置する。第一引数を固定するため、`SERVICE`より前の配置は受け付けない。

```text
# 正式な形式
vtotp get github --key PATH --storage PATH
vtotp rm github --force --key PATH --storage PATH

# 非サポート（終了コード2）
vtotp get --key PATH github
vtotp rm --force --key PATH github
```

`SERVICE`はサブコマンド直後の必須位置引数とし、`--key`、`--storage`、`--force`などはその後方だけで受け付ける。

`init` の `--key` は、新規鍵ファイルの出力先を指定する。`init` では `--storage` を受け付けない。暗号化データの保存先は `config.json` の `storage_path`、または未指定時の既定値（設定ファイルと同じディレクトリの `vtotp-secrets.enc`）を使用し、初期化時に既存の暗号化データを復号しない。

`--key` が指定されない場合は、対話入力で出力先を尋ね、入力された外部パスへ新規鍵を保存する。出力先が空の場合やキャンセルされた場合は初期化を中止する。`init` は生成した鍵のパスだけを `config.json` の `key_path` に保存する。

`init` の鍵出力先に既存ファイルがある場合は、上書き前に次の二段階確認を行う。

```text
1. 第1警告:
    指定された場所には既に鍵ファイルが存在する。新しい鍵で上書きするか確認する。

2. 第2警告:
    上書きすると、既存の暗号化データを現在の鍵で復号できなくなる可能性がある。
    既存のシークレットを失う危険を理解した上で続行するか確認する。

どちらか一方でも拒否、空入力、キャンセルされた場合は、鍵を上書きせず初期化を中止する。
```

`rekey` は、解決された鍵パスの鍵ファイル自体を更新する。`--key` が指定された場合はそのパスを一時的な更新対象として使用し、指定されない場合は `config.json` の `key_path` を使用する。`--key` による更新対象の変更は `config.json` に保存しない。

更新前の鍵ファイルは世代番号付きのファイルへ繰り上げ、同じ `<key_path>` に新しい鍵ファイルを配置する。暗号化済みTOTPシークレットデータはローテーション保存せず、同じ `storage_path` のファイルを新鍵でatomicに再暗号化する。

### 鍵ファイルのローテーション規則

```text
現在の鍵:       <key_path>
直前の鍵:       <key_path>.1
2世代前の鍵:    <key_path>.2
3世代前の鍵:    <key_path>.3
```

`MAX_ROTATED_KEYS = 3` とし、rekeyのたびに既存の鍵を次の世代へ繰り上げる。

```text
<key_path>.2 -> <key_path>.3
<key_path>.1 -> <key_path>.2
<key_path>   -> <key_path>.1
新鍵         -> <key_path>
```

`<key_path>.3` が存在する場合は、最初に次の警告を表示する。専用の強制オプションは設けない。

```text
第1警告:
ローテーション上限に達したため、最も古い鍵ファイル
<key_path>.3 を削除します。

第2警告:
この鍵を必要とするバックアップや過去の暗号化データは、
今後復号できなくなる可能性があります。続行しますか？
```

続行の明示応答が得られた場合だけ `<key_path>.3` を削除して繰り上げを実行し、拒否、空入力、キャンセルの場合はrekeyを中止する。暗号化済みTOTPシークレットファイルには `.1`、`.2`、`.3` のローテーションを作成しない。

### rekeyの鍵パス

`rekey` では旧鍵と新鍵を別々の引数で指定しない。更新対象のパスだけを指定する。

```text
vtotp rekey \
    --key KEY_PATH \
  --storage STORAGE_PATH
```

`--storage` を指定しない場合は `config.json` の `storage_path`、または設定ファイルと同じディレクトリの `vtotp-secrets.enc` を使用する。`--key` を指定しない場合は `config.json` の `key_path` を更新対象とする。

## 13. 省略形コマンドのフォールバック処理

### 予約サブコマンド

```text
init
generate
get
-g
add
remove
rm
list
ls
rekey
config
-h
--help
--version
```

### ロジックフロー

```text
入力:
    argv = ["github"]

1. argvが空か確認
   - 空の場合、helpを表示して終了

2. 第一引数を取得
   first = argv[0]

3. 第一引数がオプションか確認
   - -h、--help、--versionなどの場合、argparseへそのまま渡す

4. 第一引数が予約サブコマンドか確認
   - 予約済みの場合、argvを変更せず正式なサブコマンドとして解析する

5. 第一引数が予約サブコマンドでない場合
   - サービス名と判定する
   - argvを次のように変換する

       ["github", "--key", "keyfile"]
       ↓
       ["generate", "github", "--key", "keyfile"]

6. 変換後のargvをargparseへ渡す

7. ParsedCommandをCommandDispatcherへ渡す

8. generate処理を実行する

9. 成功時はTOTPコードだけを標準出力へ出力し、終了コード0を返す

10. 失敗時は秘密情報を含まないエラーを標準エラーへ出力する
```

### 擬似コード

```python
RESERVED_COMMANDS = {
    "init",
    "generate",
    "get",
    "add",
    "remove",
    "rm",
    "list",
    "ls",
    "rekey",
    "-h",
    "--help",
    "--version",
}


def normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return ["--help"]

    first = argv[0]

    if first in RESERVED_COMMANDS:
        return argv

    if first.startswith("-"):
        return argv

    return ["generate", first, *argv[1:]]
```

### コマンド名とサービス名が衝突する場合

```text
vtotp init
```

これはサービス名 `init` ではなく、予約サブコマンドとして扱う。サービス名が `init` の場合は、次のように明示する。

```text
vtotp get init
vtotp generate init
```

## 14. コマンド実行の依存関係

### generate / get

```text
CliHandler
    -> ConfigManager
    -> KeyManager.load_key()
    -> SecureStorage.load()
    -> ServiceRegistry.get()
    -> TotpGenerator.generate()
    -> OutputWriter.write_code()
```

### add

```text
CliHandler
    -> ConfigManager
    -> KeyManager.load_key()
    -> SecureStorage.load()
    -> シークレット入力経路の判定
         --stdin指定時: SecretInputReader.read_secret()
             標準入力をUTF-8として読み込み、先頭のUTF-8 BOM（U+FEFF、多重付与を含む）と末尾のCR/LF改行を除去する（マスキングなし）
         --stdin未指定時: 標準入力のTTY判定
             非TTY: STDIN_OPTION_REQUIREDで終了コード2、対話入力を待たずに終了
             TTY: SecretInputReader.read_secret()でマスキング入力し、空入力時はキャンセルする
    -> TotpGenerator.validate_secret()
    -> ServiceRegistry.add_or_update()
    -> SecureStorage.save()
```

### init

```text
CliHandler
    -> ConfigManager
    -> CliHandler.prompt_for_key_output_path()  # --key未指定時のみ
    -> KeyManager.check_existing_key(key_output_path)
    -> CliHandler.confirm_existing_key_warning()  # 既存の場合のみ、第1警告
    -> CliHandler.confirm_decryption_loss_warning()  # 既存の場合のみ、第2警告
    -> KeyManager.create_key_file(key_output_path)
    -> SecureStorage.initialize()
    -> ConfigManager.save_key_path(config_path, key_output_path)
```

`init` では `config.json` の `key_path` だけを更新する。暗号化データの保存先は `config.json` の `storage_path`、または未指定時の既定値（設定ファイルと同じディレクトリの `vtotp-secrets.enc`）を使用し、初期化時に既存の暗号化データを復号しない。

### rekey

```text
CliHandler
    -> ConfigManager
    -> ConfigManager.resolve(cli_key_path, cli_storage_path)
    -> KeyManager.load_key(target_key_path)
    -> KeyManager.generate_key()
    -> SecureStorage.prepare_rekey(storage_path, old_key, new_key)
    -> CliHandler.confirm_rotation_limit_warning(target_key_path)  # .3が存在する場合のみ
    -> KeyManager.rotate_key_file(target_key_path, new_key)
    -> SecureStorage.commit_rekey(storage_path, prepared_path)
```

`rekey`では、まず対象世代と上限到達の有無を確認する。上限警告に続行応答が得られた場合、旧鍵でデータを復号して新鍵で暗号化した一時ファイルを作成・検証し、その後に鍵ファイルを世代番号付きで繰り上げ、新鍵を `<key_path>` へ配置し、暗号化データをatomicに置き換える。警告への明示的な続行応答がない場合は開始前に中止する。暗号化済みシークレットデータにはローテーション用の `.1`、`.2`、`.3` を作成しない。`rekey`完了後も `config.json` は変更しない。

### config

```text
CliHandler
    -> ConfigManager
    -> KeyManager.resolve_key_path()
    -> CliHandler._resolve_storage_path()
    -> OutputWriter.write_config()
```

`config` は、`config.json` のパス、鍵パス、暗号化ストレージパスを表示する。
鍵の内容やTOTPシークレットは表示しない。鍵パスが未設定の場合は、鍵パスを
`(未設定)` と表示し、ストレージパスは通常の既定値解決結果を表示する。

## 15. 終了コード

```text
0   成功
1   一般エラー
2   CLI引数エラー
3   鍵ファイル不在・不正
4   暗号化データ破損または復号失敗
5   指定サービス未登録
6   TOTPシークレット不正
7   ユーザーキャンセル
```

鍵ファイルの保存、一時ファイル処理、UnixパーミッションまたはWindows ACL設定の失敗は
`KeyStorageError` とし、一般的なファイル I/O 失敗として終了コード `1` を返す。
終了コード `3` は鍵ファイルの不在または形式不正に限る。

## 16. テスト設計

### Unit Test

```text
- 32バイト鍵が生成される
- 不正サイズの鍵を拒否する
- 暗号化と復号で元データが復元される
- 改ざんされた暗号文を拒否する
- サービスの追加・更新・削除が機能する
- TOTPコードが固定時刻で期待値になる
- 予約コマンドがgenerateへ変換されない
- 未予約語がgenerateへ変換される
- --helpや--versionがフォールバックされない
```

### Integration Test

```text
- initからgenerateまでの一連の操作
- addからlistまでの操作
- removeの確認処理と--force
- rekey後も既存サービスのTOTPが生成できる
- rekey後の鍵ファイルが同じパスに配置される
- rekey前の鍵ファイルが`<key_path>.1`へ退避される
- 既存の`.1`、`.2`が正しい世代へ繰り上げられる
- `<key_path>.3`が存在する場合は上限警告を表示する
- 上限警告への明示的な続行応答がない場合はrekeyを中止する
- 上限警告で続行した場合だけ`<key_path>.3`を削除する
- rekey後の暗号化データにローテーション用の`.1`ファイルを作成しない
- 旧鍵ではrekey後の暗号化データを復号できない
- `--key`指定時は対象パスだけが更新され、config.jsonが変更されない
- 鍵ファイルがない場合の終了コード
- 暗号化ファイルが破損した場合の終了コード
- Windows形式のパスを扱える
```

## 17. セキュリティ上の留意点

```text
- 復号された平文シークレットおよび秘密鍵はディスクへ永続化せず、必要な処理スコープ内だけで一時的に扱う。
  処理終了後は参照を速やかに破棄し、秘密情報をメモリ上に保持する時間と範囲を最小化する。

- PythonインタプリタおよびNuitkaコンパイル後を含むネイティブ実行環境では、
  ガベージコレクションやイミュータブルオブジェクト等のメモリ管理上の特性により、
  プロセス実行中のメモリから秘密情報を完全にゼロ化できるとは限らない。
  そのため、実行中のメモリダンプやデバッガによるインメモリ解析に対する
  完全なメモリ消去・漏洩耐性を保証するものではない。

- 本設計の境界は、秘密情報をディスクへ永続化しないこと、および必要な処理スコープに
  扱いを限定することにある。インメモリの完全なゼロ化や、プロセス実行中の解析に対する
  完全な防御を保証するものではない。

- 秘密情報を例外メッセージ、デバッグログ、argparseのusage表示へ混入させない。

- コマンドライン引数による平文シークレットの直接受け渡しは全面的に廃止・禁止し、シェル履歴、OSのプロセス一覧、プロセス監査ログへの露出を根本排除する。

- 暗号化ファイルには認証付き暗号を使用する。

- ファイル保存は一時ファイルとatomic renameを利用する。

- サービス名は空文字、パス区切り、制御文字を拒否する。

- listではサービス名だけを出力し、シークレットを表示しない。

- 鍵ファイルと暗号化データを同一媒体に置く場合、端末固定の保護強度が
  下がるため、運用ドキュメントで明示する。
```

## 18. パッケージング・バイナリ保護設計

### 18.1 採用方式

配布用バイナリは、従来の PyInstaller 方式から Nuitka 方式へ全面的に移行する。
PyInstaller のように Python バイトコードをアーカイブへ同梱する方式は採用せず、
Nuitka で Python ソースを C 言語相当の中間コードへ変換し、対象プラットフォームの
C/C++ コンパイラでネイティブバイナリへコンパイルする。これにより、一般的な
Python バイトコードデコンパイラによるソース復元を困難にする。

これは暗号鍵、TOTPシークレット、復号済みデータをバイナリへ埋め込む設計ではない。
鍵と暗号化ストレージは従来どおり外部ファイルとして扱い、Zero Leakage Ruleを
維持する。Nuitka化による保護はリバースエンジニアリングのコストを上げるものであり、
ネイティブバイナリからの解析を完全に不可能にするものではない。

### 18.2 エントリポイントとビルドパラメータ

Nuitka の入力は、インストール済みコンソールスクリプトではなく、アプリケーションの
実行契約が明確な `src/vtotp/__main__.py` とする。`__main__.py` の `main()` が返す
終了コードを、生成バイナリのプロセス終了コードとして保持する。

標準のリリースビルドは次のパラメータを必須とする。

```text
python -m nuitka \
    --standalone \
    --onefile \
    --assume-yes-for-downloads \
    --output-dir=dist \
    --output-filename=vtotp \
    --include-package=vtotp \
    --include-package=cryptography \
    src/vtotp/__main__.py
```

`--standalone` は Python ランタイムと依存モジュールを配布物へ含め、
`--onefile` はそれらを単一の実行ファイルへ格納する。Windows では出力を
`dist/vtotp.exe`、Linux と macOS では `dist/vtotp` とする。`--output-filename`
はプラットフォーム間で成果物名を統一するために指定する。

`cryptography` は AES-GCM の C/Rust 拡張およびその実行時依存を含むため、Nuitkaの
自動解析に加えて `--include-package=cryptography` を指定する。アプリケーション
パッケージ全体も `--include-package=vtotp` で明示的に含める。ビルドログで除外された
モジュールがないことを確認し、暗号化・復号を実行するスモークテストで依存バンドルの
完全性を検証する。

### 18.3 ビルド環境と依存定義

リリースランナーには、次の C/C++ コンパイラを用意する。

| プラットフォーム | 推奨コンパイラ | Nuitkaの指定 | 成果物 |
| --- | --- | --- | --- |
| Windows | MSVC（推奨）または MinGW64 | MSVCは既定、MinGW64は `--mingw64` | `dist/vtotp.exe` |
| Linux | GCC または Clang | Clang使用時は `--clang` | `dist/vtotp` |
| macOS | Xcode Command Line Tools の Clang | `--clang` | `dist/vtotp` |

Windows の GitHub Actions `windows-latest` では MSVC を標準コンパイラとして使用し、
別のツールチェーンを明示的に導入しない。Linux と macOS では標準イメージの GCC/
Clang を使用し、必要な開発ヘッダーを先に導入する。コンパイラの切り替えは、同じ
リリース成果物内で混在させず、プラットフォームごとに固定する。

`pyproject.toml` では、PyInstaller をランタイム依存にも開発依存にも残さない。
Nuitka は実行時ライブラリではなくビルドツールなので、ビルド用の任意依存グループへ
追加する。`zstandard` は Nuitka の圧縮・展開を高速化するため同じグループへ追加する。
方針は次のとおりとする。

```toml
[project.optional-dependencies]
build = [
        "nuitka>=2.6",
        "zstandard>=0.23",
]
dev = [
        "pytest>=7.4",
        "pytest-cov>=4.1",
        "black>=24.0",
        "flake8>=7.0",
        "mypy>=1.8",
]
```

CI は `pip install -e ".[build]"` でビルド依存を導入し、アプリケーションの実行時
依存は引き続き `cryptography` だけを `project.dependencies` に置く。Nuitkaのメジャー
アップデートは、ビルドログ、スモークテスト、成果物の実行確認を通過した場合だけ採用する。

### 18.4 GitHub Actions リリースパイプライン

`.github/workflows/release.yml` はタグ `v*` を起点とし、Windows x64向けに
Standalone ZIP版とOnefile EXE版を同一リリースで生成する。PEの
`FileVersion`/`ProductVersion`はタグの3要素を抽出し、末尾のビルド番号
（プライベートパート）を常に`.0`に固定した4要素形式として埋め込む。
タグはプロモーション方式に従い、最初から正式版タグ名（`vX.Y.Z`、例:
`v0.2.0`）を使用し、プレリリース識別子（`-preview.x`、`-rc.x`等）は付与しない。
したがって、正式な`v0.2.0`タグは`0.2.0.0`として埋め込まれる。なお、CIは
防御的設計として、誤ってハイフン付きタグがpushされた場合でも安定版部分を切り捨て、
`0.2.0.0`のような数値4要素形式へ正規化する。

実行順序は次のとおりとする。

```text
1. actions/checkout
2. actions/setup-python（Python 3.11）
3. windows-latest の MSVC ツールチェーンを確認
4. pip install -e ".[build]"
5. Nuitkaの`--standalone`でフォルダ形式をビルド
6. Standaloneフォルダを`vtotp-windows-x64.zip`へパッケージ化
7. Nuitkaの`--standalone --onefile`で`vtotp.exe`をビルド
8. Standalone本体、ZIP展開後の実行ファイル、Onefile実行ファイルをスモークテスト
9. 両成果物と各SHA-256 sidecarを生成し、再計算で検証
10. EXE、ZIP、各sidecarをActions artifactへアップロード
11. Actions artifactをダウンロードして再検証
12. GitHub Releaseへ常にPre-releaseとして公開
```

Windowsリリースの必須成果物は次の4ファイルとする。

```text
dist/vtotp.exe
dist/vtotp.exe.sha256
dist/vtotp-windows-x64.zip
dist/vtotp-windows-x64.zip.sha256
```

各成果物のアップロード設定には`if-no-files-found: error`を指定する。これにより、
ビルド自体が成功しても出力名、ZIP内容、チェックサムsidecarのいずれかが欠落した
場合はリリースを失敗させる。Linux/macOSの成果物を追加する場合はプラットフォーム
別ジョブを分け、それぞれの実行環境で検証した成果物だけを公開する。

初期公開は常にGitHub ReleaseのPre-releaseとして行う。AV/SEPの誤検知除外申請、
実機検証、チェックサム確認が完了した後、同じタグと同じ成果物を再ビルドせずに、
`gh release edit <tag> --latest --prerelease=false`またはGitHub UIで手動プロモート
してLatestへ昇格させる。

### 18.5 バイナリスモークテスト

スモークテストは、成果物をアップロードする前にビルドした実行ファイルそのものへ
実行する。Standalone本体、ZIPを一時ディレクトリへ展開した後の実行ファイル、
Onefile EXEの3対象について、各コマンドの終了コード`0`を必須とする。

```powershell
# Standalone本体
$standaloneExe --version
$standaloneExe --help
$standaloneExe init --key "$env:RUNNER_TEMP\vtotp-standalone.key"

# ZIP展開後（配布物そのもの）
Expand-Archive dist\vtotp-windows-x64.zip -DestinationPath "$env:RUNNER_TEMP\vtotp-zip"
$zipExe = Join-Path "$env:RUNNER_TEMP\vtotp-zip" "vtotp.exe"
$zipExe --version
$zipExe --help
$zipExe init --key "$env:RUNNER_TEMP\vtotp-zip.key"

# Onefile EXE
dist\vtotp.exe --version
dist\vtotp.exe --help
dist\vtotp.exe init --key "$env:RUNNER_TEMP\vtotp-onefile.key"
```

各対象について、`init`後に32バイト鍵、`config.json`、暗号化ストレージが生成され、
出力に鍵バイト列・TOTPシークレット・トレースバック・未処理エラーが含まれないことも
検証する。ZIP展開後のテストは、圧縮前のStandaloneディレクトリだけでなく、実際に
配布するZIPが欠損なく実行可能であることを保証する。

`init` の検証では、次の条件を追加で確認する。

```text
- コマンドが終了コード0で完了する
- RUNNER_TEMP 配下に32バイトの鍵ファイルが生成される
- config.json と暗号化ストレージの初期化が完了する
- stdout/stderr に鍵の内容やTOTPシークレットが出力されない
- Python トレースバックや未処理の例外が出力されない
```

CIの一時ディレクトリを使い、開発者のホームディレクトリやリポジトリへ秘密情報を
生成しない。WindowsではPowerShellの`$LASTEXITCODE`またはActionsのコマンド終了
コードで判定し、Python実行時ではなく各Nuitka生成物を直接起動して検証する。

### 18.6 設計上の完了条件

```text
- PyInstallerの実行、依存、CIステップがリポジトリから除去されている
- Windowsのハイブリッド成果物（`vtotp-windows-x64.zip`、`vtotp.exe`）と、
    それぞれのSHA-256 sidecarが生成・検証・公開される
- Standalone/OnefileのNuitkaビルドが毎回再現可能である
- 両形態およびZIP展開後の実行ファイルで、cryptographyを含む暗号処理が動作する
- Standalone本体、ZIP展開後、Onefileそれぞれの`--version`、`--help`、`init`がCIで成功する
- Windows PEの会社名、製品名、説明、著作権が設定され、バージョンが数値4要素で
    末尾`.0`固定（`X.Y.Z.0`）としてタグ由来値と一致する
- 初期リリースが常にPre-releaseで公開され、検証・誤検知除外後に再ビルドなしで
    Latestへ手動プロモートできる
- バイナリ実行時もZero Leakage Ruleと終了コード体系が維持される
```

## 19. 多言語化詳細設計

### 19.1 パッケージ構成と型契約

実行時に読み込む翻訳ファイルを持たず、翻訳文をPythonコードとしてNuitkaの対象に含める。
新設するパッケージは次の構成とする。

```text
src/vtotp/i18n/
├── __init__.py
├── catalog.py
└── resolver.py
```

`catalog.py` は次の型を公開する。`MsgKey` は全てのユーザー向けメッセージを列挙し、
辞書のキーを文字列リテラルで重複定義しない。

```python
from enum import StrEnum
from typing import Mapping


class MsgKey(StrEnum):
    APP_DESCRIPTION = "app_description"
    KEY_NOT_FOUND = "key_not_found"
    INVALID_KEY = "invalid_key"
    STORAGE_CORRUPTED = "storage_corrupted"
    SERVICE_NOT_FOUND = "service_not_found"
    INVALID_SECRET = "invalid_secret"
    COMMAND_PARSE_ERROR = "command_parse_error"
    SECRET_ARG_DEPRECATED = "secret_arg_deprecated"
    STDIN_OPTION_REQUIRED = "stdin_option_required"
    CONFIG_SUMMARY = "config_summary"
    CONFIG_LANGUAGE_UPDATED = "config_language_updated"


Catalog = Mapping[MsgKey, str]
EN_CATALOG: Catalog = {
    # 他のメッセージキーは省略
    MsgKey.SECRET_ARG_DEPRECATED: "The --secret/-s option has been removed for security. Use interactive prompt or --stdin.",
    MsgKey.STDIN_OPTION_REQUIRED: "Standard input is not a terminal. Use --stdin to pass secrets via pipe or redirect.",
}
JA_CATALOG: Catalog = {
    # 他のメッセージキーは省略
    MsgKey.SECRET_ARG_DEPRECATED: "--secret/-s オプションはセキュリティのため廃止されました。対話入力または --stdin を使用してください。",
    MsgKey.STDIN_OPTION_REQUIRED: "標準入力がターミナルではありません。パイプやリダイレクトでシークレットを渡す場合は --stdin を指定してください。",
}
SUPPORTED_LANGUAGES = ("en", "ja")
```

英語辞書を既定かつフォールバックとし、日本語辞書も全 `MsgKey` を実装する。
辞書はモジュールロード時に一度だけ生成し、解決処理は辞書参照と文字列フォーマットだけに
限定する。外部ファイル、`gettext` の `.mo`、実行時展開用JSON、ネットワーク取得は使用しない。

### 19.2 言語解決

`LanguageResolver.resolve()` は次の順序で候補を評価する。

```text
1. コマンド引数 --lang/-l
2. 環境変数 VTOTP_LANG
3. config.json の language
4. OSロケール（LANG、LC_ALL、Windowsの既定ロケール）
5. en
```

値は小文字化し、`en-US`、`ja-JP` のようなロケールは主要言語コードへ正規化する。
`en` と `ja` 以外、空文字、不正型は候補として無視し、最終的に必ず `en` を返す。
`init` は解決済み言語を初期値として提示し、`-l/--lang` または対話回答を
`config.json` の `language` に保存する。`config` の表示は解決済み言語を使用する。

`config -l <en|ja>` と `config set language <en|ja>` は同一の更新ユースケースへ委譲し、
更新対象を `language` のみに限定する。更新は一時ファイルと `os.replace` を使い、既存の
`key_path`、`storage_path`、未知の設定項目を保持する。

### 19.3 表示とZero Leakage

表示層は `format_message(key: MsgKey, language: str, **context: str) -> str` を利用する。
`formatter.py` は `MsgKey` と安全な表示コンテキストだけを受け取り、例外文字列をそのまま
表示しない。秘密情報（鍵バイト列、シークレット、暗号文、復号JSON）はコンテキストへ
渡さず、パス名・サービス名も必要な場合だけ含める。OS例外の生メッセージも表示せず、
対応する `MsgKey` と安全なパス表示へ変換する。

## 20. CLI構文と引数解析の正規仕様

### 20.1 第一引数固定と後置オプション

`CliHandler.normalize_argv()` は、空入力をヘルプへ変換し、第一引数だけを判定する。
第一引数は予約サブコマンドまたはサービス名でなければならない。`-h`、`--help`、
`--version` だけは単独情報オプションとして例外扱いする。第一引数が `-l`、`-k`、
`--storage` などの値付きオプションの場合は、サービス名へのフォールバックを行わず、
終了コード2の `CommandParseError` とする。

正規形は次のとおりである。

```text
vtotp <command-or-service> [SERVICE] [options...]
```

`SERVICE` を必要とするコマンドではサブコマンド直後を必須位置引数とし、オプションは
その後方だけで受け付ける。`vtotp get --key PATH github` や `vtotp --lang ja init` は
非サポートであり、解析前に拒否する。`argparse` の親パーサーへ実行オプションを置かず、
各サブパーサーへ定義することで前置配置を防ぐ。

### 20.2 コマンド契約

```text
vtotp init [--key PATH] [--lang en|ja]
vtotp generate SERVICE [--key PATH] [--storage PATH] [--lang en|ja]
vtotp get SERVICE [--key PATH] [--storage PATH] [--lang en|ja]
vtotp add SERVICE [--issuer ISSUER] [--stdin] [--key PATH] [--storage PATH] [--lang en|ja]
vtotp remove SERVICE [--force] [--key PATH] [--storage PATH] [--lang en|ja]
vtotp list [--key PATH] [--storage PATH] [--lang en|ja]
vtotp rekey [--key PATH] [--storage PATH] [--lang en|ja]
vtotp config [-l|--lang en|ja]
vtotp config set language en|ja [--lang en|ja]
```

`-g`、`rm`、`ls` はそれぞれ既存の別名として同じ契約へ正規化する。`config -l/--lang`
は `config set language` と同等に `language` を保存する。設定更新時の表示言語も、
指定された新言語を使用する。

### 20.3 廃止シークレット引数の安全な拒否

CLI引数列全体（`argv`）を `argparse` の解析前に事前走査し、実行されるコマンド名や
引数の指定位置（前置・後置）に関わらず、廃止済みの `--secret`、`-s` および
値を同一トークンに結合した形式・省略形式（`--secret=VALUE`、`-sVALUE`、`--sec`等）を検知する。検知時は
`argparse` に引数を渡さず、`CommandParseError`（終了コード2、メッセージキー
`SECRET_ARG_DEPRECATED`、空のコンテキスト）で直ちに終了する。表示は翻訳済みの固定メッセージ
だけとし、入力された引数列、値、`argparse` の標準エラー文を含めない。これにより、
`unrecognized arguments: ...` によるシークレット値のエコーバックを防ぐ。

### 20.4 非TTY環境での `--stdin` 必須化

`add` で `--stdin` が指定されていない場合、シークレットの対話入力へ進む前に標準入力の
TTY状態を確認する。標準入力がTTYでない（パイプ、リダイレクト、またはTTY判定を提供しない
入力ストリーム）場合は、`STDIN_OPTION_REQUIRED` を持つ `CommandParseError`（終了コード2、
空のコンテキスト）を送出し、プロンプトを表示せず即座に終了する。TTYの場合のみ、
マスキング付きの対話入力を行う。`--stdin` 指定時はこのTTY判定を行わず、標準入力をUTF-8
として読み込み、先頭のUTF-8 BOM（U+FEFF、多重付与を含む）と末尾CR/LF改行を除去した値を
Base32形式の検証へ渡す。

## 21. ドメイン例外と表示層の連携

ドメイン例外は表示文を保持しない。各例外は終了コード、`MsgKey`、および秘密情報を
含まない構造化コンテキストを保持する。

```python
class TotpCliError(Exception):
    exit_code: int
    message_key: MsgKey
    context: Mapping[str, str]


raise KeyNotFoundError(context={"path": display_path})
```

`display_path` は引用符・制御文字を除去した表示用値であり、鍵の内容ではない。
`CliHandler` は例外を捕捉して `formatter.format_error(error, language)` に渡し、終了コード
を維持して `stderr` へ出力する。`str(error)`、traceback、低レベル例外の生メッセージを
ユーザー出力へ流さない。これにより、core/domain層は言語に依存せず、表示層だけが
ローカライズ責務を持つ。

廃止された `--secret` / `-s` の検知には、新たな例外型を設けず `CommandParseError` を使う。
この場合は終了コード `2`、メッセージキー `SECRET_ARG_DEPRECATED`、秘密値や生引数を含まない
空のコンテキストを設定する。表示層はカタログの固定文だけを出力する。

## 22. PEメタデータとリリースCI

### 22.1 NuitkaのWindows仕様

`.github/workflows/release.yml` のWindowsビルドは、タグ名から正規化したアプリケーション
バージョンを取得し、StandaloneとOnefileの両Nuitkaコマンドへ次のメタデータを明示する。

```text
--company-name="vtotp Project"
--product-name="vtotp CLI"
--file-version=<VERSION>
--product-version=<VERSION>
--file-description="Custom CLI TOTP Authenticator"
--copyright="Copyright (c) vtotp Project"
```

`--output-filename=vtotp.exe`、`--standalone`、`--onefile`、`--include-package=vtotp`、
`--include-package=cryptography` を維持する。PEメタデータはレピュテーション改善の
補助情報であり、コード署名や暗号化の代替ではない。正式リリースでは署名導入を別途
検討する。

Standalone版は`--standalone`で生成した実行ファイルと依存ファイル一式を
`vtotp-windows-x64.zip`へ格納する。Onefile版は`--standalone --onefile`で生成し、
`dist/vtotp.exe`として公開する。タグにプレリリース識別子が含まれる場合も、PEには
安定版部分だけを使用し、`X.Y.Z.0`の4要素数値形式へ正規化する。

### 22.2 チェックサムと成果物

Windowsの両成果物をビルド・スモークテストした後、同じ`dist/`内で各ファイルに対して
SHA-256 sidecarを生成する。

```powershell
foreach ($file in @("dist\vtotp.exe", "dist\vtotp-windows-x64.zip")) {
    $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
    $name = Split-Path $file -Leaf
    "$hash  $name" | Set-Content -NoNewline "$file.sha256"
}
```

各sidecarは64桁の小文字SHA-256、二つの空白、対象ファイル名の形式とする。EXE、ZIP、
各`.sha256`をGitHub ReleaseおよびActions artifactへ添付し、CIでファイルの存在と
ハッシュ再計算結果を検証する。アップロード対象が不足した場合は
`if-no-files-found: error`で失敗させる。

### 22.3 リリース順序

```text
checkout -> setup-python -> pip install -e ".[build]"
-> standalone build -> standalone smoke test -> ZIP化 -> ZIP展開後 smoke test
-> onefile build -> onefile smoke test -> PE metadata verification
-> 2成果物 + 2 sidecarのSHA-256生成・検証
-> artifact download後の再検証 -> GitHub ReleaseへPre-release公開
-> AV/実機検証 -> 再ビルドなしで手動Latestプロモート
```

スモークテストは一時ホームディレクトリで実行し、stdoutにTOTP以外の秘密情報、stderrに
鍵バイト列・シークレット・tracebackがないことを確認する。プレビュータグでは同じ検証を
行ったうえでPre-releaseとして公開し、実機検証と誤検知除外申請の完了後に正式タグへ
昇格する。

## 23. i18n・構文・パッケージングのテスト設計

### 23.1 カタログ契約テスト

```text
- set(EN_CATALOG) == set(MsgKey)
- set(JA_CATALOG) == set(MsgKey)
- 各キーの英日プレースホルダー集合が一致する
- 空文字、未翻訳のキー、未知の言語で例外を発生させない
- format_message() が秘密情報を受け取らないAPI契約を満たす
```

プレースホルダー集合は正規表現ではなく `string.Formatter().parse()` で抽出し、書式名を
比較する。これにより `{path}` と `{service}` の不足・余剰を検知する。

### 23.2 CLI・CIテスト

```text
- --lang > VTOTP_LANG > config.language > OS locale > en の解決順
- en-US/ja-JPの正規化と不正値のenフォールバック
- initの言語保存とconfigのlanguage更新
- config -l と config set language の同値性
- 前置オプションを終了コード2で拒否
- 第一引数のサービス名フォールバックと予約語衝突
- 日英の全例外表示が同じ終了コードを返す
- Nuitka実行ファイルのPEメタデータが期待値と一致する
- バイナリとSHA-256 sidecarの内容が一致する
```

既存の `pytest --cov=src/vtotp --cov-fail-under=100` を必須ゲートとし、i18n辞書、
言語解決の全分岐、構文拒否、CI補助スクリプトを単体テストで網羅する。機密値を含む
例外・ログ・CI出力がないことも回帰テストに含める。

## 24. 旧記述との整合規則

本章は本設計書の正規仕様である。特に、旧章に残る「`SERVICE` をオプションより後ろへ
置ける」「configは読み取り専用」「例外が表示文を保持する」という記述は、本章の
第一引数固定、`config` 言語更新、`MsgKey` + context方式に置き換える。鍵パス・ストレージ
パスの解決優先順位、AES-256-GCM、atomic保存、終了コード、Zero Leakage Ruleは既存章を
引き続き適用する。
