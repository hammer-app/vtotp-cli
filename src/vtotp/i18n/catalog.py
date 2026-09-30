"""型安全な多言語メッセージカタログを定義するモジュール。

DESIGN.md 19.1「パッケージ構成と型契約」に基づき、すべての利用者向け
メッセージを :class:`MsgKey`（``StrEnum``）で列挙し、英語（``EN_CATALOG``）
および日本語（``JA_CATALOG``）の辞書として純粋なPythonコード内に内包する。
外部ファイル（``.mo``、実行時展開用JSON等）は一切使用せず、辞書はモジュール
ロード時に一度だけ生成され、解決処理は辞書参照と文字列フォーマットのみに
限定する（ゼロ・オーバーヘッド、Nuitkaコンパイル時の静的構造体化）。
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping


class MsgKey(StrEnum):
    """全ユーザー向けメッセージを列挙する型安全なキー。"""

    APP_DESCRIPTION = "app_description"
    LABEL_ERROR = "label_error"
    LABEL_WARNING = "label_warning"

    KEY_NOT_FOUND = "key_not_found"
    KEY_PATH_NOT_CONFIGURED = "key_path_not_configured"
    KEY_NOT_A_FILE = "key_not_a_file"
    KEY_INVALID_SIZE = "key_invalid_size"
    KEY_INVALID_SIZE_NO_PATH = "key_invalid_size_no_path"
    KEY_PERMISSION_DENIED = "key_permission_denied"
    KEY_UNREADABLE = "key_unreadable"
    KEY_STORAGE_FAILED = "key_storage_failed"
    KEY_PERMISSION_SETUP_FAILED = "key_permission_setup_failed"

    STORAGE_FILE_NOT_FOUND = "storage_file_not_found"
    STORAGE_FILE_UNREADABLE = "storage_file_unreadable"
    STORAGE_FILE_INVALID_FORMAT = "storage_file_invalid_format"
    STORAGE_UNSUPPORTED_VERSION = "storage_unsupported_version"
    STORAGE_UNSUPPORTED_ALGORITHM = "storage_unsupported_algorithm"
    STORAGE_DECRYPTION_FAILED = "storage_decryption_failed"
    STORAGE_INVALID_STRUCTURE = "storage_invalid_structure"
    STORAGE_INVALID_FORMAT = "storage_invalid_format"
    STORAGE_REKEY_VERIFICATION_FAILED = "storage_rekey_verification_failed"

    SERVICE_NOT_FOUND = "service_not_found"
    SERVICE_NAME_EMPTY = "service_name_empty"
    SERVICE_ALREADY_REGISTERED = "service_already_registered"

    SECRET_EMPTY = "secret_empty"
    SECRET_INVALID_FORMAT = "secret_invalid_format"

    COMMAND_PARSE_ERROR = "command_parse_error"
    SERVICE_MUST_PRECEDE_OPTIONS = "service_must_precede_options"
    SECRET_ARG_DEPRECATED = "secret_arg_deprecated"
    PATH_EMPTY = "path_empty"
    PATH_UNCLOSED_QUOTE = "path_unclosed_quote"

    CANCELLED = "cancelled"
    FILE_OPERATION_FAILED = "file_operation_failed"

    INIT_PROMPT_KEY_PATH = "init_prompt_key_path"
    INIT_PROMPT_LANGUAGE = "init_prompt_language"
    INIT_KEY_EXISTS_WARNING = "init_key_exists_warning"
    INIT_DECRYPTION_LOSS_WARNING = "init_decryption_loss_warning"
    INIT_KEY_CREATED = "init_key_created"
    INIT_STORAGE_INITIALIZED = "init_storage_initialized"

    ADD_PROMPT_SECRET = "add_prompt_secret"
    ADD_SERVICE_REGISTERED = "add_service_registered"

    REMOVE_CONFIRM = "remove_confirm"
    REMOVE_SERVICE_REMOVED = "remove_service_removed"

    REKEY_ROTATION_LIMIT_NOTICE = "rekey_rotation_limit_notice"
    REKEY_ROTATION_LIMIT_CONFIRM = "rekey_rotation_limit_confirm"
    REKEY_DONE = "rekey_done"

    CONFIG_SUMMARY = "config_summary"
    CONFIG_KEY_PATH_UNSET = "config_key_path_unset"
    CONFIG_LANGUAGE_UPDATED = "config_language_updated"

    LIST_HEADER_SERVICE = "list_header_service"
    LIST_HEADER_ISSUER = "list_header_issuer"
    LIST_NO_ISSUER_PLACEHOLDER = "list_no_issuer_placeholder"


Catalog = Mapping[MsgKey, str]

#: サポート対象言語コード（優先順位ではなく、対応言語の一覧）。
SUPPORTED_LANGUAGES: tuple[str, ...] = ("en", "ja")

#: 解決に失敗した場合の既定フォールバック言語。
DEFAULT_LANGUAGE: str = "en"

EN_CATALOG: Catalog = {
    MsgKey.APP_DESCRIPTION: "Custom CLI TOTP Authenticator",
    MsgKey.LABEL_ERROR: "Error",
    MsgKey.LABEL_WARNING: "Warning",
    MsgKey.KEY_NOT_FOUND: "Key file not found: {path}",
    MsgKey.KEY_PATH_NOT_CONFIGURED: (
        "Key file path is not configured "
        "(checked --key, VTOTP_KEY_PATH, and config.json)"
    ),
    MsgKey.KEY_NOT_A_FILE: "Key file is not a regular file: {path}",
    MsgKey.KEY_INVALID_SIZE: "Key file has an invalid size (must be 32 bytes): {path}",
    MsgKey.KEY_INVALID_SIZE_NO_PATH: "Key has an invalid size (must be 32 bytes)",
    MsgKey.KEY_PERMISSION_DENIED: "No permission to read the key file: {path}",
    MsgKey.KEY_UNREADABLE: "Could not read the key file: {path}",
    MsgKey.KEY_STORAGE_FAILED: "Failed to save the key file: {path}",
    MsgKey.KEY_PERMISSION_SETUP_FAILED: (
        "Failed to restrict access to the key file to the current user: {path}"
    ),
    MsgKey.STORAGE_FILE_NOT_FOUND: "Encrypted storage file not found: {path}",
    MsgKey.STORAGE_FILE_UNREADABLE: "Could not read the encrypted storage file: {path}",
    MsgKey.STORAGE_FILE_INVALID_FORMAT: (
        "Encrypted storage file has an invalid format: {path}"
    ),
    MsgKey.STORAGE_UNSUPPORTED_VERSION: (
        "Unsupported encrypted storage format version: {version}"
    ),
    MsgKey.STORAGE_UNSUPPORTED_ALGORITHM: (
        "Unsupported encryption algorithm: {algorithm}"
    ),
    MsgKey.STORAGE_DECRYPTION_FAILED: (
        "Failed to verify the encrypted data "
        "(it may be corrupted, tampered with, or the key may be incorrect)"
    ),
    MsgKey.STORAGE_INVALID_STRUCTURE: "Decrypted data has an invalid structure",
    MsgKey.STORAGE_INVALID_FORMAT: "Decrypted data has an invalid format",
    MsgKey.STORAGE_REKEY_VERIFICATION_FAILED: "Failed to verify the re-encrypted data",
    MsgKey.SERVICE_NOT_FOUND: "Service not found: {service}",
    MsgKey.SERVICE_NAME_EMPTY: "Service name cannot be empty",
    MsgKey.SERVICE_ALREADY_REGISTERED: "Service is already registered: {service}",
    MsgKey.SECRET_EMPTY: "TOTP secret is empty",
    MsgKey.SECRET_INVALID_FORMAT: (
        "TOTP secret format is invalid (must be a Base32-encoded string)"
    ),
    MsgKey.COMMAND_PARSE_ERROR: "Argument error: {detail}",
    MsgKey.SERVICE_MUST_PRECEDE_OPTIONS: (
        "SERVICE must immediately follow the command, before any options"
    ),
    MsgKey.SECRET_ARG_DEPRECATED: (
        "The --secret/-s option has been removed for security. "
        "Use interactive prompt or --stdin."
    ),
    MsgKey.PATH_EMPTY: "Path cannot be empty",
    MsgKey.PATH_UNCLOSED_QUOTE: "Quotes are not properly closed: {value}",
    MsgKey.CANCELLED: "Operation was cancelled by the user",
    MsgKey.FILE_OPERATION_FAILED: "A file operation failed",
    MsgKey.INIT_PROMPT_KEY_PATH: (
        "Enter the output path for the new key file (leave blank to cancel):"
    ),
    MsgKey.INIT_PROMPT_LANGUAGE: (
        "Select display language [en/ja] (default: {default}):"
    ),
    MsgKey.INIT_KEY_EXISTS_WARNING: (
        "A key file already exists at this location: {path}\n"
        "Overwrite it with a new key?"
    ),
    MsgKey.INIT_DECRYPTION_LOSS_WARNING: (
        "Overwriting may make the existing encrypted data unrecoverable "
        "with the current key. Continue?"
    ),
    MsgKey.INIT_KEY_CREATED: "Key file created: {path}",
    MsgKey.INIT_STORAGE_INITIALIZED: "Encrypted storage file initialized: {path}",
    MsgKey.ADD_PROMPT_SECRET: "Enter the TOTP secret (Base32, leave blank to cancel):",
    MsgKey.ADD_SERVICE_REGISTERED: "Service registered: {service}",
    MsgKey.REMOVE_CONFIRM: "Remove service '{service}'. Are you sure?",
    MsgKey.REMOVE_SERVICE_REMOVED: "Service removed: {service}",
    MsgKey.REKEY_ROTATION_LIMIT_NOTICE: (
        "Rotation limit reached; the oldest key file will be deleted: {path}"
    ),
    MsgKey.REKEY_ROTATION_LIMIT_CONFIRM: (
        "Backups or past encrypted data requiring this key may become "
        "permanently undecryptable. Continue?"
    ),
    MsgKey.REKEY_DONE: "Key updated and data re-encrypted: {path}",
    MsgKey.CONFIG_SUMMARY: (
        "config_path: {config_path}\n"
        "key_path: {key_path}\n"
        "storage_path: {storage_path}\n"
        "language: {lang}"
    ),
    MsgKey.CONFIG_KEY_PATH_UNSET: "(not set)",
    MsgKey.CONFIG_LANGUAGE_UPDATED: "Language updated: {lang}",
    MsgKey.LIST_HEADER_SERVICE: "SERVICE",
    MsgKey.LIST_HEADER_ISSUER: "ISSUER",
    MsgKey.LIST_NO_ISSUER_PLACEHOLDER: "-",
}

JA_CATALOG: Catalog = {
    MsgKey.APP_DESCRIPTION: "カスタムCLI型TOTP認証ツール",
    MsgKey.LABEL_ERROR: "エラー",
    MsgKey.LABEL_WARNING: "警告",
    MsgKey.KEY_NOT_FOUND: "鍵ファイルが見つかりません: {path}",
    MsgKey.KEY_PATH_NOT_CONFIGURED: (
        "鍵ファイルのパスが指定されていません"
        "（--key、VTOTP_KEY_PATH、config.jsonのいずれにも指定がありません）"
    ),
    MsgKey.KEY_NOT_A_FILE: "鍵ファイルが通常のファイルではありません: {path}",
    MsgKey.KEY_INVALID_SIZE: "鍵ファイルのサイズが不正です（32バイトである必要があります）: {path}",
    MsgKey.KEY_INVALID_SIZE_NO_PATH: "鍵のサイズが不正です（32バイトである必要があります）",
    MsgKey.KEY_PERMISSION_DENIED: "鍵ファイルを読み取る権限がありません: {path}",
    MsgKey.KEY_UNREADABLE: "鍵ファイルを読み込めません: {path}",
    MsgKey.KEY_STORAGE_FAILED: "鍵ファイルを保存できませんでした: {path}",
    MsgKey.KEY_PERMISSION_SETUP_FAILED: (
        "鍵ファイルのアクセス権限を実行ユーザー専用に設定できませんでした: {path}"
    ),
    MsgKey.STORAGE_FILE_NOT_FOUND: "暗号化データファイルが見つかりません: {path}",
    MsgKey.STORAGE_FILE_UNREADABLE: "暗号化データファイルを読み込めません: {path}",
    MsgKey.STORAGE_FILE_INVALID_FORMAT: "暗号化データファイルの形式が不正です: {path}",
    MsgKey.STORAGE_UNSUPPORTED_VERSION: (
        "サポートされていない暗号化フォーマットバージョンです: {version}"
    ),
    MsgKey.STORAGE_UNSUPPORTED_ALGORITHM: "サポートされていない暗号化アルゴリズムです: {algorithm}",
    MsgKey.STORAGE_DECRYPTION_FAILED: (
        "暗号化データの認証タグ検証に失敗しました"
        "（データの改ざん、破損、または不正な鍵の可能性があります）"
    ),
    MsgKey.STORAGE_INVALID_STRUCTURE: "復号したデータの構造が不正です",
    MsgKey.STORAGE_INVALID_FORMAT: "復号したデータの形式が不正です",
    MsgKey.STORAGE_REKEY_VERIFICATION_FAILED: "再暗号化データの検証に失敗しました",
    MsgKey.SERVICE_NOT_FOUND: "サービスが見つかりません: {service}",
    MsgKey.SERVICE_NAME_EMPTY: "サービス名を空にすることはできません",
    MsgKey.SERVICE_ALREADY_REGISTERED: "サービスは既に登録されています: {service}",
    MsgKey.SECRET_EMPTY: "TOTPシークレットが空です",
    MsgKey.SECRET_INVALID_FORMAT: (
        "TOTPシークレットの形式が不正です（Base32形式の文字列である必要があります）"
    ),
    MsgKey.COMMAND_PARSE_ERROR: "引数エラー: {detail}",
    MsgKey.SERVICE_MUST_PRECEDE_OPTIONS: (
        "SERVICEはサブコマンドの直後に指定してください（オプションより前）"
    ),
    MsgKey.SECRET_ARG_DEPRECATED: (
        "--secret/-s オプションはセキュリティのため廃止されました。"
        "対話入力または --stdin を使用してください。"
    ),
    MsgKey.PATH_EMPTY: "パスを空にすることはできません",
    MsgKey.PATH_UNCLOSED_QUOTE: "引用符が正しく閉じられていません: {value}",
    MsgKey.CANCELLED: "ユーザーによって操作がキャンセルされました",
    MsgKey.FILE_OPERATION_FAILED: "ファイル操作に失敗しました",
    MsgKey.INIT_PROMPT_KEY_PATH: "鍵ファイルの新規作成先パスを入力してください（空欄でキャンセル）:",
    MsgKey.INIT_PROMPT_LANGUAGE: "表示言語を選択してください [en/ja]（既定値: {default}）:",
    MsgKey.INIT_KEY_EXISTS_WARNING: (
        "指定された場所には既に鍵ファイルが存在します: {path}\n新しい鍵で上書きしますか？"
    ),
    MsgKey.INIT_DECRYPTION_LOSS_WARNING: (
        "上書きすると、既存の暗号化データを現在の鍵で復号できなくなる可能性があります。続行しますか？"
    ),
    MsgKey.INIT_KEY_CREATED: "鍵ファイルを作成しました: {path}",
    MsgKey.INIT_STORAGE_INITIALIZED: "暗号化データファイルを初期化しました: {path}",
    MsgKey.ADD_PROMPT_SECRET: "TOTPシークレット（Base32）を入力してください（空欄でキャンセル）:",
    MsgKey.ADD_SERVICE_REGISTERED: "サービスを登録しました: {service}",
    MsgKey.REMOVE_CONFIRM: "サービス '{service}' を削除します。よろしいですか？",
    MsgKey.REMOVE_SERVICE_REMOVED: "サービスを削除しました: {service}",
    MsgKey.REKEY_ROTATION_LIMIT_NOTICE: (
        "ローテーション上限に達したため、最も古い鍵ファイル {path} を削除します。"
    ),
    MsgKey.REKEY_ROTATION_LIMIT_CONFIRM: (
        "この鍵を必要とするバックアップや過去の暗号化データは、"
        "今後復号できなくなる可能性があります。続行しますか？"
    ),
    MsgKey.REKEY_DONE: "鍵を更新し、データを再暗号化しました: {path}",
    MsgKey.CONFIG_SUMMARY: (
        "config_path: {config_path}\n"
        "key_path: {key_path}\n"
        "storage_path: {storage_path}\n"
        "language: {lang}"
    ),
    MsgKey.CONFIG_KEY_PATH_UNSET: "(未設定)",
    MsgKey.CONFIG_LANGUAGE_UPDATED: "言語を更新しました: {lang}",
    MsgKey.LIST_HEADER_SERVICE: "サービス",
    MsgKey.LIST_HEADER_ISSUER: "発行者",
    MsgKey.LIST_NO_ISSUER_PLACEHOLDER: "-",
}

#: 言語コードから対応するカタログへのマッピング。
_CATALOGS_BY_LANGUAGE: Mapping[str, Catalog] = {
    "en": EN_CATALOG,
    "ja": JA_CATALOG,
}


def get_catalog(language: str) -> Catalog:
    """言語コードに対応するカタログを返す。未知の言語はEN_CATALOGへフォールバックする。"""
    return _CATALOGS_BY_LANGUAGE.get(language, EN_CATALOG)
