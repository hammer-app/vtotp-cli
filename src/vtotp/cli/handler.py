"""CLI全体のエントリーポイントである CliHandler を定義するモジュール。

DESIGN.md 11〜14章・20〜21章に基づき、CLI引数の前処理（省略形フォールバック・
第一引数固定・後置オプション規則）、argparseによるサブコマンド解析、表示言語の
解決、各サブコマンドのユースケース実行、および例外の終了コードへの変換を担う。
TOTPシークレットや鍵の内容はいかなる場合もstdout/stderrへ出力しない
（Zero Leakage Rule）。
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import IO, Callable, NoReturn, Sequence

from vtotp import __version__
from vtotp.cli import formatter
from vtotp.core.key_manager import KeyManager
from vtotp.core.secure_storage import SecureStorage
from vtotp.core.service_registry import ServiceRegistry
from vtotp.core.totp_generator import TotpGenerator
from vtotp.domain.exceptions import (
    CancelledError,
    CommandParseError,
    InvalidSecretError,
    KeyNotFoundError,
    TotpCliError,
)
from vtotp.domain.models import SecretRecord
from vtotp.i18n.catalog import DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES, MsgKey
from vtotp.i18n.resolver import ENV_LANG_VARIABLE, LanguageResolver, detect_os_locale

#: config.json / 暗号化データファイルの既定の配置ディレクトリ。
DEFAULT_CONFIG_DIR: Path = Path.home() / ".vtotp"

#: config.jsonの既定パス。
DEFAULT_CONFIG_PATH: Path = DEFAULT_CONFIG_DIR / "config.json"

#: config.jsonにstorage_pathが未設定の場合に使用する既定の暗号化データファイル名。
DEFAULT_STORAGE_FILENAME: str = "vtotp-secrets.enc"

#: 鍵ファイルパスを指定する環境変数名。
ENV_KEY_PATH_VARIABLE: str = "VTOTP_KEY_PATH"

#: `-l`/`--lang` の選択肢（argparseの`choices`用）。
_LANG_CHOICES: list[str] = list(SUPPORTED_LANGUAGES)

#: パスの前後引用符として認識する文字。
_QUOTE_CHARS = "\"'"

#: `add --stdin` で読み込んだシークレットの末尾から除去する改行文字。
_TRAILING_NEWLINE_CHARS = "\r\n"

#: `add --stdin` で読み込んだシークレットの先頭から除去するBOM（U+FEFF）。
_BOM_CHAR = "﻿"

#: 廃止済みのシークレット引数（長形式・短形式）。
_DEPRECATED_SECRET_LONG_OPTION = "--secret"
_DEPRECATED_SECRET_SHORT_OPTION = "-s"

#: argparseの前方一致（`--sec`等）で`--secret`の省略形とみなす最短の長さ。
#: `--s`は現行の`--stdin`/`--storage`とも共通する接頭辞のため対象外とする。
_DEPRECATED_SECRET_MIN_PREFIX_LENGTH = len("--se")


def _is_deprecated_secret_arg(token: str) -> bool:
    """`token`が廃止済みの`--secret`/`-s`（値の結合形式・省略形を含む）かを判定する。

    対象は `--secret`、`--secret=VALUE`、`--sec` 等の前方一致省略形、
    および `-s`、`-sVALUE` である。
    """
    if token.startswith("--"):
        option_name = token.split("=", 1)[0]
        if len(option_name) < _DEPRECATED_SECRET_MIN_PREFIX_LENGTH:
            return False
        return _DEPRECATED_SECRET_LONG_OPTION.startswith(option_name)
    return token.startswith(_DEPRECATED_SECRET_SHORT_OPTION)


def _read_masked_input() -> str:
    """入力内容をエコーせずに（マスキングして）1行を読み込む。

    プロンプト文言は呼び出し元がstderrへ表示するため、`getpass`自体には
    空のプロンプトを渡す。
    """
    return getpass.getpass(prompt="")


def _strip_quotes(value: str, language: str) -> str:
    """前後の空白、および前後を囲む一致した引用符（`"` または `'`）を除去する。

    Windowsのエクスプローラーの「パスのコピー」やシェルの挙動によって、
    パス全体が引用符で囲まれたまま渡される場合があるため、ファイルパスを
    受け取るすべての箇所（対話入力・CLI引数）で正規化に使用する。

    以下の場合は :class:`argparse.ArgumentTypeError` を送出する。

    - 引用符が片側にしか無い、または開始・終了の引用符の種類が一致しない
      （閉じられていない引用符）場合
    - 引用符・前後の空白を除去した結果が空文字列になる場合

    エラーメッセージは`language`でローカライズされる。
    """
    stripped = value.strip()
    starts_with_quote = bool(stripped) and stripped[0] in _QUOTE_CHARS
    ends_with_quote = bool(stripped) and stripped[-1] in _QUOTE_CHARS

    if starts_with_quote or ends_with_quote:
        is_matched_pair = (
            len(stripped) >= 2
            and starts_with_quote
            and ends_with_quote
            and stripped[0] == stripped[-1]
        )
        if not is_matched_pair:
            raise argparse.ArgumentTypeError(
                formatter.format_message(
                    MsgKey.PATH_UNCLOSED_QUOTE, language, value=repr(value)
                )
            )
        stripped = stripped[1:-1].strip()

    if not stripped:
        raise argparse.ArgumentTypeError(
            formatter.format_message(MsgKey.PATH_EMPTY, language)
        )

    return stripped


class _ArgumentParser(argparse.ArgumentParser):
    """argparseの既定のexit動作を無効化し、CommandParseErrorへ変換するパーサー。

    標準の :class:`argparse.ArgumentParser` は解析エラー時に使用方法を
    表示して ``sys.exit(2)`` を呼び出すが、CliHandlerが一貫した例外処理・
    終了コード変換フローを提供できるよう、代わりに :class:`CommandParseError`
    を送出する。
    """

    error_stream: IO[str]

    def error(self, message: str) -> NoReturn:
        """使用方法を表示したうえで、CommandParseErrorを送出する。"""
        self.print_usage(self.error_stream)
        raise CommandParseError(MsgKey.COMMAND_PARSE_ERROR, context={"detail": message})


class CliHandler:
    """CLI全体のエントリーポイントを提供するクラス。

    CLI引数の初期取得・省略形コマンドの判定・argparseによる正式な引数
    解析・表示言語の解決・コマンドディスパッチ・例外のユーザー向け
    メッセージへの変換を行う。
    """

    #: 省略形フォールバックの対象外とする予約済みトークン（サブコマンド名・エイリアス・グローバルオプション）。
    #: `-l`/`--lang`はここに含めない。第一引数として値付きオプションが前置された
    #: 場合、トップレベルパーサーが未知の引数として拒否し終了コード2になる
    #: （DESIGN.md 20.1「第一引数固定と後置オプション」）。
    RESERVED_COMMANDS: frozenset[str] = frozenset(
        {
            "init",
            "generate",
            "get",
            "-g",
            "add",
            "remove",
            "rm",
            "list",
            "ls",
            "rekey",
            "config",
            "-h",
            "--help",
            "--version",
        }
    )

    #: `SERVICE` を必須位置引数とするサブコマンド（正規化後のトークン）。
    #: `-g`は`normalize_argv`で`generate`へ変換済みのため、ここには含めない。
    _SERVICE_REQUIRED_COMMANDS: frozenset[str] = frozenset(
        {"generate", "get", "add", "remove", "rm"}
    )

    def __init__(
        self,
        key_manager: KeyManager | None = None,
        secure_storage: SecureStorage | None = None,
        service_registry: ServiceRegistry | None = None,
        totp_generator: TotpGenerator | None = None,
        stdout: IO[str] | None = None,
        stderr: IO[str] | None = None,
        input_func: Callable[[], str] | None = None,
        config_path: Path | None = None,
        stdin: IO[str] | None = None,
        secret_input_func: Callable[[], str] | None = None,
    ) -> None:
        """依存コンポーネントと入出力ストリームを設定する。

        いずれの引数も省略可能で、省略時は実運用向けの既定値（実際の
        コアコンポーネント、``sys.stdin``/``sys.stdout``/``sys.stderr``、
        組み込みの ``input``、マスキング入力（``getpass``）、既定の
        config.jsonパス）が使用される。テストからはこれらを注入して
        ふるまいを検証できる。
        """
        self._key_manager = key_manager if key_manager is not None else KeyManager()
        self._secure_storage = (
            secure_storage if secure_storage is not None else SecureStorage()
        )
        self._service_registry = (
            service_registry if service_registry is not None else ServiceRegistry()
        )
        self._totp_generator = (
            totp_generator if totp_generator is not None else TotpGenerator()
        )
        self._stdout: IO[str] = stdout if stdout is not None else sys.stdout
        self._stderr: IO[str] = stderr if stderr is not None else sys.stderr
        self._stdin: IO[str] = stdin if stdin is not None else sys.stdin
        self._input: Callable[[], str] = input_func if input_func is not None else input
        self._secret_input: Callable[[], str] = (
            secret_input_func if secret_input_func is not None else _read_masked_input
        )
        self._config_path = (
            config_path if config_path is not None else DEFAULT_CONFIG_PATH
        )

        #: 直近のrun()呼び出しで解決された表示言語。parse_args()内のtype変換
        #: コールバック（`_type_path`）から動的に参照されるため、パーサー構築
        #: より前に初期化する。
        self._current_language: str = DEFAULT_LANGUAGE
        self._language_resolver = LanguageResolver()

        self._parser = self._build_parser()
        self._command_handlers: dict[str, Callable[[argparse.Namespace], int]] = {
            "init": self._cmd_init,
            "generate": self._cmd_generate,
            "get": self._cmd_generate,
            "add": self._cmd_add,
            "list": self._cmd_list,
            "ls": self._cmd_list,
            "remove": self._cmd_remove,
            "rm": self._cmd_remove,
            "rekey": self._cmd_rekey,
            "config": self._cmd_config,
        }

    # --- エントリーポイント ---

    def run(self, argv: Sequence[str]) -> int:
        """CLI全体のエントリーポイント。

        引数の正規化・表示言語の解決・解析・ディスパッチ・エラー処理を
        行い、終了コードを返す。``-h``/``--help``/``--version`` はargparseの
        標準的な挙動に従い、実際の標準出力・標準エラー出力
        （``sys.stdout``/``sys.stderr``）へ直接書き込む。それ以外のコマンド
        結果・エラーメッセージは、コンストラクタで注入されたストリームへ
        書き込む。
        """
        normalized_argv = self.normalize_argv(list(argv))
        self._current_language = self._resolve_language(
            self._prescan_lang(normalized_argv)
        )
        self._parser.description = formatter.format_message(
            MsgKey.APP_DESCRIPTION, self._current_language
        )

        try:
            self.reject_deprecated_secret_args(normalized_argv)
            self._validate_service_position(normalized_argv)
            parsed_args = self._parser.parse_args(normalized_argv)
        except SystemExit as exc:
            return self._exit_code_from_system_exit(exc)
        except CommandParseError as error:
            formatter.write_error(error, self._current_language, stream=self._stderr)
            return error.exit_code

        # 実際に解析済みの`--lang`（argparseの`choices`検証を通過した値）を
        # 優先順位解決へ再度通し、事前走査（prescan）との差異を正規化する。
        self._current_language = self._resolve_language(
            getattr(parsed_args, "lang", None)
        )

        try:
            return self._command_handlers[parsed_args.command](parsed_args)
        except TotpCliError as error:
            formatter.write_error(error, self._current_language, stream=self._stderr)
            return error.exit_code
        except OSError:
            fallback = TotpCliError(MsgKey.FILE_OPERATION_FAILED)
            formatter.write_error(fallback, self._current_language, stream=self._stderr)
            return 1

    @staticmethod
    def _exit_code_from_system_exit(exc: SystemExit) -> int:
        """``SystemExit``（``-h``/``--version``等）から終了コードを取り出す。"""
        if exc.code is None:
            return 0
        if isinstance(exc.code, int):
            return exc.code
        return 1

    def normalize_argv(self, argv: list[str]) -> list[str]:
        """省略形コマンド（サービス名のみの指定）を正式な `generate` コマンドへ変換する。

        第一引数が予約済みトークン（サブコマンド名・エイリアス・
        `-h`/`--help`/`--version` 等のオプション）でない場合、サービス名
        と判定し `generate <service>` へ読み替える。第一引数が`-l`/`-k`等の
        値付きオプションである場合はサービス名へのフォールバックを行わず
        argvをそのまま返し、後続のargparse解析で未知の引数として拒否させる
        （終了コード2、DESIGN.md 20.1）。
        """
        if not argv:
            return ["--help"]

        first = argv[0]
        if first == "-g":
            return ["generate", *argv[1:]]
        if first in self.RESERVED_COMMANDS or first.startswith("-"):
            return list(argv)
        return ["generate", first, *argv[1:]]

    def reject_deprecated_secret_args(self, argv: Sequence[str]) -> None:
        """引数列のどこかに廃止済みの `--secret`/`-s` が含まれていれば拒否する。

        argparseへ渡すと、未知の引数として `unrecognized arguments: --secret
        VALUE` のようにシークレット値をstderrへエコーバックしてしまうため、
        解析より前に検知し、固定メッセージの :class:`CommandParseError`
        （終了コード2）へ変換する。引数列や値は例外コンテキストへ一切含め
        ない（DESIGN.md 20.3、Zero Leakage Rule）。

        サブコマンドより前（`vtotp --secret VALUE add github`）、`add`以外の
        コマンドや省略形（`vtotp github --secret VALUE`）、`--` 以降も
        argparseは同様にエコーバックするため、位置・コマンドを問わず全トークンを
        検査対象とする。SERVICEの位置検証より優先してこのメッセージで拒否する。
        いずれのサブコマンドにも `-s` で始まる短形式オプションや `--se` で
        始まる長形式オプションは存在せず、`-` で始まる値はargparse自体が
        オプションとみなして値として受理しないため、正規の引数を誤検知しない。
        """
        if any(_is_deprecated_secret_arg(token) for token in argv):
            raise CommandParseError(MsgKey.SECRET_ARG_DEPRECATED, context={})

    def _validate_service_position(self, argv: Sequence[str]) -> None:
        """`SERVICE` を必須とするコマンドで、サブコマンド直後に `SERVICE` が
        指定されていること（オプションが前置されていないこと）を検証する。

        `vtotp get --key PATH github` や `vtotp generate -l ja github` の
        ように、`SERVICE` より前にオプションが置かれた場合は、argparseが
        たまたま解決してしまう前に `CommandParseError`（終了コード2）を
        送出して拒否する（DESIGN.md 20.1「第一引数固定と後置オプション」）。
        `SERVICE` 自体が省略された場合（`vtotp generate` 等）は、この検証を
        素通りさせ、argparseの必須位置引数エラーに処理を委ねる。
        """
        if not argv or argv[0] not in self._SERVICE_REQUIRED_COMMANDS:
            return
        if len(argv) >= 2 and argv[1].startswith("-"):
            raise CommandParseError(MsgKey.SERVICE_MUST_PRECEDE_OPTIONS)

    # --- 表示言語の解決 ---

    def _prescan_lang(self, argv: Sequence[str]) -> str | None:
        """argparseによる本解析より前に、argvから`-l`/`--lang`の値を事前走査する。

        パス引数の`type`変換（`_strip_quotes`）やargparse自体の解析エラーを
        ローカライズするため、正式な解析が完了する前に表示言語の推定値が
        必要となる。本走査はあくまで簡易な推定であり、実際に採用される
        言語は`parse_args()`成功後に`args.lang`で再解決される。
        """
        for index, token in enumerate(argv):
            if token in ("-l", "--lang") and index + 1 < len(argv):
                return argv[index + 1]
            if token.startswith("--lang="):
                return token.split("=", 1)[1]
        return None

    def _resolve_language(self, cli_lang: str | None) -> str:
        """CLI引数・環境変数・config.json・OSロケール・既定値の優先順位で表示言語を解決する。"""
        config = self._load_config()
        return self._language_resolver.resolve(
            cli_lang=cli_lang,
            env_lang=os.environ.get(ENV_LANG_VARIABLE),
            config_lang=config.get("language"),
            locale_lang=detect_os_locale(),
        )

    # --- argparseパーサー構築 ---

    def _build_parser(self) -> _ArgumentParser:
        """サブコマンド一式を備えたargparseパーサーを構築する。"""
        parser = _ArgumentParser(prog="vtotp")
        parser.add_argument(
            "--version", action="version", version=f"%(prog)s {__version__}"
        )

        subparsers = parser.add_subparsers(dest="command")

        def _type_path(value: str) -> Path:
            """`self._current_language`を動的に参照するパス引数の`type`コールバック。"""
            return Path(_strip_quotes(value, self._current_language))

        init_parser = subparsers.add_parser("init", help="Create a new key file")
        init_parser.add_argument("-k", "--key", type=_type_path, default=None)
        init_parser.add_argument("-l", "--lang", choices=_LANG_CHOICES, default=None)

        generate_parser = subparsers.add_parser(
            "generate", aliases=["get"], help="Generate and display a TOTP code"
        )
        generate_parser.add_argument("service")
        generate_parser.add_argument("-k", "--key", type=_type_path, default=None)
        generate_parser.add_argument("--storage", type=_type_path, default=None)
        generate_parser.add_argument(
            "-l", "--lang", choices=_LANG_CHOICES, default=None
        )

        add_parser = subparsers.add_parser("add", help="Register a new service")
        add_parser.add_argument("service")
        # シークレットをCLI引数で受け取る`--secret`/`-s`は、シェル履歴・プロセス
        # 一覧への露出を防ぐため廃止済み（REQUIREMENTS.md 3.4 / 4.1）。指定された
        # 場合は、argparseへ渡す前に`reject_deprecated_secret_args`が値をエコー
        # バックしない固定メッセージ（終了コード2）で拒否する。
        add_parser.add_argument("--issuer", default=None)
        add_parser.add_argument("--stdin", action="store_true")
        add_parser.add_argument("-k", "--key", type=_type_path, default=None)
        add_parser.add_argument("--storage", type=_type_path, default=None)
        add_parser.add_argument("-l", "--lang", choices=_LANG_CHOICES, default=None)

        list_parser = subparsers.add_parser(
            "list", aliases=["ls"], help="List registered services"
        )
        list_parser.add_argument("-k", "--key", type=_type_path, default=None)
        list_parser.add_argument("--storage", type=_type_path, default=None)
        list_parser.add_argument("-l", "--lang", choices=_LANG_CHOICES, default=None)

        remove_parser = subparsers.add_parser(
            "remove", aliases=["rm"], help="Remove a registered service"
        )
        remove_parser.add_argument("service")
        remove_parser.add_argument("--force", "-f", action="store_true")
        remove_parser.add_argument("-k", "--key", type=_type_path, default=None)
        remove_parser.add_argument("--storage", type=_type_path, default=None)
        remove_parser.add_argument("-l", "--lang", choices=_LANG_CHOICES, default=None)

        rekey_parser = subparsers.add_parser(
            "rekey", help="Rotate the key and re-encrypt the data"
        )
        rekey_parser.add_argument("-k", "--key", type=_type_path, default=None)
        rekey_parser.add_argument("--storage", type=_type_path, default=None)
        rekey_parser.add_argument("-l", "--lang", choices=_LANG_CHOICES, default=None)

        config_parser = subparsers.add_parser(
            "config", help="Show or update the resolved configuration"
        )
        # `-l`/`--lang`はconfigに限り、他コマンドの「表示言語の一時指定」ではなく
        # 「保存する言語設定の値」を兼ねるショートカットとして機能する
        # （REQUIREMENTS.md 3.2.6 / DESIGN.md 19.2）。
        config_parser.add_argument("-l", "--lang", choices=_LANG_CHOICES, default=None)
        config_subparsers = config_parser.add_subparsers(dest="config_action")
        config_set_parser = config_subparsers.add_parser("set")
        config_set_parser.add_argument("setting", choices=["language"])
        config_set_parser.add_argument("value", choices=_LANG_CHOICES)
        config_set_parser.add_argument(
            "-l", "--lang", choices=_LANG_CHOICES, default=None
        )

        # サブパーサーも `_ArgumentParser` のインスタンスであり、それぞれが
        # 独自に `.error()` を呼び出しうるため、全パーサーへ注入済みの
        # stderrストリームを設定する。
        for sub_parser in (
            parser,
            init_parser,
            generate_parser,
            add_parser,
            list_parser,
            remove_parser,
            rekey_parser,
            config_parser,
            config_set_parser,
        ):
            sub_parser.error_stream = self._stderr

        return parser

    # --- パス・設定の解決 ---

    def _load_config(self) -> dict[str, str]:
        """config.jsonを読み込む。存在しない・壊れている場合は空の設定として扱う。"""
        if not self._config_path.is_file():
            return {}
        try:
            data = json.loads(self._config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {key: value for key, value in data.items() if isinstance(value, str)}

    def _write_config(self, config: dict[str, str]) -> None:
        """`config`辞書全体をconfig.jsonへatomicに書き込む（内部ヘルパー）。"""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=self._config_path.parent, prefix=".config.", suffix=".tmp"
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(config, tmp_file, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self._config_path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def _save_key_path(self, key_path: Path) -> None:
        """config.jsonの `key_path` のみをatomicに更新する（initでのみ呼び出す）。"""
        config = self._load_config()
        config["key_path"] = str(key_path)
        self._write_config(config)

    def _save_language(self, language: str) -> None:
        """config.jsonの `language` のみをatomicに更新する（config set language等で呼び出す）。"""
        config = self._load_config()
        config["language"] = language
        self._write_config(config)

    def _resolve_key_path(self, cli_key: Path | None) -> Path:
        """CLIオプション・環境変数・config.jsonの優先順位で鍵ファイルパスを解決する。"""
        config = self._load_config()
        config_key_path = Path(config["key_path"]) if "key_path" in config else None
        environment_value = os.environ.get(ENV_KEY_PATH_VARIABLE)
        environment_key_path = Path(environment_value) if environment_value else None
        return self._key_manager.resolve_key_path(
            cli_path=cli_key,
            config_path=config_key_path,
            environment_path=environment_key_path,
        )

    def _resolve_storage_path(self, cli_storage: Path | None) -> Path:
        """CLIオプション・config.jsonの優先順位で暗号化データファイルパスを解決する。

        いずれにも指定が無い場合は、config.jsonと同じディレクトリ内の
        既定ファイル名（`vtotp-secrets.enc`）を使用する。
        """
        if cli_storage is not None:
            return cli_storage
        config = self._load_config()
        if "storage_path" in config:
            return Path(config["storage_path"])
        return self._config_path.parent / DEFAULT_STORAGE_FILENAME

    # --- 対話入力・確認 ---

    def _cancel(self) -> NoReturn:
        """ユーザーによるキャンセルとして :class:`CancelledError` を送出する。"""
        raise CancelledError(MsgKey.CANCELLED)

    def _confirm(self, key: MsgKey, **context: str) -> bool:
        """`key`をローカライズして表示し、`y`/`yes`（大文字小文字を区別しない）の
        入力のみを承認として扱う。
        """
        message = formatter.format_message(key, self._current_language, **context)
        print(f"{message} [y/N]: ", file=self._stderr)
        try:
            response = self._input()
        except EOFError:
            return False
        return response.strip().lower() in {"y", "yes"}

    def _prompt_for_key_output_path(self) -> Path | None:
        """`init` で `--key` 未指定時に、鍵ファイルの出力先を対話入力で取得する。

        空欄（Enterのみ）の場合は既定どおり無言でキャンセル扱いとする。
        引用符のみ・不一致な引用符など、明らかに不正な入力が行われた
        場合はエラーメッセージを表示したうえでキャンセル扱いとする。
        """
        print(
            formatter.format_message(
                MsgKey.INIT_PROMPT_KEY_PATH, self._current_language
            ),
            file=self._stderr,
        )
        try:
            response = self._input()
        except EOFError:
            return None
        if not response.strip():
            return None
        try:
            normalized = _strip_quotes(response, self._current_language)
        except argparse.ArgumentTypeError as error:
            label = formatter.format_message(MsgKey.LABEL_ERROR, self._current_language)
            print(f"{label}: {error}", file=self._stderr)
            return None
        return Path(normalized)

    def _prompt_for_language(self) -> str:
        """`init` で `-l`/`--lang` 未指定時に、表示言語を対話入力で取得する。

        既に解決済みの言語（`self._current_language`）をプロンプトの既定値
        として提示する（DESIGN.md 19.2「init は解決済み言語を初期値として
        提示し」）。空欄・EOF・`en`/`ja`のいずれにも正規化できない入力は、
        いずれも黙ってその既定値を採用する（鍵パスの対話入力とは異なり、
        言語選択には常に安全なフォールバック値が存在するため、キャンセル
        は行わない）。
        """
        default_language = self._current_language
        print(
            formatter.format_message(
                MsgKey.INIT_PROMPT_LANGUAGE,
                self._current_language,
                default=default_language,
            ),
            file=self._stderr,
        )
        try:
            response = self._input()
        except EOFError:
            return default_language
        normalized = self._language_resolver.normalize(response)
        return normalized if normalized is not None else default_language

    def _prompt_for_secret(self) -> str | None:
        """`add` で `--stdin` 未指定時に、TOTPシークレットをマスキング対話入力で取得する。

        入力内容は画面にエコーしない。空欄・EOFの場合は ``None`` を返し、
        呼び出し元でキャンセル扱いとする。
        """
        print(
            formatter.format_message(MsgKey.ADD_PROMPT_SECRET, self._current_language),
            file=self._stderr,
        )
        try:
            response = self._secret_input()
        except EOFError:
            return None
        response = response.strip()
        return response if response else None

    def _stdin_is_terminal(self) -> bool:
        """標準入力が対話端末（TTY）かを判定する。

        `isatty` を持たないストリーム（標準入力が存在しない実行環境等）は、
        キーボード入力を待てないため非TTYとして扱う。
        """
        isatty = getattr(self._stdin, "isatty", None)
        return callable(isatty) and bool(isatty())

    def _read_stdin_text(self) -> str:
        """標準入力全体を文字列として読み込む。

        バイナリバッファを持つ実際の標準入力は、ロケール既定のエンコーディング
        （日本語Windowsではcp932）ではなくUTF-8としてデコードする。これにより
        Windows PowerShell 5.1がコードページ65001下でパイプ先へ付与するUTF-8 BOM
        （`EF BB BF`）が `\\ufeff` として復元され、呼び出し元で除去できる。
        Base32シークレットはASCIIのみで構成されるため、UTF-8でのデコードは
        いずれのコードページから渡された正規の入力も変化させない。
        """
        buffer = getattr(self._stdin, "buffer", None)
        if buffer is None:
            return self._stdin.read()
        data: bytes = buffer.read()
        return data.decode("utf-8")

    def _read_secret_from_stdin(self) -> str:
        """`add --stdin` 指定時に、標準入力全体からTOTPシークレットを読み込む。

        先頭のUTF-8 BOM（Windows PowerShell 5.1が多重に付与する場合を含む）を
        すべて除去したうえで、末尾の改行（CR/LF）を除去して返す。パイプ連携
        向けの経路であるため、空入力は対話入力のようなキャンセルではなく、
        不正なシークレットとして :class:`InvalidSecretError` を送出する。
        デコードできないバイト列が渡された場合も同様に扱い、入力内容は例外へ
        含めない（Zero Leakage Rule）。
        """
        try:
            raw = self._read_stdin_text()
        except UnicodeDecodeError:
            raise InvalidSecretError(MsgKey.SECRET_INVALID_FORMAT) from None
        secret = raw.lstrip(_BOM_CHAR).rstrip(_TRAILING_NEWLINE_CHARS)
        if not secret:
            raise InvalidSecretError(MsgKey.SECRET_EMPTY)
        return secret

    def _confirm_existing_key_warning(self, path: Path) -> bool:
        """`init` の第1警告：既存鍵ファイルの上書き確認。"""
        return self._confirm(MsgKey.INIT_KEY_EXISTS_WARNING, path=str(path))

    def _confirm_decryption_loss_warning(self) -> bool:
        """`init` の第2警告：既存の暗号化データを復号できなくなる可能性の確認。"""
        return self._confirm(MsgKey.INIT_DECRYPTION_LOSS_WARNING)

    def _confirm_rotation_limit_warning(self, oldest_path: Path) -> bool:
        """`rekey` のローテーション上限警告：最古世代の鍵ファイル削除確認。"""
        print(
            formatter.format_message(
                MsgKey.REKEY_ROTATION_LIMIT_NOTICE,
                self._current_language,
                path=str(oldest_path),
            ),
            file=self._stderr,
        )
        return self._confirm(MsgKey.REKEY_ROTATION_LIMIT_CONFIRM)

    # --- サブコマンド実装 ---

    def _cmd_init(self, args: argparse.Namespace) -> int:
        """新しい鍵ファイルと空の暗号化ストレージを作成し、config.jsonのkey_path/languageを更新する。"""
        key_output_path: Path | None = args.key
        if key_output_path is None:
            key_output_path = self._prompt_for_key_output_path()
            if key_output_path is None:
                self._cancel()

        if self._key_manager.check_existing_key(key_output_path):
            if not self._confirm_existing_key_warning(key_output_path):
                self._cancel()
            if not self._confirm_decryption_loss_warning():
                self._cancel()

        self._key_manager.create_key_file(key_output_path)
        new_key = self._key_manager.load_key(key_output_path)

        storage_path = self._resolve_storage_path(None)
        self._secure_storage.initialize(storage_path, new_key)

        if args.lang is None:
            self._current_language = self._prompt_for_language()

        config = self._load_config()
        config["key_path"] = str(key_output_path)
        config["language"] = self._current_language
        self._write_config(config)

        formatter.write_info(
            MsgKey.INIT_KEY_CREATED,
            self._current_language,
            stream=self._stderr,
            path=str(key_output_path),
        )
        formatter.write_info(
            MsgKey.INIT_STORAGE_INITIALIZED,
            self._current_language,
            stream=self._stderr,
            path=str(storage_path),
        )
        return 0

    def _cmd_generate(self, args: argparse.Namespace) -> int:
        """指定されたサービスの現在のTOTPコードを生成し、stdoutへ出力する。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        key = self._key_manager.load_key(key_path)
        records = self._secure_storage.load_secrets(storage_path, key)
        record = self._service_registry.get(records, args.service)

        code = self._totp_generator.generate(record.secret)
        formatter.write_code(code, self._stdout)

        remaining = self._totp_generator.remaining_seconds()
        formatter.write_remaining_seconds_bar(
            remaining, self._totp_generator.time_step, self._stderr
        )
        return 0

    def _cmd_add(self, args: argparse.Namespace) -> int:
        """新しいサービスをシークレットとともに登録する。"""
        # 非TTY（パイプ・リダイレクト・CI等）では、WindowsのgetpassがOSの
        # コンソールを直接読みに行きパイプを無視して無期限に待機するため、
        # `--stdin` の指定漏れとして即座に拒否する。鍵・ストレージの状態に
        # 左右されず決定的に終了コード2となるよう、ファイルアクセスより前に行う。
        if not args.stdin and not self._stdin_is_terminal():
            raise CommandParseError(MsgKey.STDIN_OPTION_REQUIRED, context={})

        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        key = self._key_manager.load_key(key_path)
        records = self._secure_storage.load_secrets(storage_path, key)

        secret: str | None
        if args.stdin:
            secret = self._read_secret_from_stdin()
        else:
            secret = self._prompt_for_secret()
            if secret is None:
                self._cancel()

        normalized_secret = self._totp_generator.validate_secret(secret)
        record = SecretRecord(
            service_name=args.service,
            secret=normalized_secret,
            issuer=args.issuer,
        )
        updated_records = self._service_registry.add(records, record)
        self._secure_storage.save_secrets(storage_path, key, updated_records)

        formatter.write_info(
            MsgKey.ADD_SERVICE_REGISTERED,
            self._current_language,
            stream=self._stderr,
            service=args.service,
        )
        return 0

    def _cmd_list(self, args: argparse.Namespace) -> int:
        """登録済みサービスの一覧を表形式でstdoutへ出力する。シークレットは出力しない。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        key = self._key_manager.load_key(key_path)
        records = self._secure_storage.load_secrets(storage_path, key)
        names = self._service_registry.list_names(records)
        ordered_records = [records[name] for name in names]
        formatter.write_service_table(
            ordered_records, self._current_language, self._stdout
        )
        return 0

    def _cmd_remove(self, args: argparse.Namespace) -> int:
        """指定されたサービスを削除する。`--force` 未指定時は削除前に確認する。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        key = self._key_manager.load_key(key_path)
        records = self._secure_storage.load_secrets(storage_path, key)

        # 存在しないサービスの場合はここでServiceNotFoundErrorが送出される。
        self._service_registry.get(records, args.service)

        if not args.force:
            if not self._confirm(MsgKey.REMOVE_CONFIRM, service=args.service):
                self._cancel()

        updated_records = self._service_registry.remove(records, args.service)
        self._secure_storage.save_secrets(storage_path, key, updated_records)

        formatter.write_info(
            MsgKey.REMOVE_SERVICE_REMOVED,
            self._current_language,
            stream=self._stderr,
            service=args.service,
        )
        return 0

    def _cmd_rekey(self, args: argparse.Namespace) -> int:
        """鍵を更新し、既存の暗号化データを新鍵で再暗号化する。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        old_key = self._key_manager.load_key(key_path)
        new_key = self._key_manager.generate_key()

        rotated_paths = self._key_manager.rotated_key_paths(
            key_path, self._key_manager.MAX_ROTATED_KEYS
        )
        if rotated_paths and rotated_paths[-1].exists():
            if not self._confirm_rotation_limit_warning(rotated_paths[-1]):
                self._cancel()

        self._key_manager.rotate_key_file(key_path, new_key)
        self._secure_storage.rekey(storage_path, old_key, new_key)

        formatter.write_info(
            MsgKey.REKEY_DONE,
            self._current_language,
            stream=self._stderr,
            path=str(key_path),
        )
        return 0

    def _cmd_config(self, args: argparse.Namespace) -> int:
        """`config`：設定内容の表示、または言語設定の更新を行う。

        引数無しの場合は現在解決される設定内容（config.jsonのパス・鍵パス・
        データパス・表示言語）を表示する。鍵の内容やシークレットは一切
        表示しない（Zero Leakage Rule）。`-l`/`--lang`（ショートカット）または
        `set language <en|ja>`（標準構文）が指定された場合は、その言語を
        config.jsonへ保存し、保存した言語で確認メッセージを表示する。
        """
        if getattr(args, "config_action", None) == "set":
            new_language = str(args.value)
        elif args.lang is not None:
            new_language = str(args.lang)
        else:
            return self._show_config()

        self._save_language(new_language)
        self._current_language = new_language
        formatter.write_info(
            MsgKey.CONFIG_LANGUAGE_UPDATED,
            self._current_language,
            stream=self._stdout,
            lang=new_language,
        )
        return 0

    def _show_config(self) -> int:
        """現在解決される設定内容（config.jsonのパス・鍵パス・データパス・表示言語）を表示する。"""
        try:
            key_path_display = str(self._resolve_key_path(None))
        except KeyNotFoundError:
            key_path_display = formatter.format_message(
                MsgKey.CONFIG_KEY_PATH_UNSET, self._current_language
            )
        storage_path_display = str(self._resolve_storage_path(None))

        message = formatter.format_message(
            MsgKey.CONFIG_SUMMARY,
            self._current_language,
            config_path=str(self._config_path),
            key_path=key_path_display,
            storage_path=storage_path_display,
            lang=self._current_language,
        )
        print(message, file=self._stdout)
        return 0
