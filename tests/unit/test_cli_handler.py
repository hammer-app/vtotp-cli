"""vtotp.cli.handler.CliHandler の単体テスト。"""

from __future__ import annotations

import base64
import getpass
import io
import json
import os
import sys
from pathlib import Path
from typing import Callable

import pytest

from vtotp.cli.handler import CliHandler, ENV_KEY_PATH_VARIABLE
from vtotp.core.key_manager import KeyManager
from vtotp.core.secure_storage import SecureStorage
from vtotp.domain.exceptions import CommandParseError
from vtotp.domain.models import SecretRecord
from vtotp.i18n.catalog import EN_CATALOG, JA_CATALOG, MsgKey
from vtotp.i18n.resolver import ENV_LANG_VARIABLE


def _make_input(responses: list[str]) -> Callable[[], str]:
    """テスト用に、あらかじめ用意した応答を順番に返す入力関数を生成する。"""
    iterator = iter(responses)

    def _input() -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return _input


@pytest.fixture
def stdout() -> io.StringIO:
    """テスト対象へ注入する標準出力用ストリームを返す。"""
    return io.StringIO()


@pytest.fixture
def stderr() -> io.StringIO:
    """テスト対象へ注入する標準エラー出力用ストリームを返す。"""
    return io.StringIO()


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    """テスト用の一時config.jsonパスを返す（実際のホームディレクトリを使わない）。"""
    return tmp_path / "config.json"


@pytest.fixture
def handler_factory(
    stdout: io.StringIO, stderr: io.StringIO, config_path: Path
) -> Callable[..., CliHandler]:
    """注入済みストリーム・一時config.jsonを持つCliHandlerを生成するファクトリを返す。"""

    def _factory(responses: list[str] | None = None, stdin: str = "") -> CliHandler:
        # 通常の対話入力とシークレットのマスキング入力は、同じ応答列を
        # 呼び出し順に消費する（実運用の入力順序をそのまま再現する）。
        input_func = _make_input(responses or [])
        return CliHandler(
            stdout=stdout,
            stderr=stderr,
            config_path=config_path,
            input_func=input_func,
            secret_input_func=input_func,
            stdin=io.StringIO(stdin),
        )

    return _factory


@pytest.fixture
def initialized_handler(
    handler_factory: Callable[..., CliHandler],
    tmp_path: Path,
    stdout: io.StringIO,
    stderr: io.StringIO,
) -> tuple[CliHandler, Path]:
    """initを実行済みの状態のCliHandlerと鍵パスを返す。"""
    key_path = tmp_path / "master.key"
    handler = handler_factory()
    exit_code = handler.run(["init", "--key", str(key_path)])
    assert exit_code == 0
    stdout.truncate(0)
    stdout.seek(0)
    stderr.truncate(0)
    stderr.seek(0)
    return handler, key_path


class TestNormalizeArgv:
    """normalize_argv（省略形フォールバック）に関するテスト。"""

    @pytest.fixture
    def handler(self, handler_factory: Callable[..., CliHandler]) -> CliHandler:
        return handler_factory()

    def test_empty_argv_becomes_help(self, handler: CliHandler) -> None:
        """空のargvが`--help`へ変換されることを確認する。"""
        assert handler.normalize_argv([]) == ["--help"]

    @pytest.mark.parametrize(
        "command",
        [
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
        ],
    )
    def test_reserved_commands_are_not_rewritten(
        self, handler: CliHandler, command: str
    ) -> None:
        """予約済みサブコマンドはそのまま変更されないことを確認する。"""
        assert handler.normalize_argv([command, "extra"]) == [command, "extra"]

    def test_dash_g_is_translated_to_generate(self, handler: CliHandler) -> None:
        """`-g`が`generate`へ変換されることを確認する。"""
        assert handler.normalize_argv(["-g", "github"]) == ["generate", "github"]

    @pytest.mark.parametrize("flag", ["-h", "--help", "--version"])
    def test_dash_prefixed_options_are_not_rewritten(
        self, handler: CliHandler, flag: str
    ) -> None:
        """`-h`/`--help`/`--version`はそのまま変更されないことを確認する。"""
        assert handler.normalize_argv([flag]) == [flag]

    def test_unrecognized_first_token_is_treated_as_service_name(
        self, handler: CliHandler
    ) -> None:
        """未予約の第一引数がgenerateへフォールバックされることを確認する。"""
        assert handler.normalize_argv(["github", "--key", "k"]) == [
            "generate",
            "github",
            "--key",
            "k",
        ]

    def test_service_named_init_requires_explicit_generate(
        self, handler: CliHandler
    ) -> None:
        """サービス名が予約語（例: init）と衝突する場合はフォールバックされないことを確認する。"""
        assert handler.normalize_argv(["init"]) == ["init"]
        assert handler.normalize_argv(["generate", "init"]) == ["generate", "init"]


class TestInitCommand:
    """`init` サブコマンドに関するテスト。"""

    def test_creates_key_and_storage_and_updates_config(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
    ) -> None:
        """鍵ファイル・暗号化ストレージが作成され、config.jsonにkey_pathが保存されることを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", str(key_path)])

        assert exit_code == 0
        assert key_path.is_file()
        assert len(key_path.read_bytes()) == 32

        saved_config = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved_config["key_path"] == str(key_path)

        storage_path = config_path.parent / "vtotp-secrets.enc"
        assert storage_path.is_file()
        # 暗号化ストレージファイルがDESIGN.md記載のペイロード形式で作成されていることも確認する。
        storage_document = json.loads(storage_path.read_text(encoding="utf-8"))
        assert storage_document["version"] == 1
        assert storage_document["algorithm"] == "AES-256-GCM"

    def test_prompts_for_key_path_when_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """--key省略時に対話入力で出力先パスを取得することを確認する。"""
        key_path = tmp_path / "interactive.key"
        handler = handler_factory([str(key_path)])
        exit_code = handler.run(["init"])
        assert exit_code == 0
        assert key_path.is_file()

    def test_cancels_when_key_path_prompt_is_empty(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力で空欄が入力された場合、CancelledError相当の終了コード7になることを確認する。

        単なる空欄入力は既定どおりキャンセル扱いのみとなり、引用符関連の
        個別エラーメッセージは表示されないことも合わせて確認する。
        """
        handler = handler_factory([""])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "closed" not in stderr.getvalue()
        assert "cannot be empty" not in stderr.getvalue()

    def test_prompts_for_key_path_quoted_empty_string_is_cancelled_with_error(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力に空の引用符（`""`）が入力された場合、エラーを表示したうえでキャンセルされることを確認する。"""
        handler = handler_factory(['""'])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "cannot be empty" in stderr.getvalue()

    def test_prompts_for_key_path_quoted_whitespace_only_is_cancelled_with_error(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力が空白のみを引用符で囲んだ値（`'   '`）の場合、エラーを表示したうえでキャンセルされることを確認する。"""
        handler = handler_factory(["'   '"])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "cannot be empty" in stderr.getvalue()

    def test_prompts_for_key_path_mismatched_quotes_is_cancelled_with_error(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力の引用符が一致しない場合、エラーを表示したうえでキャンセルされることを確認する。"""
        handler = handler_factory(["\"invalid'"])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "not properly closed" in stderr.getvalue()

    def test_prompts_for_key_path_unclosed_quote_is_cancelled_with_error(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力の引用符が閉じられていない場合、エラーを表示したうえでキャンセルされることを確認する。"""
        handler = handler_factory(['"unclosed'])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "not properly closed" in stderr.getvalue()

    def test_prompts_for_key_path_strips_surrounding_double_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """対話入力の鍵パスがダブルクォーテーションで囲まれていても除去されることを確認する。

        Windowsエクスプローラーの「パスのコピー」等で、パス全体が
        ダブルクォーテーションで囲まれたまま貼り付けられるケースを想定する。
        """
        key_path = tmp_path / "個人用 Vault" / "master.key"
        quoted_input = f'"{key_path}"'
        handler = handler_factory([quoted_input])
        exit_code = handler.run(["init"])
        assert exit_code == 0
        assert key_path.is_file()

    def test_prompts_for_key_path_strips_surrounding_single_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """対話入力の鍵パスがシングルクォーテーションで囲まれていても除去されることを確認する。"""
        key_path = tmp_path / "vault" / "master.key"
        quoted_input = f"'{key_path}'"
        handler = handler_factory([quoted_input])
        exit_code = handler.run(["init"])
        assert exit_code == 0
        assert key_path.is_file()

    def test_existing_key_with_both_confirmations_accepted_is_overwritten(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """既存鍵がある場合、二段階警告に両方同意すると上書きされることを確認する。"""
        key_path = tmp_path / "master.key"
        key_path.write_bytes(b"\x00" * 32)
        handler = handler_factory(["y", "y"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0
        assert key_path.read_bytes() != b"\x00" * 32

    def test_existing_key_rejected_at_first_warning_is_cancelled(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """第1警告を拒否した場合、鍵ファイルが変更されずキャンセル終了コード7になることを確認する。"""
        key_path = tmp_path / "master.key"
        original_bytes = b"\x00" * 32
        key_path.write_bytes(original_bytes)
        handler = handler_factory(["n"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 7
        assert key_path.read_bytes() == original_bytes

    def test_existing_key_rejected_at_second_warning_is_cancelled(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """第2警告を拒否した場合、鍵ファイルが変更されずキャンセル終了コード7になることを確認する。"""
        key_path = tmp_path / "master.key"
        original_bytes = b"\x00" * 32
        key_path.write_bytes(original_bytes)
        handler = handler_factory(["y", "n"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 7
        assert key_path.read_bytes() == original_bytes

    def test_init_messages_do_not_leak_key_bytes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """initの案内メッセージに鍵の内容が含まれないことを確認する（Zero Leakage Rule）。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        handler.run(["init", "--key", str(key_path)])
        key_bytes = key_path.read_bytes()
        assert key_bytes.hex() not in stderr.getvalue()

    def test_key_option_strips_surrounding_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """`--key`にダブルクォーテーションで囲まれたパスを渡しても正しく解決されることを確認する。

        シェルの挙動によっては、引用符がargvの値そのものに残ったまま
        Pythonプロセスへ渡される場合があるため、argparseの`type`変換で
        正規化されることを検証する。
        """
        key_path = tmp_path / "個人用 Vault" / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", f'"{key_path}"'])
        assert exit_code == 0
        assert key_path.is_file()

    def test_short_key_option_strips_surrounding_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """短縮形`-k`にダブルクォーテーションで囲まれたパスを渡しても正しく解決されることを確認する。

        `--key`だけでなく短縮形`-k`でも同じ`type`変換（クォート除去）が
        適用されることを検証する。
        """
        key_path = tmp_path / "個人用 Vault" / "master.key"
        quoted_key_path = f'"{key_path}"'
        handler = handler_factory()
        exit_code = handler.run(["init", "-k", quoted_key_path])
        assert exit_code == 0

        # クォート除去後の期待パスに鍵ファイルが作成されていることを確認する。
        assert key_path.is_file()
        # クォート文字を含んだままのパスにはファイルが作成されていないことを確認する。
        assert not Path(quoted_key_path).exists()

        # `-k`で作成した鍵を、同じく`-k`＋クォート付きパスで読み込めることも確認する。
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        exit_code = add_handler.run(["add", "github", "-k", quoted_key_path, "--stdin"])
        assert exit_code == 0

    def test_storage_option_strips_surrounding_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """`--storage`にクォート付きパスを渡しても正しく解決されることを確認する。

        クォート除去後の期待パスにのみファイルが作成され、クォート文字を
        含んだままのパスにはファイルが作成されないこと、また`list`実行時にも
        同様にクォートが除去され登録済みサービスが読み出せることまで検証する。
        """
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "-k", str(key_path)])
        assert exit_code == 0

        custom_storage = tmp_path / "custom" / "secrets.enc"
        quoted_storage = f'"{custom_storage}"'

        # addの時点で暗号化ストレージが存在している必要があるため、
        # カスタムパスへ事前に空のストレージを直接初期化しておく
        # （`init`は`--storage`を受け付けないため）。
        SecureStorage().initialize(custom_storage, key_path.read_bytes())

        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        exit_code = add_handler.run(
            [
                "add",
                "github",
                "-k",
                str(key_path),
                "--storage",
                quoted_storage,
                "--stdin",
            ]
        )
        assert exit_code == 0

        # クォート除去後の期待パスに暗号化ストレージが存在することを確認する。
        assert custom_storage.is_file()
        # クォート文字を含んだままのパスにはファイルが作成されていないことを確認する。
        assert not Path(quoted_storage).exists()

        list_handler = handler_factory()
        exit_code = list_handler.run(
            ["list", "-k", str(key_path), "--storage", quoted_storage]
        )
        assert exit_code == 0
        assert "github" in stdout.getvalue()

    @pytest.mark.parametrize(
        ("command", "option", "value"),
        [
            ("init", "--key", ""),
            ("init", "--key", '""'),
            ("init", "--key", "''"),
            ("list", "--storage", '"   "'),
            ("list", "--storage", "'   '"),
        ],
    )
    def test_key_or_storage_option_empty_after_normalization_returns_exit_code_2(
        self,
        handler_factory: Callable[..., CliHandler],
        stderr: io.StringIO,
        command: str,
        option: str,
        value: str,
    ) -> None:
        """引用符・空白除去後に空文字列となるパスを渡すと終了コード2になることを確認する。

        `--key`は`init`で、`--storage`は（`init`が受け付けないため）`list`で
        それぞれ検証し、対象オプション自体のパス検証が働くことを確認する。
        """
        handler = handler_factory()
        exit_code = handler.run([command, option, value])
        assert exit_code == 2
        assert "Traceback" not in stderr.getvalue()
        assert "cannot be empty" in stderr.getvalue()

    @pytest.mark.parametrize(
        ("option", "value"),
        [
            ("--key", "\"invalid'"),
            ("--key", "'invalid\""),
            ("--key", '"unclosed'),
            ("--key", "unclosed'"),
        ],
    )
    def test_key_option_mismatched_or_unclosed_quotes_returns_exit_code_2(
        self,
        handler_factory: Callable[..., CliHandler],
        stderr: io.StringIO,
        option: str,
        value: str,
    ) -> None:
        """引用符が一致しない、または閉じられていないパスを渡すと終了コード2になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["init", option, value])
        assert exit_code == 2
        assert "Traceback" not in stderr.getvalue()

    def test_argument_type_error_message_is_written_to_injected_stderr(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """不正なパス引数のエラーメッセージが注入済みのstderrへ書き込まれることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", '""'])
        assert exit_code == 2
        assert "cannot be empty" in stderr.getvalue()

    def test_invalid_windows_path_characters_return_exit_code_1_without_crashing(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """Windowsで不正な文字を含むパスを指定した場合、トレースバックを出さず
        鍵保存失敗（KeyStorageError、終了コード1）として扱われることを確認する。
        """
        if not sys.platform.startswith("win"):
            pytest.skip(
                "Windows固有の不正パス文字のテストのため、Windows以外ではスキップする"
            )

        invalid_key_path = tmp_path / "in?valid" / "master.key"
        handler = handler_factory()

        exit_code = handler.run(["init", "--key", str(invalid_key_path)])

        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert "Failed to save the key file" in stderr.getvalue()
        # 未処理のPythonトレースバック（"Traceback (most recent call last)"）が
        # stderrへ現れていないことを確認する。
        assert "Traceback" not in stderr.getvalue()

    def test_os_error_during_key_creation_is_handled_gracefully(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """鍵ファイル作成時にOSErrorが発生した場合でも、run()がクラッシュせず
        KeyStorageError（終了コード1）としてわかりやすいエラーメッセージを返す
        ことを確認する（プラットフォームに依存しない決定的な検証）。
        """

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated invalid path syntax")

        monkeypatch.setattr(Path, "mkdir", _raise_os_error)

        key_path = tmp_path / "vault" / "master.key"
        handler = handler_factory()

        exit_code = handler.run(["init", "--key", str(key_path)])

        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert f"Failed to save the key file: {key_path}" in stderr.getvalue()
        assert "simulated invalid path syntax" not in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()

    def test_permission_setup_failure_aborts_init_without_key_file(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """鍵ファイルの権限設定に失敗した場合、initが終了コード1で中断し、
        鍵ファイル・一時ファイル・暗号化データを一切残さないことを確認する。
        """

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated permission failure")

        monkeypatch.setattr(os, "chmod", _raise_os_error)
        monkeypatch.setattr("subprocess.run", _raise_os_error)

        key_dir = tmp_path / "vault"
        key_path = key_dir / "master.key"
        handler = handler_factory()

        exit_code = handler.run(["init", "--key", str(key_path)])

        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert "Failed to restrict access to the key file" in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()
        assert list(key_dir.iterdir()) == []

    def test_unexpected_os_error_outside_key_storage_falls_back_to_exit_code_1(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """鍵保存以外の処理で未変換のOSErrorが発生した場合、汎用のファイル操作
        エラー（終了コード1）としてトレースバックなしで扱われることを確認する。
        """

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated storage failure")

        monkeypatch.setattr(SecureStorage, "initialize", _raise_os_error)

        handler = handler_factory()
        exit_code = handler.run(["init", "--key", str(tmp_path / "master.key")])

        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert "A file operation failed" in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()


class TestGenerateCommand:
    """`generate`/`get`/`-g`/省略形フォールバックに関するテスト。"""

    def _add_github(
        self, handler_factory: Callable[..., CliHandler], key_path: Path
    ) -> None:
        handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        exit_code = handler.run(
            [
                "add",
                "github",
                "--key",
                str(key_path),
                "--stdin",
                "--issuer",
                "GitHub",
            ]
        )
        assert exit_code == 0

    def test_generate_outputs_six_digit_code_on_stdout(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """generateがstdoutへ6桁のコードのみを出力することを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["generate", "github", "--key", str(key_path)])
        assert exit_code == 0
        output = stdout.getvalue().strip()
        assert output.isdigit()
        assert len(output) == 6

    def test_get_alias_produces_same_code_as_generate(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`get`エイリアスが`generate`と同じ結果になることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["get", "github", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()

    def test_dash_g_alias_produces_a_code(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`-g`エイリアスが正しくgenerateとして動作することを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["-g", "github", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()

    def test_bare_service_name_falls_back_to_generate(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """予約語でないサービス名のみの指定が自動的にgenerateとして扱われることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["github", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()

    def test_writes_remaining_seconds_bar_to_stderr(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stderr: io.StringIO,
    ) -> None:
        """remaining_secondsバーがstderrへ出力されることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        handler.run(["generate", "github", "--key", str(key_path)])
        assert "[" in stderr.getvalue()
        assert "]" in stderr.getvalue()

    def test_stdout_contains_only_the_code_and_no_progress_bar(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """stdoutにはコードのみが出力され、remaining_secondsバーが含まれないことを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        handler.run(["generate", "github", "--key", str(key_path)])

        output = stdout.getvalue()
        assert output == output.strip() + "\n"
        assert "[" not in output
        assert "]" not in output
        assert "#" not in output
        assert "-" not in output

    def test_stderr_does_not_contain_the_generated_code(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """stderrには生成された6桁コードが含まれないことを確認する（stdout/stderrの厳密な分離）。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        handler.run(["generate", "github", "--key", str(key_path)])

        code = stdout.getvalue().strip()
        assert code not in stderr.getvalue()

    def test_missing_key_file_returns_exit_code_3(
        self, handler_factory: Callable[..., CliHandler], tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合、終了コード3になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(
            ["generate", "github", "--key", str(tmp_path / "missing.key")]
        )
        assert exit_code == 3

    def test_missing_service_returns_exit_code_5(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """未登録のサービスを指定した場合、終了コード5になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(["generate", "unknown-service", "--key", str(key_path)])
        assert exit_code == 5

    def test_corrupted_storage_returns_exit_code_4(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
    ) -> None:
        """暗号化ストレージが破損している場合、終了コード4になることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        config = json.loads(config_path.read_text(encoding="utf-8"))
        storage_path = config_path.parent / "vtotp-secrets.enc"
        document = json.loads(storage_path.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 0xFF
        document["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
        storage_path.write_text(json.dumps(document), encoding="utf-8")

        handler = handler_factory()
        exit_code = handler.run(["generate", "github", "--key", str(key_path)])
        assert exit_code == 4
        assert config  # サニティチェック（未使用警告防止）

    def test_generate_stdout_never_contains_secret_or_key_bytes(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """stdout/stderrのいずれにも元のシークレットや鍵の内容が現れないことを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)
        key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["generate", "github", "--key", str(key_path)])

        combined = stdout.getvalue() + stderr.getvalue()
        assert "JBSWY3DPEHPK3PXP" not in combined
        assert key_bytes.hex() not in combined


class TestAddCommand:
    """`add` サブコマンドに関するテスト。"""

    @staticmethod
    def _load_records(config_path: Path, key_path: Path) -> dict[str, SecretRecord]:
        """既定の暗号化データファイルから登録済みレコードを直接読み出す。"""
        return SecureStorage().load_secrets(
            config_path.parent / "vtotp-secrets.enc", key_path.read_bytes()
        )

    @pytest.mark.parametrize(
        "payload",
        ["JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP\n", "JBSWY3DPEHPK3PXP\r\n"],
    )
    def test_add_with_stdin_registers_service(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
        payload: str,
    ) -> None:
        """`--stdin`で標準入力から読み込んだシークレットでサービスが登録され、
        末尾の改行（LF/CRLF）が除去されることを確認する。
        """
        _, key_path = initialized_handler
        handler = handler_factory(stdin=payload)
        exit_code = handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 0

        records = self._load_records(config_path, key_path)
        assert records["github"].secret == "JBSWY3DPEHPK3PXP"
        assert records["github"].issuer is None

    def test_add_with_stdin_and_issuer_registers_issuer(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
    ) -> None:
        """`--stdin`と`--issuer`を併用した場合、発行者名も登録されることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        exit_code = handler.run(
            ["add", "github", "--issuer", "GitHub", "--stdin", "--key", str(key_path)]
        )
        assert exit_code == 0

        records = self._load_records(config_path, key_path)
        assert records["github"].issuer == "GitHub"

    def test_add_with_stdin_does_not_show_interactive_prompt(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`--stdin`指定時は対話プロンプトを表示・使用せず、標準入力の値を採用することを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory(["KRSXG5CTMVRXEZLU"], stdin="JBSWY3DPEHPK3PXP\n")
        exit_code = handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 0

        assert "Enter the TOTP secret" not in stderr.getvalue()
        records = self._load_records(config_path, key_path)
        assert records["github"].secret == "JBSWY3DPEHPK3PXP"

    @pytest.mark.parametrize("payload", ["", "\n", "\r\n", "\n\n", "\r\n\r\n"])
    def test_add_with_empty_stdin_returns_exit_code_6(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
        stderr: io.StringIO,
        payload: str,
    ) -> None:
        """`--stdin`で空文字列・改行のみが渡された場合、キャンセル(7)ではなく
        不正なシークレット（終了コード6）として扱われ、何も登録されないことを確認する。
        """
        _, key_path = initialized_handler
        handler = handler_factory(stdin=payload)
        exit_code = handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 6
        assert "TOTP secret is empty" in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()
        assert self._load_records(config_path, key_path) == {}

    def test_add_with_whitespace_only_stdin_returns_exit_code_6(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`--stdin`で空白のみが渡された場合も、終了コード6になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory(stdin="   \n")
        exit_code = handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 6

    def test_add_with_undecodable_stdin_returns_exit_code_6(
        self,
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """標準入力がテキストとしてデコードできない場合、トレースバックや入力内容を
        出力せずに終了コード6になることを確認する（Zero Leakage Rule）。
        """
        _, key_path = initialized_handler
        handler = CliHandler(
            stdout=stdout,
            stderr=stderr,
            config_path=config_path,
            stdin=io.TextIOWrapper(io.BytesIO(b"\xff\xfeJBSWY3DPEHPK3PXP"), "utf-8"),
        )
        exit_code = handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 6

        combined = stdout.getvalue() + stderr.getvalue()
        assert "Traceback" not in combined
        assert "JBSWY3DPEHPK3PXP" not in combined
        assert "0xff" not in combined

    def test_add_prompts_for_secret_when_stdin_option_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`--stdin`未指定時にプロンプトをstderrへ表示し、対話入力でシークレットを取得することを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory(["JBSWY3DPEHPK3PXP"])
        exit_code = handler.run(["add", "github", "--key", str(key_path)])
        assert exit_code == 0
        assert "Enter the TOTP secret" in stderr.getvalue()

        records = self._load_records(config_path, key_path)
        assert records["github"].secret == "JBSWY3DPEHPK3PXP"

    def test_interactive_secret_prompt_uses_masked_getpass_by_default(
        self,
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`secret_input_func`未注入時、シークレットの対話入力にエコー無しの
        `getpass.getpass`が使われ、入力値が画面へ出力されないことを確認する。
        """
        _, key_path = initialized_handler
        calls: list[str] = []

        def _fake_getpass(prompt: str = "Password: ", stream: object = None) -> str:
            calls.append(prompt)
            return "JBSWY3DPEHPK3PXP"

        monkeypatch.setattr(getpass, "getpass", _fake_getpass)
        handler = CliHandler(stdout=stdout, stderr=stderr, config_path=config_path)
        exit_code = handler.run(["add", "github", "--key", str(key_path)])
        assert exit_code == 0

        # プロンプト文言はCliHandler自身がstderrへ表示し、getpassには空文字列を渡す。
        assert calls == [""]
        assert "Enter the TOTP secret" in stderr.getvalue()
        assert "JBSWY3DPEHPK3PXP" not in stdout.getvalue() + stderr.getvalue()

    def test_stdin_option_reads_sys_stdin_by_default(
        self,
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`stdin`未注入時、`--stdin`が`sys.stdin`から読み込むことを確認する。"""
        _, key_path = initialized_handler
        monkeypatch.setattr(sys, "stdin", io.StringIO("JBSWY3DPEHPK3PXP\n"))
        handler = CliHandler(stdout=stdout, stderr=stderr, config_path=config_path)
        exit_code = handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 0

        records = self._load_records(config_path, key_path)
        assert records["github"].secret == "JBSWY3DPEHPK3PXP"

    def test_add_cancelled_when_secret_prompt_is_empty(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """シークレット入力が空欄の場合、終了コード7（キャンセル）になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory([""])
        exit_code = handler.run(["add", "github", "--key", str(key_path)])
        assert exit_code == 7

    def test_add_with_invalid_secret_returns_exit_code_6(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """不正な形式のシークレットの場合、終了コード6になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory(stdin="not-valid-base32!!!\n")
        exit_code = handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 6

    def test_add_duplicate_service_returns_exit_code_1(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """重複登録の場合、終了コード1（一般エラー）になることを確認する。"""
        _, key_path = initialized_handler
        first = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        assert (
            first.run(
                [
                    "add",
                    "github",
                    "--key",
                    str(key_path),
                    "--stdin",
                ]
            )
            == 0
        )

        second = handler_factory(stdin="KRSXG5CTMVRXEZLU\n")
        exit_code = second.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 1

    def test_add_output_never_leaks_the_secret_value(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """addの標準出力・標準エラー出力に、渡したシークレットの値が含まれないことを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        combined = stdout.getvalue() + stderr.getvalue()
        assert "JBSWY3DPEHPK3PXP" not in combined

    def test_duplicate_service_error_does_not_leak_the_attempted_secret(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """重複登録（終了コード1）の際、入力したシークレットがstdout/stderrに現れないことを確認する。"""
        _, key_path = initialized_handler
        first = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        assert (
            first.run(
                [
                    "add",
                    "github",
                    "--key",
                    str(key_path),
                    "--stdin",
                ]
            )
            == 0
        )
        stdout.truncate(0)
        stdout.seek(0)
        stderr.truncate(0)
        stderr.seek(0)

        second = handler_factory(stdin="KRSXG5CTMVRXEZLU\n")
        exit_code = second.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 1

        combined = stdout.getvalue() + stderr.getvalue()
        assert "KRSXG5CTMVRXEZLU" not in combined
        assert "JBSWY3DPEHPK3PXP" not in combined

    def test_invalid_secret_error_does_not_leak_the_attempted_secret(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """不正なシークレット（終了コード6）の際、入力したシークレットがstdout/stderrに現れないことを確認する。"""
        _, key_path = initialized_handler
        invalid_secret = "not-valid-base32!!!"

        handler = handler_factory(stdin=f"{invalid_secret}\n")
        exit_code = handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        assert exit_code == 6

        combined = stdout.getvalue() + stderr.getvalue()
        assert invalid_secret not in combined


#: 廃止引数のテストで渡すシークレット値（stdout/stderrに現れてはならない）。
_DEPRECATED_ARG_SECRET = "GEZDGNBVGY3TQOJQ"


class TestDeprecatedSecretArgRejection:
    """廃止済み`--secret`/`-s`の事前検査とエコーバック防止に関するテスト（DESIGN.md 20.3）。"""

    @staticmethod
    def _storage_is_empty(config_path: Path, key_path: Path) -> bool:
        records = SecureStorage().load_secrets(
            config_path.parent / "vtotp-secrets.enc", key_path.read_bytes()
        )
        return records == {}

    @pytest.mark.parametrize(
        "secret_args",
        [
            ["--secret", _DEPRECATED_ARG_SECRET],
            ["-s", _DEPRECATED_ARG_SECRET],
            [f"--secret={_DEPRECATED_ARG_SECRET}"],
            [f"-s{_DEPRECATED_ARG_SECRET}"],
            ["--sec", _DEPRECATED_ARG_SECRET],
            [f"--secre={_DEPRECATED_ARG_SECRET}"],
            ["--stdin", "--secret", _DEPRECATED_ARG_SECRET],
            ["--issuer", "GitHub", "-s", _DEPRECATED_ARG_SECRET],
            ["--", "--secret", _DEPRECATED_ARG_SECRET],
        ],
    )
    def test_deprecated_secret_arg_is_rejected_without_echoing_value(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
        secret_args: list[str],
    ) -> None:
        """`--secret`/`-s`（結合形式・省略形を含む）が終了コード2で拒否され、stderrには
        固定の`SECRET_ARG_DEPRECATED`文言だけが出力され、シークレット値は一切含まれない
        ことを確認する。
        """
        _, key_path = initialized_handler
        handler = handler_factory(
            [_DEPRECATED_ARG_SECRET], stdin=f"{_DEPRECATED_ARG_SECRET}\n"
        )
        exit_code = handler.run(["add", "github", "--key", str(key_path), *secret_args])

        assert exit_code == 2
        expected_message = EN_CATALOG[MsgKey.SECRET_ARG_DEPRECATED]
        assert stderr.getvalue() == f"Error: {expected_message}\n"
        assert _DEPRECATED_ARG_SECRET not in stderr.getvalue()
        assert _DEPRECATED_ARG_SECRET not in stdout.getvalue()
        assert "unrecognized arguments" not in stderr.getvalue()
        assert self._storage_is_empty(config_path, key_path)

    @pytest.mark.parametrize(
        "argv",
        [
            ["add", "--secret", _DEPRECATED_ARG_SECRET, "github"],
            ["add", f"-s{_DEPRECATED_ARG_SECRET}", "github"],
        ],
    )
    def test_deprecated_secret_arg_before_service_takes_precedence(
        self,
        handler_factory: Callable[..., CliHandler],
        stderr: io.StringIO,
        argv: list[str],
    ) -> None:
        """SERVICEより前に置かれた場合も、位置検証ではなく廃止引数のメッセージで拒否されることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(argv)
        assert exit_code == 2
        assert EN_CATALOG[MsgKey.SECRET_ARG_DEPRECATED] in stderr.getvalue()
        assert _DEPRECATED_ARG_SECRET not in stderr.getvalue()

    def test_rejection_message_is_localized_to_japanese(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stderr: io.StringIO,
    ) -> None:
        """`-l ja`指定時、廃止引数の拒否メッセージが日本語で表示されることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(
            [
                "add",
                "github",
                "--key",
                str(key_path),
                "--secret",
                _DEPRECATED_ARG_SECRET,
                "-l",
                "ja",
            ]
        )
        assert exit_code == 2
        assert stderr.getvalue() == (
            f"エラー: {JA_CATALOG[MsgKey.SECRET_ARG_DEPRECATED]}\n"
        )
        assert _DEPRECATED_ARG_SECRET not in stderr.getvalue()

    @pytest.mark.parametrize(
        "secret_token",
        [
            "--secret",
            f"--secret={_DEPRECATED_ARG_SECRET}",
            f"-s{_DEPRECATED_ARG_SECRET}",
        ],
    )
    def test_raised_error_carries_no_secret_or_raw_arguments(
        self, handler_factory: Callable[..., CliHandler], secret_token: str
    ) -> None:
        """送出される`CommandParseError`が終了コード2・`SECRET_ARG_DEPRECATED`・空の
        コンテキストのみを持ち、引数列やシークレット値を保持しないことを確認する。
        """
        handler = handler_factory()
        with pytest.raises(CommandParseError) as exc_info:
            handler.reject_deprecated_secret_args(
                ["add", "github", secret_token, _DEPRECATED_ARG_SECRET]
            )

        error = exc_info.value
        assert error.exit_code == 2
        assert error.message_key is MsgKey.SECRET_ARG_DEPRECATED
        assert dict(error.context) == {}
        assert _DEPRECATED_ARG_SECRET not in str(error)
        assert _DEPRECATED_ARG_SECRET not in repr(error.args)

    @pytest.mark.parametrize(
        "argv",
        [
            [],
            ["generate", "github", "-s", _DEPRECATED_ARG_SECRET],
            ["add", "github"],
            ["add", "github", "--stdin", "--storage", "PATH", "--issuer", "X"],
            ["add", "github", "--st", "-k", "PATH", "-l", "ja", "-h"],
            ["add", "github", "--s"],
            ["add", "github", "--storage=--secret-store.enc"],
        ],
    )
    def test_non_deprecated_arguments_pass_through(
        self, handler_factory: Callable[..., CliHandler], argv: list[str]
    ) -> None:
        """`add`以外のコマンドや、現行オプション（`--stdin`/`--storage`等・`--s`/`--st`の
        曖昧な省略形）は事前検査で誤検知されず、後続の解析へ委ねられることを確認する。
        """
        handler = handler_factory()
        handler.reject_deprecated_secret_args(argv)


class TestListCommand:
    """`list`/`ls` サブコマンドに関するテスト。"""

    def test_empty_registry_produces_empty_stdout(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """未登録の状態では標準出力が空であることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(["list", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue() == ""

    def test_lists_registered_services_without_secrets(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """登録済みサービス名が一覧に含まれ、シークレットは含まれないことを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        add_handler.run(["add", "github", "--key", str(key_path), "--stdin"])

        list_handler = handler_factory()
        exit_code = list_handler.run(["list", "--key", str(key_path)])
        assert exit_code == 0
        assert "github" in stdout.getvalue()
        assert "JBSWY3DPEHPK3PXP" not in stdout.getvalue()

    def test_ls_alias_behaves_like_list(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`ls`エイリアスが`list`と同じ結果になることを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        add_handler.run(["add", "github", "--key", str(key_path), "--stdin"])

        ls_handler = handler_factory()
        exit_code = ls_handler.run(["ls", "--key", str(key_path)])
        assert exit_code == 0
        assert "github" in stdout.getvalue()


class TestRemoveCommand:
    """`remove`/`rm` サブコマンドに関するテスト。"""

    def _add_github(
        self, handler_factory: Callable[..., CliHandler], key_path: Path
    ) -> None:
        handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        handler.run(["add", "github", "--key", str(key_path), "--stdin"])

    def test_remove_with_force_skips_confirmation(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """--force指定時は確認なしで削除されることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["remove", "github", "--force", "--key", str(key_path)])
        assert exit_code == 0

        list_handler = handler_factory()
        list_handler.run(["list", "--key", str(key_path)])
        assert "github" not in stdout.getvalue()

    def test_remove_confirmed_deletes_service(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """確認に同意した場合、サービスが削除されることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory(["y"])
        exit_code = handler.run(["remove", "github", "--key", str(key_path)])
        assert exit_code == 0

    def test_remove_rejected_is_cancelled_and_keeps_service(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """確認を拒否した場合、キャンセルされサービスが残ることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory(["n"])
        exit_code = handler.run(["remove", "github", "--key", str(key_path)])
        assert exit_code == 7

        list_handler = handler_factory()
        list_handler.run(["list", "--key", str(key_path)])
        assert "github" in stdout.getvalue()

    def test_remove_missing_service_returns_exit_code_5(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """未登録のサービスを削除しようとすると終了コード5になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(
            ["remove", "unknown-service", "--force", "--key", str(key_path)]
        )
        assert exit_code == 5

    def test_rm_alias_behaves_like_remove(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`rm`エイリアスが`remove`と同じ結果になることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["rm", "github", "--force", "--key", str(key_path)])
        assert exit_code == 0


class TestRekeyCommand:
    """`rekey` サブコマンドに関するテスト。"""

    def test_rekey_replaces_key_and_reencrypts_data(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """rekey後、新しい鍵でサービス情報が読み込めることを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        add_handler.run(["add", "github", "--key", str(key_path), "--stdin"])
        old_key_bytes = key_path.read_bytes()

        rekey_handler = handler_factory()
        exit_code = rekey_handler.run(["rekey", "--key", str(key_path)])
        assert exit_code == 0
        assert key_path.read_bytes() != old_key_bytes

        list_handler = handler_factory()
        list_stdout_exit_code = list_handler.run(["list", "--key", str(key_path)])
        assert list_stdout_exit_code == 0

    def test_rekey_creates_generation_one_backup_of_old_key(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """rekey後、旧鍵が`<key_path>.1`へ退避されることを確認する。"""
        _, key_path = initialized_handler
        old_key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["rekey", "--key", str(key_path)])

        rotated = Path(f"{key_path}.1")
        assert rotated.is_file()
        assert rotated.read_bytes() == old_key_bytes

    def test_rekey_permission_failure_keeps_old_key_and_data_usable(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """新鍵の権限設定に失敗した場合、rekeyが終了コード1で中断し、
        旧鍵・暗号化データがそのまま利用可能であることを確認する（フェイルセーフ）。
        """
        _, key_path = initialized_handler
        handler_factory(stdin="JBSWY3DPEHPK3PXP\n").run(
            ["add", "github", "--key", str(key_path), "--stdin"]
        )
        old_key_bytes = key_path.read_bytes()

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated permission failure")

        with monkeypatch.context() as patch:
            patch.setattr(os, "chmod", _raise_os_error)
            patch.setattr("subprocess.run", _raise_os_error)
            exit_code = handler_factory().run(["rekey", "--key", str(key_path)])

        assert exit_code == 1
        assert "Failed to restrict access to the key file" in stderr.getvalue()
        assert key_path.read_bytes() == old_key_bytes
        assert not Path(f"{key_path}.1").exists()
        assert handler_factory().run(["list", "--key", str(key_path)]) == 0

    def test_rekey_prompts_rotation_limit_warning_when_three_generations_exist(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`.3`世代が既に存在する場合、上限警告に同意しなければキャンセルされることを確認する。"""
        _, key_path = initialized_handler
        for generation in (1, 2, 3):
            Path(f"{key_path}.{generation}").write_bytes(bytes([generation]) * 32)

        handler = handler_factory(["n"])
        exit_code = handler.run(["rekey", "--key", str(key_path)])
        assert exit_code == 7

        accepted_handler = handler_factory(["y"])
        exit_code = accepted_handler.run(["rekey", "--key", str(key_path)])
        assert exit_code == 0

    def test_rekey_output_does_not_leak_key_bytes(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """rekeyの出力に鍵の内容が含まれないことを確認する（Zero Leakage Rule）。"""
        _, key_path = initialized_handler
        old_key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["rekey", "--key", str(key_path)])
        new_key_bytes = key_path.read_bytes()

        combined = stdout.getvalue() + stderr.getvalue()
        assert old_key_bytes.hex() not in combined
        assert new_key_bytes.hex() not in combined


class TestShortKeyOption:
    """`-k`（`--key`の短縮オプション）が全サブコマンドで使用できることに関するテスト。"""

    def test_init_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """`init -k PATH`が`--key`指定時と同様に鍵ファイルを作成することを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "-k", str(key_path)])
        assert exit_code == 0
        assert key_path.is_file()

    def test_generate_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`generate -k PATH SERVICE`が正しく鍵パスを解決してコードを生成することを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        add_handler.run(["add", "github", "-k", str(key_path), "--stdin"])

        handler = handler_factory()
        exit_code = handler.run(["generate", "github", "-k", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()

    def test_add_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`add -k PATH SERVICE`が正しく鍵パスを解決してサービスを登録できることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        exit_code = handler.run(["add", "github", "-k", str(key_path), "--stdin"])
        assert exit_code == 0

    def test_list_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`list -k PATH`が正しく鍵パスを解決してサービス一覧を表示できることを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        add_handler.run(["add", "github", "-k", str(key_path), "--stdin"])

        handler = handler_factory()
        exit_code = handler.run(["list", "-k", str(key_path)])
        assert exit_code == 0
        assert "github" in stdout.getvalue()

    def test_remove_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`remove -k PATH SERVICE`が正しく鍵パスを解決してサービスを削除できることを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        add_handler.run(["add", "github", "-k", str(key_path), "--stdin"])

        handler = handler_factory()
        exit_code = handler.run(["remove", "github", "--force", "-k", str(key_path)])
        assert exit_code == 0

    def test_rekey_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`rekey -k PATH`が正しく鍵パスを解決して鍵を更新できることを確認する。"""
        _, key_path = initialized_handler
        old_key_bytes = key_path.read_bytes()

        handler = handler_factory()
        exit_code = handler.run(["rekey", "-k", str(key_path)])
        assert exit_code == 0
        assert key_path.read_bytes() != old_key_bytes


class TestConfigCommand:
    """`config` サブコマンドに関するテスト。"""

    def test_shows_unset_key_path_before_init(
        self,
        handler_factory: Callable[..., CliHandler],
        stdout: io.StringIO,
    ) -> None:
        """init前はkey_pathが未設定として表示されることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert "(not set)" in stdout.getvalue()

    def test_shows_resolved_paths_after_init(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """init後は解決済みのkey_path/storage_pathが表示されることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert str(key_path) in stdout.getvalue()

    def test_config_output_does_not_leak_key_bytes(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """configコマンドの出力に鍵の内容が含まれないことを確認する。"""
        _, key_path = initialized_handler
        key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["config"])
        assert key_bytes.hex() not in stdout.getvalue()


class TestArgumentParseErrors:
    """CLI引数解析エラーに関するテスト。"""

    def test_missing_required_positional_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """generateにサービス名を指定しない場合、終了コード2になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["generate"])
        assert exit_code == 2

    def test_unknown_option_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """未知のオプションを指定した場合、終了コード2になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["list", "--no-such-option"])
        assert exit_code == 2

    def test_parse_error_message_is_written_to_injected_stderr(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """解析エラーのメッセージが注入済みのstderrへ書き込まれることを確認する。"""
        handler = handler_factory()
        handler.run(["generate"])
        assert "Error" in stderr.getvalue()


class TestHelpAndVersion:
    """`-h`/`--help`/`--version`に関するテスト（argparseの標準出力を使うためcapsysで検証する）。"""

    def test_help_exits_with_code_zero(
        self,
        handler_factory: Callable[..., CliHandler],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`--help`が終了コード0で完了することを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["--help"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "usage" in captured.out.lower()

    def test_no_arguments_shows_help_and_exits_with_code_zero(
        self,
        handler_factory: Callable[..., CliHandler],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """引数なしで実行した場合、ヘルプを表示して終了コード0になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run([])
        assert exit_code == 0

    def test_version_exits_with_code_zero(
        self,
        handler_factory: Callable[..., CliHandler],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`--version`が終了コード0で完了することを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["--version"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "vtotp" in captured.out


class TestKeyManagerIntegration:
    """CliHandlerが実際のKeyManagerと整合していることを確認するテスト。"""

    def test_default_key_manager_matches_max_rotated_keys_constant(self) -> None:
        """CliHandlerが依存するKeyManagerの世代数上限が3であることを確認する（DESIGN.md準拠）。"""
        assert KeyManager.MAX_ROTATED_KEYS == 3


class TestConfigFileHandling:
    """config.jsonの読み込み・パス解決の境界値・異常系に関するテスト。"""

    def test_totp_key_path_environment_variable_is_used_when_cli_key_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--key未指定でもVTOTP_KEY_PATH環境変数の鍵パスが使われ、コマンドが正常動作することを確認する。

        config.jsonにはkey_pathを一切保存せず、環境変数のみから鍵パスが
        解決されることを明確に示すため、config.json自体を作成しない。
        """
        key_path = tmp_path / "env-master.key"
        storage_path = tmp_path / "env-secrets.enc"

        key_manager = KeyManager()
        key_manager.create_key_file(key_path)
        key_bytes = key_manager.load_key(key_path)
        SecureStorage().save_secrets(
            storage_path,
            key_bytes,
            {"github": SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP")},
        )

        monkeypatch.setenv(ENV_KEY_PATH_VARIABLE, str(key_path))

        handler = handler_factory()
        exit_code = handler.run(["list", "--storage", str(storage_path)])

        assert exit_code == 0
        assert "github" in stdout.getvalue()

    def test_cli_key_option_takes_priority_over_environment_variable(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CLIの`-k`/`--key`がVTOTP_KEY_PATH環境変数より優先されることを確認する。

        環境変数側の鍵で暗号化されたストレージは`--storage`で指定しない
        ため、もしCLI指定が無視され環境変数の鍵が使われてしまった場合は
        復号に失敗し（終了コード4）、優先順位の誤りが明確に検出できる。
        """
        cli_key_path = tmp_path / "cli-master.key"
        cli_storage_path = tmp_path / "cli-secrets.enc"
        env_key_path = tmp_path / "env-master.key"

        cli_key_manager = KeyManager()
        cli_key_manager.create_key_file(cli_key_path)
        SecureStorage().save_secrets(
            cli_storage_path,
            cli_key_manager.load_key(cli_key_path),
            {
                "from-cli": SecretRecord(
                    service_name="from-cli", secret="JBSWY3DPEHPK3PXP"
                )
            },
        )
        # 環境変数側の鍵は、CLI指定の鍵とは異なるバイト列であればよい。
        KeyManager().create_key_file(env_key_path)

        monkeypatch.setenv(ENV_KEY_PATH_VARIABLE, str(env_key_path))

        handler = handler_factory()
        exit_code = handler.run(
            ["list", "-k", str(cli_key_path), "--storage", str(cli_storage_path)]
        )

        assert exit_code == 0
        assert "from-cli" in stdout.getvalue()

    def test_environment_variable_takes_priority_over_config_file(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        stdout: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VTOTP_KEY_PATH環境変数がconfig.jsonのkey_pathより優先されることを確認する。

        config.json側の鍵で暗号化されたストレージは`--storage`で指定しない
        ため、もし環境変数が無視されconfig.jsonの鍵が使われてしまった場合は
        復号に失敗し（終了コード4）、優先順位の誤りが明確に検出できる。
        """
        config_key_path = tmp_path / "config-master.key"
        env_key_path = tmp_path / "env-master.key"
        env_storage_path = tmp_path / "env-secrets.enc"

        KeyManager().create_key_file(config_key_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps({"key_path": str(config_key_path)}), encoding="utf-8"
        )

        env_key_manager = KeyManager()
        env_key_manager.create_key_file(env_key_path)
        SecureStorage().save_secrets(
            env_storage_path,
            env_key_manager.load_key(env_key_path),
            {
                "from-env": SecretRecord(
                    service_name="from-env", secret="JBSWY3DPEHPK3PXP"
                )
            },
        )

        monkeypatch.setenv(ENV_KEY_PATH_VARIABLE, str(env_key_path))

        handler = handler_factory()
        exit_code = handler.run(["list", "--storage", str(env_storage_path)])

        assert exit_code == 0
        assert "from-env" in stdout.getvalue()

    def test_invalid_json_config_file_is_treated_as_empty(
        self,
        handler_factory: Callable[..., CliHandler],
        config_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """config.jsonがJSONとして解析できない場合、空の設定として扱われることを確認する。"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("{not valid json", encoding="utf-8")

        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert "(not set)" in stdout.getvalue()

    def test_non_object_json_config_file_is_treated_as_empty(
        self,
        handler_factory: Callable[..., CliHandler],
        config_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """config.jsonのトップレベルがオブジェクトでない場合、空の設定として扱われることを確認する。"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("[]", encoding="utf-8")

        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert "(not set)" in stdout.getvalue()

    def test_explicit_storage_option_overrides_config_and_default(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        tmp_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """`--storage`を明示指定した場合、そのパスが暗号化データファイルとして使われることを確認する。"""
        _, key_path = initialized_handler
        custom_storage = tmp_path / "custom" / "secrets.enc"
        SecureStorage().initialize(custom_storage, key_path.read_bytes())

        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        exit_code = add_handler.run(
            [
                "add",
                "github",
                "--key",
                str(key_path),
                "--storage",
                str(custom_storage),
                "--stdin",
            ]
        )
        assert exit_code == 0
        assert custom_storage.is_file()

        list_handler = handler_factory()
        exit_code = list_handler.run(
            ["list", "--key", str(key_path), "--storage", str(custom_storage)]
        )
        assert exit_code == 0
        assert "github" in stdout.getvalue()

    def test_storage_path_from_config_file_is_used_when_cli_option_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """config.jsonにstorage_pathが設定済みの場合、そのパスが使われることを確認する。"""
        key_path = tmp_path / "master.key"
        custom_storage = tmp_path / "configured" / "secrets.enc"

        init_handler = handler_factory()
        assert init_handler.run(["init", "--key", str(key_path)]) == 0
        SecureStorage().initialize(custom_storage, key_path.read_bytes())

        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["storage_path"] = str(custom_storage)
        config_path.write_text(json.dumps(config), encoding="utf-8")

        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        exit_code = add_handler.run(
            ["add", "github", "--key", str(key_path), "--stdin"]
        )
        assert exit_code == 0
        assert custom_storage.is_file()

        list_handler = handler_factory()
        list_handler.run(["list", "--key", str(key_path)])
        assert "github" in stdout.getvalue()

    def test_save_key_path_failure_propagates_and_cleans_up_temp_file(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """config.json保存（_save_key_path）でos.replaceが失敗した場合、例外が伝播し一時ファイルが残らないことを確認する。"""
        key_path = tmp_path / "master.key"

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated replace failure")

        monkeypatch.setattr(os, "replace", _raise_os_error)

        handler = handler_factory()
        with pytest.raises(OSError):
            handler._save_key_path(key_path)

        assert not config_path.exists()
        leftover = [
            entry
            for entry in config_path.parent.iterdir()
            if entry.name.startswith(".config.")
        ]
        assert leftover == []


class TestExitCodeFromSystemExit:
    """CliHandler._exit_code_from_system_exit（SystemExit→終了コード変換）に関するテスト。"""

    def test_none_code_maps_to_zero(self) -> None:
        """SystemExit(None)が終了コード0へ変換されることを確認する。"""
        assert CliHandler._exit_code_from_system_exit(SystemExit(None)) == 0

    def test_integer_code_is_returned_as_is(self) -> None:
        """整数の終了コードがそのまま返されることを確認する。"""
        assert CliHandler._exit_code_from_system_exit(SystemExit(2)) == 2

    def test_non_integer_code_maps_to_one(self) -> None:
        """文字列など整数でない終了コードが一般エラー(1)へ変換されることを確認する。"""
        assert CliHandler._exit_code_from_system_exit(SystemExit("some message")) == 1


class TestInteractivePromptEofHandling:
    """対話入力が枯渇（EOF）した場合のフォールバック挙動に関するテスト。"""

    def test_confirm_treats_eof_as_rejection(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """確認プロンプトでEOFになった場合、拒否（キャンセル）として扱われることを確認する。"""
        key_path = tmp_path / "master.key"
        key_path.write_bytes(b"\x00" * 32)

        # 2段階警告の1回目の応答すら得られずEOFになるケース。
        handler = handler_factory([])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 7

    def test_prompt_for_key_output_path_treats_eof_as_cancel(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """鍵出力先パスの対話入力でEOFになった場合、キャンセルとして扱われることを確認する。"""
        handler = handler_factory([])
        exit_code = handler.run(["init"])
        assert exit_code == 7

    def test_prompt_for_secret_treats_eof_as_cancel(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """シークレットの対話入力でEOFになった場合、キャンセルとして扱われることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory([])
        exit_code = handler.run(["add", "github", "--key", str(key_path)])
        assert exit_code == 7


class TestLanguageOption:
    """`-l`/`--lang` オプションおよび表示言語解決優先順位に関するテスト（DESIGN.md 23.2）。"""

    def test_error_message_defaults_to_english_without_lang_option(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`-l`未指定・環境変数未設定の場合、既定で英語のエラーメッセージになることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(
            ["generate", "github", "--key", str(tmp_path / "missing.key")]
        )
        assert exit_code == 3
        assert "Error: Key file not found" in stderr.getvalue()

    def test_lang_option_switches_error_message_to_japanese(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`-l ja`指定時、エラーメッセージが日本語で表示されることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(
            [
                "generate",
                "github",
                "--key",
                str(tmp_path / "missing.key"),
                "-l",
                "ja",
            ]
        )
        assert exit_code == 3
        assert "エラー: 鍵ファイルが見つかりません" in stderr.getvalue()

    def test_long_lang_option_form_also_switches_language(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`--lang ja`（長形式）でも同様に言語が切り替わることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(
            [
                "generate",
                "github",
                "--key",
                str(tmp_path / "missing.key"),
                "--lang",
                "ja",
            ]
        )
        assert exit_code == 3
        assert "エラー" in stderr.getvalue()

    def test_option_before_service_is_rejected_with_exit_code_2(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`SERVICE`より前に置かれたオプションは終了コード2で拒否されることを確認する
        （DESIGN.md 20.1「第一引数固定と後置オプション」。旧5章の「順不同」記述は
        24章により本ルールへ置き換えられている）。
        """
        handler = handler_factory()
        exit_code = handler.run(
            ["generate", "-l", "ja", "github", "--key", str(tmp_path / "missing.key")]
        )
        assert exit_code == 2
        assert "Traceback" not in stderr.getvalue()

    def test_lang_equals_syntax_is_recognized_during_prescan(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`--lang=ja`（`=`区切り形式）でも表示言語が切り替わることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(
            [
                "generate",
                "github",
                "--key",
                str(tmp_path / "missing.key"),
                "--lang=ja",
            ]
        )
        assert exit_code == 3
        assert "エラー" in stderr.getvalue()

    def test_invalid_lang_value_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """`en`/`ja`以外の`--lang`値は終了コード2になることを確認する（argparseのchoices検証）。"""
        handler = handler_factory()
        exit_code = handler.run(["list", "--lang", "fr"])
        assert exit_code == 2

    def test_env_variable_selects_language_without_cli_flag(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`-l`未指定でも、VTOTP_LANG環境変数により表示言語が切り替わることを確認する。"""
        monkeypatch.setenv(ENV_LANG_VARIABLE, "ja")
        handler = handler_factory()
        exit_code = handler.run(
            ["generate", "github", "--key", str(tmp_path / "missing.key")]
        )
        assert exit_code == 3
        assert "エラー" in stderr.getvalue()

    def test_cli_flag_overrides_environment_variable(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`-l`がVTOTP_LANG環境変数より優先されることを確認する。"""
        monkeypatch.setenv(ENV_LANG_VARIABLE, "ja")
        handler = handler_factory()
        exit_code = handler.run(
            [
                "generate",
                "github",
                "--key",
                str(tmp_path / "missing.key"),
                "-l",
                "en",
            ]
        )
        assert exit_code == 3
        assert "Error: Key file not found" in stderr.getvalue()

    def test_config_language_field_is_used_when_cli_and_env_are_absent(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """config.jsonのlanguageフィールドが、CLI引数・環境変数未指定時に使われることを確認する。"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({"language": "ja"}), encoding="utf-8")

        handler = handler_factory()
        exit_code = handler.run(
            ["generate", "github", "--key", str(tmp_path / "missing.key")]
        )
        assert exit_code == 3
        assert "エラー" in stderr.getvalue()

    def test_environment_variable_overrides_config_file_language(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VTOTP_LANG環境変数がconfig.jsonのlanguageより優先されることを確認する。"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({"language": "ja"}), encoding="utf-8")
        monkeypatch.setenv(ENV_LANG_VARIABLE, "en")

        handler = handler_factory()
        exit_code = handler.run(
            ["generate", "github", "--key", str(tmp_path / "missing.key")]
        )
        assert exit_code == 3
        assert "Error: Key file not found" in stderr.getvalue()

    @pytest.mark.parametrize("language", ["en", "ja"])
    def test_exit_codes_are_identical_regardless_of_language(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        language: str,
    ) -> None:
        """同一エラーの終了コードが、表示言語に関わらず常に同じであることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(
            [
                "generate",
                "github",
                "--key",
                str(tmp_path / "missing.key"),
                "-l",
                language,
            ]
        )
        assert exit_code == 3

    def test_help_and_error_output_contain_no_traceback_regardless_of_language(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """日本語表示時もPythonトレースバックが出力されないことを確認する。"""
        handler = handler_factory()
        handler.run(
            ["generate", "github", "--key", str(tmp_path / "missing.key"), "-l", "ja"]
        )
        assert "Traceback" not in stderr.getvalue()


class TestPrePositionedOptionRejection:
    """第一引数固定・オプション後置原則に関するテスト（DESIGN.md 20.1）。"""

    @pytest.mark.parametrize(
        "argv",
        [
            ["-l", "ja", "get", "github"],
            ["--lang", "ja", "get", "github"],
            ["-k", "some.key", "list"],
            ["--key", "some.key", "list"],
            ["--storage", "some.enc", "list"],
            ["--lang", "ja", "init"],
        ],
    )
    def test_leading_option_before_subcommand_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler], argv: list[str]
    ) -> None:
        """サブコマンド/サービス名より前に置かれた値付きオプションは終了コード2で拒否されることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(argv)
        assert exit_code == 2

    def test_leading_option_rejection_does_not_crash_with_traceback(
        self,
        handler_factory: Callable[..., CliHandler],
        stderr: io.StringIO,
    ) -> None:
        """前置オプション拒否時にPythonトレースバックが出力されないことを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["-k", "some.key", "list"])
        assert exit_code == 2
        assert "Traceback" not in stderr.getvalue()

    def test_option_after_subcommand_is_accepted(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """サブコマンドの後方に置かれたオプションは正常に受理されることを確認する（対照テスト）。"""
        _, key_path = initialized_handler
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        add_handler.run(["add", "github", "--key", str(key_path), "--stdin"])

        handler = handler_factory()
        exit_code = handler.run(["get", "github", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()


class TestServicePositionStrictness:
    """`SERVICE`がサブコマンド直後の必須位置引数であることに関するテスト（DESIGN.md 20.1）。

    `SERVICE`を必要とするコマンド（`generate`/`get`/`add`/`remove`/`rm`）では、
    サブコマンドの直後に`SERVICE`を置かなければならず、オプションを前置した
    場合は終了コード2で拒否される。旧REQUIREMENTS.md 5.1に残る「位置引数
    `SERVICE`とオプションは順不同」という記述は、DESIGN.md 24章により本原則へ
    置き換えられている。
    """

    @pytest.mark.parametrize(
        "argv",
        [
            ["get", "--key", "PATH", "github"],
            ["generate", "-l", "ja", "github"],
            ["generate", "--storage", "PATH", "github"],
            ["add", "--issuer", "X", "github"],
            ["add", "--stdin", "github"],
            ["remove", "--force", "github"],
            ["remove", "-k", "PATH", "github"],
            ["rm", "--force", "github"],
        ],
    )
    def test_option_before_service_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler], argv: list[str]
    ) -> None:
        """`SERVICE`より前に置かれたオプションが終了コード2で拒否されることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(argv)
        assert exit_code == 2

    def test_option_before_service_does_not_crash_with_traceback(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """`SERVICE`前置オプションの拒否時にPythonトレースバックが出力されないことを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["get", "--key", "PATH", "github"])
        assert exit_code == 2
        assert "Traceback" not in stderr.getvalue()

    def test_rejection_message_is_localized(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """拒否時のエラーメッセージが表示言語に応じてローカライズされることを確認する。"""
        handler = handler_factory()
        handler.run(["get", "--key", "PATH", "github", "-l", "ja"])
        assert "SERVICEはサブコマンドの直後に指定してください" in stderr.getvalue()

    @pytest.mark.parametrize(
        "argv",
        [
            ["get", "github", "--key", "PATH"],
            ["generate", "github", "-l", "ja"],
            ["add", "github", "--issuer", "X", "--stdin"],
            ["remove", "github", "--force"],
        ],
    )
    def test_service_immediately_after_command_is_still_accepted(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        argv: list[str],
    ) -> None:
        """`SERVICE`をサブコマンド直後に置き、オプションを後置した形式は引き続き
        受理されることを確認する（本検証はパース前の拒否のみを目的とし、
        後続の解析・実行結果を妨げないことの対照テスト）。
        """
        _, key_path = initialized_handler
        add_handler = handler_factory(stdin="JBSWY3DPEHPK3PXP\n")
        add_handler.run(["add", "github", "--key", str(key_path), "--stdin"])

        # `PATH`プレースホルダーを実際の一時鍵パスへ差し替える。
        resolved_argv = [str(key_path) if token == "PATH" else token for token in argv]
        handler = handler_factory()
        exit_code = handler.run(resolved_argv)
        # 既に登録済みのgithubへ再度addするケースは重複登録エラー(終了コード1)に
        # なるが、少なくとも「オプション前置」による終了コード2にはならないことを
        # もって、位置検証を正しく通過したことを確認する。
        assert exit_code != 2

    def test_service_missing_entirely_still_uses_argparse_required_error(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """`SERVICE`自体が省略された場合は、本検証を素通りしてargparseの
        必須位置引数エラー（終了コード2）に委ねられることを確認する。
        """
        handler = handler_factory()
        exit_code = handler.run(["generate"])
        assert exit_code == 2


class TestConfigLanguageUpdate:
    """`config`の言語表示・更新（`-l`ショートカット/`set language`標準構文）に関するテスト。"""

    def test_config_with_no_args_shows_resolved_language(
        self,
        handler_factory: Callable[..., CliHandler],
        stdout: io.StringIO,
    ) -> None:
        """引数無しの`config`が、解決済みの表示言語を出力に含むことを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert "language: en" in stdout.getvalue()

    def test_config_with_lang_argument_only_previews_display_language(
        self,
        handler_factory: Callable[..., CliHandler],
        stdout: io.StringIO,
    ) -> None:
        """`config`単独実行時とは異なり、`config -l ja`は表示のみでなく更新を行うことを確認する準備として、
        まず`-l`無しでは`language: en`が表示されることを確認する（対照ケース）。
        """
        handler = handler_factory()
        handler.run(["config"])
        assert "language: en" in stdout.getvalue()

    def test_shortcut_updates_language_and_confirms_in_new_language(
        self,
        handler_factory: Callable[..., CliHandler],
        stdout: io.StringIO,
        config_path: Path,
    ) -> None:
        """`config -l ja`が言語設定を更新し、確認メッセージも新しい言語で表示されることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["config", "-l", "ja"])
        assert exit_code == 0
        assert "言語を更新しました" in stdout.getvalue()

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "ja"

    def test_set_language_standard_syntax_is_equivalent_to_shortcut(
        self,
        handler_factory: Callable[..., CliHandler],
        config_path: Path,
    ) -> None:
        """`config set language en`が`config -l en`と同じくlanguageを更新することを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["config", "set", "language", "en"])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "en"

    def test_language_update_preserves_existing_key_path_and_storage_path(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
    ) -> None:
        """言語更新が既存のkey_path/storage_pathを変更しないことを確認する。"""
        _, key_path = initialized_handler
        before = json.loads(config_path.read_text(encoding="utf-8"))

        handler = handler_factory()
        exit_code = handler.run(["config", "-l", "ja"])
        assert exit_code == 0

        after = json.loads(config_path.read_text(encoding="utf-8"))
        assert after["key_path"] == before["key_path"]
        assert after["language"] == "ja"

    def test_set_language_invalid_value_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """`config set language <不正な値>`が終了コード2になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["config", "set", "language", "fr"])
        assert exit_code == 2

    def test_set_invalid_setting_key_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """`config set <language以外のキー>`が終了コード2になることを確認する（v0.2.x時点の更新対象制限）。"""
        handler = handler_factory()
        exit_code = handler.run(["config", "set", "key_path", "/some/path"])
        assert exit_code == 2

    def test_config_output_does_not_leak_secrets_after_language_update(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """言語更新後の`config`出力にも鍵の内容が含まれないことを確認する（Zero Leakage Rule）。"""
        _, key_path = initialized_handler
        key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["config", "-l", "ja"])
        assert key_bytes.hex() not in stdout.getvalue()


class TestConfigShortcutStandardSyntaxEquivalence:
    """`config -l <lang>`と`config set language <lang>`の完全同値性に関するテスト。

    両構文が「languageのみを更新するユースケースへ委譲する」という
    DESIGN.md 19.2の記述どおり、同一の初期config.jsonから出発した場合に
    保存されるconfig.jsonの内容・画面出力・終了コードが完全に一致すること
    を直接比較する。
    """

    @staticmethod
    def _seed_config(config_path: Path) -> None:
        """key_path/storage_pathのみを持つ、両シナリオ共通の初期config.jsonを用意する。"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(
                {
                    "key_path": "C:/shared/master.key",
                    "storage_path": "C:/shared/vtotp-secrets.enc",
                }
            ),
            encoding="utf-8",
        )

    def _run_update(
        self, config_path: Path, argv: list[str]
    ) -> tuple[int, str, str, dict[str, str]]:
        """`config_path`を初期状態にしたうえで`argv`を実行し、結果一式を返す。"""
        self._seed_config(config_path)
        stdout = io.StringIO()
        stderr = io.StringIO()
        handler = CliHandler(
            stdout=stdout,
            stderr=stderr,
            config_path=config_path,
            input_func=_make_input([]),
        )
        exit_code = handler.run(argv)
        saved_config = json.loads(config_path.read_text(encoding="utf-8"))
        return exit_code, stdout.getvalue(), stderr.getvalue(), saved_config

    @pytest.mark.parametrize("language", ["en", "ja"])
    def test_shortcut_and_standard_syntax_produce_identical_results(
        self, tmp_path: Path, language: str
    ) -> None:
        """同一の初期状態に対し、両構文の終了コード・画面出力・保存内容が完全一致することを確認する。"""
        shortcut_exit, shortcut_stdout, shortcut_stderr, shortcut_config = (
            self._run_update(
                tmp_path / "shortcut" / "config.json", ["config", "-l", language]
            )
        )
        standard_exit, standard_stdout, standard_stderr, standard_config = (
            self._run_update(
                tmp_path / "standard" / "config.json",
                ["config", "set", "language", language],
            )
        )

        assert shortcut_exit == standard_exit == 0
        assert shortcut_stdout == standard_stdout
        assert shortcut_stderr == standard_stderr
        assert shortcut_config == standard_config
        assert shortcut_config["language"] == language

    @pytest.mark.parametrize("language", ["en", "ja"])
    def test_both_forms_report_the_confirmation_on_stdout(
        self, tmp_path: Path, language: str
    ) -> None:
        """両構文とも、確認メッセージがstdoutへ書き込まれ、stderrには何も出力しないことを確認する。"""
        _, shortcut_stdout, shortcut_stderr, _ = self._run_update(
            tmp_path / "shortcut" / "config.json", ["config", "-l", language]
        )
        _, standard_stdout, standard_stderr, _ = self._run_update(
            tmp_path / "standard" / "config.json",
            ["config", "set", "language", language],
        )

        assert shortcut_stdout.strip() != ""
        assert standard_stdout.strip() != ""
        assert shortcut_stderr == ""
        assert standard_stderr == ""


class TestInitLanguagePersistence:
    """`init`が言語設定をconfig.jsonへ保存することに関するテスト。"""

    def test_init_saves_explicit_lang_option_to_config(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
    ) -> None:
        """`init --key PATH -l ja`実行後、config.jsonのlanguageが'ja'になることを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", str(key_path), "-l", "ja"])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "ja"

    def test_init_without_lang_option_saves_auto_resolved_language(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
    ) -> None:
        """`-l`未指定の`init`が、自動解決された言語（既定でen）をconfig.jsonへ保存することを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "en"

    def test_init_confirmation_messages_use_the_saved_language(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`init -l ja`実行時、鍵作成・ストレージ初期化の案内が日本語で表示されることを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        handler.run(["init", "--key", str(key_path), "-l", "ja"])
        assert "鍵ファイルを作成しました" in stderr.getvalue()
        assert "暗号化データファイルを初期化しました" in stderr.getvalue()


class TestInitLanguagePrompt:
    """`init`で`-l`/`--lang`未指定時の対話式言語入力に関するテスト（DESIGN.md 19.2）。"""

    def test_prompts_for_language_when_lang_option_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`-l`未指定の`init`が、対話で言語選択プロンプトを表示することを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory(["ja"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0
        assert "Select display language" in stderr.getvalue()

    def test_interactive_ja_response_is_saved_to_config(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
    ) -> None:
        """対話プロンプトで`ja`と応答した場合、config.jsonのlanguageが'ja'になることを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory(["ja"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "ja"

    def test_interactive_en_response_is_saved_to_config(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
    ) -> None:
        """対話プロンプトで`en`と応答した場合、config.jsonのlanguageが'en'になることを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory(["en"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "en"

    def test_interactive_response_is_case_insensitive(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
    ) -> None:
        """対話プロンプトへの応答が大文字小文字を区別せず正規化されることを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory(["JA"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "ja"

    def test_blank_response_accepts_the_displayed_default(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """空欄（Enterのみ）の場合、表示されていた既定値がそのまま採用されることを確認する。"""
        monkeypatch.setenv(ENV_LANG_VARIABLE, "ja")
        key_path = tmp_path / "master.key"
        handler = handler_factory([""])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "ja"

    def test_unrecognized_response_falls_back_to_the_displayed_default(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`en`/`ja`のいずれにも正規化できない応答は、既定値へ黙ってフォールバックすることを確認する。"""
        monkeypatch.setenv(ENV_LANG_VARIABLE, "ja")
        key_path = tmp_path / "master.key"
        handler = handler_factory(["xyz"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "ja"

    def test_eof_during_language_prompt_accepts_the_default_without_cancelling(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
    ) -> None:
        """言語プロンプトでEOFになった場合、（鍵パスプロンプトとは異なり）キャンセル
        せず既定値を黙って採用し、initが正常終了することを確認する。
        """
        key_path = tmp_path / "master.key"
        handler = handler_factory([])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0

        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "en"

    def test_prompt_default_reflects_the_pre_resolved_language(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """プロンプト自体が、事前に解決済みの言語（例: VTOTP_LANG=ja）を
        既定値として表示することを確認する。
        """
        monkeypatch.setenv(ENV_LANG_VARIABLE, "ja")
        key_path = tmp_path / "master.key"
        handler = handler_factory(["en"])
        handler.run(["init", "--key", str(key_path)])
        assert "既定値: ja" in stderr.getvalue()

    def test_explicit_lang_option_skips_the_prompt_entirely(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """`-l`明示指定時はプロンプト自体が表示されないことを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", str(key_path), "-l", "ja"])
        assert exit_code == 0
        assert "Select display language" not in stderr.getvalue()
        assert "表示言語を選択してください" not in stderr.getvalue()
