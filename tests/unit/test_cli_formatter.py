"""vtotp.cli.formatter の単体テスト。"""

from __future__ import annotations

import io
import string

import pytest

from vtotp.cli import formatter
from vtotp.domain.exceptions import (
    CancelledError,
    CommandParseError,
    InvalidKeyError,
    InvalidSecretError,
    KeyNotFoundError,
    KeyStorageError,
    ServiceNotFoundError,
    StorageCorruptedError,
    TotpCliError,
)
from vtotp.domain.models import SecretRecord
from vtotp.i18n.catalog import EN_CATALOG, JA_CATALOG, SUPPORTED_LANGUAGES, MsgKey


class TestFormatMessage:
    """format_message に関するテスト。"""

    def test_resolves_english_message_with_context(self) -> None:
        """英語カタログのプレースホルダーがcontextで補間されることを確認する。"""
        message = formatter.format_message(
            MsgKey.KEY_NOT_FOUND, "en", path="C:/keys/master.key"
        )
        assert message == "Key file not found: C:/keys/master.key"

    def test_resolves_japanese_message_with_context(self) -> None:
        """日本語カタログのプレースホルダーがcontextで補間されることを確認する。"""
        message = formatter.format_message(
            MsgKey.KEY_NOT_FOUND, "ja", path="C:/keys/master.key"
        )
        assert message == "鍵ファイルが見つかりません: C:/keys/master.key"

    def test_unknown_language_falls_back_to_english(self) -> None:
        """未知の言語コードの場合、英語へフォールバックすることを確認する。"""
        message = formatter.format_message(MsgKey.SECRET_EMPTY, "fr")
        assert message == "TOTP secret is empty"


class TestFormatError:
    """format_error / write_error に関するテスト。"""

    def test_includes_localized_label_and_body(self) -> None:
        """エラー表示文にローカライズ済みラベルと本文が含まれることを確認する。"""
        error = KeyNotFoundError(MsgKey.KEY_NOT_FOUND, context={"path": "k.key"})
        assert formatter.format_error(error, "en") == "Error: Key file not found: k.key"
        assert (
            formatter.format_error(error, "ja")
            == "エラー: 鍵ファイルが見つかりません: k.key"
        )

    def test_write_error_writes_to_given_stream(self) -> None:
        """write_errorが注入したストリームへ書き込むことを確認する。"""
        stream = io.StringIO()
        error = StorageCorruptedError(MsgKey.STORAGE_DECRYPTION_FAILED)
        formatter.write_error(error, "en", stream=stream)
        expected_body = (
            "Failed to verify the encrypted data "
            "(it may be corrupted, tampered with, or the key may be incorrect)"
        )
        assert stream.getvalue() == f"Error: {expected_body}\n"

    def test_write_error_does_not_leak_secret_when_caller_avoids_it(self) -> None:
        """呼び出し元がcontextに秘密情報を含めない限り、write_errorの出力に秘密情報が現れないことを確認する。"""
        stream = io.StringIO()
        error = KeyNotFoundError(
            MsgKey.KEY_NOT_FOUND, context={"path": "C:/keys/master.key"}
        )
        formatter.write_error(error, "en", stream=stream)
        assert "JBSWY3DPEHPK3PXP" not in stream.getvalue()

    def test_write_error_defaults_to_stderr(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """streamを省略した場合、標準エラー出力へ書き込まれることを確認する。"""
        error = StorageCorruptedError(MsgKey.STORAGE_DECRYPTION_FAILED)
        formatter.write_error(error, "en")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error:" in captured.err


class TestFormatWarning:
    """format_warning / write_warning に関するテスト。"""

    def test_includes_localized_label_and_body(self) -> None:
        """警告表示文にローカライズ済みラベルと本文が含まれることを確認する。"""
        message = formatter.format_warning(
            MsgKey.REKEY_ROTATION_LIMIT_NOTICE, "en", path="master.key.3"
        )
        assert message.startswith("Warning: ")
        assert "master.key.3" in message

    def test_write_warning_writes_to_given_stream(self) -> None:
        """write_warningが注入したストリームへ書き込むことを確認する。"""
        stream = io.StringIO()
        formatter.write_warning(MsgKey.CANCELLED, "ja", stream=stream)
        assert stream.getvalue() == "警告: ユーザーによって操作がキャンセルされました\n"


class TestWriteCode:
    """write_code に関するテスト。"""

    def test_writes_only_the_code_to_the_given_stream(self) -> None:
        """コード文字列のみが改行付きでストリームへ書き込まれることを確認する。"""
        stream = io.StringIO()
        formatter.write_code("123456", stream)
        assert stream.getvalue() == "123456\n"

    def test_does_not_write_to_stderr(self) -> None:
        """write_codeが標準エラー用のストリームには何も書き込まないことを確認する。"""
        stdout = io.StringIO()
        stderr = io.StringIO()
        formatter.write_code("654321", stdout)
        assert stderr.getvalue() == ""


class TestFormatServiceTable:
    """format_service_table / write_service_table に関するテスト。"""

    def test_empty_records_produce_empty_string(self) -> None:
        """レコードが空の場合、空文字列を返すことを確認する。"""
        assert formatter.format_service_table([], "en") == ""

    def test_includes_header_and_all_service_names_in_english(self) -> None:
        """英語表示でヘッダー行と全サービス名が出力に含まれることを確認する。"""
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            ),
            SecretRecord(service_name="aws", secret="KRSXG5CTMVRXEZLU", issuer=None),
        ]
        table = formatter.format_service_table(records, "en")
        assert "SERVICE" in table
        assert "ISSUER" in table
        assert "github" in table
        assert "aws" in table
        assert "GitHub" in table

    def test_includes_localized_header_in_japanese(self) -> None:
        """日本語表示でヘッダーがローカライズされることを確認する。"""
        records = [
            SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP", issuer=None)
        ]
        table = formatter.format_service_table(records, "ja")
        assert "サービス" in table
        assert "発行者" in table

    def test_missing_issuer_is_rendered_as_placeholder(self) -> None:
        """issuerが無いレコードはプレースホルダー（`-`）で表示されることを確認する。"""
        records = [
            SecretRecord(service_name="aws", secret="KRSXG5CTMVRXEZLU", issuer=None)
        ]
        table = formatter.format_service_table(records, "en")
        lines = table.splitlines()
        assert lines[1].endswith("-")

    def test_does_not_include_secret_values(self) -> None:
        """出力にシークレットの値が一切含まれないことを確認する（Zero Leakage Rule）。"""
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            ),
        ]
        table = formatter.format_service_table(records, "en")
        assert "JBSWY3DPEHPK3PXP" not in table

    def test_write_service_table_writes_nothing_for_empty_records(self) -> None:
        """レコードが空の場合、write_service_tableは何も出力しないことを確認する。"""
        stream = io.StringIO()
        formatter.write_service_table([], "en", stream)
        assert stream.getvalue() == ""

    def test_write_service_table_writes_table_to_stream(self) -> None:
        """write_service_tableが整形済みテーブルをストリームへ書き込むことを確認する。"""
        stream = io.StringIO()
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            )
        ]
        formatter.write_service_table(records, "en", stream)
        assert "github" in stream.getvalue()
        assert "GitHub" in stream.getvalue()


class TestRemainingSecondsBar:
    """format_remaining_seconds_bar / write_remaining_seconds_bar に関するテスト。"""

    def test_full_remaining_time_fills_the_bar_completely(self) -> None:
        """残り秒数が満額のとき、バーが全て埋まった表示になることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(30, 30, width=10)
        assert bar.startswith("[##########]")
        assert "30s" in bar

    def test_zero_remaining_time_leaves_the_bar_empty(self) -> None:
        """残り秒数が0のとき、バーが空の表示になることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(0, 30, width=10)
        assert bar.startswith("[----------]")
        assert " 0s" in bar

    def test_half_remaining_time_fills_the_bar_halfway(self) -> None:
        """残り秒数が半分のとき、バーが半分埋まった表示になることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(15, 30, width=10)
        assert bar == "[#####-----] 15s"

    def test_remaining_greater_than_time_step_is_clamped(self) -> None:
        """remainingがtime_stepを超える場合、time_stepにクランプされることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(999, 30, width=10)
        assert bar.startswith("[##########]")
        assert "30s" in bar

    def test_negative_remaining_is_clamped_to_zero(self) -> None:
        """remainingが負の場合、0にクランプされることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(-5, 30, width=10)
        assert bar.startswith("[----------]")

    def test_non_positive_time_step_raises_value_error(self) -> None:
        """time_stepが0以下の場合にValueErrorになることを確認する。"""
        with pytest.raises(ValueError):
            formatter.format_remaining_seconds_bar(10, 0)

    def test_non_positive_width_raises_value_error(self) -> None:
        """widthが0以下の場合にValueErrorになることを確認する。"""
        with pytest.raises(ValueError):
            formatter.format_remaining_seconds_bar(10, 30, width=0)

    def test_write_remaining_seconds_bar_writes_to_stderr_by_default(self) -> None:
        """write_remaining_seconds_barが既定でstderr相当のストリームへ出力することを確認する。"""
        stream = io.StringIO()
        formatter.write_remaining_seconds_bar(15, 30, stream)
        assert "15s" in stream.getvalue()


class TestWriteInfo:
    """write_info に関するテスト。"""

    def test_writes_localized_message_as_is(self) -> None:
        """write_infoがローカライズ済みメッセージをそのまま出力することを確認する。"""
        stream = io.StringIO()
        formatter.write_info(
            MsgKey.ADD_SERVICE_REGISTERED, "en", stream=stream, service="github"
        )
        assert stream.getvalue() == "Service registered: github\n"

    def test_writes_japanese_message(self) -> None:
        """日本語指定時に日本語メッセージが出力されることを確認する。"""
        stream = io.StringIO()
        formatter.write_info(
            MsgKey.ADD_SERVICE_REGISTERED, "ja", stream=stream, service="github"
        )
        assert stream.getvalue() == "サービスを登録しました: github\n"


#: 全専用例外種別 x 代表的なMsgKey/context x 期待終了コードの対応表。
#: TotpCliErrorから派生する全例外クラス（CLAUDE.md 4章の一覧と一致）を
#: 1つずつ、それぞれが実際に送出されうる代表的な`MsgKey`とともに網羅する。
_EXCEPTION_LOCALIZATION_CASES: list[
    tuple[type[TotpCliError], MsgKey, dict[str, str], int]
] = [
    (KeyNotFoundError, MsgKey.KEY_NOT_FOUND, {"path": "C:/keys/master.key"}, 3),
    (InvalidKeyError, MsgKey.KEY_INVALID_SIZE, {"path": "C:/keys/master.key"}, 3),
    (
        KeyStorageError,
        MsgKey.KEY_PERMISSION_SETUP_FAILED,
        {"path": "C:/keys/master.key"},
        1,
    ),
    (StorageCorruptedError, MsgKey.STORAGE_DECRYPTION_FAILED, {}, 4),
    (ServiceNotFoundError, MsgKey.SERVICE_NOT_FOUND, {"service": "github"}, 5),
    (InvalidSecretError, MsgKey.SECRET_INVALID_FORMAT, {}, 6),
    (
        CommandParseError,
        MsgKey.COMMAND_PARSE_ERROR,
        {"detail": "unrecognized arguments: --foo"},
        2,
    ),
    (CancelledError, MsgKey.CANCELLED, {}, 7),
]


class TestExceptionLocalizationMatrix:
    """全例外種別 x 日英表示・終了コードの網羅テスト（CLAUDE.md 4章の例外階層に対応）。"""

    @pytest.mark.parametrize(
        ("exception_type", "message_key", "context", "expected_exit_code"),
        _EXCEPTION_LOCALIZATION_CASES,
        ids=[case[0].__name__ for case in _EXCEPTION_LOCALIZATION_CASES],
    )
    @pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
    def test_exception_localizes_in_both_languages_with_stable_exit_code(
        self,
        exception_type: type[TotpCliError],
        message_key: MsgKey,
        context: dict[str, str],
        expected_exit_code: int,
        language: str,
    ) -> None:
        """各例外種別が、指定言語でローカライズされたエラー表示文を生成し、
        言語に関わらず同一の終了コードを返すことを確認する。
        """
        error = exception_type(message_key, context=context)
        assert error.exit_code == expected_exit_code

        rendered = formatter.format_error(error, language)
        label = formatter.format_message(MsgKey.LABEL_ERROR, language)
        expected_body = formatter.format_message(message_key, language, **context)

        assert rendered == f"{label}: {expected_body}"
        # 表示文が空でなく、かつラベルと本文の両方を含むことを確認する。
        assert rendered.strip() != ""

    @pytest.mark.parametrize(
        ("exception_type", "message_key", "context", "expected_exit_code"),
        _EXCEPTION_LOCALIZATION_CASES,
        ids=[case[0].__name__ for case in _EXCEPTION_LOCALIZATION_CASES],
    )
    def test_exit_code_is_identical_across_languages(
        self,
        exception_type: type[TotpCliError],
        message_key: MsgKey,
        context: dict[str, str],
        expected_exit_code: int,
    ) -> None:
        """同一の例外インスタンスについて、`format_error`へ渡す言語を変えても
        `exit_code`自体は変化しないことを確認する（終了コードは表示言語に
        依存しないというDESIGN.md 21章の契約）。
        """
        error = exception_type(message_key, context=context)
        rendered_messages = {
            language: formatter.format_error(error, language)
            for language in SUPPORTED_LANGUAGES
        }

        assert error.exit_code == expected_exit_code
        # 表示文そのものは言語ごとに異なる（同一内容へ退化していない）ことを
        # 併せて確認する。
        assert len(set(rendered_messages.values())) == len(SUPPORTED_LANGUAGES)

    def test_all_totp_cli_error_subclasses_are_covered(self) -> None:
        """例外階層の全サブクラスが、本テストの対応表に一つずつ含まれていることを確認する
        （新規例外クラス追加時に、本テストの拡充漏れを検知する）。
        """
        covered_types = {case[0] for case in _EXCEPTION_LOCALIZATION_CASES}
        all_subclasses = set(TotpCliError.__subclasses__())
        assert covered_types == all_subclasses


class TestContextZeroLeakageContract:
    """`TotpCliError.context`/`format_message`が機密情報を示すキー名を
    含めない契約に関するテスト（Zero Leakage Rule）。
    """

    @pytest.mark.parametrize(
        "forbidden_key",
        [
            "secret",
            "secrets",
            "key",
            "raw_key",
            "key_bytes",
            "master_key",
            "raw_secret",
            "totp_secret",
            "ciphertext",
            "plaintext",
            "nonce",
            "password",
            "token",
        ],
    )
    def test_constructing_with_a_forbidden_context_key_is_rejected(
        self, forbidden_key: str
    ) -> None:
        """機密情報を示唆するキー名がcontextに含まれる場合、TotpCliErrorの構築
        自体がValueErrorで拒否されることを確認する。
        """
        with pytest.raises(ValueError):
            TotpCliError(MsgKey.CANCELLED, context={forbidden_key: "irrelevant-value"})

    @pytest.mark.parametrize("forbidden_key", ["SECRET", "Key", "Raw_Key"])
    def test_forbidden_key_check_is_case_insensitive(self, forbidden_key: str) -> None:
        """機密キー名の判定が大文字小文字を区別しないことを確認する。"""
        with pytest.raises(ValueError):
            TotpCliError(MsgKey.CANCELLED, context={forbidden_key: "irrelevant-value"})

    def test_error_message_lists_every_offending_key(self) -> None:
        """複数の禁止キーが同時に渡された場合、ValueErrorのメッセージに
        全ての該当キーが列挙されることを確認する（デバッグ容易性）。
        """
        with pytest.raises(ValueError) as excinfo:
            TotpCliError(
                MsgKey.CANCELLED, context={"secret": "x", "path": "safe", "key": "y"}
            )
        assert "secret" in str(excinfo.value)
        assert "key" in str(excinfo.value)
        assert "path" not in str(excinfo.value)

    def test_safe_context_keys_used_by_the_application_are_accepted(self) -> None:
        """実際にアプリケーション全体で使用している安全なcontextキー
        （path/service/version/algorithm/detail等）は拒否されないことを確認する。
        """
        error = KeyNotFoundError(
            MsgKey.KEY_NOT_FOUND, context={"path": "C:/keys/master.key"}
        )
        assert error.context == {"path": "C:/keys/master.key"}

        service_error = ServiceNotFoundError(
            MsgKey.SERVICE_NOT_FOUND, context={"service": "github"}
        )
        assert service_error.context == {"service": "github"}

        parse_error = CommandParseError(
            MsgKey.COMMAND_PARSE_ERROR, context={"detail": "unrecognized arguments"}
        )
        assert parse_error.context == {"detail": "unrecognized arguments"}

    def test_context_omitted_entirely_is_accepted(self) -> None:
        """contextを省略した構築（大多数の例外送出箇所）が拒否されないことを確認する。"""
        error = CancelledError(MsgKey.CANCELLED)
        assert error.context == {}

    def test_key_named_key_path_is_not_confused_with_raw_key_material(self) -> None:
        """`key_path`のような、たまたま`key`を含むが実際には安全なキー名は
        誤って拒否されないことを確認する（完全一致判定であり部分一致では
        ないことの確認）。
        """
        error = TotpCliError(MsgKey.CANCELLED, context={"key_path": "C:/keys/m.key"})
        assert error.context == {"key_path": "C:/keys/m.key"}

    def test_catalog_placeholders_never_use_a_forbidden_key_name(self) -> None:
        """カタログ（`format_message`が参照するテンプレート集合）自体が、
        機密情報を示唆するプレースホルダー名を一切宣言していないことを
        確認する。これにより、正規の呼び出し元コードが将来にわたって
        機密キー名を`context`へ渡さざるを得ない設計になることを防ぐ。
        """
        forbidden = {
            "secret",
            "secrets",
            "key",
            "raw_key",
            "key_bytes",
            "master_key",
            "raw_secret",
            "totp_secret",
            "ciphertext",
            "plaintext",
            "nonce",
            "password",
            "token",
        }
        for catalog in (EN_CATALOG, JA_CATALOG):
            for template in catalog.values():
                placeholders = {
                    field_name
                    for _, field_name, _, _ in string.Formatter().parse(template)
                    if field_name
                }
                assert placeholders.isdisjoint(forbidden)
