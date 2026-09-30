"""vtotp.domain パッケージ（例外階層・ドメインモデル）の単体テスト。"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from vtotp.domain import (
    AppConfig,
    CancelledError,
    CommandParseError,
    EncryptedPayload,
    InvalidKeyError,
    InvalidSecretError,
    KeyNotFoundError,
    KeyStorageError,
    SecretRecord,
    ServiceNotFoundError,
    StorageCorruptedError,
    TotpCliError,
)
from vtotp.i18n.catalog import MsgKey


class TestExceptionHierarchy:
    """例外クラス階層に関するテスト。"""

    @pytest.mark.parametrize(
        ("exception_type", "expected_exit_code"),
        [
            (KeyNotFoundError, 3),
            (InvalidKeyError, 3),
            (KeyStorageError, 1),
            (StorageCorruptedError, 4),
            (ServiceNotFoundError, 5),
            (InvalidSecretError, 6),
            (CommandParseError, 2),
            (CancelledError, 7),
        ],
    )
    def test_subclasses_inherit_from_base_and_expose_exit_code(
        self,
        exception_type: type[TotpCliError],
        expected_exit_code: int,
    ) -> None:
        """各専用例外がTotpCliErrorを継承し、規定の終了コードを持つことを確認する。"""
        assert issubclass(exception_type, TotpCliError)
        assert exception_type.exit_code == expected_exit_code

    def test_base_error_default_exit_code_is_general_error(self) -> None:
        """基底例外の既定終了コードが一般エラー(1)であることを確認する。"""
        assert TotpCliError.exit_code == 1

    def test_message_key_and_context_are_preserved(self) -> None:
        """message_keyとcontextがそのまま保持され、標準のExceptionを継承していることを確認する。"""
        error = KeyNotFoundError(
            MsgKey.KEY_NOT_FOUND, context={"path": "C:/keys/master.key"}
        )
        assert isinstance(error, Exception)
        assert error.message_key is MsgKey.KEY_NOT_FOUND
        assert error.context == {"path": "C:/keys/master.key"}

    def test_context_defaults_to_empty_mapping_when_omitted(self) -> None:
        """contextを省略した場合、空のマッピングになることを確認する。"""
        error = InvalidSecretError(MsgKey.SECRET_EMPTY)
        assert error.context == {}

    def test_str_representation_is_the_message_key_value_only(self) -> None:
        """例外の既定のstr表現が、表示文ではなくmessage_keyの値のみであることを確認する
        （例外は表示文を保持しない。ローカライズはformatter側の責務）。
        """
        error = InvalidSecretError(MsgKey.SECRET_INVALID_FORMAT)
        assert str(error) == MsgKey.SECRET_INVALID_FORMAT.value


#: Zero Leakage Rule の徹底確認対象となる、全ての専用例外クラス。
ALL_TOTP_CLI_EXCEPTION_TYPES: list[type[TotpCliError]] = [
    TotpCliError,
    KeyNotFoundError,
    InvalidKeyError,
    KeyStorageError,
    StorageCorruptedError,
    ServiceNotFoundError,
    InvalidSecretError,
    CommandParseError,
    CancelledError,
]


class TestZeroLeakageRuleAcrossExceptions:
    """全例外クラス共通のZero Leakage Rule（秘密情報の非漏洩）を確認するテスト。

    例外オブジェクトはmessage_keyと、呼び出し元が渡した安全なcontextの値
    しか保持しないため、呼び出し元が秘密情報をcontextへ含めない限り漏洩し
    得ないことを保証する。
    """

    @pytest.mark.parametrize("exception_type", ALL_TOTP_CLI_EXCEPTION_TYPES)
    def test_instance_holds_only_message_key_and_context(
        self, exception_type: type[TotpCliError]
    ) -> None:
        """例外インスタンスがmessage_key/context以外の隠れた属性を保持しないことを確認する。"""
        error = exception_type(MsgKey.CANCELLED, context={"path": "safe/path"})
        assert vars(error) == {
            "message_key": MsgKey.CANCELLED,
            "context": {"path": "safe/path"},
        }

    @pytest.mark.parametrize("exception_type", ALL_TOTP_CLI_EXCEPTION_TYPES)
    def test_str_and_repr_never_contain_context_secret_markers(
        self, exception_type: type[TotpCliError]
    ) -> None:
        """strとreprの既定表現に、渡したcontextの値自体は含まれない（message_keyのみ）ことを確認する。"""
        error = exception_type(
            MsgKey.STORAGE_DECRYPTION_FAILED,
            context={"secret_marker": "JBSWY3DPEHPK3PXP"},
        )
        assert "JBSWY3DPEHPK3PXP" not in str(error)
        assert "JBSWY3DPEHPK3PXP" not in repr(error)

    def test_storage_corrupted_error_context_holds_only_safe_values(
        self,
    ) -> None:
        """StorageCorruptedErrorのcontextに、呼び出し元が渡した安全な値（パス等）のみが
        保持されることを確認する。
        """
        error = StorageCorruptedError(
            MsgKey.STORAGE_FILE_NOT_FOUND, context={"path": "C:/data/vtotp-secrets.enc"}
        )
        assert error.context == {"path": "C:/data/vtotp-secrets.enc"}
        assert "JBSWY" not in str(error)

    def test_storage_corrupted_error_does_not_expose_underlying_cause_secrets(
        self,
    ) -> None:
        """__cause__経由で連鎖された下位例外の内容が、StorageCorruptedError自体の
        strには現れない（呼び出し元が安全なコンテキストへ変換する責務を持つ）ことを確認する。
        """
        underlying_secret_leak = ValueError(
            "raw-master-key-bytes-should-not-appear-here"
        )
        try:
            try:
                raise underlying_secret_leak
            except ValueError as exc:
                raise StorageCorruptedError(MsgKey.STORAGE_DECRYPTION_FAILED) from exc
        except StorageCorruptedError as error:
            assert "raw-master-key-bytes-should-not-appear-here" not in str(error)
            assert error.__cause__ is underlying_secret_leak


class TestSecretRecord:
    """SecretRecord ドメインモデルに関するテスト。"""

    def test_fields_are_stored_correctly(self) -> None:
        """コンストラクタに渡した値が各フィールドへ正しく格納されることを確認する。"""
        record = SecretRecord(
            service_name="github",
            secret="JBSWY3DPEHPK3PXP",
            issuer="GitHub",
        )
        assert record.service_name == "github"
        assert record.secret == "JBSWY3DPEHPK3PXP"
        assert record.issuer == "GitHub"

    def test_issuer_defaults_to_none(self) -> None:
        """issuerを省略した場合にNoneが既定値となることを確認する。"""
        record = SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP")
        assert record.issuer is None

    def test_instance_is_immutable(self) -> None:
        """フィールドへの再代入がFrozenInstanceErrorを送出することを確認する。"""
        record = SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP")
        with pytest.raises(FrozenInstanceError):
            record.secret = "other-secret"  # type: ignore[misc]

    def test_repr_does_not_leak_secret(self) -> None:
        """文字列表現にシークレットの生の値が含まれないことを確認する（Zero Leakage Rule）。"""
        record = SecretRecord(
            service_name="github",
            secret="JBSWY3DPEHPK3PXP",
            issuer="GitHub",
        )
        representation = repr(record)
        assert "JBSWY3DPEHPK3PXP" not in representation
        assert "github" in representation


class TestAppConfig:
    """AppConfig ドメインモデルに関するテスト。"""

    def test_fields_are_stored_as_path(self) -> None:
        """key_pathとstorage_pathがPathとして格納されることを確認する。"""
        config = AppConfig(
            key_path=Path("C:/keys/master.key"),
            storage_path=Path("C:/data/vtotp-secrets.enc"),
        )
        assert config.key_path == Path("C:/keys/master.key")
        assert config.storage_path == Path("C:/data/vtotp-secrets.enc")

    def test_instance_is_immutable(self) -> None:
        """フィールドへの再代入がFrozenInstanceErrorを送出することを確認する。"""
        config = AppConfig(
            key_path=Path("master.key"),
            storage_path=Path("vtotp-secrets.enc"),
        )
        with pytest.raises(FrozenInstanceError):
            config.key_path = Path("other.key")  # type: ignore[misc]

    def test_repr_contains_only_paths_no_secret_material(self) -> None:
        """AppConfigは鍵の内容を保持しないため、文字列表現にはパスのみが含まれることを確認する。"""
        config = AppConfig(
            key_path=Path("master.key"),
            storage_path=Path("vtotp-secrets.enc"),
        )
        representation = repr(config)
        assert "master.key" in representation
        assert "vtotp-secrets.enc" in representation


class TestEncryptedPayload:
    """EncryptedPayload ドメインモデルに関するテスト。"""

    def test_fields_are_stored_correctly(self) -> None:
        """version、algorithm、nonce、ciphertextが正しく格納されることを確認する。"""
        payload = EncryptedPayload(
            version=1,
            algorithm="AES-256-GCM",
            nonce=b"\x00" * 12,
            ciphertext=b"\x01" * 32,
        )
        assert payload.version == 1
        assert payload.algorithm == "AES-256-GCM"
        assert payload.nonce == b"\x00" * 12
        assert payload.ciphertext == b"\x01" * 32

    def test_instance_is_immutable(self) -> None:
        """フィールドへの再代入がFrozenInstanceErrorを送出することを確認する。"""
        payload = EncryptedPayload(
            version=1,
            algorithm="AES-256-GCM",
            nonce=b"\x00" * 12,
            ciphertext=b"\x01" * 32,
        )
        with pytest.raises(FrozenInstanceError):
            payload.ciphertext = b"\x02" * 32  # type: ignore[misc]

    def test_repr_does_not_leak_raw_nonce_or_ciphertext_bytes(self) -> None:
        """文字列表現に生のnonce・ciphertextバイト列が含まれないことを確認する。"""
        nonce = b"\x11" * 12
        ciphertext = b"\x22" * 48
        payload = EncryptedPayload(
            version=1,
            algorithm="AES-256-GCM",
            nonce=nonce,
            ciphertext=ciphertext,
        )
        representation = repr(payload)
        assert nonce.hex() not in representation
        assert ciphertext.hex() not in representation
        assert "12 bytes" in representation
        assert "48 bytes" in representation


class TestDomainPackageExports:
    """vtotp.domain パッケージの公開インターフェースに関するテスト。"""

    def test_all_expected_symbols_are_exported(self) -> None:
        """__all__に定義された全シンボルがdomainパッケージ直下から参照できることを確認する。"""
        import vtotp.domain as domain_package

        expected_symbols = {
            "TotpCliError",
            "KeyNotFoundError",
            "InvalidKeyError",
            "KeyStorageError",
            "StorageCorruptedError",
            "ServiceNotFoundError",
            "InvalidSecretError",
            "CommandParseError",
            "CancelledError",
            "SecretRecord",
            "AppConfig",
            "EncryptedPayload",
        }
        assert expected_symbols == set(domain_package.__all__)
        for symbol in expected_symbols:
            assert hasattr(domain_package, symbol)
