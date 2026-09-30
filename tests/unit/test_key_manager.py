"""vtotp.core.key_manager.KeyManager の単体テスト。"""

from __future__ import annotations

import getpass
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from vtotp.core import key_manager as key_manager_module
from vtotp.core.key_manager import KeyManager
from vtotp.domain.exceptions import InvalidKeyError, KeyNotFoundError, KeyStorageError
from vtotp.i18n.catalog import MsgKey

#: chmodによる読み取り権限剥奪がOSレベルで機能しない環境（主にWindows）を判定する。
IS_WINDOWS = sys.platform.startswith("win")


@pytest.fixture
def key_manager() -> KeyManager:
    """テスト対象のKeyManagerインスタンスを返す。"""
    return KeyManager()


class TestGenerateKey:
    """generate_key に関するテスト。"""

    def test_generated_key_is_32_bytes(self, key_manager: KeyManager) -> None:
        """生成された鍵がAES-256に必要な32バイトであることを確認する。"""
        key = key_manager.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_generated_keys_are_random(self, key_manager: KeyManager) -> None:
        """連続して生成した鍵が毎回異なる（暗号学的に安全な乱数である）ことを確認する。"""
        first_key = key_manager.generate_key()
        second_key = key_manager.generate_key()
        assert first_key != second_key


class TestCreateKeyFile:
    """create_key_file に関するテスト。"""

    def test_creates_file_with_generated_key_when_key_is_none(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """keyを省略した場合に新規生成された32バイト鍵がファイルへ書き込まれることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        assert target.is_file()
        assert len(target.read_bytes()) == 32

    def test_creates_file_with_given_key_bytes(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """指定したバイト列がそのままファイルへ書き込まれることを確認する。"""
        target = tmp_path / "master.key"
        explicit_key = bytes(range(32))
        key_manager.create_key_file(target, key=explicit_key)
        assert target.read_bytes() == explicit_key

    def test_creates_parent_directories_if_missing(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """出力先ディレクトリが存在しない場合でも自動作成されることを確認する。"""
        target = tmp_path / "nested" / "vault" / "master.key"
        key_manager.create_key_file(target)
        assert target.is_file()

    def test_rejects_key_with_invalid_size(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """32バイトでない鍵を渡した場合にInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        with pytest.raises(InvalidKeyError):
            key_manager.create_key_file(target, key=b"too-short")
        assert not target.exists()

    def test_does_not_leave_temp_file_behind(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """atomic書き込み後に一時ファイルが残らないことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        remaining_files = list(tmp_path.iterdir())
        assert remaining_files == [target]


class TestCheckExistingKey:
    """check_existing_key に関するテスト。"""

    def test_returns_true_when_file_exists(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """既存の鍵ファイルがある場合にTrueを返すことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        assert key_manager.check_existing_key(target) is True

    def test_returns_false_when_file_does_not_exist(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合にFalseを返すことを確認する。"""
        target = tmp_path / "missing.key"
        assert key_manager.check_existing_key(target) is False

    def test_returns_false_when_path_is_a_directory(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """パスがディレクトリの場合にFalseを返すことを確認する。"""
        directory = tmp_path / "master.key"
        directory.mkdir()
        assert key_manager.check_existing_key(directory) is False


class TestValidateKeyFile:
    """validate_key_file に関するテスト。"""

    def test_passes_for_valid_32_byte_file(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """正しい32バイトの鍵ファイルでは例外が発生しないことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        key_manager.validate_key_file(target)

    def test_raises_key_not_found_error_when_missing(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合にKeyNotFoundErrorが送出されることを確認する。"""
        target = tmp_path / "missing.key"
        with pytest.raises(KeyNotFoundError):
            key_manager.validate_key_file(target)

    def test_raises_invalid_key_error_when_path_is_directory(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """パスが通常ファイルでない場合にInvalidKeyErrorが送出されることを確認する。"""
        directory = tmp_path / "master.key"
        directory.mkdir()
        with pytest.raises(InvalidKeyError):
            key_manager.validate_key_file(directory)

    def test_raises_invalid_key_error_when_size_is_wrong(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """ファイルサイズが32バイトでない場合にInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        target.write_bytes(b"\x00" * 16)
        with pytest.raises(InvalidKeyError):
            key_manager.validate_key_file(target)

    @pytest.mark.parametrize("size", [0, 31, 33])
    def test_raises_invalid_key_error_at_size_boundaries(
        self, key_manager: KeyManager, tmp_path: Path, size: int
    ) -> None:
        """31バイト・33バイト・0バイト（空ファイル）の境界値でInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        target.write_bytes(b"\x00" * size)
        with pytest.raises(InvalidKeyError):
            key_manager.validate_key_file(target)

    @pytest.mark.skipif(
        IS_WINDOWS, reason="Windowsではos.chmodによる読み取り権限の剥奪が保証されない"
    )
    def test_raises_invalid_key_error_when_not_readable_via_chmod(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """os.chmodで読み取り権限を剥奪した実ファイルに対してInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        os.chmod(target, 0o000)
        try:
            with pytest.raises(InvalidKeyError):
                key_manager.validate_key_file(target)
        finally:
            os.chmod(target, 0o600)

    def test_raises_invalid_key_error_when_os_access_denies_read(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """os.access(path, os.R_OK)がFalseを返す場合に

        InvalidKeyErrorが送出されることを確認する（プラットフォーム非依存）。
        """
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        monkeypatch.setattr(os, "access", lambda path, mode: False)
        with pytest.raises(InvalidKeyError):
            key_manager.validate_key_file(target)


class TestVerifyKeyFile:
    """verify_key_file に関するテスト。"""

    def test_passes_for_valid_key_file(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """正しい鍵ファイルに対しては例外が発生しないことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        key_manager.verify_key_file(target)

    def test_raises_key_not_found_error_when_missing(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合にKeyNotFoundErrorが送出されることを確認する。"""
        target = tmp_path / "missing.key"
        with pytest.raises(KeyNotFoundError):
            key_manager.verify_key_file(target)


class TestLoadKey:
    """load_key に関するテスト。"""

    def test_returns_exact_key_bytes(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """ファイルに書き込んだ鍵の内容がそのまま読み込まれることを確認する。"""
        target = tmp_path / "master.key"
        explicit_key = secrets_like_key()
        key_manager.create_key_file(target, key=explicit_key)
        assert key_manager.load_key(target) == explicit_key

    def test_raises_key_not_found_error_when_missing(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合にKeyNotFoundErrorが送出されることを確認する。"""
        target = tmp_path / "missing.key"
        with pytest.raises(KeyNotFoundError):
            key_manager.load_key(target)

    def test_raises_invalid_key_error_when_size_is_wrong(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """サイズ不正な鍵ファイルに対してInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        target.write_bytes(b"\xff" * 40)
        with pytest.raises(InvalidKeyError):
            key_manager.load_key(target)

    def test_error_message_does_not_leak_key_content(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """例外のmessage_key/contextに鍵の内容（バイト列）が含まれないことを確認する（Zero Leakage Rule）。"""
        target = tmp_path / "master.key"
        marker = b"\xde\xad\xbe\xef" * 10
        target.write_bytes(marker)
        with pytest.raises(InvalidKeyError) as excinfo:
            key_manager.load_key(target)
        assert marker.hex() not in str(excinfo.value)
        assert "deadbeef" not in str(excinfo.value)
        assert all(
            marker.hex() not in value for value in excinfo.value.context.values()
        )

    def test_raises_invalid_key_error_when_read_raises_permission_error(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """検証を通過した後の実読み込みでPermissionErrorが発生した場合にInvalidKeyErrorへ変換されることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)

        def _raise_permission_error(self: Path) -> bytes:
            raise PermissionError("permission denied")

        monkeypatch.setattr(Path, "read_bytes", _raise_permission_error)
        with pytest.raises(InvalidKeyError):
            key_manager.load_key(target)

    def test_raises_invalid_key_error_when_read_bytes_length_mismatches_stat(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """statによる事前検証を通過しても、実読み込み結果が32バイトでなければInvalidKeyErrorになることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target, key=b"\x00" * 32)

        monkeypatch.setattr(Path, "read_bytes", lambda self: b"\x00" * 16)
        with pytest.raises(InvalidKeyError):
            key_manager.load_key(target)


class TestResolveKeyPath:
    """resolve_key_path に関するテスト（優先順位: CLI > 環境変数 > config.json）。"""

    def test_cli_path_has_highest_priority(self, key_manager: KeyManager) -> None:
        """CLIパスが指定されている場合、他の指定より優先されることを確認する。"""
        result = key_manager.resolve_key_path(
            cli_path=Path("cli.key"),
            config_path=Path("config.key"),
            environment_path=Path("env.key"),
        )
        assert result == Path("cli.key")

    def test_environment_path_used_when_cli_path_missing(
        self, key_manager: KeyManager
    ) -> None:
        """CLI未指定時は環境変数のパスがconfig.jsonより優先されることを確認する。"""
        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=Path("config.key"),
            environment_path=Path("env.key"),
        )
        assert result == Path("env.key")

    def test_config_path_used_when_only_config_available(
        self, key_manager: KeyManager
    ) -> None:
        """CLI・環境変数ともに未指定の場合、config.jsonのパスが使われることを確認する。"""
        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=Path("config.key"),
            environment_path=None,
        )
        assert result == Path("config.key")

    def test_raises_key_not_found_error_when_all_unspecified(
        self, key_manager: KeyManager
    ) -> None:
        """いずれの指定も存在しない場合にKeyNotFoundErrorが送出されることを確認する。"""
        with pytest.raises(KeyNotFoundError):
            key_manager.resolve_key_path(
                cli_path=None, config_path=None, environment_path=None
            )


def _read_key_path_from_environment(
    variable_name: str = "VTOTP_KEY_PATH",
) -> Path | None:
    """環境変数からのパス読み取りを模した補助関数。

    呼び出し元（本来はConfigManager等）が実際のOS環境変数を読み取り、
    空文字列は「未指定」として扱ったうえで `KeyManager.resolve_key_path`
    へ渡すことを想定した変換ロジックをテスト内で再現する。
    """
    raw_value = os.environ.get(variable_name)
    if not raw_value:
        return None
    return Path(raw_value)


class TestResolveKeyPathWithRealEnvironmentAndConfig:
    """実際のOS環境変数とconfig.jsonファイルを用いたresolve_key_pathの統合的な優先順位検証。"""

    def test_cli_option_overrides_real_environment_variable_and_config_file(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """実際にVTOTP_KEY_PATHとconfig.jsonが設定されていても、--key相当の指定が最優先されることを確認する。"""
        config_path = tmp_path / "config.key"
        config_path.write_text("dummy")
        env_path = tmp_path / "env.key"
        monkeypatch.setenv("VTOTP_KEY_PATH", str(env_path))

        cli_path = tmp_path / "cli.key"
        result = key_manager.resolve_key_path(
            cli_path=cli_path,
            config_path=config_path,
            environment_path=_read_key_path_from_environment(),
        )
        assert result == cli_path

    def test_real_environment_variable_overrides_config_file_when_cli_unset(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--key未指定時は、実際に設定されたVTOTP_KEY_PATHがconfig.jsonより優先されることを確認する。"""
        config_path = tmp_path / "config.key"
        config_path.write_text("dummy")
        env_path = tmp_path / "env.key"
        monkeypatch.setenv("VTOTP_KEY_PATH", str(env_path))

        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=config_path,
            environment_path=_read_key_path_from_environment(),
        )
        assert result == env_path

    def test_falls_back_to_config_file_when_environment_variable_is_unset(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VTOTP_KEY_PATHが未設定の場合、config.jsonのkey_pathが使われることを確認する。"""
        monkeypatch.delenv("VTOTP_KEY_PATH", raising=False)
        config_path = tmp_path / "config.key"
        config_path.write_text("dummy")

        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=config_path,
            environment_path=_read_key_path_from_environment(),
        )
        assert result == config_path

    def test_empty_string_environment_variable_is_treated_as_unset(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VTOTP_KEY_PATHが空文字列の場合は未指定として扱われ、config.jsonへフォールバックすることを確認する。"""
        monkeypatch.setenv("VTOTP_KEY_PATH", "")
        config_path = tmp_path / "config.key"
        config_path.write_text("dummy")

        environment_path = _read_key_path_from_environment()
        assert environment_path is None

        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=config_path,
            environment_path=environment_path,
        )
        assert result == config_path

    def test_raises_key_not_found_error_when_environment_empty_and_config_absent(
        self,
        key_manager: KeyManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VTOTP_KEY_PATHが空文字列で、CLIもconfig.jsonも未指定の場合はKeyNotFoundErrorになることを確認する。"""
        monkeypatch.setenv("VTOTP_KEY_PATH", "")
        with pytest.raises(KeyNotFoundError):
            key_manager.resolve_key_path(
                cli_path=None,
                config_path=None,
                environment_path=_read_key_path_from_environment(),
            )


class TestRotatedKeyPaths:
    """rotated_key_paths に関するテスト。"""

    def test_returns_default_three_generations(self, key_manager: KeyManager) -> None:
        """既定では`.1`から`.3`までの3世代分のパスを返すことを確認する。"""
        base = Path("/vault/master.key")
        result = key_manager.rotated_key_paths(base)
        assert result == [
            Path("/vault/master.key.1"),
            Path("/vault/master.key.2"),
            Path("/vault/master.key.3"),
        ]

    def test_respects_custom_max_generations(self, key_manager: KeyManager) -> None:
        """max_generationsを指定した場合、その世代数分のパスが返ることを確認する。"""
        base = Path("/vault/master.key")
        result = key_manager.rotated_key_paths(base, max_generations=1)
        assert result == [Path("/vault/master.key.1")]


class TestRotateKeyFile:
    """rotate_key_file に関するテスト。"""

    def test_new_key_is_written_to_path(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """繰り上げ後、新鍵がpathへ保存されることを確認する。"""
        target = tmp_path / "master.key"
        new_key = key_manager.generate_key()
        returned_path = key_manager.rotate_key_file(target, new_key)
        assert returned_path == target
        assert target.read_bytes() == new_key

    def test_does_not_create_generation_files_when_nothing_existed(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """既存の鍵ファイルが無い状態からのローテーションでは`.1`が作成されないことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.rotate_key_file(target, key_manager.generate_key())
        assert not Path(f"{target}.1").exists()

    def test_existing_key_is_shifted_to_generation_one(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """既存鍵が`<key_path>.1`へ退避されることを確認する。"""
        target = tmp_path / "master.key"
        old_key = key_manager.generate_key()
        key_manager.create_key_file(target, key=old_key)

        new_key = key_manager.generate_key()
        key_manager.rotate_key_file(target, new_key)

        assert target.read_bytes() == new_key
        assert Path(f"{target}.1").read_bytes() == old_key

    def test_full_rotation_shifts_all_generations_and_discards_oldest(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """3世代すべて存在する状態からのローテーションで最古の世代が破棄されることを確認する。"""
        target = tmp_path / "master.key"
        key0 = b"\x00" * 32
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        key3 = b"\x03" * 32

        target.write_bytes(key0)
        Path(f"{target}.1").write_bytes(key1)
        Path(f"{target}.2").write_bytes(key2)
        Path(f"{target}.3").write_bytes(key3)

        new_key = b"\x99" * 32
        key_manager.rotate_key_file(target, new_key)

        assert target.read_bytes() == new_key
        assert Path(f"{target}.1").read_bytes() == key0
        assert Path(f"{target}.2").read_bytes() == key1
        assert Path(f"{target}.3").read_bytes() == key2

    def test_repeated_rotations_never_exceed_max_generations(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """max_generationsを超える世代が繰り返しのrekeyでも一切生成されないことを境界値として確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target, key=b"\x00" * 32)

        history: list[bytes] = [b"\x00" * 32]
        for generation in range(1, 6):
            new_key = bytes([generation]) * 32
            key_manager.rotate_key_file(target, new_key)
            history.append(new_key)

            # MAX_ROTATED_KEYS(=3)を超える世代のファイルは存在しない。
            assert not Path(f"{target}.{key_manager.MAX_ROTATED_KEYS + 1}").exists()

        # 直近の3世代（.1, .2, .3）だけが、投入順の新しい方から残っている。
        expected_generations = list(reversed(history[-4:-1]))
        for offset, expected_key in enumerate(expected_generations, start=1):
            assert Path(f"{target}.{offset}").read_bytes() == expected_key
        assert target.read_bytes() == history[-1]


class _RunRecorder:
    """subprocess.run の代替。呼び出し引数を記録し、指定された例外を送出する。"""

    def __init__(self, error: BaseException | None = None) -> None:
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.error = error

    def __call__(
        self, args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((list(args), kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(args, 0, b"", b"")


@pytest.fixture
def force_unix(monkeypatch: pytest.MonkeyPatch) -> None:
    """実行OSに関わらず、Unix系の権限設定経路を通るようにする。"""
    monkeypatch.setattr(key_manager_module, "_is_windows", lambda: False)


@pytest.fixture
def force_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """実行OSに関わらず、Windowsの権限設定経路を通るようにする。"""
    monkeypatch.setattr(key_manager_module, "_is_windows", lambda: True)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setenv("USERNAME", "alice")
    monkeypatch.setenv("USERDOMAIN", "WORKGROUP")


@pytest.fixture
def run_recorder(monkeypatch: pytest.MonkeyPatch) -> _RunRecorder:
    """subprocess.run を成功を返す記録用スタブへ差し替える。"""
    recorder = _RunRecorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    return recorder


def _expected_icacls() -> str:
    """force_windows 環境下で期待される icacls.exe の絶対パスを返す。"""
    return str(Path(r"C:\Windows") / "System32" / "icacls.exe")


def _raise_os_error(*args: object, **kwargs: object) -> None:
    """常に OSError を送出する差し替え用関数。"""
    raise OSError("simulated failure")


class TestIsWindows:
    """_is_windows に関するテスト。"""

    def test_reflects_os_name(self) -> None:
        """os.name が "nt" の場合にのみ True を返すことを確認する。"""
        assert key_manager_module._is_windows() is (os.name == "nt")


class TestSetPrivatePermissionsUnix:
    """set_private_permissions の Unix 系経路（chmod）に関するテスト。"""

    def test_applies_owner_only_mode(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_unix: None,
    ) -> None:
        """os.chmod(path, 0o600) が呼ばれ、icacls は呼ばれないことを確認する。"""
        target = tmp_path / "master.key"
        calls: list[tuple[object, int]] = []
        monkeypatch.setattr(os, "chmod", lambda path, mode: calls.append((path, mode)))
        recorder = _RunRecorder()
        monkeypatch.setattr(subprocess, "run", recorder)

        key_manager.set_private_permissions(target)

        assert calls == [(target, 0o600)]
        assert recorder.calls == []

    def test_chmod_failure_raises_key_storage_error(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_unix: None,
    ) -> None:
        """chmod の OSError が握りつぶされず KeyStorageError へ変換されることを確認する。"""
        target = tmp_path / "master.key"
        monkeypatch.setattr(os, "chmod", _raise_os_error)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.set_private_permissions(target)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}

    @pytest.mark.skipif(
        IS_WINDOWS, reason="Unixのモードビットは Windows では検証できない"
    )
    def test_created_key_file_is_owner_read_write_only(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """実環境で作成された鍵ファイルのモードが 0600 であることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


class TestSetPrivatePermissionsWindows:
    """set_private_permissions の Windows 経路（icacls）に関するテスト。"""

    def test_invokes_icacls_with_argument_list(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        force_windows: None,
        run_recorder: _RunRecorder,
    ) -> None:
        """継承遮断と実行ユーザー専用の付与を、shell を使わず引数配列で渡すことを確認する。"""
        target = tmp_path / "master.key"

        key_manager.set_private_permissions(target)

        assert run_recorder.calls == [
            (
                [
                    _expected_icacls(),
                    str(target),
                    "/inheritance:r",
                    "/grant:r",
                    "WORKGROUP\\alice:(R,W,D)",
                ],
                {"check": True, "capture_output": True},
            )
        ]

    def test_does_not_call_chmod(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: None,
        run_recorder: _RunRecorder,
    ) -> None:
        """Windows 経路では os.chmod を使わないことを確認する。"""
        monkeypatch.setattr(os, "chmod", _raise_os_error)
        key_manager.set_private_permissions(tmp_path / "master.key")
        assert len(run_recorder.calls) == 1

    def test_account_without_domain(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: None,
        run_recorder: _RunRecorder,
    ) -> None:
        """USERDOMAIN が無い場合はユーザー名のみを付与対象にすることを確認する。"""
        monkeypatch.delenv("USERDOMAIN")
        key_manager.set_private_permissions(tmp_path / "master.key")
        assert run_recorder.calls[0][0][-1] == "alice:(R,W,D)"

    def test_falls_back_to_getpass_when_username_is_unset(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: None,
        run_recorder: _RunRecorder,
    ) -> None:
        """環境変数 USERNAME が無い場合は getpass.getuser() の結果を使うことを確認する。"""
        monkeypatch.delenv("USERNAME")
        monkeypatch.setattr(getpass, "getuser", lambda: "bob")
        key_manager.set_private_permissions(tmp_path / "master.key")
        assert run_recorder.calls[0][0][-1] == "WORKGROUP\\bob:(R,W,D)"

    def test_uses_default_system_root_when_unset(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: None,
        run_recorder: _RunRecorder,
    ) -> None:
        """SystemRoot が無い場合も System32 配下の icacls.exe を絶対パスで指定することを確認する。"""
        monkeypatch.delenv("SystemRoot")
        key_manager.set_private_permissions(tmp_path / "master.key")
        assert run_recorder.calls[0][0][0] == _expected_icacls()

    @pytest.mark.parametrize(
        "error",
        [OSError("no user"), ImportError("No module named 'pwd'"), KeyError("uid")],
    )
    def test_user_lookup_failure_raises_key_storage_error(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: None,
        run_recorder: _RunRecorder,
        error: BaseException,
    ) -> None:
        """実行ユーザー名を取得できない場合、icacls を呼ばずに KeyStorageError になることを確認する。"""
        monkeypatch.delenv("USERNAME")

        def _raise() -> str:
            raise error

        monkeypatch.setattr(getpass, "getuser", _raise)
        target = tmp_path / "master.key"

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.set_private_permissions(target)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert run_recorder.calls == []

    def test_empty_user_name_raises_key_storage_error(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: None,
        run_recorder: _RunRecorder,
    ) -> None:
        """ユーザー名が空文字列の場合も KeyStorageError になることを確認する。"""
        monkeypatch.setenv("USERNAME", "")
        monkeypatch.setattr(getpass, "getuser", lambda: "")
        with pytest.raises(KeyStorageError):
            key_manager.set_private_permissions(tmp_path / "master.key")
        assert run_recorder.calls == []

    @pytest.mark.parametrize(
        "error",
        [
            subprocess.CalledProcessError(
                5, ["icacls"], output=b"SENTINEL-OUT", stderr=b"SENTINEL-ERR"
            ),
            FileNotFoundError("icacls.exe not found"),
            subprocess.TimeoutExpired(["icacls"], 1.0),
        ],
    )
    def test_icacls_failure_raises_key_storage_error_without_output(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: None,
        error: BaseException,
    ) -> None:
        """icacls の失敗が KeyStorageError になり、コマンド出力を例外に残さないことを確認する。"""
        monkeypatch.setattr(subprocess, "run", _RunRecorder(error))
        target = tmp_path / "master.key"

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.set_private_permissions(target)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True
        assert "SENTINEL" not in repr(excinfo.value)

    def test_create_key_file_end_to_end_with_stubbed_icacls(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        force_windows: None,
        run_recorder: _RunRecorder,
    ) -> None:
        """Windows 経路でも一時ファイルへ ACL を設定してから配置されることを確認する。"""
        target = tmp_path / "master.key"
        key = b"\x11" * 32

        key_manager.create_key_file(target, key=key)

        assert target.read_bytes() == key
        assert list(tmp_path.iterdir()) == [target]
        acl_target = Path(run_recorder.calls[0][0][1])
        assert acl_target.parent == tmp_path
        assert acl_target.name.startswith(".master.key.")
        assert acl_target.name.endswith(".tmp")

    @pytest.mark.skipif(
        not IS_WINDOWS, reason="実際の icacls による ACL 検証は Windows 専用"
    )
    def test_created_key_file_has_explicit_owner_only_acl(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """実環境で作成された鍵ファイルが継承 ACE を持たず、実行ユーザーのみに付与されていることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)

        result = subprocess.run(
            [KeyManager._icacls_executable(), str(target)],
            check=True,
            capture_output=True,
        )
        output = result.stdout.decode(errors="replace")
        account = KeyManager._current_windows_account(target)
        ace_lines = [line for line in output.splitlines() if ":(" in line]
        assert len(ace_lines) == 1, output
        assert ace_lines[0].rstrip().endswith(f"{account}:(R,W,D)")
        assert "(I)" not in output
        assert len(key_manager.load_key(target)) == 32


class TestSafeAtomicWrite:
    """_store_key による安全な不可分書き込みとフェイルセーフに関するテスト。"""

    def test_permissions_are_set_on_empty_temp_file_before_writing(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """権限設定が同一ディレクトリの空の一時ファイルに対し、鍵の書き込み前に行われることを確認する。"""
        target = tmp_path / "master.key"
        observed: list[tuple[Path, int]] = []

        def _record(self: KeyManager, path: Path) -> None:
            observed.append((path, path.stat().st_size))

        monkeypatch.setattr(KeyManager, "set_private_permissions", _record)

        key_manager.create_key_file(target, key=b"\x22" * 32)

        assert len(observed) == 1
        temp_path, size_at_call = observed[0]
        assert size_at_call == 0
        assert temp_path.parent == tmp_path
        assert temp_path != target
        assert not temp_path.exists()
        assert target.read_bytes() == b"\x22" * 32

    def test_permission_failure_aborts_and_cleans_up(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """権限設定失敗時は鍵を書き込まずに中断し、一時ファイルを残さないことを確認する。"""
        target = tmp_path / "master.key"
        original = b"\x01" * 32
        target.write_bytes(original)

        def _fail(self: KeyManager, path: Path) -> None:
            raise KeyStorageError(
                MsgKey.KEY_PERMISSION_SETUP_FAILED, context={"path": str(path)}
            )

        monkeypatch.setattr(KeyManager, "set_private_permissions", _fail)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target, key=b"\x02" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert target.read_bytes() == original
        assert list(tmp_path.iterdir()) == [target]

    def test_replace_failure_raises_key_storage_error_and_cleans_up(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """os.replace が失敗した場合、KeyStorageError となり一時ファイルが残らないことを確認する。"""
        target = tmp_path / "master.key"
        monkeypatch.setattr(os, "replace", _raise_os_error)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target, key=b"\x00" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED
        assert isinstance(excinfo.value.__cause__, OSError)
        assert not target.exists()
        assert list(tmp_path.iterdir()) == []

    def test_temp_file_creation_failure_raises_key_storage_error(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """一時ファイルの作成に失敗した場合 KeyStorageError になることを確認する。"""
        monkeypatch.setattr(tempfile, "mkstemp", _raise_os_error)
        with pytest.raises(KeyStorageError):
            key_manager.create_key_file(tmp_path / "master.key")
        assert list(tmp_path.iterdir()) == []

    def test_parent_directory_failure_raises_key_storage_error(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """親パスが通常ファイルでディレクトリを作成できない場合 KeyStorageError になることを確認する。"""
        blocker = tmp_path / "not-a-dir"
        blocker.write_bytes(b"")
        target = blocker / "master.key"

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target)

        assert excinfo.value.context == {"path": str(target)}

    def test_short_write_is_detected_before_replace(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """書き込み後のサイズが32バイトでない場合、配置せずに KeyStorageError となることを確認する。"""
        target = tmp_path / "master.key"
        original = b"\x01" * 32
        target.write_bytes(original)
        monkeypatch.setattr(os, "fsync", lambda fd: os.ftruncate(fd, 16))

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target, key=b"\x02" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED
        assert target.read_bytes() == original
        assert list(tmp_path.iterdir()) == [target]

    def test_cleanup_failure_does_not_mask_original_error(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """一時ファイルの削除にも失敗した場合、元の失敗が KeyStorageError として優先されることを確認する。"""
        monkeypatch.setattr(os, "replace", _raise_os_error)
        monkeypatch.setattr(Path, "unlink", _raise_os_error)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(tmp_path / "master.key")

        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED

    def test_error_does_not_leak_key_bytes(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """保存失敗時の例外に鍵のバイト列が含まれないことを確認する（Zero Leakage Rule）。"""
        key = b"\xde\xad\xbe\xef" * 8
        monkeypatch.setattr(os, "replace", _raise_os_error)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(tmp_path / "master.key", key=key)

        rendered = repr(excinfo.value) + str(excinfo.value.__cause__)
        assert key.hex() not in rendered
        assert all(key.hex() not in value for value in excinfo.value.context.values())

    def test_load_and_verify_do_not_enforce_permissions(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """読み取り経路では権限設定・検査を行わない（FAT32/exFAT 運用の維持）ことを確認する。"""
        target = tmp_path / "master.key"
        target.write_bytes(b"\x05" * 32)
        monkeypatch.setattr(KeyManager, "set_private_permissions", _raise_os_error)
        monkeypatch.setattr(subprocess, "run", _raise_os_error)
        monkeypatch.setattr(os, "chmod", _raise_os_error)

        key_manager.verify_key_file(target)
        assert key_manager.load_key(target) == b"\x05" * 32


class TestRotateKeyFileFailSafe:
    """rotate_key_file のフェイルセーフ（失敗時に既存鍵を保全する）挙動に関するテスト。"""

    @staticmethod
    def _seed_generations(target: Path) -> dict[Path, bytes]:
        """正式鍵と `.1`・`.2` を作成し、パスと内容の対応を返す。"""
        contents = {
            target: b"\x00" * 32,
            Path(f"{target}.1"): b"\x01" * 32,
            Path(f"{target}.2"): b"\x02" * 32,
        }
        for path, data in contents.items():
            path.write_bytes(data)
        return contents

    def test_rejects_invalid_new_key_before_shifting(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """不正サイズの新鍵では世代繰り上げを一切行わずに InvalidKeyError となることを確認する。"""
        target = tmp_path / "master.key"
        contents = self._seed_generations(target)

        with pytest.raises(InvalidKeyError):
            key_manager.rotate_key_file(target, b"short")

        assert {p: p.read_bytes() for p in contents} == contents
        assert not Path(f"{target}.3").exists()

    def test_permission_failure_leaves_generations_untouched(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """権限設定に失敗した場合、既存鍵と世代ファイルが変更されないことを確認する。"""
        target = tmp_path / "master.key"
        contents = self._seed_generations(target)
        monkeypatch.setattr(os, "chmod", _raise_os_error)
        monkeypatch.setattr(subprocess, "run", _RunRecorder(OSError("denied")))

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert {p: p.read_bytes() for p in contents} == contents
        assert sorted(tmp_path.iterdir()) == sorted(contents)

    def test_final_replace_failure_rolls_back_shifted_generations(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """新鍵の配置に失敗した場合、繰り上げ済みの世代が元に戻ることを確認する。"""
        target = tmp_path / "master.key"
        contents = self._seed_generations(target)
        real_replace = os.replace

        def _fail_on_temp(source: Path, destination: Path) -> None:
            if str(source).endswith(".tmp"):
                raise OSError("simulated replace failure")
            real_replace(source, destination)

        monkeypatch.setattr(os, "replace", _fail_on_temp)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED
        assert {p: p.read_bytes() for p in contents} == contents
        assert sorted(tmp_path.iterdir()) == sorted(contents)

    def test_rollback_failure_still_reports_original_error(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ロールバック自体が失敗しても、元の配置失敗が KeyStorageError として送出されることを確認する。"""
        target = tmp_path / "master.key"
        self._seed_generations(target)
        real_replace = os.replace
        shifted: list[str] = []

        def _fail_after_shift(source: Path, destination: Path) -> None:
            if str(source).endswith(".tmp") or str(source) in shifted:
                raise OSError("simulated replace failure")
            real_replace(source, destination)
            shifted.append(str(destination))

        monkeypatch.setattr(os, "replace", _fail_after_shift)

        with pytest.raises(KeyStorageError):
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert not list(tmp_path.glob("*.tmp"))


def secrets_like_key() -> bytes:
    """テスト用に、生成鍵と同じ形式（32バイト）のダミー鍵バイト列を返す。"""
    return bytes(range(32))
