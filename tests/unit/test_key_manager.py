"""vtotp.core.key_manager.KeyManager の単体テスト。"""

from __future__ import annotations

import ctypes
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vtotp.core import key_manager as key_manager_module
from vtotp.core import windows_key_file as win
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


@pytest.fixture
def force_unix(monkeypatch: pytest.MonkeyPatch) -> None:
    """実行OSに関わらず、Unix系の一時ファイル生成経路を通るようにする。"""
    monkeypatch.setattr(key_manager_module, "_is_windows", lambda: False)


#: 偽の Win32 API が返す実行ユーザーの SID。
_FAKE_USER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"

#: 偽の Win32 API が返す、現在のプロセスに紐づく Logon SID。
_FAKE_LOGON_SID = "S-1-5-5-0-123456"

#: 別のログオンセッション（別 LUID）の Logon SID。
_OTHER_SESSION_LOGON_SID = "S-1-5-5-0-654321"


class _FakeWindowsFiles:
    """Windows の鍵一時ファイル生成経路で使う Win32 層の偽実装。

    :mod:`vtotp.core.windows_key_file` の Win32 依存部分（DLL 読み込み・SDDL 変換・
    `CreateFileW`・`msvcrt.open_osfhandle`・トークン SID・ハンドルの DACL 取得）を
    差し替え、実行 OS に関わらず `KeyManager` の Windows 経路を最後まで通す。
    `CreateFileW` 相当では実際にファイルを排他作成して fd を保持し、偽のハンドルを
    返す。`open_osfhandle` 相当はその fd の所有権を呼び出し元へ渡し、`CloseHandle`
    相当は移譲前の fd を閉じる。呼び出し順序と解放回数を記録する。
    """

    DESCRIPTOR = 0x5D5D
    HANDLE_BASE = 0x4000

    def __init__(self) -> None:
        self.events: list[tuple[str, object]] = []
        self.sddls: list[str] = []
        self.freed_pointers: list[int | None] = []
        self.closed_handles: list[int] = []
        self.created_paths: list[Path] = []
        self.granted_sids: list[str] = [_FAKE_USER_SID]
        self.create_error: OSError | None = None
        self.open_osfhandle_error: OSError | None = None
        self._open: dict[int, tuple[Path, int]] = {}

        def local_free(pointer: ctypes.c_void_p) -> None:
            self.freed_pointers.append(pointer.value)

        def close_handle(handle: int) -> int:
            self.closed_handles.append(handle)
            _, fd = self._open.pop(handle)
            os.close(fd)
            return 1

        def _unused(*args: object) -> int:
            raise AssertionError("must not be called")

        self.library = SimpleNamespace(
            LocalFree=local_free, CloseHandle=close_handle, CreateFileW=_unused
        )

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """windows_key_file の Win32 依存部分を本偽実装へ差し替える。"""
        monkeypatch.setattr(win, "_load_windows_library", lambda name: self.library)
        monkeypatch.setattr(win, "_security_descriptor_from_sddl", self._descriptor)
        monkeypatch.setattr(win, "_create_new_file", self._create_new_file)
        monkeypatch.setattr(win, "_open_osfhandle", self._open_osfhandle)
        monkeypatch.setattr(win, "current_user_sid", lambda: _FAKE_USER_SID)
        monkeypatch.setattr(
            win, "current_logon_sids", lambda: frozenset({_FAKE_LOGON_SID})
        )
        monkeypatch.setattr(win, "protected_dacl_granting_sids", self._granting_sids)

    def _descriptor(self, advapi32: object, sddl: str) -> ctypes.c_void_p:
        self.events.append(("sddl", sddl))
        self.sddls.append(sddl)
        return ctypes.c_void_p(self.DESCRIPTOR)

    def _create_new_file(
        self, kernel32: object, path: Path, descriptor: ctypes.c_void_p
    ) -> int:
        assert descriptor.value == self.DESCRIPTOR
        if self.create_error is not None:
            raise self.create_error
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        handle = self.HANDLE_BASE + len(self.created_paths)
        self.created_paths.append(path)
        self._open[handle] = (path, fd)
        self.events.append(("create", path))
        return handle

    def _open_osfhandle(self, handle: int) -> int:
        self.events.append(("open_osfhandle", handle))
        if self.open_osfhandle_error is not None:
            raise self.open_osfhandle_error
        _, fd = self._open.pop(handle)
        return fd

    def _granting_sids(self, handle: int) -> list[str]:
        path, _ = self._open[handle]
        self.events.append(("verify", (path, path.stat().st_size)))
        return list(self.granted_sids)


@pytest.fixture
def force_windows(monkeypatch: pytest.MonkeyPatch) -> _FakeWindowsFiles:
    """実行OSに関わらず、Windowsの生成時保護 DACL 経路を偽の Win32 層で通るようにする。"""
    monkeypatch.setattr(key_manager_module, "_is_windows", lambda: True)
    fake = _FakeWindowsFiles()
    fake.install(monkeypatch)
    return fake


def _raise_os_error(*args: object, **kwargs: object) -> Any:
    """常に OSError を送出する差し替え用関数。"""
    raise OSError("SENTINEL-OS-ERROR")


def _system32_tool(name: str) -> str:
    """テスト用に System32 内の標準コマンドの絶対パスを返す（Windows 専用）。"""
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / name)


def _real_sddl_of(path: Path) -> str:
    """icacls /save でファイルの DACL を SDDL として取得する（Windows 専用）。"""
    saved = path.with_name(path.name + ".acl")
    subprocess.run(
        [_system32_tool("icacls.exe"), str(path), "/save", str(saved)],
        check=True,
        capture_output=True,
    )
    try:
        return saved.read_bytes().decode("utf-16-le").splitlines()[1]
    finally:
        saved.unlink()


def _real_file_with_sddl(path: Path, sddl: str) -> int:
    """`sddl` の DACL を生成時に付与したファイルを作成し、そのハンドルを返す（Windows 専用）。"""
    advapi32 = win._load_windows_library("advapi32")
    kernel32 = win._load_windows_library("kernel32")
    win._configure_file_apis(kernel32)
    descriptor = win._security_descriptor_from_sddl(advapi32, sddl)
    try:
        handle = win._create_new_file(kernel32, path, descriptor)
    finally:
        kernel32.LocalFree(descriptor)
    assert handle is not None
    return handle


def _close_real_handle(handle: int) -> None:
    """_real_file_with_sddl で作成したハンドルを閉じる（Windows 専用）。"""
    kernel32 = win._load_windows_library("kernel32")
    win._configure_file_apis(kernel32)
    kernel32.CloseHandle(handle)


class TestIsWindows:
    """_is_windows に関するテスト。"""

    def test_reflects_os_name(self) -> None:
        """os.name が "nt" の場合にのみ True を返すことを確認する。"""
        assert key_manager_module._is_windows() is (os.name == "nt")


class TestSetPrivatePermissions:
    """set_private_permissions（Unix系の chmod 0600）に関するテスト。"""

    def test_applies_owner_only_mode(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """os.chmod(path, 0o600) が呼ばれることを確認する。"""
        target = tmp_path / "master.key"
        calls: list[tuple[object, int]] = []
        monkeypatch.setattr(os, "chmod", lambda path, mode: calls.append((path, mode)))

        key_manager.set_private_permissions(target)

        assert calls == [(target, 0o600)]

    def test_chmod_failure_raises_key_storage_error_without_details(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """chmod の OSError が握りつぶされず、詳細を連結しない KeyStorageError になることを確認する。"""
        target = tmp_path / "master.key"
        monkeypatch.setattr(os, "chmod", _raise_os_error)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.set_private_permissions(target)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True

    @pytest.mark.skipif(
        IS_WINDOWS, reason="Unixのモードビットは Windows では検証できない"
    )
    def test_created_key_file_is_owner_read_write_only(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """実環境で作成・ローテーションされた鍵ファイルのモードが 0600 であることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        key_manager.rotate_key_file(target, b"\x07" * 32)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert stat.S_IMODE(Path(f"{target}.1").stat().st_mode) == 0o600


class TestUnixKeyCreation:
    """Unix系の一時ファイル生成経路（mkstemp + chmod 0600）に関するテスト。"""

    def test_does_not_load_windows_specific_module(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_unix: None,
    ) -> None:
        """非 Windows 経路では Windows 固有モジュール（Win32 DLL・msvcrt）を読み込まないことを確認する。"""
        import vtotp.core as core_package

        monkeypatch.delitem(sys.modules, win.__name__)
        monkeypatch.delattr(core_package, "windows_key_file")
        target = tmp_path / "master.key"

        key_manager.create_key_file(target, key=b"\x41" * 32)
        key_manager.rotate_key_file(target, b"\x42" * 32)

        assert win.__name__ not in sys.modules
        assert target.read_bytes() == b"\x42" * 32

    def test_uses_mkstemp_and_chmod_on_empty_temp_file_before_writing(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_unix: None,
    ) -> None:
        """mkstemp で同一ディレクトリに作成した空の一時ファイルへ、書き込み前に 0600 を設定することを確認する。"""
        target = tmp_path / "master.key"
        real_mkstemp = tempfile.mkstemp
        mkstemp_calls: list[dict[str, object]] = []
        observed: list[tuple[Path, int]] = []

        def _mkstemp(**kwargs: Any) -> tuple[int, str]:
            mkstemp_calls.append(kwargs)
            return real_mkstemp(**kwargs)

        def _record(self: KeyManager, path: Path) -> None:
            observed.append((path, path.stat().st_size))

        monkeypatch.setattr(tempfile, "mkstemp", _mkstemp)
        monkeypatch.setattr(KeyManager, "set_private_permissions", _record)

        key_manager.create_key_file(target, key=b"\x22" * 32)

        assert mkstemp_calls == [
            {"dir": tmp_path, "prefix": ".master.key.", "suffix": ".tmp"}
        ]
        assert len(observed) == 1
        temp_path, size_at_call = observed[0]
        assert size_at_call == 0
        assert temp_path.parent == tmp_path
        assert not temp_path.exists()
        assert target.read_bytes() == b"\x22" * 32

    def test_dacl_is_not_verified_on_unix(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_unix: None,
    ) -> None:
        """Unix 系では DACL 再検証を行わない（chmod 0600 のみ）ことを確認する。"""
        monkeypatch.setattr(KeyManager, "verify_windows_dacl", _raise_os_error)
        target = tmp_path / "master.key"

        key_manager.create_key_file(target, key=b"\x44" * 32)

        assert target.read_bytes() == b"\x44" * 32

    def test_permission_failure_closes_fd_and_removes_temp_file(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_unix: None,
    ) -> None:
        """chmod 失敗時は鍵を書き込まず、fd を閉じて一時ファイルを削除し、既存鍵を変更しないことを確認する。"""
        target = tmp_path / "master.key"
        original = b"\x01" * 32
        target.write_bytes(original)
        real_mkstemp, real_close = tempfile.mkstemp, os.close
        created: list[int] = []
        closed: list[int] = []

        def _mkstemp(**kwargs: Any) -> tuple[int, str]:
            fd, name = real_mkstemp(**kwargs)
            created.append(fd)
            return fd, name

        def _close(fd: int) -> None:
            closed.append(fd)
            real_close(fd)

        monkeypatch.setattr(tempfile, "mkstemp", _mkstemp)
        monkeypatch.setattr(os, "close", _close)
        monkeypatch.setattr(os, "chmod", _raise_os_error)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target, key=b"\x02" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert closed == created
        assert target.read_bytes() == original
        assert list(tmp_path.iterdir()) == [target]

    def test_temp_file_creation_failure_raises_key_storage_error(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_unix: None,
    ) -> None:
        """一時ファイルの作成に失敗した場合 KeyStorageError になることを確認する。"""
        monkeypatch.setattr(tempfile, "mkstemp", _raise_os_error)
        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(tmp_path / "master.key")
        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED
        assert excinfo.value.__cause__ is None
        assert list(tmp_path.iterdir()) == []


class TestWindowsKeyCreation:
    """Windows の生成時保護 DACL 経路（CreateFileW + SDDL）に関するテスト。"""

    def test_creates_protected_then_verifies_then_writes(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        force_windows: _FakeWindowsFiles,
    ) -> None:
        """ユーザー SID の保護 SDDL で作成し、書き込み前（空）の同一ハンドルで再検証してから
        書き込み・配置することを確認する。
        """
        target = tmp_path / "master.key"
        key = bytes(range(32))

        key_manager.create_key_file(target, key=key)

        (temp_path,) = force_windows.created_paths
        assert force_windows.events == [
            ("sddl", f"D:P(A;;FA;;;{_FAKE_USER_SID})"),
            ("create", temp_path),
            ("verify", (temp_path, 0)),
            ("open_osfhandle", _FakeWindowsFiles.HANDLE_BASE),
        ]
        assert temp_path.parent == tmp_path
        assert re.fullmatch(r"\.master\.key\.[0-9a-f]{16}\.tmp", temp_path.name)
        assert target.read_bytes() == key
        assert list(tmp_path.iterdir()) == [target]
        # 記述子は一度だけ解放し、所有権を移譲したハンドルは CloseHandle しない。
        assert force_windows.freed_pointers == [_FakeWindowsFiles.DESCRIPTOR]
        assert force_windows.closed_handles == []

    def test_does_not_use_chmod_or_set_private_permissions(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: _FakeWindowsFiles,
    ) -> None:
        """Windows 経路では mkstemp・chmod・set_private_permissions を使わないことを確認する。"""
        monkeypatch.setattr(os, "chmod", _raise_os_error)
        monkeypatch.setattr(tempfile, "mkstemp", _raise_os_error)
        monkeypatch.setattr(KeyManager, "set_private_permissions", _raise_os_error)
        target = tmp_path / "master.key"

        key_manager.create_key_file(target, key=b"\x33" * 32)
        key_manager.rotate_key_file(target, b"\x34" * 32)

        assert target.read_bytes() == b"\x34" * 32
        assert Path(f"{target}.1").read_bytes() == b"\x33" * 32

    def test_user_sid_does_not_depend_on_environment_variables(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: _FakeWindowsFiles,
    ) -> None:
        """USERNAME・USERDOMAIN・SystemRoot を改ざんしても SDDL の付与先が変わらないことを確認する。"""
        monkeypatch.setenv("USERNAME", "attacker")
        monkeypatch.setenv("USERDOMAIN", "EVIL")
        monkeypatch.setenv("SystemRoot", r"C:\evil")

        key_manager.create_key_file(tmp_path / "master.key")

        assert force_windows.sddls == [f"D:P(A;;FA;;;{_FAKE_USER_SID})"]

    @pytest.mark.parametrize(
        "failing_step", ["current_user_sid", "_security_descriptor_from_sddl"]
    )
    def test_protection_setup_failure_aborts_before_creating(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: _FakeWindowsFiles,
        failing_step: str,
    ) -> None:
        """SID 取得・SDDL 変換の失敗では何も作成せず、詳細を含まない権限設定エラーとなることを確認する。"""

        def _fail(*args: object) -> Any:
            raise win.ProtectedDaclError("SENTINEL-WIN32")

        monkeypatch.setattr(
            win,
            failing_step,
            _raise_os_error if failing_step == "current_user_sid" else _fail,
        )
        target = tmp_path / "master.key"
        target.write_bytes(b"\x01" * 32)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target, key=b"\x02" * 32)

        assert excinfo.value.exit_code == 1
        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True
        assert "SENTINEL" not in repr(excinfo.value)
        assert force_windows.created_paths == []
        assert target.read_bytes() == b"\x01" * 32
        assert list(tmp_path.iterdir()) == [target]

    def test_create_failure_raises_storage_error_without_details(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        force_windows: _FakeWindowsFiles,
    ) -> None:
        """CreateFileW の失敗は詳細を含まない KEY_STORAGE_FAILED となり、記述子を解放することを確認する。"""
        force_windows.create_error = OSError("SENTINEL-CREATE")
        target = tmp_path / "master.key"

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target)

        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True
        assert force_windows.freed_pointers == [_FakeWindowsFiles.DESCRIPTOR]
        assert list(tmp_path.iterdir()) == []

    def test_unapproved_ace_aborts_before_writing_and_cleans_up(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        force_windows: _FakeWindowsFiles,
    ) -> None:
        """許可リスト外の ACE を検出したら鍵を書かずに中断し、ハンドルを一度だけ閉じて
        一時ファイルを削除し、既存鍵を変更しないことを確認する。
        """
        target = tmp_path / "master.key"
        original = b"\x01" * 32
        target.write_bytes(original)
        force_windows.granted_sids = [_FAKE_USER_SID, "S-1-5-32-545"]

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target, key=b"\x02" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        # 利用者には一時ファイル名ではなく保存先パスを示す。
        assert excinfo.value.context == {"path": str(target)}
        assert ("open_osfhandle", _FakeWindowsFiles.HANDLE_BASE) not in (
            force_windows.events
        )
        assert force_windows.closed_handles == [_FakeWindowsFiles.HANDLE_BASE]
        assert target.read_bytes() == original
        assert list(tmp_path.iterdir()) == [target]

    def test_handle_conversion_failure_closes_handle_once_and_cleans_up(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        force_windows: _FakeWindowsFiles,
    ) -> None:
        """ハンドルの fd 変換に失敗した場合、ハンドルを一度だけ閉じ、一時ファイルを削除することを確認する。"""
        force_windows.open_osfhandle_error = OSError("SENTINEL-CRT")
        target = tmp_path / "master.key"

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target)

        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED
        assert excinfo.value.__cause__ is None
        assert force_windows.closed_handles == [_FakeWindowsFiles.HANDLE_BASE]
        assert list(tmp_path.iterdir()) == []

    def test_cleanup_failure_after_verification_is_reported(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: _FakeWindowsFiles,
    ) -> None:
        """検証失敗後の一時ファイル削除にも失敗した場合、元のエラーを優先しつつ残存パスを通知することを確認する。"""
        leftovers: list[Path] = []
        key_manager = KeyManager(on_cleanup_failure=leftovers.append)
        force_windows.granted_sids = ["S-1-1-0"]
        monkeypatch.setattr(Path, "unlink", _raise_os_error)
        target = tmp_path / "master.key"

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(target)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert leftovers == force_windows.created_paths

    @pytest.mark.skipif(not IS_WINDOWS, reason="実際の DACL による検証は Windows 専用")
    def test_real_key_files_keep_protected_dacl_for_current_user_only(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """実環境で、親に Everyone の継承可能 ACE があっても、作成・ローテーション後の鍵と
        世代ファイルの DACL が保護され、実行ユーザーのみを許可することを確認する。
        """
        vault = tmp_path / "vault"
        vault.mkdir()
        subprocess.run(
            [_system32_tool("icacls.exe"), str(vault), "/grant", "*S-1-1-0:(OI)(F)"],
            check=True,
            capture_output=True,
        )
        target = vault / "master.key"
        # CR / LF / Ctrl-Z を含む鍵がテキスト変換されずに保存されることも確認する。
        first_key = bytes([0x0A, 0x0D, 0x1A]) + bytes(range(29))

        key_manager.create_key_file(target, key=first_key)
        key_manager.rotate_key_file(target, b"\x0a" * 32)

        expected = f"D:P(A;;FA;;;{win.current_user_sid()})"
        assert _real_sddl_of(target) == expected
        assert _real_sddl_of(Path(f"{target}.1")) == expected
        assert target.read_bytes() == b"\x0a" * 32
        assert Path(f"{target}.1").read_bytes() == first_key
        assert sorted(p.name for p in vault.iterdir()) == [
            "master.key",
            "master.key.1",
        ]


#: 許可リストに含まれない SID（別ユーザー・組み込みグループ・別セッションの Logon SID）。
_FOREIGN_SIDS = [
    "S-1-5-21-1111111111-2222222222-3333333333-1002",  # 別のローカルユーザー
    "S-1-5-32-545",  # BUILTIN\Users
    "S-1-5-11",  # Authenticated Users
    "S-1-1-0",  # Everyone
    _OTHER_SESSION_LOGON_SID,  # 別のログオンセッション（別 LUID）
]

#: 許可リストに含まれる SID（実行ユーザー・SYSTEM・Administrators・OWNER RIGHTS・
#: 現在のプロセスの Logon SID）。
_ALLOWLISTED_SIDS = [
    _FAKE_USER_SID,
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-3-4",
    _FAKE_LOGON_SID,
]


class TestVerifyWindowsDacl:
    """verify_windows_dacl（ハンドルによる DACL 許可リスト再検証）に関するテスト。"""

    HANDLE = 0x7A7A

    @pytest.fixture(autouse=True)
    def _token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(win, "current_user_sid", lambda: _FAKE_USER_SID)
        monkeypatch.setattr(
            win, "current_logon_sids", lambda: frozenset({_FAKE_LOGON_SID})
        )

    def _stub_granted(self, monkeypatch: pytest.MonkeyPatch, sids: list[str]) -> None:
        def _granted(handle: int) -> list[str]:
            assert handle == self.HANDLE
            return sids

        monkeypatch.setattr(win, "protected_dacl_granting_sids", _granted)

    def test_accepts_allowlisted_sids(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """実行ユーザー・SYSTEM・Administrators・OWNER RIGHTS・Logon SID のみなら通過することを確認する。"""
        self._stub_granted(monkeypatch, _ALLOWLISTED_SIDS)

        key_manager.verify_windows_dacl(self.HANDLE, tmp_path / "master.key")

    @pytest.mark.parametrize("foreign_sid", _FOREIGN_SIDS)
    def test_rejects_granting_ace_for_unapproved_account(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        foreign_sid: str,
    ) -> None:
        """許可リスト外のアカウントへの許可 ACE が 1 つでもあれば KeyStorageError となることを確認する。"""
        self._stub_granted(monkeypatch, [*_ALLOWLISTED_SIDS, foreign_sid])
        target = tmp_path / "master.key"

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.verify_windows_dacl(self.HANDLE, target)

        assert excinfo.value.exit_code == 1
        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert foreign_sid not in repr(excinfo.value)

    def test_logon_sid_must_match_current_process_exactly(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Logon SID は接頭辞ではなく、現在のプロセスの Logon SID との完全一致で判定することを確認する。"""
        target = tmp_path / "master.key"
        self._stub_granted(monkeypatch, [_FAKE_USER_SID, _FAKE_LOGON_SID])
        key_manager.verify_windows_dacl(self.HANDLE, target)

        self._stub_granted(monkeypatch, [_FAKE_USER_SID, _OTHER_SESSION_LOGON_SID])
        with pytest.raises(KeyStorageError):
            key_manager.verify_windows_dacl(self.HANDLE, target)

    def test_logon_sid_ace_is_rejected_when_token_has_no_logon_sid(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """トークンに Logon SID が無い場合、どの Logon SID の許可 ACE も拒否することを確認する。"""
        monkeypatch.setattr(win, "current_logon_sids", frozenset)
        self._stub_granted(monkeypatch, [_FAKE_USER_SID, _FAKE_LOGON_SID])

        with pytest.raises(KeyStorageError):
            key_manager.verify_windows_dacl(self.HANDLE, tmp_path / "master.key")

    @pytest.mark.parametrize(
        "failing_helper",
        ["protected_dacl_granting_sids", "current_user_sid", "current_logon_sids"],
    )
    def test_unverifiable_dacl_raises_without_details(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failing_helper: str,
    ) -> None:
        """DACL（非保護・NULL・未解釈 ACE を含む）やトークン情報を検証できない場合も中断し、
        失敗詳細を例外に残さないことを確認する。
        """
        monkeypatch.setattr(win, failing_helper, _raise_os_error)
        target = tmp_path / "master.key"

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.verify_windows_dacl(self.HANDLE, target)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert excinfo.value.context == {"path": str(target)}
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True


@pytest.mark.skipif(not IS_WINDOWS, reason="実際の DACL による検証は Windows 専用")
class TestVerifyWindowsDaclReal:
    """実際の Win32 API による verify_windows_dacl の検証（Windows 専用）。"""

    def test_protected_dacl_for_current_user_passes(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """実行ユーザーだけを許可する保護 DACL は再検証を通過することを確認する。"""
        sddl = win.protected_sddl(win.current_user_sid())
        handle = _real_file_with_sddl(tmp_path / "a.tmp", sddl)
        try:
            key_manager.verify_windows_dacl(handle, tmp_path / "master.key")
        finally:
            _close_real_handle(handle)

    @pytest.mark.parametrize(
        "extra_ace",
        ["(A;;FR;;;S-1-5-32-546)", "(A;;FR;;;WD)", "(A;;FR;;;BU)"],
        ids=["guests", "everyone", "users"],
    )
    def test_unapproved_ace_is_rejected(
        self, key_manager: KeyManager, tmp_path: Path, extra_ace: str
    ) -> None:
        """保護 DACL でも、許可リスト外のアカウントへの許可 ACE があれば拒否することを確認する。"""
        sddl = win.protected_sddl(win.current_user_sid()) + extra_ace
        handle = _real_file_with_sddl(tmp_path / "a.tmp", sddl)
        try:
            with pytest.raises(KeyStorageError) as excinfo:
                key_manager.verify_windows_dacl(handle, tmp_path / "master.key")
        finally:
            _close_real_handle(handle)
        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED

    def test_logon_sid_ace_is_checked_against_current_session(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """現在のセッションの Logon SID の ACE は許可し、別セッションのものは拒否することを確認する。"""
        (current_logon_sid,) = win.current_logon_sids()
        luid_high, luid_low = current_logon_sid.rsplit("-", 2)[1:]
        other_logon_sid = f"S-1-5-5-{luid_high}-{int(luid_low) + 1}"
        user_sddl = win.protected_sddl(win.current_user_sid())

        for logon_sid, accepted in [
            (current_logon_sid, True),
            (other_logon_sid, False),
        ]:
            handle = _real_file_with_sddl(
                tmp_path / f"{accepted}.tmp", f"{user_sddl}(A;;FR;;;{logon_sid})"
            )
            try:
                if accepted:
                    key_manager.verify_windows_dacl(handle, tmp_path / "master.key")
                else:
                    with pytest.raises(KeyStorageError):
                        key_manager.verify_windows_dacl(handle, tmp_path / "master.key")
            finally:
                _close_real_handle(handle)

    def test_unprotected_dacl_is_rejected(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """許可リスト内の SID だけを許可していても、親から継承した（保護されていない）
        DACL は拒否することを確認する。

        `CreateFileW` に DACL を明示すると OS が保護済みとして扱うため、ここでは
        セキュリティ記述子を渡さずに通常作成したファイルを用いる。
        """
        import msvcrt

        target = tmp_path / "inherited.key"
        target.write_bytes(b"")
        fd = os.open(target, os.O_RDONLY)
        try:
            with pytest.raises(KeyStorageError):
                key_manager.verify_windows_dacl(
                    msvcrt.get_osfhandle(fd), tmp_path / "master.key"
                )
        finally:
            os.close(fd)

    def test_null_dacl_is_rejected(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """NULL DACL（全員にフルアクセス）は保護フラグがあっても拒否することを確認する。"""
        handle = _real_file_with_sddl(tmp_path / "a.tmp", "D:PNO_ACCESS_CONTROL")
        try:
            with pytest.raises(KeyStorageError):
                key_manager.verify_windows_dacl(handle, tmp_path / "master.key")
        finally:
            _close_real_handle(handle)

    def test_invalid_handle_is_rejected(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """DACL を取得できない（無効なハンドル）場合に KeyStorageError となることを確認する。"""
        with pytest.raises(KeyStorageError):
            key_manager.verify_windows_dacl(0, tmp_path / "master.key")


class TestSafeAtomicWrite:
    """_store_key による安全な不可分書き込みとフェイルセーフに関するテスト。"""

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
        # OS のエラー詳細は例外チェーンにも残さない（Zero Leakage Rule）。
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True
        assert not target.exists()
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
        """一時ファイルの削除にも失敗した場合、元の失敗が KeyStorageError として優先されることを確認する。

        通知先（on_cleanup_failure）が未指定でも例外にならない。
        """
        monkeypatch.setattr(os, "replace", _raise_os_error)
        monkeypatch.setattr(Path, "unlink", _raise_os_error)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.create_key_file(tmp_path / "master.key")

        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED

    def test_cleanup_failure_reports_only_leftover_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """一時ファイルが削除できず残存した場合、そのパスだけを on_cleanup_failure へ通知することを確認する。"""
        leftovers: list[Path] = []
        key_manager = KeyManager(on_cleanup_failure=leftovers.append)
        monkeypatch.setattr(os, "replace", _raise_os_error)
        monkeypatch.setattr(Path, "unlink", _raise_os_error)
        target = tmp_path / "master.key"

        with pytest.raises(KeyStorageError):
            key_manager.create_key_file(target)

        (leftover,) = tmp_path.iterdir()
        assert leftovers == [leftover]
        assert leftover.name.startswith(".master.key.")
        assert leftover.name.endswith(".tmp")

    def test_successful_cleanup_is_not_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """一時ファイルを削除できた場合は on_cleanup_failure を呼ばないことを確認する。"""
        leftovers: list[Path] = []
        key_manager = KeyManager(on_cleanup_failure=leftovers.append)
        monkeypatch.setattr(os, "replace", _raise_os_error)

        with pytest.raises(KeyStorageError):
            key_manager.create_key_file(tmp_path / "master.key")

        assert leftovers == []
        assert list(tmp_path.iterdir()) == []

    def test_open_writer_closes_fd_when_file_object_cannot_be_created(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FileIO の生成に失敗した場合、所有権を受け取った fd を一度だけ閉じることを確認する。"""
        fd = os.open(tmp_path / "x", os.O_CREAT | os.O_WRONLY)
        real_close = os.close
        closed: list[int] = []

        def _close(descriptor: int) -> None:
            closed.append(descriptor)
            real_close(descriptor)

        monkeypatch.setattr(os, "close", _close)
        monkeypatch.setattr(io, "FileIO", _raise_os_error)

        with pytest.raises(OSError):
            KeyManager._open_writer(fd)

        assert closed == [fd]

    def test_open_writer_closes_file_io_when_buffer_cannot_be_created(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """バッファの生成に失敗した場合、fd を所有する FileIO だけを閉じる（二重解放しない）ことを確認する。"""
        fd = os.open(tmp_path / "x", os.O_CREAT | os.O_WRONLY)
        raw_objects: list[io.FileIO] = []
        real_file_io = io.FileIO
        closed: list[int] = []

        def _file_io(descriptor: int, mode: str) -> io.FileIO:
            raw = real_file_io(descriptor, mode)
            raw_objects.append(raw)
            return raw

        monkeypatch.setattr(io, "FileIO", _file_io)
        monkeypatch.setattr(io, "BufferedWriter", _raise_os_error)
        monkeypatch.setattr(os, "close", closed.append)

        with pytest.raises(OSError):
            KeyManager._open_writer(fd)

        assert closed == []
        assert raw_objects[0].closed

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

        rendered = repr(excinfo.value) + str(excinfo.value)
        assert excinfo.value.__cause__ is None
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
        monkeypatch.setattr(KeyManager, "verify_windows_dacl", _raise_os_error)
        monkeypatch.setattr(win, "create_protected_temp_file", _raise_os_error)
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
        # Unix系は chmod、Windows は保護 DACL 用のユーザー SID 取得を失敗させる。
        monkeypatch.setattr(os, "chmod", _raise_os_error)
        monkeypatch.setattr(win, "current_user_sid", _raise_os_error)

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


#: 最古世代の退避ファイル名（`<key_path>.3.<16桁の16進数>.old`）。
_PARKED_OLDEST_NAME = re.compile(r"master\.key\.3\.[0-9a-f]{16}\.old")


class TestRotateKeyFileOldestGenerationProtection:
    """上限到達時（`.3` が存在する場合）の最古世代の退避とロールバックに関するテスト。"""

    @staticmethod
    def _seed_full_generations(target: Path) -> dict[Path, bytes]:
        """正式鍵と `.1`〜`.3` をすべて作成し、パスと内容の対応を返す。"""
        contents = {
            target: b"\x00" * 32,
            Path(f"{target}.1"): b"\x01" * 32,
            Path(f"{target}.2"): b"\x02" * 32,
            Path(f"{target}.3"): b"\x03" * 32,
        }
        for path, data in contents.items():
            path.write_bytes(data)
        return contents

    @staticmethod
    def _fail_replace_when(
        monkeypatch: pytest.MonkeyPatch, should_fail: Any
    ) -> list[tuple[str, str]]:
        """`should_fail(source, destination)` が真となる os.replace だけを失敗させる。"""
        real_replace = os.replace
        calls: list[tuple[str, str]] = []

        def _replace(source: Path, destination: Path) -> None:
            calls.append((str(source), str(destination)))
            if should_fail(str(source), str(destination)):
                raise OSError("simulated replace failure")
            real_replace(source, destination)

        monkeypatch.setattr(os, "replace", _replace)
        return calls

    def test_successful_rotation_parks_then_discards_oldest(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`.3` を退避してから繰り上げ、配置成功後に退避ファイルが残らないことを確認する。"""
        target = tmp_path / "master.key"
        self._seed_full_generations(target)
        calls = self._fail_replace_when(monkeypatch, lambda source, dest: False)

        key_manager.rotate_key_file(target, b"\x09" * 32)

        parked_source, parked_destination = calls[0]
        assert parked_source == f"{target}.3"
        assert _PARKED_OLDEST_NAME.fullmatch(Path(parked_destination).name)
        assert [source for source, _ in calls[1:]][:3] == [
            f"{target}.2",
            f"{target}.1",
            str(target),
        ]
        assert target.read_bytes() == b"\x09" * 32
        assert Path(f"{target}.1").read_bytes() == b"\x00" * 32
        assert Path(f"{target}.2").read_bytes() == b"\x01" * 32
        assert Path(f"{target}.3").read_bytes() == b"\x02" * 32
        assert sorted(p.name for p in tmp_path.iterdir()) == [
            "master.key",
            "master.key.1",
            "master.key.2",
            "master.key.3",
        ]

    def test_final_replace_failure_restores_parked_oldest_generation(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """4 回目以降のローテーションで新鍵の配置に失敗した場合、`.3` を含む全世代が元に戻ることを確認する。"""
        target = tmp_path / "master.key"
        contents = self._seed_full_generations(target)
        self._fail_replace_when(
            monkeypatch, lambda source, dest: source.endswith(".tmp")
        )

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert excinfo.value.exit_code == 1
        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED
        assert {p: p.read_bytes() for p in contents} == contents
        assert sorted(tmp_path.iterdir()) == sorted(contents)

    @pytest.mark.parametrize("failing_source", [".2", ".1", ""])
    def test_shift_failure_restores_parked_oldest_generation(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failing_source: str,
    ) -> None:
        """途中の世代繰り上げに失敗した場合も、退避した `.3` を含めて元に戻ることを確認する。"""
        target = tmp_path / "master.key"
        contents = self._seed_full_generations(target)
        failing_path = f"{target}{failing_source}"
        self._fail_replace_when(
            monkeypatch, lambda source, dest: source == failing_path
        )

        with pytest.raises(KeyStorageError):
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert {p: p.read_bytes() for p in contents} == contents
        assert sorted(tmp_path.iterdir()) == sorted(contents)

    @pytest.mark.parametrize(
        "failing_reverse_move",
        [
            ("", ".1"),  # .1 -> master.key（現在の鍵の復元）
            (".1", ".2"),  # .2 -> .1
            (".2", ".3"),  # .3 -> .2
            (".3", ".old"),  # 退避ファイル -> .3
        ],
        ids=["active-key", "generation-1", "generation-2", "parked-oldest"],
    )
    def test_rollback_stops_at_first_failed_reverse_move_without_losing_keys(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failing_reverse_move: tuple[str, str],
    ) -> None:
        """ロールバックの逆移動が失敗したら即座に中断し、どの世代の鍵も上書きで失われないことを確認する。

        例えば `.1 -> master.key` の復元に失敗した場合、`.1` には現在の鍵が
        残っている。ここで続行すると次の `.2 -> .1` が現在の鍵を上書きして
        永久に失うため、以降の逆移動は一切行わない。送出される例外は、元の
        配置失敗を原因として保持する。
        """
        target = tmp_path / "master.key"
        contents = self._seed_full_generations(target)
        restore_to, restore_from = failing_reverse_move
        real_replace = os.replace
        calls: list[tuple[str, str]] = []

        def _is_failing_reverse_move(source: str, destination: str) -> bool:
            if destination != f"{target}{restore_to}":
                return False
            if restore_from == ".old":
                return _PARKED_OLDEST_NAME.fullmatch(Path(source).name) is not None
            return source == f"{target}{restore_from}"

        def _replace(source: Path, destination: Path) -> None:
            calls.append((str(source), str(destination)))
            if str(source).endswith(".tmp"):
                raise OSError("simulated placement failure")
            if _is_failing_reverse_move(str(source), str(destination)):
                raise OSError("simulated rollback failure")
            real_replace(source, destination)

        monkeypatch.setattr(os, "replace", _replace)

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_STORAGE_FAILED
        assert excinfo.value.__cause__ is None
        # 失敗した逆移動が最後の os.replace 呼び出しであり、以降は何も移動しない。
        assert _is_failing_reverse_move(*calls[-1])
        # 4 世代すべての鍵が、いずれかのファイルにそれぞれ 1 つずつ残っている。
        surviving = sorted(p.read_bytes() for p in tmp_path.iterdir())
        assert surviving == sorted(contents.values())
        assert not list(tmp_path.glob("*.tmp"))

    def test_place_key_file_reraises_original_error_when_rollback_fails(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """逆移動が失敗しても、ロールバックの失敗ではなく元の配置失敗を再送出することを確認する。"""
        target = tmp_path / "master.key"
        self._seed_full_generations(target)
        temp_path = tmp_path / ".master.key.x.tmp"
        temp_path.write_bytes(b"\x09" * 32)
        real_replace = os.replace

        def _replace(source: Path, destination: Path) -> None:
            if str(source) == str(temp_path):
                raise OSError("simulated placement failure")
            if str(destination) == str(target):
                raise OSError("simulated rollback failure")
            real_replace(source, destination)

        monkeypatch.setattr(os, "replace", _replace)

        with pytest.raises(OSError, match="simulated placement failure"):
            key_manager._place_key_file(temp_path, target, rotate=True)

    def test_rollback_failure_on_active_key_keeps_it_in_generation_one(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`.1 -> master.key` の復元に失敗した場合、現在の鍵が `.1` に残り、`.2 -> .1` が実行されないことを確認する。"""
        target = tmp_path / "master.key"
        self._seed_full_generations(target)
        calls = self._fail_replace_when(
            monkeypatch,
            lambda source, dest: source.endswith(".tmp")
            or (source == f"{target}.1" and dest == str(target)),
        )

        with pytest.raises(KeyStorageError):
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert (f"{target}.2", f"{target}.1") not in calls
        assert not target.exists()
        assert Path(f"{target}.1").read_bytes() == b"\x00" * 32  # 現在の鍵
        assert Path(f"{target}.2").read_bytes() == b"\x01" * 32
        assert Path(f"{target}.3").read_bytes() == b"\x02" * 32
        parked = [p for p in tmp_path.iterdir() if p.name.endswith(".old")]
        assert len(parked) == 1
        assert parked[0].read_bytes() == b"\x03" * 32

    def test_parking_failure_leaves_generations_untouched(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`.3` の退避自体に失敗した場合、何も移動せずに中断することを確認する。"""
        target = tmp_path / "master.key"
        contents = self._seed_full_generations(target)
        calls = self._fail_replace_when(
            monkeypatch, lambda source, dest: dest.endswith(".old")
        )

        with pytest.raises(KeyStorageError):
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert len(calls) == 1
        assert {p: p.read_bytes() for p in contents} == contents
        assert sorted(tmp_path.iterdir()) == sorted(contents)

    def test_parked_file_deletion_failure_is_reported_not_raised(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """配置成功後の退避ファイル削除に失敗しても、例外を送出せずローテーションを完了し、
        残存した退避ファイルのパスだけを通知することを確認する。
        """
        leftovers: list[Path] = []
        key_manager = KeyManager(on_cleanup_failure=leftovers.append)
        target = tmp_path / "master.key"
        self._seed_full_generations(target)
        real_unlink = Path.unlink

        def _unlink(self: Path, missing_ok: bool = False) -> None:
            if self.name.endswith(".old"):
                raise OSError("simulated unlink failure")
            real_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", _unlink)

        key_manager.rotate_key_file(target, b"\x09" * 32)

        assert target.read_bytes() == b"\x09" * 32
        assert Path(f"{target}.3").read_bytes() == b"\x02" * 32
        parked = [p for p in tmp_path.iterdir() if p.name.endswith(".old")]
        assert len(parked) == 1
        assert _PARKED_OLDEST_NAME.fullmatch(parked[0].name)
        assert parked[0].read_bytes() == b"\x03" * 32
        assert leftovers == parked

    def test_dacl_rejection_leaves_all_generations_untouched(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        force_windows: _FakeWindowsFiles,
    ) -> None:
        """Windows の DACL 再検証で拒否された場合、`.3` を含む全世代を一切移動しないことを確認する。"""
        target = tmp_path / "master.key"
        contents = self._seed_full_generations(target)
        force_windows.granted_sids = [_FAKE_USER_SID, "S-1-1-0"]

        with pytest.raises(KeyStorageError) as excinfo:
            key_manager.rotate_key_file(target, b"\x09" * 32)

        assert excinfo.value.message_key is MsgKey.KEY_PERMISSION_SETUP_FAILED
        assert {p: p.read_bytes() for p in contents} == contents
        assert sorted(tmp_path.iterdir()) == sorted(contents)


def secrets_like_key() -> bytes:
    """テスト用に、生成鍵と同じ形式（32バイト）のダミー鍵バイト列を返す。"""
    return bytes(range(32))
