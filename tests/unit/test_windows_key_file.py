"""vtotp.core.windows_key_file（Windows 専用の鍵一時ファイル生成・DACL 検証）の単体テスト。

Win32 API は偽の `advapi32` / `kernel32` / `msvcrt` に差し替え、Windows 以外でも
成功・各失敗・資源解放の経路を検証する。実際の Win32 API による検証は
Windows でのみ実行する。
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

import pytest

from vtotp.core import windows_key_file as win

IS_WINDOWS = sys.platform.startswith("win")

#: 偽の Win32 API が返す実行ユーザーの SID。
_FAKE_USER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"

#: 偽の Win32 API が返す、現在のプロセスに紐づく Logon SID。
_FAKE_LOGON_SID = "S-1-5-5-0-123456"

#: `CreateFileW` の失敗時の戻り値（ポインタ幅の -1）。
_INVALID_HANDLE = ctypes.c_void_p(-1).value

windows_only = pytest.mark.skipif(
    not IS_WINDOWS, reason="実際の Win32 API による検証は Windows 専用"
)


def _raise_os_error(*args: object, **kwargs: object) -> Any:
    """常に OSError を送出する差し替え用関数。"""
    raise OSError("SENTINEL-WIN32")


def _system32_tool(name: str) -> str:
    """テスト用に System32 内の標準コマンドの絶対パスを返す（Windows 専用）。"""
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / name)


def _whoami_user_sid() -> str:
    """whoami.exe から実行ユーザーの SID を取得する（Windows 専用の独立した検証手段）。"""
    result = subprocess.run(
        [_system32_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip().split(",")[-1].strip('"')


class TestLoadWindowsLibrary:
    """_load_windows_library / _last_error に関するテスト。"""

    def test_fails_without_windll(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ctypes.WinDLL が無い環境では OSError になることを確認する。"""
        monkeypatch.delattr(ctypes, "WinDLL", raising=False)
        with pytest.raises(OSError):
            win._load_windows_library("advapi32")

    def test_uses_windll_with_last_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ctypes.WinDLL を use_last_error=True で呼び出すことを確認する。"""
        calls: list[tuple[str, dict[str, object]]] = []

        def _fake_windll(name: str, **kwargs: object) -> str:
            calls.append((name, kwargs))
            return f"<{name}>"

        monkeypatch.setattr(ctypes, "WinDLL", _fake_windll, raising=False)

        assert win._load_windows_library("kernel32") == "<kernel32>"
        assert calls == [("kernel32", {"use_last_error": True})]

    def test_last_error_reads_ctypes_last_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_last_error が ctypes.get_last_error の値を返すことを確認する。"""
        monkeypatch.setattr(ctypes, "get_last_error", lambda: 80, raising=False)
        assert win._last_error() == 80


class _FakeTokenWin32:
    """トークン情報取得に使う `advapi32` / `kernel32` の偽実装。

    ctypes の出力引数（`byref`）へ実際に値を書き込み、Windows 以外でも
    構造体の解釈・解放処理・各失敗経路を検証できるようにする。
    """

    TOKEN_HANDLE = 0xBEEF
    SID_POINTER = 0x5151
    GROUP_SID_POINTER_BASE = 0x6000

    def __init__(
        self,
        *,
        open_token: bool = True,
        token_user_size: int = 44,
        token_information: bool = True,
        convert_sid: bool = True,
        groups: list[tuple[str, int]] | None = None,
        token_groups_size: int | None = None,
    ) -> None:
        self.closed_handles: list[int | None] = []
        self.freed_pointers: list[int | None] = []
        self.requested_access: list[int] = []
        self.requested_classes: list[int] = []
        self.converted_sids: list[int] = []
        self._keep_alive: list[ctypes.Array[ctypes.c_wchar]] = []
        token_groups = groups or []
        self._sid_strings = {self.SID_POINTER: _FAKE_USER_SID} | {
            self.GROUP_SID_POINTER_BASE + index: sid
            for index, (sid, _) in enumerate(token_groups)
        }
        groups_offset = win._TokenGroups.Groups.offset
        entry_size = ctypes.sizeof(win._SidAndAttributes)
        if token_groups_size is None:
            token_groups_size = groups_offset + entry_size * max(len(token_groups), 1)

        def open_process_token(process: object, access: int, token: Any) -> int:
            self.requested_access.append(access)
            if not open_token:
                return 0
            token._obj.value = self.TOKEN_HANDLE
            return 1

        def get_token_information(
            token: object, info_class: int, buffer: Any, length: int, size: Any
        ) -> int:
            assert info_class in (1, 2)  # TokenUser / TokenGroups
            if buffer is None:
                self.requested_classes.append(info_class)
                size._obj.value = (
                    token_user_size if info_class == 1 else token_groups_size
                )
                return 0
            if not token_information:
                return 0
            if info_class == 1:
                pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))
                pointer[0] = self.SID_POINTER
                return 1
            header = ctypes.cast(buffer, ctypes.POINTER(win._TokenGroups)).contents
            header.GroupCount = len(token_groups)
            entries = ctypes.cast(
                ctypes.addressof(buffer) + groups_offset,
                ctypes.POINTER(win._SidAndAttributes),
            )
            for index, (_, attributes) in enumerate(token_groups):
                entries[index].Sid = self.GROUP_SID_POINTER_BASE + index
                entries[index].Attributes = attributes
            return 1

        def convert_sid_to_string_sid(sid: int, string_sid: Any) -> int:
            self.converted_sids.append(sid)
            if not convert_sid:
                return 0
            text = ctypes.create_unicode_buffer(self._sid_strings[sid])
            self._keep_alive.append(text)
            string_sid._obj.value = ctypes.addressof(text)
            return 1

        def close_handle(handle: ctypes.c_void_p) -> int:
            self.closed_handles.append(handle.value)
            return 1

        def local_free(pointer: ctypes.c_void_p) -> None:
            self.freed_pointers.append(pointer.value)

        self.advapi32 = SimpleNamespace(
            OpenProcessToken=open_process_token,
            GetTokenInformation=get_token_information,
            ConvertSidToStringSidW=convert_sid_to_string_sid,
        )
        self.kernel32 = SimpleNamespace(
            GetCurrentProcess=lambda: -1,
            CloseHandle=close_handle,
            LocalFree=local_free,
        )

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`_load_windows_library` を本偽実装へ差し替える。"""
        libraries = {"advapi32": self.advapi32, "kernel32": self.kernel32}
        monkeypatch.setattr(win, "_load_windows_library", libraries.__getitem__)


class TestTokenSids:
    """current_user_sid / current_logon_sids（プロセストークンの SID 取得）のテスト。"""

    def test_current_user_sid_reads_token_user_and_releases_resources(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TokenUser の SID を文字列化して返し、ハンドルと文字列領域を解放することを確認する。"""
        fake = _FakeTokenWin32()
        fake.install(monkeypatch)

        assert win.current_user_sid() == _FAKE_USER_SID
        assert fake.requested_access == [0x0008]  # TOKEN_QUERY
        assert fake.converted_sids == [_FakeTokenWin32.SID_POINTER]
        assert fake.closed_handles == [_FakeTokenWin32.TOKEN_HANDLE]
        assert len(fake.freed_pointers) == 1
        assert fake.freed_pointers[0] is not None

    def test_open_process_token_failure_raises_without_closing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OpenProcessToken が失敗した場合、OSError となり未取得のハンドルを閉じないことを確認する。"""
        fake = _FakeTokenWin32(open_token=False)
        fake.install(monkeypatch)

        with pytest.raises(OSError):
            win.current_user_sid()
        assert fake.closed_handles == []

    @pytest.mark.parametrize(
        "options",
        [
            {"token_user_size": 0},
            {"token_information": False},
            {"convert_sid": False},
        ],
        ids=["size-query", "token-information", "convert-sid"],
    )
    def test_token_query_failures_raise_and_close_handle(
        self, monkeypatch: pytest.MonkeyPatch, options: dict[str, Any]
    ) -> None:
        """トークン情報の取得・SID 変換の失敗時も OSError となり、トークンハンドルを閉じることを確認する。"""
        fake = _FakeTokenWin32(**options)
        fake.install(monkeypatch)

        with pytest.raises(OSError):
            win.current_user_sid()
        assert fake.closed_handles == [_FakeTokenWin32.TOKEN_HANDLE]
        assert fake.freed_pointers == []

    def test_current_logon_sids_selects_only_logon_id_groups(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TokenGroups のうち SE_GROUP_LOGON_ID 属性を持つ SID だけを返し、資源を解放することを確認する。"""
        fake = _FakeTokenWin32(
            groups=[
                ("S-1-1-0", 0x00000007),  # Everyone（必須・既定で有効）
                (_FAKE_LOGON_SID, 0xC0000007),  # 現在のセッションの Logon SID
                ("S-1-5-32-545", 0x00000007),  # BUILTIN\Users
                ("S-1-5-5-0-999", 0x80000000),  # 属性の一部しか持たないものは除外
            ]
        )
        fake.install(monkeypatch)

        assert win.current_logon_sids() == frozenset({_FAKE_LOGON_SID})
        assert fake.requested_access == [0x0008]  # TOKEN_QUERY
        assert fake.requested_classes == [2]  # TokenGroups
        assert fake.converted_sids == [_FakeTokenWin32.GROUP_SID_POINTER_BASE + 1]
        assert fake.closed_handles == [_FakeTokenWin32.TOKEN_HANDLE]
        assert len(fake.freed_pointers) == 1

    def test_token_logon_sid_pointers_accepts_header_only_buffer(self) -> None:
        """グループ 0 件でヘッダー分しかない（構造体より小さい）バッファでも ValueError にならないことを確認する。"""
        header_only_size = win._TokenGroups.Groups.offset
        assert header_only_size < ctypes.sizeof(win._TokenGroups)
        buffer = ctypes.create_string_buffer(header_only_size)  # GroupCount = 0

        assert win._token_logon_sid_pointers(buffer) == []

    def test_current_logon_sids_with_zero_groups_returns_empty_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ヘッダー分のサイズだけを返すグループ 0 件のトークンでも、空集合を返すことを確認する。"""
        fake = _FakeTokenWin32(
            groups=[], token_groups_size=win._TokenGroups.Groups.offset
        )
        fake.install(monkeypatch)

        assert win.current_logon_sids() == frozenset()
        assert fake.converted_sids == []
        assert fake.closed_handles == [_FakeTokenWin32.TOKEN_HANDLE]

    def test_current_logon_sids_is_empty_without_logon_id_group(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Logon SID を持たないトークンでは空集合を返す（何も追加で許可しない）ことを確認する。"""
        fake = _FakeTokenWin32(groups=[("S-1-1-0", 0x00000007)])
        fake.install(monkeypatch)

        assert win.current_logon_sids() == frozenset()
        assert fake.converted_sids == []
        assert fake.closed_handles == [_FakeTokenWin32.TOKEN_HANDLE]

    def test_current_logon_sids_open_token_failure_raises_without_closing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OpenProcessToken が失敗した場合、OSError となり未取得のハンドルを閉じないことを確認する。"""
        fake = _FakeTokenWin32(open_token=False, groups=[(_FAKE_LOGON_SID, 0xC0000007)])
        fake.install(monkeypatch)

        with pytest.raises(OSError):
            win.current_logon_sids()
        assert fake.closed_handles == []

    @pytest.mark.parametrize(
        "options",
        [
            {"token_groups_size": 0},
            {"token_information": False},
            {"convert_sid": False},
        ],
        ids=["size-query", "token-information", "convert-sid"],
    )
    def test_current_logon_sids_query_failures_raise_and_close_handle(
        self, monkeypatch: pytest.MonkeyPatch, options: dict[str, Any]
    ) -> None:
        """TokenGroups の取得・SID 変換の失敗時も OSError となり、トークンハンドルを閉じることを確認する。"""
        fake = _FakeTokenWin32(groups=[(_FAKE_LOGON_SID, 0xC0000007)], **options)
        fake.install(monkeypatch)

        with pytest.raises(OSError):
            win.current_logon_sids()
        assert fake.closed_handles == [_FakeTokenWin32.TOKEN_HANDLE]
        assert fake.freed_pointers == []

    @windows_only
    def test_real_current_user_sid_matches_whoami(self) -> None:
        """実環境のプロセストークンから取得した SID が whoami の結果と一致することを確認する。"""
        assert win.current_user_sid() == _whoami_user_sid()

    @windows_only
    def test_real_logon_sids_match_whoami_logonid(self) -> None:
        """current_logon_sids の結果が whoami /logonid と一致することを確認する。

        `whoami /groups` は Logon SID を列挙しないため、SID のみを出力する
        `whoami /logonid` を独立した照合元として用いる。
        """
        result = subprocess.run(
            [_system32_tool("whoami.exe"), "/logonid"],
            check=True,
            capture_output=True,
            text=True,
        )
        logon_sids = win.current_logon_sids()
        assert logon_sids == {result.stdout.strip()}
        assert all(re.fullmatch(r"S-1-5-5-\d+-\d+", sid) for sid in logon_sids)


#: Win32 の ACE 種別（ACCESS_ALLOWED / DENIED と、その OBJECT・CALLBACK 版）。
_ALLOWED, _DENIED, _ALLOWED_OBJECT, _DENIED_OBJECT = 0x00, 0x01, 0x05, 0x06
_ALLOWED_CALLBACK, _DENIED_CALLBACK = 0x09, 0x0A
_ALLOWED_CALLBACK_OBJECT, _DENIED_CALLBACK_OBJECT = 0x0B, 0x0C
_MANDATORY_LABEL = 0x11

#: 保護された DACL を持つ記述子の制御フラグ（SE_DACL_PRESENT | SE_DACL_PROTECTED）。
_PROTECTED_CONTROL = 0x0004 | 0x1000


class _FakeDaclWin32:
    """ハンドルからの DACL 取得・走査に使う `advapi32` / `kernel32` の偽実装。

    `aces` で指定した (ACE 種別, SID 文字列) の並びを実メモリ上の ACL・ACE として
    構築し、`GetSecurityInfo` / `GetSecurityDescriptorControl` / `GetAce` /
    `ConvertSidToStringSidW` の出力引数（`byref`）へ実際の値を書き込む。
    """

    DESCRIPTOR = 0xD0D0

    def __init__(
        self,
        aces: list[tuple[int, str]],
        *,
        status: int = 0,
        control: int = _PROTECTED_CONTROL,
        control_ok: bool = True,
        null_dacl: bool = False,
        failing_ace_index: int | None = None,
        null_ace_index: int | None = None,
        convert_sid: bool = True,
    ) -> None:
        self.security_info_calls: list[tuple[object, ...]] = []
        self.control_queries: list[int | None] = []
        self.converted_sids: list[int] = []
        self.freed_pointers: list[int | None] = []
        self._keep_alive: list[ctypes.Array[ctypes.c_wchar]] = []
        self._acl = win._AclHeader(AclRevision=2, AceCount=len(aces))
        self._ace_buffers: list[ctypes.Array[ctypes.c_char]] = []
        self._sid_by_address: dict[int, str] = {}
        for ace_type, sid in aces:
            buffer = ctypes.create_string_buffer(16)  # ヘッダー + マスク + SID領域
            header = win._AceHeader.from_buffer(buffer)
            header.AceType = ace_type
            header.AceSize = len(buffer)
            self._ace_buffers.append(buffer)
            self._sid_by_address[ctypes.addressof(buffer) + 8] = sid

        def get_security_info(
            handle: int,
            object_type: int,
            information: int,
            owner: object,
            group: object,
            dacl: Any,
            sacl: object,
            descriptor: Any,
        ) -> int:
            self.security_info_calls.append(
                (handle, object_type, information, owner, group, sacl)
            )
            if status:
                return status
            dacl._obj.value = None if null_dacl else ctypes.addressof(self._acl)
            descriptor._obj.value = self.DESCRIPTOR
            return 0

        def get_security_descriptor_control(
            descriptor: ctypes.c_void_p, control_out: Any, revision: Any
        ) -> int:
            self.control_queries.append(descriptor.value)
            if not control_ok:
                return 0
            control_out._obj.value = control
            revision._obj.value = 1
            return 1

        def get_ace(acl: object, index: int, ace: Any) -> int:
            if index == failing_ace_index:
                return 0
            if index == null_ace_index:
                ace._obj.value = None
                return 1
            ace._obj.value = ctypes.addressof(self._ace_buffers[index])
            return 1

        def convert_sid_to_string_sid(sid: int, string_sid: Any) -> int:
            self.converted_sids.append(sid)
            if not convert_sid:
                return 0
            text = ctypes.create_unicode_buffer(self._sid_by_address[sid])
            self._keep_alive.append(text)
            string_sid._obj.value = ctypes.addressof(text)
            return 1

        def local_free(pointer: ctypes.c_void_p) -> None:
            self.freed_pointers.append(pointer.value)

        self.advapi32 = SimpleNamespace(
            GetSecurityInfo=get_security_info,
            GetSecurityDescriptorControl=get_security_descriptor_control,
            GetAce=get_ace,
            ConvertSidToStringSidW=convert_sid_to_string_sid,
        )
        self.kernel32 = SimpleNamespace(LocalFree=local_free)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`_load_windows_library` を本偽実装へ差し替える。"""
        libraries = {"advapi32": self.advapi32, "kernel32": self.kernel32}
        monkeypatch.setattr(win, "_load_windows_library", libraries.__getitem__)


class TestProtectedDaclGrantingSids:
    """protected_dacl_granting_sids（ハンドルの DACL 走査）に関するテスト。"""

    HANDLE = 0x7A7A

    def test_returns_sids_of_granting_aces_and_skips_deny_aces(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """通常形式の許可 ACE の SID を順に返し、拒否 ACE（全 4 形式）は読み飛ばすことを確認する。"""
        fake = _FakeDaclWin32(
            [
                (_ALLOWED, _FAKE_USER_SID),
                (_DENIED, "S-1-1-0"),
                (_DENIED_OBJECT, "S-1-5-32-545"),
                (_ALLOWED, "S-1-5-18"),
                (_DENIED_CALLBACK, "S-1-5-11"),
                (_DENIED_CALLBACK_OBJECT, "S-1-5-32-546"),
            ]
        )
        fake.install(monkeypatch)

        sids = win.protected_dacl_granting_sids(self.HANDLE)

        assert sids == [_FAKE_USER_SID, "S-1-5-18"]
        # パスではなくハンドルを渡し、SE_FILE_OBJECT(1) / DACL_SECURITY_INFORMATION(4)
        # で DACL のみを要求する。
        assert fake.security_info_calls == [(self.HANDLE, 1, 4, None, None, None)]
        assert fake.control_queries == [_FakeDaclWin32.DESCRIPTOR]
        assert len(fake.converted_sids) == 2
        # SID 文字列 2 件と、最後にセキュリティ記述子を解放する。
        assert len(fake.freed_pointers) == 3
        assert fake.freed_pointers[-1] == _FakeDaclWin32.DESCRIPTOR

    def test_empty_protected_dacl_returns_no_sids(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ACE を持たない保護 DACL（誰にも許可しない）では空の一覧を返すことを確認する。"""
        fake = _FakeDaclWin32([])
        fake.install(monkeypatch)

        assert win.protected_dacl_granting_sids(self.HANDLE) == []
        assert fake.freed_pointers == [_FakeDaclWin32.DESCRIPTOR]

    def test_security_info_failure_raises_without_freeing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GetSecurityInfo の失敗で OSError となり、未取得の記述子を解放しないことを確認する。"""
        fake = _FakeDaclWin32([(_ALLOWED, _FAKE_USER_SID)], status=5)
        fake.install(monkeypatch)

        with pytest.raises(OSError) as excinfo:
            win.protected_dacl_granting_sids(self.HANDLE)
        assert "5" not in str(excinfo.value)
        assert fake.freed_pointers == []

    @pytest.mark.parametrize(
        "options",
        [
            {"control_ok": False},
            {"control": 0x0004},  # SE_DACL_PRESENT のみ（継承を遮断していない）
            {"null_dacl": True},
            {"failing_ace_index": 1},
            {"null_ace_index": 0},
            {"convert_sid": False},
        ],
        ids=[
            "control-query",
            "unprotected-dacl",
            "null-dacl",
            "get-ace",
            "null-ace",
            "convert-sid",
        ],
    )
    def test_unverifiable_dacl_raises_and_frees_descriptor(
        self, monkeypatch: pytest.MonkeyPatch, options: dict[str, Any]
    ) -> None:
        """制御フラグ取得失敗・非保護 DACL・NULL DACL・ACE 取得失敗・SID 変換失敗は
        OSError となり、記述子を解放することを確認する。
        """
        fake = _FakeDaclWin32(
            [(_ALLOWED, _FAKE_USER_SID), (_ALLOWED, "S-1-5-18")], **options
        )
        fake.install(monkeypatch)

        with pytest.raises(OSError):
            win.protected_dacl_granting_sids(self.HANDLE)
        assert fake.freed_pointers[-1] == _FakeDaclWin32.DESCRIPTOR

    def test_null_dacl_is_rejected_even_when_marked_protected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """保護フラグがあっても NULL DACL は全員へのフルアクセスとして拒否することを確認する。"""
        fake = _FakeDaclWin32([], null_dacl=True, control=_PROTECTED_CONTROL)
        fake.install(monkeypatch)

        with pytest.raises(OSError, match="NULL DACL"):
            win.protected_dacl_granting_sids(self.HANDLE)

    @pytest.mark.parametrize(
        "ace_type",
        [
            _ALLOWED_CALLBACK,
            _ALLOWED_OBJECT,
            _ALLOWED_CALLBACK_OBJECT,
            _MANDATORY_LABEL,
        ],
        ids=["allowed-callback", "allowed-object", "allowed-callback-object", "label"],
    )
    @pytest.mark.parametrize("granted_sid", [_FAKE_USER_SID, "S-1-1-0"])
    def test_unsupported_ace_type_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch, ace_type: int, granted_sid: str
    ) -> None:
        """通常形式以外の ACE 種別は、SID が許可リスト内であっても未解釈として OSError とすることを確認する。"""
        fake = _FakeDaclWin32([(_ALLOWED, _FAKE_USER_SID), (ace_type, granted_sid)])
        fake.install(monkeypatch)

        with pytest.raises(OSError):
            win.protected_dacl_granting_sids(self.HANDLE)
        assert fake.freed_pointers[-1] == _FakeDaclWin32.DESCRIPTOR


class TestProtectedSddl:
    """protected_sddl / _security_descriptor_from_sddl に関するテスト。"""

    def test_builds_protected_full_access_sddl_for_user(self) -> None:
        """継承を遮断（P）し、指定ユーザーだけにフルアクセス（FA）を与える SDDL を返すことを確認する。"""
        assert win.protected_sddl(_FAKE_USER_SID) == f"D:P(A;;FA;;;{_FAKE_USER_SID})"

    @pytest.mark.parametrize(
        "sid",
        ["", "WD", "S-1", "S-1-5-21-1)(A;;FA;;;WD", "S-1-5-18\n", " S-1-5-18"],
    )
    def test_rejects_malformed_sid(self, sid: str) -> None:
        """S-1-... 形式でない SID は SDDL へ埋め込まず ProtectedDaclError とすることを確認する。"""
        with pytest.raises(win.ProtectedDaclError):
            win.protected_sddl(sid)

    def test_converts_sddl_with_revision_1(self) -> None:
        """SDDL_REVISION_1 で変換し、作成された記述子を返すことを確認する。"""
        calls: list[tuple[str, int, object]] = []

        def convert(sddl: str, revision: int, descriptor: Any, size: object) -> int:
            calls.append((sddl, revision, size))
            descriptor._obj.value = 0x5D5D
            return 1

        advapi32 = SimpleNamespace(
            ConvertStringSecurityDescriptorToSecurityDescriptorW=convert
        )

        descriptor = win._security_descriptor_from_sddl(advapi32, "D:P(A;;FA;;;SY)")

        assert descriptor.value == 0x5D5D
        assert calls == [("D:P(A;;FA;;;SY)", 1, None)]

    def test_conversion_failure_raises_protected_dacl_error(self) -> None:
        """記述子の作成に失敗した場合は ProtectedDaclError を送出することを確認する。"""
        advapi32 = SimpleNamespace(
            ConvertStringSecurityDescriptorToSecurityDescriptorW=lambda *args: 0
        )
        with pytest.raises(win.ProtectedDaclError):
            win._security_descriptor_from_sddl(advapi32, "D:P(A;;FA;;;SY)")


class TestCreateNewFile:
    """_create_new_file（CreateFileW による生成時 DACL 付きの排他作成）に関するテスト。"""

    @staticmethod
    def _kernel32(result: int | None, calls: list[dict[str, Any]]) -> SimpleNamespace:
        def create_file(
            name: str,
            access: int,
            share: int,
            attributes: Any,
            disposition: int,
            flags: int,
            template: object,
        ) -> int | None:
            security = attributes._obj
            calls.append(
                {
                    "name": name,
                    "access": access,
                    "share": share,
                    "nLength": security.nLength,
                    "descriptor": security.lpSecurityDescriptor,
                    "inherit": security.bInheritHandle,
                    "disposition": disposition,
                    "flags": flags,
                    "template": template,
                }
            )
            return result

        return SimpleNamespace(CreateFileW=create_file)

    def test_passes_security_attributes_and_create_new(self, tmp_path: Path) -> None:
        """SECURITY_ATTRIBUTES（構造体サイズ・記述子・継承無効）と CREATE_NEW 等を渡すことを確認する。"""
        calls: list[dict[str, Any]] = []
        target = tmp_path / ".master.key.abc.tmp"

        handle = win._create_new_file(
            self._kernel32(0x1234, calls), target, ctypes.c_void_p(0x5D5D)
        )

        assert handle == 0x1234
        assert calls == [
            {
                "name": str(target),
                "access": 0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                "share": 0x7,  # FILE_SHARE_READ | WRITE | DELETE
                "nLength": ctypes.sizeof(win._SecurityAttributes),
                "descriptor": 0x5D5D,
                "inherit": 0,
                "disposition": 1,  # CREATE_NEW
                "flags": 0x80,  # FILE_ATTRIBUTE_NORMAL
                "template": None,
            }
        ]

    @pytest.mark.parametrize("error", [80, 183])
    def test_name_collision_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: int
    ) -> None:
        """ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS の場合は None（再試行対象）を返すことを確認する。"""
        monkeypatch.setattr(win, "_last_error", lambda: error)
        kernel32 = self._kernel32(_INVALID_HANDLE, [])

        assert (
            win._create_new_file(kernel32, tmp_path / "x", ctypes.c_void_p(1)) is None
        )

    @pytest.mark.parametrize("result", [_INVALID_HANDLE, None])
    def test_other_failure_raises_os_error_without_details(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: int | None
    ) -> None:
        """名前衝突以外の失敗（アクセス拒否等）は詳細を含まない OSError とすることを確認する。"""
        monkeypatch.setattr(win, "_last_error", lambda: 5)  # ERROR_ACCESS_DENIED
        kernel32 = self._kernel32(result, [])

        with pytest.raises(OSError) as excinfo:
            win._create_new_file(kernel32, tmp_path / "x", ctypes.c_void_p(1))
        assert str(excinfo.value) == "CreateFileW failed"


class TestOpenOsfhandle:
    """_open_osfhandle（msvcrt によるハンドル所有権の移譲）に関するテスト。"""

    def test_uses_msvcrt_open_osfhandle_for_writing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """msvcrt.open_osfhandle へハンドルと書き込み用フラグを渡し、その fd を返すことを確認する。"""
        calls: list[tuple[int, int]] = []

        def open_osfhandle(handle: int, flags: int) -> int:
            calls.append((handle, flags))
            return 42

        monkeypatch.setitem(
            sys.modules, "msvcrt", SimpleNamespace(open_osfhandle=open_osfhandle)
        )

        assert win._open_osfhandle(0x1234) == 42
        assert calls == [(0x1234, os.O_WRONLY | getattr(os, "O_BINARY", 0))]


class _FakeFileWin32:
    """create_protected_temp_file が使う Win32 / msvcrt の偽実装。

    `CreateFileW` は実際にファイルを排他作成して偽のハンドルを返し、
    `open_osfhandle` はそのファイルを書き込み用に開いた fd を返す。
    呼び出し順序と、ハンドル・記述子の解放回数を記録する。
    """

    DESCRIPTOR = 0x5D5D
    HANDLE_BASE = 0x4000

    def __init__(
        self,
        *,
        convert_sddl: bool = True,
        create_error: int | None = None,
        open_osfhandle_fails: bool = False,
    ) -> None:
        self.events: list[tuple[str, object]] = []
        self.closed_handles: list[int] = []
        self.freed_pointers: list[int | None] = []
        self.attempted_paths: list[Path] = []
        self.handles: dict[int, Path] = {}
        self.fds: list[int] = []

        def convert(sddl: str, revision: int, descriptor: Any, size: object) -> int:
            self.events.append(("sddl", sddl))
            if not convert_sddl:
                return 0
            descriptor._obj.value = self.DESCRIPTOR
            return 1

        def create_file(
            name: str,
            access: int,
            share: int,
            attributes: Any,
            disposition: int,
            flags: int,
            template: object,
        ) -> int | None:
            path = Path(name)
            self.attempted_paths.append(path)
            assert attributes._obj.lpSecurityDescriptor == self.DESCRIPTOR
            if create_error is not None:
                self._error = create_error
                return _INVALID_HANDLE
            if path.exists():
                self._error = 80  # ERROR_FILE_EXISTS
                return _INVALID_HANDLE
            path.touch(exist_ok=False)
            handle = self.HANDLE_BASE + len(self.handles)
            self.handles[handle] = path
            self.events.append(("create", path))
            return handle

        def close_handle(handle: int) -> int:
            self.closed_handles.append(handle)
            return 1

        def local_free(pointer: ctypes.c_void_p) -> None:
            self.events.append(("free", pointer.value))
            self.freed_pointers.append(pointer.value)

        def open_osfhandle(handle: int, flags: int) -> int:
            self.events.append(("open_osfhandle", handle))
            if open_osfhandle_fails:
                raise OSError("SENTINEL-CRT")
            fd = os.open(self.handles[handle], os.O_WRONLY | getattr(os, "O_BINARY", 0))
            self.fds.append(fd)
            return fd

        self._error = 0
        self.advapi32 = SimpleNamespace(
            ConvertStringSecurityDescriptorToSecurityDescriptorW=convert
        )
        self.kernel32 = SimpleNamespace(
            CreateFileW=create_file, CloseHandle=close_handle, LocalFree=local_free
        )
        self.msvcrt = SimpleNamespace(open_osfhandle=open_osfhandle)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Win32 DLL・msvcrt・ユーザー SID の取得を本偽実装へ差し替える。"""
        libraries = {"advapi32": self.advapi32, "kernel32": self.kernel32}
        monkeypatch.setattr(win, "_load_windows_library", libraries.__getitem__)
        monkeypatch.setattr(win, "_last_error", lambda: self._error)
        monkeypatch.setitem(sys.modules, "msvcrt", self.msvcrt)

        def _user_sid() -> str:
            self.events.append(("user_sid", None))
            return _FAKE_USER_SID

        monkeypatch.setattr(win, "current_user_sid", _user_sid)

    def close_fds(self) -> None:
        """テストで開いた fd を閉じる。"""
        for fd in self.fds:
            with contextlib.suppress(OSError):
                os.close(fd)


@pytest.fixture
def fake_files(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeFileWin32]:
    """成功する Win32 ファイル API の偽実装を差し替えて返す。"""
    fake = _FakeFileWin32()
    fake.install(monkeypatch)
    yield fake
    fake.close_fds()


class _Recorder:
    """verify / discard コールバックの呼び出しを記録する。"""

    def __init__(self, events: list[tuple[str, object]]) -> None:
        self.events = events
        self.verified: list[int] = []
        self.discarded: list[Path] = []
        self.verify_error: BaseException | None = None

    def verify(self, handle: int) -> None:
        self.events.append(("verify", handle))
        self.verified.append(handle)
        if self.verify_error is not None:
            raise self.verify_error

    def discard(self, path: Path) -> None:
        self.discarded.append(path)
        path.unlink(missing_ok=True)


class TestCreateProtectedTempFile:
    """create_protected_temp_file（生成時保護 DACL 付き一時ファイル作成）に関するテスト。"""

    @staticmethod
    def _create(tmp_path: Path, recorder: _Recorder) -> tuple[int, Path]:
        return win.create_protected_temp_file(
            tmp_path,
            ".master.key.",
            ".tmp",
            verify=recorder.verify,
            discard=recorder.discard,
        )

    def test_creates_with_protected_sddl_then_verifies_before_handing_over(
        self, tmp_path: Path, fake_files: _FakeFileWin32
    ) -> None:
        """SID 取得 → 保護 SDDL 変換 → 作成 → 記述子解放 → 再検証 → fd 移譲 の順に行うことを確認する。"""
        recorder = _Recorder(fake_files.events)

        fd, temp_path = self._create(tmp_path, recorder)

        handle = _FakeFileWin32.HANDLE_BASE
        assert fake_files.events == [
            ("user_sid", None),
            ("sddl", f"D:P(A;;FA;;;{_FAKE_USER_SID})"),
            ("create", temp_path),
            ("free", _FakeFileWin32.DESCRIPTOR),
            ("verify", handle),
            ("open_osfhandle", handle),
        ]
        assert fd == fake_files.fds[0]
        assert re.fullmatch(r"\.master\.key\.[0-9a-f]{16}\.tmp", temp_path.name)
        assert temp_path.parent == tmp_path
        # 所有権は fd へ移っているため、ハンドルを閉じない（二重解放しない）。
        assert fake_files.closed_handles == []
        assert recorder.discarded == []
        os.write(fd, b"\x0a\x0d" * 16)
        assert temp_path.read_bytes() == b"\x0a\x0d" * 16

    def test_retries_only_on_name_collision_without_touching_existing_file(
        self,
        tmp_path: Path,
        fake_files: _FakeFileWin32,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """名前衝突時は別のランダム名で再試行し、衝突した既存ファイルを削除・変更しないことを確認する。"""
        names = iter(["aaaa", "aaaa", "bbbb"])
        monkeypatch.setattr(win.secrets, "token_hex", lambda size: next(names))
        existing = tmp_path / ".master.key.aaaa.tmp"
        existing.write_bytes(b"someone else")
        recorder = _Recorder(fake_files.events)

        _, temp_path = self._create(tmp_path, recorder)

        assert temp_path == tmp_path / ".master.key.bbbb.tmp"
        assert fake_files.attempted_paths == [existing, existing, temp_path]
        assert existing.read_bytes() == b"someone else"
        assert fake_files.freed_pointers == [_FakeFileWin32.DESCRIPTOR]

    def test_gives_up_after_max_attempts(
        self,
        tmp_path: Path,
        fake_files: _FakeFileWin32,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """再試行上限に達した場合は OSError で中断し、記述子を解放し既存ファイルを残すことを確認する。"""
        monkeypatch.setattr(win.secrets, "token_hex", lambda size: "aaaa")
        existing = tmp_path / ".master.key.aaaa.tmp"
        existing.write_bytes(b"someone else")
        recorder = _Recorder(fake_files.events)

        with pytest.raises(OSError):
            self._create(tmp_path, recorder)

        assert len(fake_files.attempted_paths) == win.MAX_CREATE_ATTEMPTS
        assert fake_files.freed_pointers == [_FakeFileWin32.DESCRIPTOR]
        assert recorder.verified == []
        assert list(tmp_path.iterdir()) == [existing]

    def test_other_create_failure_aborts_without_retry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """名前衝突以外の作成失敗は再試行せず中断し、記述子を解放することを確認する。"""
        fake = _FakeFileWin32(create_error=5)
        fake.install(monkeypatch)
        recorder = _Recorder(fake.events)

        with pytest.raises(OSError):
            self._create(tmp_path, recorder)

        assert len(fake.attempted_paths) == 1
        assert fake.freed_pointers == [_FakeFileWin32.DESCRIPTOR]
        assert fake.closed_handles == []
        assert list(tmp_path.iterdir()) == []

    def test_user_sid_failure_raises_protected_dacl_error_before_creating(
        self,
        tmp_path: Path,
        fake_files: _FakeFileWin32,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ユーザー SID を取得できない場合、何も作成せず詳細を含まない ProtectedDaclError となることを確認する。"""
        monkeypatch.setattr(win, "current_user_sid", _raise_os_error)

        with pytest.raises(win.ProtectedDaclError) as excinfo:
            self._create(tmp_path, _Recorder(fake_files.events))

        assert "SENTINEL" not in str(excinfo.value)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is True
        assert fake_files.attempted_paths == []
        assert fake_files.freed_pointers == []

    def test_sddl_conversion_failure_raises_before_creating(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """セキュリティ記述子を作成できない場合、何も作成・解放せず中断することを確認する。"""
        fake = _FakeFileWin32(convert_sddl=False)
        fake.install(monkeypatch)

        with pytest.raises(win.ProtectedDaclError):
            self._create(tmp_path, _Recorder(fake.events))

        assert fake.attempted_paths == []
        assert fake.freed_pointers == []
        assert list(tmp_path.iterdir()) == []

    def test_verify_failure_closes_handle_once_and_discards_file(
        self, tmp_path: Path, fake_files: _FakeFileWin32
    ) -> None:
        """DACL 再検証に失敗した場合、移譲前のハンドルを一度だけ閉じ、作成した一時ファイルを
        削除してから、検証の例外をそのまま伝播することを確認する。
        """
        recorder = _Recorder(fake_files.events)
        error = RuntimeError("verification rejected")
        recorder.verify_error = error

        with pytest.raises(RuntimeError) as excinfo:
            self._create(tmp_path, recorder)

        assert excinfo.value is error
        assert fake_files.closed_handles == [_FakeFileWin32.HANDLE_BASE]
        assert ("open_osfhandle", _FakeFileWin32.HANDLE_BASE) not in fake_files.events
        assert recorder.discarded == [fake_files.attempted_paths[0]]
        assert list(tmp_path.iterdir()) == []

    def test_open_osfhandle_failure_closes_handle_once_and_discards_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ハンドルの移譲に失敗した場合、ハンドルを一度だけ閉じて一時ファイルを削除することを確認する。"""
        fake = _FakeFileWin32(open_osfhandle_fails=True)
        fake.install(monkeypatch)
        recorder = _Recorder(fake.events)

        with pytest.raises(OSError):
            self._create(tmp_path, recorder)

        assert fake.closed_handles == [_FakeFileWin32.HANDLE_BASE]
        assert recorder.discarded == [fake.attempted_paths[0]]
        assert list(tmp_path.iterdir()) == []


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


@windows_only
class TestRealWindowsCreation:
    """実際の Win32 API による生成時保護 DACL の検証（Windows 専用）。"""

    @staticmethod
    def _grant_everyone_inheritable(directory: Path) -> None:
        """親ディレクトリへ Everyone の継承可能なフルアクセス ACE を追加する。"""
        subprocess.run(
            [
                _system32_tool("icacls.exe"),
                str(directory),
                "/grant",
                "*S-1-1-0:(OI)(F)",
            ],
            check=True,
            capture_output=True,
        )

    def test_temp_file_is_protected_from_creation_even_with_inheritable_parent_ace(
        self, tmp_path: Path
    ) -> None:
        """親に他アカウントの継承可能 ACE があっても、作成直後（書き込み前）の DACL が保護され、
        実行ユーザーのみを許可していることを、作成したハンドルで確認する。
        """
        vault = tmp_path / "vault"
        vault.mkdir()
        self._grant_everyone_inheritable(vault)
        control = vault / "control.txt"
        control.write_bytes(b"")
        # 対照: 通常作成したファイルは Everyone の ACE を継承する（前提の確認）。
        assert "(A;ID;FA;;;WD)" in _real_sddl_of(control)

        observed: list[list[str]] = []
        sizes: list[int] = []

        def _verify(handle: int) -> None:
            observed.append(win.protected_dacl_granting_sids(handle))
            (temp_file,) = vault.glob("*.tmp")
            sizes.append(temp_file.stat().st_size)

        fd, temp_path = win.create_protected_temp_file(
            vault,
            ".master.key.",
            ".tmp",
            verify=_verify,
            discard=lambda path: path.unlink(),
        )
        try:
            os.write(fd, bytes(range(32)))
        finally:
            os.close(fd)

        assert observed == [[_whoami_user_sid()]]
        assert sizes == [0]
        sddl = _real_sddl_of(temp_path)
        assert sddl == f"D:P(A;;FA;;;{_whoami_user_sid()})", sddl
        assert temp_path.read_bytes() == bytes(range(32))

    def test_real_verify_failure_closes_handle_and_removes_file(
        self, tmp_path: Path
    ) -> None:
        """実環境で検証が失敗した場合、ハンドルを閉じたうえで一時ファイルを削除できることを確認する。"""

        def _reject(handle: int) -> None:
            raise RuntimeError("rejected")

        with pytest.raises(RuntimeError):
            win.create_protected_temp_file(
                tmp_path,
                ".master.key.",
                ".tmp",
                verify=_reject,
                discard=lambda path: path.unlink(),
            )
        assert list(tmp_path.iterdir()) == []

    def test_unprotected_inherited_dacl_is_rejected(self, tmp_path: Path) -> None:
        """通常作成された（親から継承した、保護されていない）DACL は検証不能として拒否することを確認する。"""
        import msvcrt

        target = tmp_path / "inherited.key"
        target.write_bytes(b"")
        fd = os.open(target, os.O_RDONLY)
        try:
            with pytest.raises(OSError, match="not protected"):
                win.protected_dacl_granting_sids(msvcrt.get_osfhandle(fd))
        finally:
            os.close(fd)

    def test_extra_ace_in_protected_dacl_is_reported(self, tmp_path: Path) -> None:
        """保護 DACL に追加の許可 ACE がある場合、その SID も列挙されることを確認する。"""
        user_sid = win.current_user_sid()
        sddl = f"D:P(A;;FA;;;{user_sid})(A;;FR;;;S-1-5-32-546)"
        advapi32 = win._load_windows_library("advapi32")
        kernel32 = win._load_windows_library("kernel32")
        win._configure_file_apis(kernel32)
        descriptor = win._security_descriptor_from_sddl(advapi32, sddl)
        try:
            handle = win._create_new_file(kernel32, tmp_path / "x.tmp", descriptor)
        finally:
            kernel32.LocalFree(descriptor)
        assert handle is not None
        try:
            assert win.protected_dacl_granting_sids(handle) == [
                user_sid,
                "S-1-5-32-546",
            ]
        finally:
            kernel32.CloseHandle(handle)
