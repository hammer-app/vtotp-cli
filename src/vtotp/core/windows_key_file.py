"""Windows 専用の鍵一時ファイル生成と DACL 検証を担うモジュール。

DESIGN.md 6章「Windows の生成時 DACL と資源管理」「Windows DACL 許可リスト
再検証」に基づき、`CreateFileW` + SDDL によって生成時点から保護された DACL を
持つ一時ファイルを作成し、作成したハンドルの DACL を検査する。

本モジュールは Windows 上で鍵を保存する場合にのみ
:mod:`vtotp.core.key_manager` から遅延インポートされる。Win32 DLL の読み込み・
SID / SDDL / DACL の処理・`msvcrt` の利用はすべて本モジュール内に閉じ込め、
非 Windows 環境ではいずれも読み込み・評価しない。Win32 API の失敗は詳細を
含まない :class:`OSError` として送出し、エラーコードや鍵の内容を例外へ
含めない（Zero Leakage Rule）。
"""

from __future__ import annotations

import ctypes
import importlib
import os
import re
import secrets
from pathlib import Path
from typing import Any, Callable

#: `OpenProcessToken` の要求アクセス権（トークン情報の参照のみ）。
_TOKEN_QUERY: int = 0x0008

#: `GetTokenInformation` の情報クラス `TokenUser`。
_TOKEN_USER_CLASS: int = 1

#: `GetTokenInformation` の情報クラス `TokenGroups`。
_TOKEN_GROUPS_CLASS: int = 2

#: ログオンセッション SID を表すグループ属性 `SE_GROUP_LOGON_ID`。
_SE_GROUP_LOGON_ID: int = 0xC0000000

#: `GetSecurityInfo` の対象種別 `SE_FILE_OBJECT`。
_SE_FILE_OBJECT: int = 1

#: `GetSecurityInfo` で DACL を要求する `DACL_SECURITY_INFORMATION`。
_DACL_SECURITY_INFORMATION: int = 0x00000004

#: セキュリティ記述子の制御フラグ `SE_DACL_PROTECTED`（親からの継承を遮断）。
_SE_DACL_PROTECTED: int = 0x1000

#: `ConvertStringSecurityDescriptorToSecurityDescriptorW` の `SDDL_REVISION_1`。
_SDDL_REVISION_1: int = 1

#: `CreateFileW` の要求アクセス権。書き込み（`GENERIC_WRITE`）に加え、
#: `os.fstat` による属性参照と DACL の読み取り（`READ_CONTROL` を含む
#: `GENERIC_READ`）に必要な権限を要求する。
_GENERIC_READ: int = 0x80000000
_GENERIC_WRITE: int = 0x40000000

#: `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`。
_FILE_SHARE_ALL: int = 0x00000001 | 0x00000002 | 0x00000004

#: `CreateFileW` の作成方法 `CREATE_NEW`（既存ファイルがあれば失敗する）。
_CREATE_NEW: int = 1

#: `CreateFileW` のファイル属性 `FILE_ATTRIBUTE_NORMAL`。
_FILE_ATTRIBUTE_NORMAL: int = 0x00000080

#: `CREATE_NEW` が名前衝突で失敗したことを表すエラーコード
#: （`ERROR_FILE_EXISTS` / `ERROR_ALREADY_EXISTS`）。
_NAME_COLLISION_ERRORS: frozenset[int] = frozenset({80, 183})

#: 名前衝突時に別のランダム名で作成を試みる上限回数。
MAX_CREATE_ATTEMPTS: int = 16

#: 一時ファイル名のランダム部分のバイト数（16 進数で 2 倍の文字数になる）。
_RANDOM_NAME_BYTES: int = 8

#: `CreateFileW` が失敗時に返す `INVALID_HANDLE_VALUE`（ポインタ幅の -1）。
_INVALID_HANDLE_VALUE: int | None = ctypes.c_void_p(-1).value

#: SDDL へ埋め込む SID 文字列の形式（`S-1-<権限>-<副権限>...`）。
_SID_PATTERN: re.Pattern[str] = re.compile(r"S-1-\d+(?:-\d+)+")

#: SID を照合する許可 ACE 種別（通常形式の `ACCESS_ALLOWED_ACE` のみ。SID が
#: ヘッダーとアクセスマスクの直後に続く）。CALLBACK・OBJECT 形式など、これ以外の
#: 許可 ACE は DESIGN.md 6章に従い未解釈として拒否する（フェイルクローズ）。
_ACCESS_ALLOWED_ACE_TYPES: frozenset[int] = frozenset({0x00})

#: アクセスを拒否する ACE 種別（`ACCESS_DENIED_ACE` と、その OBJECT /
#: CALLBACK / CALLBACK_OBJECT 版）。許可を与えないため再検証の対象外とする。
_ACCESS_DENIED_ACE_TYPES: frozenset[int] = frozenset({0x01, 0x06, 0x0A, 0x0C})

#: `ACE_HEADER`（4バイト）と `ACCESS_MASK`（4バイト）に続く SID の開始位置。
_ACE_SID_OFFSET: int = 8


class ProtectedDaclError(OSError):
    """保護 DACL の構築に必要な情報（ユーザー SID・セキュリティ記述子）を
    用意できないことを表す例外。

    呼び出し元はこれを「権限設定の失敗」として扱う。Win32 のエラー詳細は
    含めない。
    """


class _AclHeader(ctypes.Structure):
    """Win32 の `ACL` 構造体（ACE 本体はこのヘッダーの後に続く）。"""

    _fields_ = [
        ("AclRevision", ctypes.c_uint8),
        ("Sbz1", ctypes.c_uint8),
        ("AclSize", ctypes.c_uint16),
        ("AceCount", ctypes.c_uint16),
        ("Sbz2", ctypes.c_uint16),
    ]


class _AceHeader(ctypes.Structure):
    """Win32 の `ACE_HEADER` 構造体。"""

    _fields_ = [
        ("AceType", ctypes.c_uint8),
        ("AceFlags", ctypes.c_uint8),
        ("AceSize", ctypes.c_uint16),
    ]


class _SidAndAttributes(ctypes.Structure):
    """Win32 の `SID_AND_ATTRIBUTES` 構造体。"""

    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_uint32)]


class _TokenGroups(ctypes.Structure):
    """Win32 の `TOKEN_GROUPS` 構造体（`Groups` は可変長配列の先頭要素）。"""

    _fields_ = [("GroupCount", ctypes.c_uint32), ("Groups", _SidAndAttributes * 1)]


class _SecurityAttributes(ctypes.Structure):
    """Win32 の `SECURITY_ATTRIBUTES` 構造体。"""

    _fields_ = [
        ("nLength", ctypes.c_uint32),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", ctypes.c_int),
    ]


def _load_windows_library(name: str) -> Any:
    """Win32 のDLLを読み込む（テストで偽のDLLへ差し替え可能にするための関数）。

    `ctypes.WinDLL` はWindowsでのみ提供されるため、存在しない環境では
    :class:`OSError` を送出する。
    """
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError(f"{name} is only available on Windows")
    return loader(name, use_last_error=True)


def _last_error() -> int:
    """直前の Win32 API 呼び出しのエラーコードを返す。

    `use_last_error=True` で読み込んだ DLL の呼び出し直後に参照する。
    `ctypes.get_last_error` は Windows でのみ提供されるため属性経由で参照する。
    """
    get_last_error: Callable[[], int] = getattr(ctypes, "get_last_error")
    return int(get_last_error())


def _configure_sid_conversion(advapi32: Any, kernel32: Any) -> None:
    """`ConvertSidToStringSidW` と `LocalFree` の引数・戻り値の型を設定する。"""
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p


def _sid_to_string(advapi32: Any, kernel32: Any, sid: int | None) -> str:
    """バイナリ SID を `S-1-...` 形式の文字列へ変換する。

    `ConvertSidToStringSidW` が確保した文字列領域は必ず解放する。変換に
    失敗した場合は :class:`OSError` を送出する。呼び出し前に
    :func:`_configure_sid_conversion` で型を設定しておくこと。
    """
    string_sid = ctypes.c_void_p()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(string_sid)):
        raise OSError("ConvertSidToStringSidW failed")
    try:
        return ctypes.wstring_at(string_sid)
    finally:
        kernel32.LocalFree(string_sid)


def _token_user_sid_pointers(buffer: ctypes.Array[ctypes.c_char]) -> list[int | None]:
    """`TOKEN_USER` からユーザー SID のポインタを取り出す。

    `TOKEN_USER` は `SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; }` で
    始まるため、先頭のポインタ値がユーザー SID を指す。
    """
    return [ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]]


def _token_logon_sid_pointers(buffer: ctypes.Array[ctypes.c_char]) -> list[int | None]:
    """`TOKEN_GROUPS` から `SE_GROUP_LOGON_ID` 属性を持つグループ SID のポインタを取り出す。

    グループが 0 件のトークンでは、バッファが `_TokenGroups` 構造体（配列要素
    1 件分を含む）より小さくなり得る。`from_buffer` はサイズ不足で
    :class:`ValueError` を送出するため、サイズ検査を伴わない `cast` で
    先頭の `GroupCount` だけを読み取る。
    """
    header = ctypes.cast(buffer, ctypes.POINTER(_TokenGroups)).contents
    groups = ctypes.cast(
        ctypes.addressof(buffer) + _TokenGroups.Groups.offset,
        ctypes.POINTER(_SidAndAttributes),
    )
    return [
        groups[index].Sid
        for index in range(header.GroupCount)
        if groups[index].Attributes & _SE_GROUP_LOGON_ID == _SE_GROUP_LOGON_ID
    ]


def _token_sids(
    info_class: int,
    select_sids: Callable[[ctypes.Array[ctypes.c_char]], list[int | None]],
) -> list[str]:
    """現在のプロセストークンの情報クラス `info_class` から SID を文字列で返す。

    `OpenProcessToken` と `GetTokenInformation` で取得したバッファから
    `select_sids` が選んだ SID を `ConvertSidToStringSidW` で文字列化する。
    トークンハンドルと文字列 SID の領域は必ず解放する。取得に失敗した場合は
    :class:`OSError` を送出する。
    """
    advapi32 = _load_windows_library("advapi32")
    kernel32 = _load_windows_library("kernel32")
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    _configure_sid_conversion(advapi32, kernel32)
    advapi32.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.OpenProcessToken.restype = ctypes.c_int
    advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    advapi32.GetTokenInformation.restype = ctypes.c_int

    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise OSError("OpenProcessToken failed")
    try:
        # 1回目の呼び出しで必要なバッファサイズを取得する
        # （この呼び出し自体はバッファ不足で失敗するのが正常）。
        required_size = ctypes.c_uint32(0)
        advapi32.GetTokenInformation(
            token, info_class, None, 0, ctypes.byref(required_size)
        )
        if required_size.value == 0:
            raise OSError("GetTokenInformation returned no size")
        information = ctypes.create_string_buffer(required_size.value)
        if not advapi32.GetTokenInformation(
            token,
            info_class,
            information,
            required_size.value,
            ctypes.byref(required_size),
        ):
            raise OSError("GetTokenInformation failed")

        return [
            _sid_to_string(advapi32, kernel32, sid) for sid in select_sids(information)
        ]
    finally:
        kernel32.CloseHandle(token)


def current_user_sid() -> str:
    """現在のプロセストークンからユーザー SID（`S-1-5-21-...` 形式）を返す。

    環境変数や `getpass.getuser()` には依存せず、`GetTokenInformation(TokenUser)`
    で取得した SID を使う。取得に失敗した場合は :class:`OSError` を送出する。
    """
    return _token_sids(_TOKEN_USER_CLASS, _token_user_sid_pointers)[0]


def current_logon_sids() -> frozenset[str]:
    """現在のプロセスに紐づくログオンセッション SID（`S-1-5-5-X-Y` 形式）を返す。

    `GetTokenInformation(TokenGroups)` のグループのうち、属性に
    `SE_GROUP_LOGON_ID` を持つものだけを抽出する。他のセッションの Logon SID は
    含まない。取得に失敗した場合は :class:`OSError` を送出する。
    """
    return frozenset(_token_sids(_TOKEN_GROUPS_CLASS, _token_logon_sid_pointers))


def protected_dacl_granting_sids(handle: int) -> list[str]:
    """開いたファイル `handle` の DACL から、アクセスを許可し得る ACE の SID を列挙する。

    パスの差し替えで別ファイルを検査しないよう、`GetSecurityInfo` に作成済みの
    ハンドルを渡して DACL を取得し、`GetAce` で走査する。拒否 ACE は許可を
    与えないため対象外とする。次の場合は検証不能として :class:`OSError` を
    送出する（フェイルクローズ）。

    - Win32 API（DACL 取得・制御フラグ取得・ACE 取得・SID 文字列化）の失敗
    - `SE_DACL_PROTECTED` を持たない（親からの継承を遮断していない）DACL
    - NULL DACL（全員にフルアクセスを与える状態）
    - SID の位置を解釈できない、許可・拒否以外の ACE 種別

    `GetSecurityInfo` が確保したセキュリティ記述子は必ず `LocalFree` で解放する。
    """
    advapi32 = _load_windows_library("advapi32")
    kernel32 = _load_windows_library("kernel32")
    advapi32.GetSecurityInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = ctypes.c_uint32
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    advapi32.GetSecurityDescriptorControl.restype = ctypes.c_int
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = ctypes.c_int
    _configure_sid_conversion(advapi32, kernel32)

    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = advapi32.GetSecurityInfo(
        handle,
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status != 0:
        raise OSError("GetSecurityInfo failed")
    try:
        control = ctypes.c_uint16(0)
        revision = ctypes.c_uint32(0)
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise OSError("GetSecurityDescriptorControl failed")
        if not control.value & _SE_DACL_PROTECTED:
            raise OSError("DACL is not protected from inheritance")
        if not dacl.value:
            raise OSError("NULL DACL grants access to everyone")
        ace_count = ctypes.cast(dacl, ctypes.POINTER(_AclHeader)).contents.AceCount
        sids: list[str] = []
        for index in range(ace_count):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)) or not ace.value:
                raise OSError("GetAce failed")
            ace_type = ctypes.cast(ace, ctypes.POINTER(_AceHeader)).contents.AceType
            if ace_type in _ACCESS_DENIED_ACE_TYPES:
                continue
            if ace_type not in _ACCESS_ALLOWED_ACE_TYPES:
                raise OSError("unsupported ACE type in DACL")
            sid_address = ace.value + _ACE_SID_OFFSET
            sids.append(_sid_to_string(advapi32, kernel32, sid_address))
        return sids
    finally:
        kernel32.LocalFree(descriptor)


def protected_sddl(user_sid: str) -> str:
    """`user_sid` だけにフルアクセスを与える保護 DACL の SDDL を返す。

    `D:P` は親からの DACL 継承を遮断し、`FA`（FILE_ALL_ACCESS）は削除権限を
    含むため、親の子削除権限に依存せず置換・世代繰り上げ・一時ファイル削除を
    行える。SID が `S-1-...` 形式でない場合は SDDL へ埋め込まず
    :class:`ProtectedDaclError` を送出する。
    """
    if not _SID_PATTERN.fullmatch(user_sid):
        raise ProtectedDaclError("unexpected SID format")
    return f"D:P(A;;FA;;;{user_sid})"


def _security_descriptor_from_sddl(advapi32: Any, sddl: str) -> ctypes.c_void_p:
    """SDDL から自己相対形式のセキュリティ記述子を作成する。

    返された記述子は呼び出し元が `LocalFree` で解放する。変換に失敗した場合は
    :class:`ProtectedDaclError` を送出する。
    """
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None
    ):
        raise ProtectedDaclError("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    return descriptor


def _configure_file_apis(kernel32: Any) -> None:
    """`CreateFileW` / `CloseHandle` / `LocalFree` の引数・戻り値の型を設定する。"""
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(_SecurityAttributes),
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p


def _create_new_file(
    kernel32: Any, path: Path, descriptor: ctypes.c_void_p
) -> int | None:
    """`descriptor` を適用した新規ファイルを `CreateFileW(CREATE_NEW)` で作成する。

    作成と保護 DACL の付与を同一操作で行う。成功時は書き込み・DACL 読み取りが
    可能なハンドルを返し、名前衝突時は ``None`` を返す（既存ファイルには
    触れない）。それ以外の失敗は :class:`OSError` を送出する。呼び出し前に
    :func:`_configure_file_apis` で型を設定しておくこと。
    """
    attributes = _SecurityAttributes(
        nLength=ctypes.sizeof(_SecurityAttributes),
        lpSecurityDescriptor=descriptor.value,
        bInheritHandle=0,
    )
    handle: int | None = kernel32.CreateFileW(
        str(path),
        _GENERIC_READ | _GENERIC_WRITE,
        _FILE_SHARE_ALL,
        ctypes.byref(attributes),
        _CREATE_NEW,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle is not None and handle != _INVALID_HANDLE_VALUE:
        return handle
    if _last_error() in _NAME_COLLISION_ERRORS:
        return None
    raise OSError("CreateFileW failed")


def _open_osfhandle(handle: int) -> int:
    """Win32 ファイルハンドルの所有権を C ランタイムのファイルディスクリプタへ移す。

    成功後はハンドルを `CloseHandle` で閉じてはならず、返されたファイル
    ディスクリプタを閉じることでハンドルも閉じられる。失敗した場合、ハンドルの
    所有権は呼び出し元に残る。
    """
    msvcrt: Any = importlib.import_module("msvcrt")
    flags = os.O_WRONLY | getattr(os, "O_BINARY", 0)
    return int(msvcrt.open_osfhandle(handle, flags))


def create_protected_temp_file(
    directory: Path,
    prefix: str,
    suffix: str,
    *,
    verify: Callable[[int], None],
    discard: Callable[[Path], None],
) -> tuple[int, Path]:
    """保護 DACL 付きの空の一時ファイルを `directory` に排他的に作成する。

    DESIGN.md 6章「Windows の生成時 DACL と資源管理」の手順に従う。

    1. プロセストークンからユーザー SID を取得し、保護 SDDL
       （`D:P(A;;FA;;;<SID>)`）からセキュリティ記述子を作成する。
    2. 予測困難な名前に対し `CreateFileW(CREATE_NEW)` で記述子を渡して作成する。
       名前衝突時のみ別のランダム名で :data:`MAX_CREATE_ATTEMPTS` 回まで
       再試行する。記述子は `CreateFileW` が戻った後に解放する。
    3. 鍵の書き込み前に、作成したハンドルを `verify` へ渡して DACL を再検証する。
    4. ハンドルを `msvcrt.open_osfhandle` でファイルディスクリプタへ移譲し、
       ``(ファイルディスクリプタ, パス)`` を返す。以後の所有者は呼び出し元である。

    ユーザー SID の取得・記述子の作成に失敗した場合は
    :class:`ProtectedDaclError`、作成・移譲の失敗や再試行上限到達時は
    :class:`OSError` を送出し、`verify` が送出した例外はそのまま伝播させる。
    いずれの失敗でも、自身が開いたハンドルを一度だけ閉じてから、自身が作成した
    ファイルを `discard` で削除する。
    """
    advapi32 = _load_windows_library("advapi32")
    kernel32 = _load_windows_library("kernel32")
    _configure_file_apis(kernel32)
    try:
        sddl = protected_sddl(current_user_sid())
    except OSError:
        raise ProtectedDaclError("user SID is unavailable") from None
    descriptor = _security_descriptor_from_sddl(advapi32, sddl)

    created: tuple[int, Path] | None = None
    try:
        for _ in range(MAX_CREATE_ATTEMPTS):
            random_part = secrets.token_hex(_RANDOM_NAME_BYTES)
            candidate = directory / f"{prefix}{random_part}{suffix}"
            handle = _create_new_file(kernel32, candidate, descriptor)
            if handle is not None:
                created = (handle, candidate)
                break
    finally:
        kernel32.LocalFree(descriptor)
    if created is None:
        raise OSError("could not find an unused temporary file name")

    handle, temp_path = created
    try:
        try:
            verify(handle)
            fd = _open_osfhandle(handle)
        except BaseException:
            # open_osfhandle が成功する前はハンドルの所有者は本関数である。
            kernel32.CloseHandle(handle)
            raise
    except BaseException:
        discard(temp_path)
        raise
    return fd, temp_path
