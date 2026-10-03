"""鍵ファイル（AES-256用マスターキー）の管理を担う KeyManager を定義するモジュール。

DESIGN.md 6章「KeyManager」に基づき、鍵の生成・読み込み・検証・存在確認、
CLI/環境変数/config.jsonからのパス解決、および世代管理（ローテーション）を
提供する。鍵の内容はいかなる場合もログや例外メッセージへ出力しない
（Zero Leakage Rule）。
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from vtotp.domain.exceptions import (
    InvalidKeyError,
    KeyNotFoundError,
    KeyStorageError,
)
from vtotp.i18n.catalog import MsgKey


def _is_windows() -> bool:
    """実行環境がWindowsかどうかを返す（テストで差し替え可能にするための関数）。"""
    return os.name == "nt"


#: `OpenProcessToken` の要求アクセス権（トークン情報の参照のみ）。
_TOKEN_QUERY: int = 0x0008

#: `GetTokenInformation` の情報クラス `TokenUser`。
_TOKEN_USER_CLASS: int = 1

#: `GetTokenInformation` の情報クラス `TokenGroups`。
_TOKEN_GROUPS_CLASS: int = 2

#: ログオンセッション SID を表すグループ属性 `SE_GROUP_LOGON_ID`。
_SE_GROUP_LOGON_ID: int = 0xC0000000

#: `GetSystemDirectoryW` に渡すバッファの文字数（拡張パス長の上限）。
_SYSTEM_DIRECTORY_BUFFER_CHARS: int = 32768

#: `GetNamedSecurityInfoW` の対象種別 `SE_FILE_OBJECT`。
_SE_FILE_OBJECT: int = 1

#: `GetNamedSecurityInfoW` で DACL を要求する `DACL_SECURITY_INFORMATION`。
_DACL_SECURITY_INFORMATION: int = 0x00000004

#: アクセスを許可する ACE 種別のうち、SID がヘッダーとアクセスマスクの直後に
#: 続く形式（`ACCESS_ALLOWED_ACE` / `ACCESS_ALLOWED_CALLBACK_ACE`）。
_ACCESS_ALLOWED_ACE_TYPES: frozenset[int] = frozenset({0x00, 0x09})

#: アクセスを拒否する ACE 種別（`ACCESS_DENIED_ACE` と、その OBJECT /
#: CALLBACK / CALLBACK_OBJECT 版）。許可を与えないため再検証の対象外とする。
_ACCESS_DENIED_ACE_TYPES: frozenset[int] = frozenset({0x01, 0x06, 0x0A, 0x0C})

#: `ACE_HEADER`（4バイト）と `ACCESS_MASK`（4バイト）に続く SID の開始位置。
_ACE_SID_OFFSET: int = 8


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


def _load_windows_library(name: str) -> Any:
    """Win32 のDLLを読み込む（テストで偽のDLLへ差し替え可能にするための関数）。

    `ctypes.WinDLL` はWindowsでのみ提供されるため、存在しない環境では
    :class:`OSError` を送出する。
    """
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError(f"{name} is only available on Windows")
    return loader(name, use_last_error=True)


def _windows_system_directory() -> str:
    """`GetSystemDirectoryW` で実際の System32 ディレクトリの絶対パスを返す。

    `SystemRoot` 等の環境変数には依存しない。取得に失敗した場合は
    :class:`OSError` を送出する。
    """
    kernel32 = _load_windows_library("kernel32")
    kernel32.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    kernel32.GetSystemDirectoryW.restype = ctypes.c_uint32

    buffer = ctypes.create_unicode_buffer(_SYSTEM_DIRECTORY_BUFFER_CHARS)
    length = kernel32.GetSystemDirectoryW(buffer, _SYSTEM_DIRECTORY_BUFFER_CHARS)
    if not 0 < length < _SYSTEM_DIRECTORY_BUFFER_CHARS:
        raise OSError("GetSystemDirectoryW failed")
    return buffer.value


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
    """`TOKEN_GROUPS` から `SE_GROUP_LOGON_ID` 属性を持つグループ SID のポインタを取り出す。"""
    header = _TokenGroups.from_buffer(buffer)
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


def _current_user_sid() -> str:
    """現在のプロセストークンからユーザー SID（`S-1-5-21-...` 形式）を返す。

    環境変数や `getpass.getuser()` には依存せず、`GetTokenInformation(TokenUser)`
    で取得した SID を使う。取得に失敗した場合は :class:`OSError` を送出する。
    """
    return _token_sids(_TOKEN_USER_CLASS, _token_user_sid_pointers)[0]


def _current_logon_sids() -> frozenset[str]:
    """現在のプロセスに紐づくログオンセッション SID（`S-1-5-5-X-Y` 形式）を返す。

    `GetTokenInformation(TokenGroups)` のグループのうち、属性に
    `SE_GROUP_LOGON_ID` を持つものだけを抽出する。他のセッションの Logon SID は
    含まない。取得に失敗した場合は :class:`OSError` を送出する。
    """
    return frozenset(_token_sids(_TOKEN_GROUPS_CLASS, _token_logon_sid_pointers))


def _granting_ace_sids(path: Path) -> list[str]:
    """`path` の DACL から、アクセスを許可し得る ACE の SID を文字列で列挙する。

    `GetNamedSecurityInfoW(DACL_SECURITY_INFORMATION)` で DACL を取得し、
    `GetAce` で走査する。拒否 ACE は許可を与えないため対象外とする。
    次の場合は検証不能として :class:`OSError` を送出する（フェイルクローズ）。

    - Win32 API（DACL 取得・ACE 取得・SID 文字列化）の失敗
    - NULL DACL（全員にフルアクセスを与える状態）
    - SID の位置を解釈できない、許可・拒否以外の ACE 種別

    `GetNamedSecurityInfoW` が確保したセキュリティ記述子は必ず解放する。
    """
    advapi32 = _load_windows_library("advapi32")
    kernel32 = _load_windows_library("kernel32")
    advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = ctypes.c_int
    _configure_sid_conversion(advapi32, kernel32)

    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status != 0:
        raise OSError("GetNamedSecurityInfoW failed")
    try:
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


class KeyManager:
    """AES-256用マスターキーファイルの生成・検証・解決・世代管理を行うクラス。

    鍵ファイルは常に `config.json` とは分離された外部パスに保持され、
    このクラス自身は鍵の内容をインスタンス変数として保持しない。
    """

    #: マスターキーの必須サイズ（AES-256のため32バイト）。
    KEY_SIZE_BYTES: int = 32

    #: 保持する鍵ファイルの世代数の上限（`<key_path>.1` 〜 `<key_path>.3`）。
    MAX_ROTATED_KEYS: int = 3

    #: Unix系OSで鍵ファイルへ設定するパーミッション（所有者のみ読み書き可）。
    UNIX_PRIVATE_MODE: int = 0o600

    #: Windowsで実行ユーザーへ付与するACL権限。読み書きに加え、自身の削除（D）を
    #: 含める。親ディレクトリが「変更」権限のみ（FILE_DELETE_CHILDなし）の場合、
    #: Dが無いと `os.replace` による配置・世代繰り上げ・一時ファイル削除が失敗する。
    WINDOWS_PRIVATE_GRANT: str = "(R,W,D)"

    #: DACL 再検証で、実行ユーザーと現在の Logon SID 以外に許可 ACE の残存を
    #: 認める既知の SID（`SYSTEM` / `Administrators` / `OWNER RIGHTS`。
    #: REQUIREMENTS.md 4.1 の注記）。
    WINDOWS_ALLOWED_WELL_KNOWN_SIDS: frozenset[str] = frozenset(
        {"S-1-5-18", "S-1-5-32-544", "S-1-3-4"}
    )

    def generate_key(self) -> bytes:
        """暗号学的に安全な32バイト鍵を生成する。"""
        return secrets.token_bytes(self.KEY_SIZE_BYTES)

    def create_key_file(self, path: Path, key: bytes | None = None) -> None:
        """鍵を生成または受け取り、安全に一時保存して指定パスへ配置する。

        `key` が指定されない場合は新規に生成する。保存は
        :meth:`_store_key` の共通フロー（実行ユーザー専用権限の一時ファイル
        経由のatomic置換）で行う。
        """
        actual_key = key if key is not None else self.generate_key()
        self._ensure_valid_key_size(path, actual_key)
        self._store_key(path, actual_key)

    def rotate_key_file(self, path: Path, new_key: bytes) -> Path:
        """既存鍵を世代番号付きファイルへ繰り上げ、新鍵を `path` へ保存する。

        新鍵を実行ユーザー専用権限の一時ファイルへ書き込み終えてから、
        既存の最古世代 `<key_path>.3` を `<key_path>.3.<hex>.old` へ退避し、
        `<key_path>.2` -> `<key_path>.3`、`<key_path>.1` -> `<key_path>.2`、
        `path` -> `<key_path>.1` の順に繰り上げ、一時ファイルを `path` へ
        配置する。退避・繰り上げ・配置に失敗した場合は、実施済みの移動を
        逆順に元に戻す（退避した `.3` も復元する）。退避ファイルは配置の成功後
        にのみ削除する。上限到達時（`<key_path>.3` が既に存在する場合）の
        削除可否の確認は、呼び出し元（CliHandler）が事前に対話確認を
        済ませていることを前提とする。
        """
        self._ensure_valid_key_size(path, new_key)
        self._store_key(path, new_key, rotate=True)
        return path

    def rotated_key_paths(self, path: Path, max_generations: int = 3) -> list[Path]:
        """`path.1` から `path.N` までのローテーション対象パスを返す。"""
        return [
            Path(f"{path}.{generation}") for generation in range(1, max_generations + 1)
        ]

    def check_existing_key(self, path: Path) -> bool:
        """指定パスに既存の鍵ファイルがあるか確認する。"""
        return path.is_file()

    def verify_key_file(self, path: Path) -> None:
        """外部指定された既存の鍵ファイルを検証する。

        通常の読み込み処理（generate/get/add等）で、指定された鍵パスに
        既存の鍵ファイルがあること、および形式が正しいことを保証するために
        呼び出す。FAT32/exFAT等の外部メディア運用を妨げないよう、
        パーミッション・ACLの検査は行わない。
        """
        self.validate_key_file(path)

    def load_key(self, path: Path) -> bytes:
        """鍵を読み込み、32バイトであることを検証する。

        パーミッション・ACLの検査は行わない（:meth:`verify_key_file` と同様）。
        """
        self.validate_key_file(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise InvalidKeyError(
                MsgKey.KEY_UNREADABLE, context={"path": str(path)}
            ) from exc

        if len(data) != self.KEY_SIZE_BYTES:
            raise InvalidKeyError(MsgKey.KEY_INVALID_SIZE, context={"path": str(path)})
        return data

    def resolve_key_path(
        self,
        cli_path: Path | None,
        config_path: Path | None,
        environment_path: Path | None,
    ) -> Path:
        """優先順位に従い、実際に使用する鍵ファイルパスを解決する。

        優先順位:
            1. CLIオプション `--key`
            2. 環境変数 `VTOTP_KEY_PATH`
            3. `config.json` の `key_path`
            4. いずれも未指定の場合はエラー
        """
        if cli_path is not None:
            return cli_path
        if environment_path is not None:
            return environment_path
        if config_path is not None:
            return config_path
        raise KeyNotFoundError(MsgKey.KEY_PATH_NOT_CONFIGURED)

    def validate_key_file(self, path: Path) -> None:
        """存在、通常ファイル、サイズ、読み取り可否を検証する。"""
        if not path.exists():
            raise KeyNotFoundError(MsgKey.KEY_NOT_FOUND, context={"path": str(path)})
        if not path.is_file():
            raise InvalidKeyError(MsgKey.KEY_NOT_A_FILE, context={"path": str(path)})
        if path.stat().st_size != self.KEY_SIZE_BYTES:
            raise InvalidKeyError(MsgKey.KEY_INVALID_SIZE, context={"path": str(path)})
        if not os.access(path, os.R_OK):
            raise InvalidKeyError(
                MsgKey.KEY_PERMISSION_DENIED, context={"path": str(path)}
            )

    def set_private_permissions(self, path: Path) -> None:
        """鍵ファイルを実行ユーザーだけが読み書きできる状態にする。

        Unix系では `os.chmod(path, 0o600)` を実行する。Windowsでは標準コマンド
        `icacls` を引数配列（`shell=False`）で呼び出し、親フォルダからの継承を
        遮断したうえで、プロセストークンから取得した実行ユーザーの SID
        （`*S-1-...` 形式）のみに権限を付与する。Win32 APIの失敗を含め、いずれの失敗も
        握りつぶさず :class:`KeyStorageError` として送出する。OSのエラー詳細や
        コマンド出力は例外の表示内容に含めない（Zero Leakage Rule）。
        """
        context = {"path": str(path)}
        if not _is_windows():
            try:
                os.chmod(path, self.UNIX_PRIVATE_MODE)
            except OSError as exc:
                raise KeyStorageError(
                    MsgKey.KEY_PERMISSION_SETUP_FAILED, context=context
                ) from exc
            return

        try:
            command = [
                self._icacls_executable(),
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{_current_user_sid()}:{self.WINDOWS_PRIVATE_GRANT}",
            ]
            subprocess.run(command, check=True, capture_output=True)
        except (OSError, subprocess.SubprocessError):
            # Win32 APIの失敗詳細やコマンド出力を例外チェーンにも残さないよう、
            # 原因は連結しない。
            raise KeyStorageError(
                MsgKey.KEY_PERMISSION_SETUP_FAILED, context=context
            ) from None

    def verify_windows_dacl(self, path: Path) -> None:
        """Windowsで `path` の DACL を許可リストと照合する（DESIGN.md 6章）。

        アクセスを許可する ACE の SID が、実行ユーザー（プロセストークンの
        `TokenUser`）、現在のプロセスに紐づく Logon SID（`TokenGroups` のうち
        `SE_GROUP_LOGON_ID` 属性を持つもの）、
        :attr:`WINDOWS_ALLOWED_WELL_KNOWN_SIDS` のいずれとも完全一致しない
        場合は :class:`KeyStorageError` を送出する（他セッションの Logon SID は
        拒否する）。拒否 ACE は検証対象外とする。DACL やトークン情報を取得
        できない場合（Win32 API の失敗等）も同じく中断する。Win32 API の失敗
        詳細は例外チェーンにも残さない（Zero Leakage Rule）。
        """
        context = {"path": str(path)}
        try:
            allowed_sids = {
                _current_user_sid(),
                *_current_logon_sids(),
                *self.WINDOWS_ALLOWED_WELL_KNOWN_SIDS,
            }
            granted_sids = _granting_ace_sids(path)
        except OSError:
            raise KeyStorageError(
                MsgKey.KEY_PERMISSION_SETUP_FAILED, context=context
            ) from None

        if any(sid not in allowed_sids for sid in granted_sids):
            raise KeyStorageError(MsgKey.KEY_PERMISSION_SETUP_FAILED, context=context)

    def _ensure_valid_key_size(self, path: Path, key: bytes) -> None:
        """保存しようとする鍵が32バイトであることを、ファイル操作の前に検証する。"""
        if len(key) != self.KEY_SIZE_BYTES:
            raise InvalidKeyError(MsgKey.KEY_INVALID_SIZE, context={"path": str(path)})

    def _store_key(self, path: Path, key: bytes, *, rotate: bool = False) -> None:
        """鍵を実行ユーザー専用の一時ファイル経由で `path` へatomicに配置する。

        DESIGN.md 6章「鍵ファイル保存とパーミッション制御」の共通フロー:

        1. 親ディレクトリを作成または検証する。
        2. 予測困難な名前の一時ファイルを同一ディレクトリに排他的に作成する。
        3. 鍵を書き込む前に、一時ファイルへ実行ユーザー専用の権限を設定する。
        4. Windowsでは、権限設定の完了後に DACL を許可リストと再検証する。
        5. 鍵を書き込み、flushおよびfsyncを実行する。
        6. 32バイトであることを検証し、`os.replace` で原子的に配置する
           （`rotate=True` の場合は配置直前に既存鍵を世代繰り上げする）。
        7. 成功・失敗を問わず、残存した一時ファイルを削除する。

        いずれかの段階で失敗した場合は :class:`KeyStorageError` を送出する。
        """
        context = {"path": str(path)}
        temp_path: Path | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(
                dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
            )
            temp_path = Path(temp_name)
            with os.fdopen(fd, "wb") as temp_file:
                try:
                    self.set_private_permissions(temp_path)
                    if _is_windows():
                        self.verify_windows_dacl(temp_path)
                except KeyStorageError:
                    # 利用者には一時ファイル名ではなく保存先パスを示す。
                    raise KeyStorageError(
                        MsgKey.KEY_PERMISSION_SETUP_FAILED, context=context
                    ) from None
                temp_file.write(key)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                written_size = os.fstat(temp_file.fileno()).st_size

            if written_size != self.KEY_SIZE_BYTES:
                raise KeyStorageError(MsgKey.KEY_STORAGE_FAILED, context=context)

            self._place_key_file(temp_path, path, rotate=rotate)
        except OSError as exc:
            raise KeyStorageError(MsgKey.KEY_STORAGE_FAILED, context=context) from exc
        finally:
            if temp_path is not None:
                self._discard_temp_file(temp_path)

    def _place_key_file(self, temp_path: Path, path: Path, *, rotate: bool) -> None:
        """一時ファイルを正式パスへ配置する（必要に応じて世代繰り上げを伴う）。

        世代繰り上げでは、既存の最古世代を同一ディレクトリの退避ファイル
        （`<key_path>.3.<hex>.old`）へ移してから繰り上げる。退避・繰り上げ
        または配置が失敗した場合は、実施済みの移動を逆順に戻してから元の
        例外を再送出する。退避ファイルは配置が成功した場合にのみ削除する。
        """
        completed_moves: list[tuple[Path, Path]] = []
        parked_oldest: Path | None = None
        try:
            if rotate:
                chain = [path, *self.rotated_key_paths(path, self.MAX_ROTATED_KEYS)]
                oldest = chain[-1]
                if oldest.exists():
                    parked_oldest = Path(f"{oldest}.{secrets.token_hex(8)}.old")
                    os.replace(oldest, parked_oldest)
                    completed_moves.append((oldest, parked_oldest))
                for index in range(len(chain) - 1, 0, -1):
                    source, destination = chain[index - 1], chain[index]
                    if source.exists():
                        os.replace(source, destination)
                        completed_moves.append((source, destination))
            os.replace(temp_path, path)
        except OSError:
            for source, destination in reversed(completed_moves):
                # 復旧は最善努力で行い、元の失敗原因を優先して送出する。
                with contextlib.suppress(OSError):
                    os.replace(destination, source)
            raise

        if parked_oldest is not None:
            # 新鍵の配置が成功した後にのみ、退避した最古世代を破棄する。
            self._discard_temp_file(parked_oldest)

    @staticmethod
    def _discard_temp_file(temp_path: Path) -> None:
        """残存した一時ファイル（最古世代の退避ファイルを含む）を削除する。

        削除自体の失敗で元の例外（または成功結果）を上書きしないよう、
        ここでの `OSError` のみ抑止する。いずれのファイルも鍵の書き込み前に
        実行ユーザー専用の権限が設定済みである。
        """
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)

    @staticmethod
    def _icacls_executable() -> str:
        """Windows標準の `icacls.exe` の絶対パスを返す。

        `shell=False` でもコマンド名のみを渡すと、Windowsのプロセス生成は
        カレントディレクトリを `System32` より先に探索する。同名の不正な
        実行ファイルを誤って起動しないよう、`GetSystemDirectoryW` で取得した
        システムディレクトリを明示する（環境変数には依存しない）。
        """
        return str(Path(_windows_system_directory()) / "icacls.exe")
