"""鍵ファイル（AES-256用マスターキー）の管理を担う KeyManager を定義するモジュール。

DESIGN.md 6章「KeyManager」に基づき、鍵の生成・読み込み・検証・存在確認、
CLI/環境変数/config.jsonからのパス解決、および世代管理（ローテーション）を
提供する。鍵の内容はいかなる場合もログや例外メッセージへ出力しない
（Zero Leakage Rule）。

鍵の一時ファイル生成は OS ごとに分離する。Windows 固有の処理（Win32 API・
SID・DACL・`msvcrt`）は :mod:`vtotp.core.windows_key_file` に閉じ込め、
Windows 上で鍵を保存・検証する場合にのみ遅延インポートする。
"""

from __future__ import annotations

import contextlib
import io
import os
import secrets
import tempfile
from pathlib import Path
from typing import BinaryIO, Callable

from vtotp.domain.exceptions import (
    InvalidKeyError,
    KeyNotFoundError,
    KeyStorageError,
)
from vtotp.i18n.catalog import MsgKey


def _is_windows() -> bool:
    """実行環境がWindowsかどうかを返す（テストで差し替え可能にするための関数）。"""
    return os.name == "nt"


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

    #: DACL 再検証で、実行ユーザーと現在の Logon SID 以外に許可 ACE の残存を
    #: 認める既知の SID（`SYSTEM` / `Administrators` / `OWNER RIGHTS`。
    #: REQUIREMENTS.md 4.1 の注記）。
    WINDOWS_ALLOWED_WELL_KNOWN_SIDS: frozenset[str] = frozenset(
        {"S-1-5-18", "S-1-5-32-544", "S-1-3-4"}
    )

    def __init__(
        self, on_cleanup_failure: Callable[[Path], None] | None = None
    ) -> None:
        """鍵ファイル管理を初期化する。

        `on_cleanup_failure` は、自身が作成した一時ファイル（最古世代の退避
        ファイルを含む）を削除できず残存した場合に、そのパスを受け取って利用者へ
        通知するコールバックである。OS のエラー詳細や鍵の内容は渡さない。
        省略時は通知しない。
        """
        self._on_cleanup_failure = on_cleanup_failure

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
        """Unix系の一時鍵ファイルを所有者だけが読み書きできる状態（0600）にする。

        `os.chmod(path, 0o600)` を実行する。Windows の鍵保存では呼び出さない
        （生成時点で保護 DACL を付与する :mod:`vtotp.core.windows_key_file`
        を使う）。失敗は握りつぶさず :class:`KeyStorageError` として送出し、
        OS のエラー詳細は例外チェーンにも残さない（Zero Leakage Rule）。
        """
        try:
            os.chmod(path, self.UNIX_PRIVATE_MODE)
        except OSError:
            raise KeyStorageError(
                MsgKey.KEY_PERMISSION_SETUP_FAILED, context={"path": str(path)}
            ) from None

    def verify_windows_dacl(self, handle: int, path: Path) -> None:
        """Windowsで作成済みハンドル `handle` の DACL を許可リストと照合する。

        DESIGN.md 6章「Windows DACL 許可リスト再検証」に基づき、パスではなく
        開いたハンドルの DACL を検査する。`path` は利用者向けエラー表示にのみ
        使う。次のいずれかに該当する場合は :class:`KeyStorageError` を送出する。

        - DACL が `SE_DACL_PROTECTED` を持たない、または NULL DACL である
        - SID の位置を解釈できない許可 ACE 種別を含む
        - 許可 ACE の SID が、実行ユーザー（プロセストークンの `TokenUser`）、
          現在のプロセスに紐づく Logon SID（`TokenGroups` のうち
          `SE_GROUP_LOGON_ID` 属性を持つもの）、
          :attr:`WINDOWS_ALLOWED_WELL_KNOWN_SIDS` のいずれとも完全一致しない
          （他セッションの Logon SID は拒否する）
        - DACL やトークン情報を取得できない（Win32 API の失敗等）

        拒否 ACE は検証対象外とする。Win32 API の失敗詳細は例外チェーンにも
        残さない（Zero Leakage Rule）。
        """
        from vtotp.core import windows_key_file

        context = {"path": str(path)}
        try:
            allowed_sids = {
                windows_key_file.current_user_sid(),
                *windows_key_file.current_logon_sids(),
                *self.WINDOWS_ALLOWED_WELL_KNOWN_SIDS,
            }
            granted_sids = windows_key_file.protected_dacl_granting_sids(handle)
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
        2. OS 固有処理（:meth:`_create_private_temp_file`）で、実行ユーザー
           専用の権限と必要な検証を済ませた空の一時ファイルを同一ディレクトリに
           排他的に作成する。
        3. 鍵を書き込み、flushおよびfsyncを実行し、ファイルを閉じる。
        4. 32バイトであることを検証し、`os.replace` で原子的に配置する
           （`rotate=True` の場合は配置直前に既存鍵を世代繰り上げする）。
        5. 成功・失敗を問わず、自身が作成した一時ファイルが残っていれば削除する。

        本処理は Win32 ハンドルや SID を扱わない。いずれかの段階で失敗した
        場合は、保存先パスを示す :class:`KeyStorageError` を送出する。OS / Win32
        のエラー詳細は例外チェーンにも残さない（Zero Leakage Rule）。
        """
        context = {"path": str(path)}
        temp_path: Path | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_path = self._create_private_temp_file(path)
            with self._open_writer(fd) as temp_file:
                temp_file.write(key)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                written_size = os.fstat(temp_file.fileno()).st_size

            if written_size != self.KEY_SIZE_BYTES:
                raise KeyStorageError(MsgKey.KEY_STORAGE_FAILED, context=context)

            self._place_key_file(temp_path, path, rotate=rotate)
        except KeyStorageError as error:
            # 利用者には一時ファイル名ではなく保存先パスを示す。
            raise KeyStorageError(error.message_key, context=context) from None
        except OSError:
            raise KeyStorageError(MsgKey.KEY_STORAGE_FAILED, context=context) from None
        finally:
            if temp_path is not None:
                self._discard_temp_file(temp_path)

    def _create_private_temp_file(self, path: Path) -> tuple[int, Path]:
        """`path` と同じディレクトリに実行ユーザー専用の空の一時ファイルを作成する。

        OS を判定し、対応する生成処理だけを呼び出す。書き込み用のファイル
        ディスクリプタ（所有権は呼び出し元へ移る）と一時ファイルのパスを返す。
        失敗時は生成処理が自身の資源を解放し、作成済みの一時ファイルを削除する。

        - Unix系: :meth:`_create_unix_temp_file`（`mkstemp` + `chmod 0600`）
        - Windows: :func:`vtotp.core.windows_key_file.create_protected_temp_file`
          （`CreateFileW` + 保護 SDDL と、書き込み前の
          :meth:`verify_windows_dacl`）。Windows 固有モジュールはこの分岐内で
          のみ読み込む。
        """
        directory, prefix, suffix = path.parent, f".{path.name}.", ".tmp"
        if not _is_windows():
            return self._create_unix_temp_file(directory, prefix, suffix)

        from vtotp.core import windows_key_file

        try:
            return windows_key_file.create_protected_temp_file(
                directory,
                prefix,
                suffix,
                verify=lambda handle: self.verify_windows_dacl(handle, path),
                discard=self._discard_temp_file,
            )
        except windows_key_file.ProtectedDaclError:
            raise KeyStorageError(
                MsgKey.KEY_PERMISSION_SETUP_FAILED, context={"path": str(path)}
            ) from None

    def _create_unix_temp_file(
        self, directory: Path, prefix: str, suffix: str
    ) -> tuple[int, Path]:
        """`mkstemp` で一時ファイルを排他的に作成し、鍵の書き込み前に 0600 にする。

        権限設定に失敗した場合は、ファイルディスクリプタを閉じて一時ファイルを
        削除してから例外を再送出する。
        """
        fd, temp_name = tempfile.mkstemp(dir=directory, prefix=prefix, suffix=suffix)
        temp_path = Path(temp_name)
        try:
            self.set_private_permissions(temp_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(fd)
            self._discard_temp_file(temp_path)
            raise
        return fd, temp_path

    @staticmethod
    def _open_writer(fd: int) -> BinaryIO:
        """ファイルディスクリプタ `fd` の所有権を受け取り、バイナリ書き込み用に開く。

        `os.fdopen` 相当の処理を二段階で行い、各段階の所有者を一つに限定する。
        `FileIO` の生成に失敗した場合は `fd` を閉じ、生成後は `FileIO` が `fd` を
        所有するため、バッファの生成に失敗した場合は `FileIO` を閉じる
        （二重解放やディスクリプタ漏れを起こさない）。
        """
        try:
            raw = io.FileIO(fd, "wb")
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
        try:
            return io.BufferedWriter(raw)
        except BaseException:
            raw.close()
            raise

    def _place_key_file(self, temp_path: Path, path: Path, *, rotate: bool) -> None:
        """一時ファイルを正式パスへ配置する（必要に応じて世代繰り上げを伴う）。

        世代繰り上げでは、既存の最古世代を同一ディレクトリの退避ファイル
        （`<key_path>.3.<hex>.old`）へ移してから繰り上げる。退避・繰り上げ
        または配置が失敗した場合は、実施済みの移動を逆順に戻してから元の
        例外を再送出する。逆移動が1つでも失敗した場合は、その時点で復元を
        打ち切る（後続の逆移動が、戻せなかった鍵の残る移動先を上書きして鍵を
        失うのを防ぐため、残りの世代・退避ファイルはそのまま保全する）。
        退避ファイルは配置が成功した場合にのみ削除する。
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
                try:
                    os.replace(destination, source)
                except OSError:
                    # 戻せなかった鍵は destination に残っている。ここで続行すると
                    # 次の逆移動がその destination を上書きして鍵を失うため中断する。
                    # 元の失敗原因を優先して送出する。
                    break
            raise

        if parked_oldest is not None:
            # 新鍵の配置が成功した後にのみ、退避した最古世代を破棄する。
            self._discard_temp_file(parked_oldest)

    def _discard_temp_file(self, temp_path: Path) -> None:
        """残存した一時ファイル（最古世代の退避ファイルを含む）を削除する。

        削除自体の失敗で元の例外（または成功結果）を上書きしないよう、
        ここでの `OSError` は送出しない。代わりに、残存したパスだけを
        `on_cleanup_failure` へ渡して利用者へ通知する（OS のエラー詳細や鍵の
        内容は渡さない）。いずれのファイルも鍵の書き込み前に実行ユーザー専用の
        権限が設定済みである。
        """
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            if self._on_cleanup_failure is not None:
                self._on_cleanup_failure(temp_path)
