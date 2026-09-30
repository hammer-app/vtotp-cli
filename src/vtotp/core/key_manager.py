"""鍵ファイル（AES-256用マスターキー）の管理を担う KeyManager を定義するモジュール。

DESIGN.md 6章「KeyManager」に基づき、鍵の生成・読み込み・検証・存在確認、
CLI/環境変数/config.jsonからのパス解決、および世代管理（ローテーション）を
提供する。鍵の内容はいかなる場合もログや例外メッセージへ出力しない
（Zero Leakage Rule）。
"""

from __future__ import annotations

import contextlib
import getpass
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

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

    #: Windowsで実行ユーザーへ付与するACL権限。読み書きに加え、自身の削除（D）を
    #: 含める。親ディレクトリが「変更」権限のみ（FILE_DELETE_CHILDなし）の場合、
    #: Dが無いと `os.replace` による配置・世代繰り上げ・一時ファイル削除が失敗する。
    WINDOWS_PRIVATE_GRANT: str = "(R,W,D)"

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
        `<key_path>.2` -> `<key_path>.3`、`<key_path>.1` -> `<key_path>.2`、
        `path` -> `<key_path>.1` の順に繰り上げ、一時ファイルを `path` へ
        配置する。繰り上げ・配置に失敗した場合は、実施済みの繰り上げを
        可能な範囲で元に戻す。上限到達時（`<key_path>.3` が既に存在する場合）
        の削除可否の確認は、呼び出し元（CliHandler）が事前に対話確認を
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
        遮断したうえで実行ユーザーのみに権限を付与する。いずれの失敗も
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

        command = [
            self._icacls_executable(),
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{self._current_windows_account(path)}:{self.WINDOWS_PRIVATE_GRANT}",
        ]
        try:
            subprocess.run(command, check=True, capture_output=True)
        except (OSError, subprocess.SubprocessError):
            # コマンド出力を例外チェーンにも残さないよう、原因は連結しない。
            raise KeyStorageError(
                MsgKey.KEY_PERMISSION_SETUP_FAILED, context=context
            ) from None

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
        4. 鍵を書き込み、flushおよびfsyncを実行する。
        5. 32バイトであることを検証し、`os.replace` で原子的に配置する
           （`rotate=True` の場合は配置直前に既存鍵を世代繰り上げする）。
        6. 成功・失敗を問わず、残存した一時ファイルを削除する。

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

        繰り上げまたは配置が失敗した場合は、実施済みの繰り上げを逆順に
        戻してから元の例外を再送出する。
        """
        completed_moves: list[tuple[Path, Path]] = []
        try:
            if rotate:
                chain = [path, *self.rotated_key_paths(path, self.MAX_ROTATED_KEYS)]
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

    @staticmethod
    def _discard_temp_file(temp_path: Path) -> None:
        """残存した一時ファイルを削除する。

        削除自体の失敗で元の例外（または成功結果）を上書きしないよう、
        ここでの `OSError` のみ抑止する。一時ファイルは書き込み前に実行
        ユーザー専用の権限が設定済みである。
        """
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)

    @staticmethod
    def _icacls_executable() -> str:
        """Windows標準の `icacls.exe` の絶対パスを返す。

        `shell=False` でもコマンド名のみを渡すと、Windowsのプロセス生成は
        カレントディレクトリを `System32` より先に探索する。同名の不正な
        実行ファイルを誤って起動しないよう、システムディレクトリを明示する。
        """
        system_root = os.environ.get("SystemRoot") or r"C:\Windows"
        return str(Path(system_root) / "System32" / "icacls.exe")

    @staticmethod
    def _current_windows_account(path: Path) -> str:
        """ACL付与対象となる実行ユーザーのアカウント名（`DOMAIN\\user`）を返す。

        取得できない場合は :class:`KeyStorageError` を送出する。
        """
        try:
            username = os.environ.get("USERNAME") or getpass.getuser()
        except (OSError, ImportError, KeyError):
            username = ""
        if not username:
            raise KeyStorageError(
                MsgKey.KEY_PERMISSION_SETUP_FAILED, context={"path": str(path)}
            )
        domain = os.environ.get("USERDOMAIN")
        return f"{domain}\\{username}" if domain else username
