"""vtotp.domain パッケージの公開インターフェース。

ドメインモデルおよび例外クラスを外部モジュールへ公開する。
"""

from __future__ import annotations

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
from vtotp.domain.models import AppConfig, EncryptedPayload, SecretRecord

__all__ = [
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
]
