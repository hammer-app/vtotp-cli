"""vtotp パッケージのバージョンメタデータに関する単体テスト。"""

from __future__ import annotations

import tomllib
from pathlib import Path

import vtotp

# tests/unit/test_version.py から見たプロジェクトルートの pyproject.toml。
PYPROJECT_PATH = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _read_pyproject_version() -> str:
    """`pyproject.toml` の `[project]` テーブルから `version` を読み取る。"""
    with PYPROJECT_PATH.open("rb") as f:
        version = tomllib.load(f)["project"]["version"]
    assert isinstance(version, str)
    return version


class TestVersion:
    """`vtotp.__version__` に関するテスト。"""

    def test_version_matches_pyproject_toml(self) -> None:
        """`__version__` が `pyproject.toml` の `[project].version` と一致することを確認する。"""
        assert vtotp.__version__ == _read_pyproject_version()

    def test_version_is_exported_via_all(self) -> None:
        """`__version__` が `__all__` を通じて公開されていることを確認する。"""
        assert vtotp.__all__ == ["__version__"]
        assert "__version__" in vtotp.__all__
