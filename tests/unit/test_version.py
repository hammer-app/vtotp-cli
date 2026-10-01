"""vtotp パッケージのバージョンメタデータに関する単体テスト。"""

from __future__ import annotations

import vtotp


class TestVersion:
    """`vtotp.__version__` に関するテスト。"""

    def test_version_matches_pyproject_toml(self) -> None:
        """`__version__` が `pyproject.toml` の `version`（0.3.0）と一致することを確認する。"""
        assert vtotp.__version__ == "0.3.0"

    def test_version_is_exported_via_all(self) -> None:
        """`__version__` が `__all__` を通じて公開されていることを確認する。"""
        assert vtotp.__all__ == ["__version__"]
        assert "__version__" in vtotp.__all__
