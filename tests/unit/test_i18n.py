"""vtotp.i18n パッケージ（MsgKey・カタログ・言語解決）の単体テスト。"""

from __future__ import annotations

import locale
import string
import sys

import pytest

from vtotp.i18n.catalog import (
    DEFAULT_LANGUAGE,
    EN_CATALOG,
    JA_CATALOG,
    SUPPORTED_LANGUAGES,
    MsgKey,
    get_catalog,
)
from vtotp.i18n.resolver import ENV_LANG_VARIABLE, LanguageResolver, detect_os_locale

#: conftest.pyのautouse fixtureがモックする前の、実際のlocale関数への参照。
_REAL_SETLOCALE = locale.setlocale
_REAL_GETLOCALE = locale.getlocale


def _placeholders(template: str) -> set[str]:
    """フォーマット文字列に含まれる名前付きプレースホルダーの集合を返す。"""
    return {
        field_name
        for _, field_name, _, _ in string.Formatter().parse(template)
        if field_name
    }


class TestCatalogContract:
    """カタログ契約テスト（DESIGN.md 23.1）。"""

    def test_en_catalog_covers_every_msg_key(self) -> None:
        """EN_CATALOGがMsgKeyの全メンバーを過不足なく網羅することを確認する。"""
        assert set(EN_CATALOG.keys()) == set(MsgKey)

    def test_ja_catalog_covers_every_msg_key(self) -> None:
        """JA_CATALOGがMsgKeyの全メンバーを過不足なく網羅することを確認する。"""
        assert set(JA_CATALOG.keys()) == set(MsgKey)

    @pytest.mark.parametrize("key", list(MsgKey))
    def test_placeholders_match_between_languages(self, key: MsgKey) -> None:
        """各キーの英日プレースホルダー集合が一致することを確認する（string.Formatter().parse()使用）。"""
        assert _placeholders(EN_CATALOG[key]) == _placeholders(JA_CATALOG[key])

    @pytest.mark.parametrize("key", list(MsgKey))
    def test_messages_are_non_empty_strings(self, key: MsgKey) -> None:
        """未翻訳（空文字列）のキーが無いことを確認する。"""
        assert isinstance(EN_CATALOG[key], str) and EN_CATALOG[key].strip()
        assert isinstance(JA_CATALOG[key], str) and JA_CATALOG[key].strip()

    def test_supported_languages_are_en_and_ja(self) -> None:
        """サポート対象言語がenとjaの2言語であることを確認する。"""
        assert SUPPORTED_LANGUAGES == ("en", "ja")

    def test_default_language_is_en(self) -> None:
        """既定フォールバック言語がenであることを確認する。"""
        assert DEFAULT_LANGUAGE == "en"


class TestGetCatalog:
    """get_catalog() に関するテスト。"""

    def test_returns_en_catalog_for_en(self) -> None:
        """ "en"を指定するとEN_CATALOGが返ることを確認する。"""
        assert get_catalog("en") is EN_CATALOG

    def test_returns_ja_catalog_for_ja(self) -> None:
        """ "ja"を指定するとJA_CATALOGが返ることを確認する。"""
        assert get_catalog("ja") is JA_CATALOG

    def test_unknown_language_falls_back_to_en_catalog(self) -> None:
        """未知の言語コードを指定した場合、EN_CATALOGへフォールバックすることを確認する。"""
        assert get_catalog("fr") is EN_CATALOG


class TestLanguageResolver:
    """LanguageResolver.resolve() の優先順位解決に関するテスト。"""

    @pytest.fixture
    def resolver(self) -> LanguageResolver:
        return LanguageResolver()

    def test_cli_argument_has_highest_priority(
        self, resolver: LanguageResolver
    ) -> None:
        """CLI引数が最優先で採用されることを確認する。"""
        assert (
            resolver.resolve(
                cli_lang="ja",
                env_lang="en",
                config_lang="en",
                locale_lang="en",
            )
            == "ja"
        )

    def test_env_variable_used_when_cli_omitted(
        self, resolver: LanguageResolver
    ) -> None:
        """CLI引数が無い場合、環境変数が優先されることを確認する。"""
        assert (
            resolver.resolve(
                cli_lang=None,
                env_lang="ja",
                config_lang="en",
                locale_lang="en",
            )
            == "ja"
        )

    def test_config_used_when_cli_and_env_omitted(
        self, resolver: LanguageResolver
    ) -> None:
        """CLI引数・環境変数が無い場合、config.jsonの設定が優先されることを確認する。"""
        assert (
            resolver.resolve(
                cli_lang=None,
                env_lang=None,
                config_lang="ja",
                locale_lang="en",
            )
            == "ja"
        )

    def test_os_locale_used_when_all_else_omitted(
        self, resolver: LanguageResolver
    ) -> None:
        """CLI引数・環境変数・config.jsonが無い場合、OSロケールが使われることを確認する。"""
        assert (
            resolver.resolve(
                cli_lang=None,
                env_lang=None,
                config_lang=None,
                locale_lang="ja",
            )
            == "ja"
        )

    def test_falls_back_to_en_when_nothing_resolves(
        self, resolver: LanguageResolver
    ) -> None:
        """いずれの候補も無い場合、既定のenへフォールバックすることを確認する。"""
        assert (
            resolver.resolve(
                cli_lang=None, env_lang=None, config_lang=None, locale_lang=None
            )
            == "en"
        )

    @pytest.mark.parametrize(
        "raw_value",
        ["en-US", "en_US", "EN", "En-Us"],
    )
    def test_locale_style_values_are_normalized_to_primary_language(
        self, resolver: LanguageResolver, raw_value: str
    ) -> None:
        """en-US、en_USのようなロケール表記が主要言語コード(en)へ正規化されることを確認する。"""
        assert resolver.resolve(cli_lang=raw_value) == "en"

    @pytest.mark.parametrize(
        "raw_value",
        ["ja-JP", "ja_JP", "JA"],
    )
    def test_locale_style_values_are_normalized_to_japanese(
        self, resolver: LanguageResolver, raw_value: str
    ) -> None:
        """ja-JP、ja_JPのようなロケール表記がjaへ正規化されることを確認する。"""
        assert resolver.resolve(cli_lang=raw_value) == "ja"

    @pytest.mark.parametrize("raw_value", ["fr", "de-DE", "", "   ", "0"])
    def test_unsupported_or_empty_values_are_ignored(
        self, resolver: LanguageResolver, raw_value: str
    ) -> None:
        """未サポート言語・空文字は候補として無視され、下位候補または既定値になることを確認する。"""
        assert resolver.resolve(cli_lang=raw_value, env_lang="ja") == "ja"
        assert resolver.resolve(cli_lang=raw_value) == "en"

    def test_non_string_candidate_is_ignored(self, resolver: LanguageResolver) -> None:
        """文字列でない候補値は無視されることを確認する。"""
        result = resolver.resolve(cli_lang=123, env_lang="ja")  # type: ignore[arg-type]
        assert result == "ja"


class TestDetectOsLocale:
    """detect_os_locale() に関するテスト。"""

    def test_env_lang_variable_lookup_name(self) -> None:
        """VTOTP_LANG環境変数名の定数が正しいことを確認する。"""
        assert ENV_LANG_VARIABLE == "VTOTP_LANG"

    def test_prefers_lc_all_over_lang(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """LC_ALLがLANGより優先されることを確認する。"""
        monkeypatch.setenv("LC_ALL", "ja_JP.UTF-8")
        monkeypatch.setenv("LANG", "en_US.UTF-8")
        assert detect_os_locale() == "ja_JP.UTF-8"

    def test_falls_back_to_lang_when_lc_all_and_lc_messages_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LC_ALL/LC_MESSAGESが未設定の場合、LANGが使われることを確認する。"""
        monkeypatch.delenv("LC_ALL", raising=False)
        monkeypatch.delenv("LC_MESSAGES", raising=False)
        monkeypatch.setenv("LANG", "ja_JP.UTF-8")
        assert detect_os_locale() == "ja_JP.UTF-8"

    def test_falls_back_to_locale_module_when_no_env_vars_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """環境変数が無い場合、localeモジュールの既定ロケールが使われることを確認する。"""
        monkeypatch.delenv("LC_ALL", raising=False)
        monkeypatch.delenv("LC_MESSAGES", raising=False)
        monkeypatch.delenv("LANG", raising=False)

        import locale as locale_module

        monkeypatch.setattr(locale_module, "setlocale", lambda *a, **k: "C")
        monkeypatch.setattr(
            locale_module, "getlocale", lambda *a, **k: ("ja_JP", "UTF-8")
        )
        assert detect_os_locale() == "ja_JP"

    def test_returns_none_when_locale_module_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """localeモジュールがロケール解決に失敗した場合、Noneを返すことを確認する。"""
        import locale as locale_module

        monkeypatch.delenv("LC_ALL", raising=False)
        monkeypatch.delenv("LC_MESSAGES", raising=False)
        monkeypatch.delenv("LANG", raising=False)

        def _raise(*_args: object, **_kwargs: object) -> None:
            raise locale_module.Error("unsupported locale")

        monkeypatch.setattr(locale_module, "setlocale", _raise)
        assert detect_os_locale() is None

    def test_queries_lc_ctype_instead_of_lc_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """複合ロケール文字列を避けるため、LC_ALLではなくLC_CTYPEで問い合わせることを確認する。"""
        import locale as locale_module

        categories: list[int] = []

        def _record_setlocale(category: int, *_args: object) -> str:
            categories.append(category)
            return "C"

        def _record_getlocale(category: int) -> tuple[str, str]:
            categories.append(category)
            return ("ja_JP", "UTF-8")

        monkeypatch.setattr(locale_module, "setlocale", _record_setlocale)
        monkeypatch.setattr(locale_module, "getlocale", _record_getlocale)

        assert detect_os_locale() == "ja_JP"
        assert categories
        assert all(category == locale_module.LC_CTYPE for category in categories)

    def test_returns_none_when_getlocale_cannot_parse_locale_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """getlocaleが未知のロケール名でValueErrorを送出した場合、Noneを返すことを確認する。"""
        import locale as locale_module

        def _raise(*_args: object, **_kwargs: object) -> None:
            raise ValueError("unknown locale")

        monkeypatch.setattr(locale_module, "getlocale", _raise)
        assert detect_os_locale() is None

    def test_does_not_raise_with_real_locale_module_and_mixed_categories(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """実際のlocaleモジュールで、カテゴリ混在時にも例外を送出しないことを確認する。

        POSIX環境では ``LC_CTYPE`` のみを設定すると ``setlocale(LC_ALL)`` が複合文字列を
        返す状態になり、以前の実装では ``getlocale(LC_ALL)`` が ``TypeError`` を送出していた。
        """
        import locale as locale_module

        monkeypatch.setattr(locale_module, "setlocale", _REAL_SETLOCALE)
        monkeypatch.setattr(locale_module, "getlocale", _REAL_GETLOCALE)
        if not sys.platform.startswith("win"):
            monkeypatch.setenv("LC_CTYPE", "C.UTF-8")

        result = detect_os_locale()
        assert result is None or isinstance(result, str)
