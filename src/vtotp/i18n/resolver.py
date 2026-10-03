"""表示言語の解決ロジックを定義するモジュール。

DESIGN.md 19.2「言語解決」に基づき、コマンド引数・環境変数・
``config.json``・OSロケール・既定値の優先順位で表示言語を解決する。
"""

from __future__ import annotations

import locale
import os

from vtotp.i18n.catalog import DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES

#: 表示言語を指定する環境変数名。
ENV_LANG_VARIABLE: str = "VTOTP_LANG"

#: OSロケール検出時に優先順位順で確認する環境変数名。
_LOCALE_ENV_VARIABLES: tuple[str, ...] = ("LC_ALL", "LC_MESSAGES", "LANG")


def detect_os_locale() -> str | None:
    """OSロケール環境（``LC_ALL``、``LC_MESSAGES``、``LANG``、OS既定ロケール）を検出する。

    環境変数がいずれも設定されていない場合は、``locale`` モジュールを介して
    OSの既定ロケールを問い合わせる。検出に失敗した場合は ``None`` を返す。

    問い合わせには ``LC_CTYPE`` カテゴリを用いる。``LC_ALL`` はPOSIX環境で
    カテゴリごとに値が異なると複合文字列（``LC_CTYPE=C.UTF-8;LC_NUMERIC=C;...``）
    となり、:func:`locale.getlocale` が ``TypeError`` を送出するため使用しない。
    ``LC_MESSAGES`` はWindowsに存在しないため使用しない。
    """
    for variable in _LOCALE_ENV_VARIABLES:
        value = os.environ.get(variable)
        if value:
            return value

    try:
        previous = locale.setlocale(locale.LC_CTYPE)
        try:
            locale.setlocale(locale.LC_CTYPE, "")
            language_code, _encoding = locale.getlocale(locale.LC_CTYPE)
        finally:
            locale.setlocale(locale.LC_CTYPE, previous)
    except (locale.Error, ValueError):
        return None
    return language_code


class LanguageResolver:
    """優先順位に従って最終的な表示言語コードを解決するクラス。

    優先順位:
        1. コマンド引数（``-l``/``--lang``）
        2. 環境変数（``VTOTP_LANG``）
        3. ``config.json`` の ``language``
        4. OSロケール
        5. 既定フォールバック言語（``en``）
    """

    def resolve(
        self,
        cli_lang: str | None = None,
        env_lang: str | None = None,
        config_lang: str | None = None,
        locale_lang: str | None = None,
    ) -> str:
        """優先順位に従い候補を評価し、最終的な言語コードを返す。

        ``en``/``ja`` 以外、空文字、文字列でない値は候補として無視する。
        いずれの候補も採用できない場合は :data:`DEFAULT_LANGUAGE` を返す。
        """
        for candidate in (cli_lang, env_lang, config_lang, locale_lang):
            normalized = self.normalize(candidate)
            if normalized is not None:
                return normalized
        return DEFAULT_LANGUAGE

    @staticmethod
    def normalize(value: object) -> str | None:
        """ロケール表記（``en-US``、``ja_JP`` 等）を主要言語コードへ正規化する。

        `SUPPORTED_LANGUAGES` に含まれない値、空文字、文字列以外の値は
        ``None`` として無視する。対話プロンプトの自由入力（例: `init` の
        言語選択）を正規化する際にも再利用する。
        """
        if not isinstance(value, str):
            return None
        stripped = value.strip()
        if not stripped:
            return None
        primary = stripped.lower().replace("_", "-").split("-")[0]
        if primary in SUPPORTED_LANGUAGES:
            return primary
        return None
