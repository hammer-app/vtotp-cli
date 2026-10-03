"""CLIコマンドのフルライフサイクルに関するE2E/統合テスト。

`python -m vtotp` を実際にサブプロセスとして起動し、実運用の利用者に
近い形で一連のコマンド（``init``/``add``/``list``/``generate``/``rekey``/
``remove``）とエラー経路・終了コードを検証する。``HOME``/``USERPROFILE``
をテストごとに隔離したディレクトリへ差し替えることで、``CliHandler``が
既定で参照する ``~/.vtotp`` を一切変更しない。
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

import pytest

#: サブプロセス1回あたりのタイムアウト秒数。
_SUBPROCESS_TIMEOUT_SECONDS = 30

#: 本テストスイート全体で使い回す、有効なBase32形式のダミーTOTPシークレット。
_GITHUB_SECRET = "JBSWY3DPEHPK3PXP"
_AWS_SECRET = "KRSXG5CTMVRXEZLU"


def _run_cli(
    args: Sequence[str],
    home_dir: Path,
    extra_env: dict[str, str] | None = None,
    force_lang: str | None = "en",
    stdin_text: str = "",
) -> subprocess.CompletedProcess[str]:
    """``python -m vtotp`` をサブプロセスとして実行し、結果を返す。

    ``HOME``/``USERPROFILE`` を ``home_dir`` へ差し替えることで、
    ``CliHandler`` が既定で使用する ``Path.home() / ".vtotp"``
    （config.json・暗号化ストレージの既定配置先）を隔離し、実際の
    ユーザーのホームディレクトリを一切変更しないようにする。

    ホストOSのロケール（日本語環境等）や既存の``VTOTP_LANG``/``LANG``/
    ``LC_ALL``/``LC_MESSAGES``に依存して結果が揺れないよう、``LC_ALL``/
    ``LC_MESSAGES``/``LANG``は常に除去し、``VTOTP_LANG``は既定で``"en"``に
    固定する。日本語表示を検証したいテストは``extra_env={"VTOTP_LANG":
    "ja"}``で明示的に上書きするか、``force_lang="ja"``を渡す。
    ``config.json``に保存された``language``設定が（``VTOTP_LANG``無指定の
    まま）実際に解決へ反映されることそのものを検証したい場合は
    ``force_lang=None``を渡し、``VTOTP_LANG``を一切注入しない。

    ``add --stdin`` でシークレットを渡す場合は ``stdin_text`` を指定する。
    それ以外は、プロンプトが誤って発生した場合にサブプロセスが無限に
    待機しないよう、標準入力には空文字列を渡す（即座にEOFとして扱われる）。
    """
    env = os.environ.copy()
    env["HOME"] = str(home_dir)
    env["USERPROFILE"] = str(home_dir)
    env.pop("VTOTP_KEY_PATH", None)
    env.pop("VTOTP_LANG", None)
    for locale_variable in ("LC_ALL", "LC_MESSAGES", "LANG"):
        env.pop(locale_variable, None)
    if force_lang is not None:
        env["VTOTP_LANG"] = force_lang
    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        [sys.executable, "-m", "vtotp", *args],
        cwd=home_dir,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        input=stdin_text,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )


@pytest.fixture
def home_dir(tmp_path: Path) -> Path:
    """テストごとに隔離された、実際のユーザーホームディレクトリの代わりとなるパスを返す。"""
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    return isolated_home


class TestFullLifecycle:
    """init→add→list→generate→rekey→removeの一連のライフサイクルに関するテスト。"""

    def test_full_lifecycle_succeeds_end_to_end(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """フルライフサイクルを通して各コマンドが期待どおりに動作することを確認する。"""
        key_path = tmp_path / "master.key"
        session_log: list[subprocess.CompletedProcess[str]] = []

        def run(
            args: Sequence[str], stdin_text: str = ""
        ) -> subprocess.CompletedProcess[str]:
            result = _run_cli(args, home_dir, stdin_text=stdin_text)
            session_log.append(result)
            return result

        # 1. init: 新規鍵および暗号化ストレージを作成する。
        result = run(["init", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        assert key_path.is_file()
        assert len(key_path.read_bytes()) == 32

        config_path = home_dir / ".vtotp" / "config.json"
        storage_path = home_dir / ".vtotp" / "vtotp-secrets.enc"
        assert config_path.is_file()
        assert storage_path.is_file()

        # 2. add: 複数サービス（github, aws）を登録する。
        result = run(
            [
                "add",
                "github",
                "--key",
                str(key_path),
                "--stdin",
                "--issuer",
                "GitHub",
            ],
            stdin_text=f"{_GITHUB_SECRET}\n",
        )
        assert result.returncode == 0, result.stderr

        result = run(
            ["add", "aws", "--key", str(key_path), "--stdin"],
            stdin_text=f"{_AWS_SECRET}\r\n",
        )
        assert result.returncode == 0, result.stderr

        # 3. list: 昇順・シークレット非表示で一覧が出力されることを確認する。
        result = run(["list", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        service_lines = [
            line
            for line in result.stdout.splitlines()
            if line.strip() and not line.upper().startswith("SERVICE")
        ]
        service_names_in_order = [line.split()[0] for line in service_lines]
        assert service_names_in_order == sorted(service_names_in_order)
        assert "aws" in service_names_in_order
        assert "github" in service_names_in_order
        assert _GITHUB_SECRET not in result.stdout
        assert _AWS_SECRET not in result.stdout

        # 4. generate: 6桁のTOTPコードがstdoutへ出力されることを確認する。
        result = run(["generate", "github", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        code = result.stdout.strip()
        assert code.isdigit()
        assert len(code) == 6

        # 5. rekey: 鍵をローテーションする。
        old_key_bytes = key_path.read_bytes()
        result = run(["rekey", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr

        new_key_bytes = key_path.read_bytes()
        assert new_key_bytes != old_key_bytes
        assert len(new_key_bytes) == 32

        backup_key_path = Path(f"{key_path}.1")
        assert backup_key_path.is_file()
        assert backup_key_path.read_bytes() == old_key_bytes

        # rekey後、新鍵で既存データが引き続き読み出せることを確認する。
        result = run(["list", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        assert "github" in result.stdout
        assert "aws" in result.stdout

        result = run(["generate", "github", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().isdigit()

        # 6. remove: 指定サービスを削除し、listから消えることを確認する。
        result = run(["remove", "github", "--force", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr

        result = run(["list", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        remaining_names = [
            line.split()[0]
            for line in result.stdout.splitlines()
            if line.strip() and not line.upper().startswith("SERVICE")
        ]
        assert "github" not in remaining_names
        assert "aws" in remaining_names

        # Zero Leakage Rule: セッション全体のstdout/stderrに、平文シークレットや
        # 生鍵バイト列（旧鍵・新鍵）が一切現れないことを確認する。
        combined_log = "".join(proc.stdout + proc.stderr for proc in session_log)
        assert _GITHUB_SECRET not in combined_log
        assert _AWS_SECRET not in combined_log
        assert old_key_bytes.hex() not in combined_log
        assert new_key_bytes.hex() not in combined_log


class TestRekeyGenerationLimit:
    """世代上限（`.3`）到達後のrekeyに関するE2Eテスト。"""

    def test_fourth_rekey_rotates_generations_without_leftover_files(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """4回目のrekeyで上限警告に同意すると最古世代だけが破棄され、退避ファイル等が残らないことを確認する。

        Windowsでは各鍵の保存時に、実際のDACL許可リスト再検証も通過する。
        """
        key_dir = tmp_path / "keys"
        key_path = key_dir / "master.key"
        result = _run_cli(["init", "--key", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        result = _run_cli(
            ["add", "github", "--key", str(key_path), "--stdin"],
            home_dir,
            stdin_text=f"{_GITHUB_SECRET}\n",
        )
        assert result.returncode == 0, result.stderr

        history = [key_path.read_bytes()]
        for _ in range(3):
            result = _run_cli(["rekey", "--key", str(key_path)], home_dir)
            assert result.returncode == 0, result.stderr
            history.append(key_path.read_bytes())
        assert Path(f"{key_path}.3").read_bytes() == history[0]

        # 4回目: .3 が存在するため上限警告が表示され、"y" で続行する。
        result = _run_cli(["rekey", "--key", str(key_path)], home_dir, stdin_text="y\n")
        assert result.returncode == 0, result.stderr
        assert f"{key_path}.3" in result.stderr

        assert Path(f"{key_path}.1").read_bytes() == history[3]
        assert Path(f"{key_path}.2").read_bytes() == history[2]
        assert Path(f"{key_path}.3").read_bytes() == history[1]
        assert sorted(p.name for p in key_dir.iterdir()) == [
            "master.key",
            "master.key.1",
            "master.key.2",
            "master.key.3",
        ]

        result = _run_cli(["generate", "github", "--key", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().isdigit()


class TestArgumentAndEnvironmentIntegration:
    """`-k`/`--key`とVTOTP_KEY_PATH環境変数の統合シナリオに関するテスト。"""

    def test_short_key_option_works_across_the_command_sequence(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """`-k`による明示的な鍵パス指定で一連のコマンドが正しく動作することを確認する。"""
        key_path = tmp_path / "master.key"

        assert _run_cli(["init", "-k", str(key_path)], home_dir).returncode == 0
        assert (
            _run_cli(
                ["add", "github", "-k", str(key_path), "--stdin"],
                home_dir,
                stdin_text=f"{_GITHUB_SECRET}\n",
            ).returncode
            == 0
        )

        result = _run_cli(["generate", "github", "-k", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().isdigit()

    def test_subcommand_omission_fallback_generates_code(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """サービス名のみ（サブコマンド省略形）を渡した場合、自動的にgenerateとして
        実行され、終了コード0で6桁のTOTPコードが出力されることを確認する。
        """
        key_path = tmp_path / "master.key"

        assert _run_cli(["init", "-k", str(key_path)], home_dir).returncode == 0
        assert (
            _run_cli(
                ["add", "github", "-k", str(key_path), "--stdin"],
                home_dir,
                stdin_text=f"{_GITHUB_SECRET}\n",
            ).returncode
            == 0
        )

        result = _run_cli(["github", "-k", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        code = result.stdout.strip()
        assert code.isdigit()
        assert len(code) == 6

    def test_totp_key_path_environment_variable_drives_full_sequence(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """VTOTP_KEY_PATH環境変数を設定した状態で、`--key`省略のまま一連のコマンドが動作することを確認する。"""
        key_path = tmp_path / "env-master.key"

        # initはconfig.jsonのkey_pathも更新するため、初回のみ--keyで明示する。
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        env_override = {"VTOTP_KEY_PATH": str(key_path)}

        result = _run_cli(
            ["add", "github", "--stdin"],
            home_dir,
            stdin_text=f"{_GITHUB_SECRET}\n",
            extra_env=env_override,
        )
        assert result.returncode == 0, result.stderr

        result = _run_cli(["list"], home_dir, extra_env=env_override)
        assert result.returncode == 0, result.stderr
        assert "github" in result.stdout

        result = _run_cli(["generate", "github"], home_dir, extra_env=env_override)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().isdigit()

        result = _run_cli(
            ["remove", "github", "--force"], home_dir, extra_env=env_override
        )
        assert result.returncode == 0, result.stderr


class TestErrorHandlingExitCodes:
    """エラーハンドリングおよび終了コードに関するテスト。"""

    def test_generate_on_missing_service_returns_exit_code_5(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """未登録のサービスへのgenerateが終了コード5になることを確認する。"""
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            ["generate", "unknown-service", "--key", str(key_path)], home_dir
        )
        assert result.returncode == 5

    def test_remove_on_missing_service_returns_exit_code_5(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """未登録のサービスへのremoveが終了コード5になることを確認する。"""
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            ["remove", "unknown-service", "--force", "--key", str(key_path)], home_dir
        )
        assert result.returncode == 5

    def test_add_with_invalid_base32_secret_returns_exit_code_6(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """不正なBase32シークレットでのaddが終了コード6になり、入力した不正な値が
        stdout/stderrのいずれにも含まれないことを確認する（Zero Leakage Rule）。
        """
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        invalid_secret = "not-valid-base32!!!"
        result = _run_cli(
            ["add", "github", "--key", str(key_path), "--stdin"],
            home_dir,
            stdin_text=f"{invalid_secret}\n",
        )
        assert result.returncode == 6
        assert invalid_secret not in result.stdout
        assert invalid_secret not in result.stderr

    @pytest.mark.parametrize("stdin_text", ["", "\n"])
    def test_add_with_empty_stdin_returns_exit_code_6(
        self, home_dir: Path, tmp_path: Path, stdin_text: str
    ) -> None:
        """`--stdin`へ空入力・改行のみを渡したaddが終了コード6になり、何も登録されないことを確認する。"""
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            ["add", "github", "--key", str(key_path), "--stdin"],
            home_dir,
            stdin_text=stdin_text,
        )
        assert result.returncode == 6
        assert "Traceback" not in result.stderr

        result = _run_cli(["list", "--key", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        assert "github" not in result.stdout

    @pytest.mark.parametrize("bom_prefix", ["﻿", "﻿﻿"])
    def test_add_with_bom_prefixed_stdin_registers_service(
        self, home_dir: Path, tmp_path: Path, bom_prefix: str
    ) -> None:
        """Windows PowerShell 5.1（コードページ65001）のように先頭へ単一・複数の
        UTF-8 BOMが付与された標準入力でも、実プロセス実行で正しく登録され、
        TOTPコードを生成できることを確認する。
        """
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            ["add", "github", "--key", str(key_path), "--stdin"],
            home_dir,
            stdin_text=f"{bom_prefix}{_GITHUB_SECRET}\r\n",
        )
        assert result.returncode == 0, result.stderr

        result = _run_cli(["generate", "github", "--key", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().isdigit()

    @pytest.mark.parametrize("stdin_text", [f"{_GITHUB_SECRET}\n", ""])
    def test_add_without_stdin_option_on_pipe_fails_fast_with_exit_code_2(
        self, home_dir: Path, tmp_path: Path, stdin_text: str
    ) -> None:
        """パイプ（非TTY）で`--stdin`を指定せずにaddした場合、キーボード入力を待って
        ハングせずに終了コード2で`--stdin`の指定を促し、シークレットをエコーバック
        せず、サービスも登録しないことを確認する。
        """
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            ["add", "github", "--key", str(key_path)],
            home_dir,
            stdin_text=stdin_text,
        )
        assert result.returncode == 2
        assert "Standard input is not a terminal" in result.stderr
        assert "Enter the TOTP secret" not in result.stderr
        assert _GITHUB_SECRET not in result.stdout + result.stderr
        assert "Traceback" not in result.stderr

        result = _run_cli(["list", "--key", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        assert "github" not in result.stdout

    def test_add_without_stdin_option_on_pipe_returns_exit_code_2_before_key_access(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない（initなし）状態でも、パイプで`--stdin`を指定し忘れた
        addは、鍵不在（終了コード3）ではなく決定的に終了コード2になることを確認する。
        """
        missing_key_path = tmp_path / "does-not-exist.key"

        result = _run_cli(
            ["add", "github", "--key", str(missing_key_path)],
            home_dir,
            stdin_text=f"{_GITHUB_SECRET}\n",
        )
        assert result.returncode == 2
        assert "Standard input is not a terminal" in result.stderr
        assert "Key file not found" not in result.stderr
        assert _GITHUB_SECRET not in result.stdout + result.stderr

    @pytest.mark.parametrize(
        "secret_args",
        [
            ["--secret", _GITHUB_SECRET],
            ["-s", _GITHUB_SECRET],
            [f"--secret={_GITHUB_SECRET}"],
            [f"-s{_GITHUB_SECRET}"],
        ],
    )
    def test_removed_secret_option_returns_exit_code_2_without_echo(
        self, home_dir: Path, tmp_path: Path, secret_args: list[str]
    ) -> None:
        """廃止された`--secret`/`-s`を指定したaddが、実プロセス実行でも終了コード2で
        拒否され、stderrに固定の廃止メッセージだけが出力されてシークレット値が
        エコーバックされず、サービスも登録されないことを確認する。
        """
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            ["add", "github", "--key", str(key_path), *secret_args],
            home_dir,
        )
        assert result.returncode == 2
        assert "The --secret/-s option has been removed for security" in result.stderr
        assert _GITHUB_SECRET not in result.stderr
        assert _GITHUB_SECRET not in result.stdout
        assert "unrecognized arguments" not in result.stderr
        assert "Traceback" not in result.stderr

        result = _run_cli(["list", "--key", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        assert "github" not in result.stdout

    @pytest.mark.parametrize(
        "secret_args",
        [
            ["--secret", _GITHUB_SECRET],
            ["-s", _GITHUB_SECRET],
            [f"--secret={_GITHUB_SECRET}"],
            [f"-s{_GITHUB_SECRET}"],
        ],
    )
    def test_secret_option_before_subcommand_returns_exit_code_2_without_echo(
        self, home_dir: Path, tmp_path: Path, secret_args: list[str]
    ) -> None:
        """サブコマンドより前に置かれた`--secret`/`-s`（`vtotp --secret VALUE add github`）も、
        実プロセス実行で終了コード2として拒否され、固定の廃止メッセージだけが出力されて
        シークレット値がエコーバックされないことを確認する。
        """
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            [*secret_args, "add", "github", "--key", str(key_path)],
            home_dir,
        )
        assert result.returncode == 2
        assert "The --secret/-s option has been removed for security" in result.stderr
        assert _GITHUB_SECRET not in result.stderr
        assert _GITHUB_SECRET not in result.stdout
        assert "unrecognized arguments" not in result.stderr
        assert "usage:" not in result.stderr
        assert "Traceback" not in result.stderr

        result = _run_cli(["list", "--key", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        assert "github" not in result.stdout

    def test_corrupted_storage_returns_exit_code_4(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """暗号化ストレージファイルが1バイト改ざんされている場合、generateが終了コード4になることを確認する。"""
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0
        assert (
            _run_cli(
                ["add", "github", "--key", str(key_path), "--stdin"],
                home_dir,
                stdin_text=f"{_GITHUB_SECRET}\n",
            ).returncode
            == 0
        )

        storage_path = home_dir / ".vtotp" / "vtotp-secrets.enc"
        document = json.loads(storage_path.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 0xFF
        document["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
        storage_path.write_text(json.dumps(document), encoding="utf-8")

        result = _run_cli(["generate", "github", "--key", str(key_path)], home_dir)
        assert result.returncode == 4

    def test_running_without_an_existing_key_returns_exit_code_3(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """存在しない鍵ファイルを指定した実行が終了コード3になることを確認する（initなし）。"""
        missing_key_path = tmp_path / "does-not-exist.key"

        result = _run_cli(
            ["generate", "github", "--key", str(missing_key_path)], home_dir
        )
        assert result.returncode == 3

    def test_error_messages_are_written_to_stderr_not_stdout(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """エラー発生時、標準出力ではなく標準エラー出力へメッセージが書かれることを確認する。"""
        missing_key_path = tmp_path / "does-not-exist.key"

        result = _run_cli(
            ["generate", "github", "--key", str(missing_key_path)], home_dir
        )
        assert result.returncode == 3
        assert result.stdout == ""
        assert result.stderr.strip() != ""


class TestI18nIntegration:
    """多言語化（`-l`/`--lang`、`VTOTP_LANG`、`init`/`config`の言語永続化）に関する統合テスト。"""

    def test_lang_option_localizes_error_message_end_to_end(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """実プロセス実行で`-l ja`がエラーメッセージを日本語化することを確認する。"""
        missing_key_path = tmp_path / "does-not-exist.key"
        result = _run_cli(
            ["generate", "github", "--key", str(missing_key_path), "-l", "ja"],
            home_dir,
        )
        assert result.returncode == 3
        assert "エラー: 鍵ファイルが見つかりません" in result.stderr

    def test_default_language_is_english_without_any_override(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """CLI引数・環境変数・config.jsonのいずれも無い場合、既定で英語表示になることを確認する。"""
        missing_key_path = tmp_path / "does-not-exist.key"
        result = _run_cli(
            ["generate", "github", "--key", str(missing_key_path)], home_dir
        )
        assert result.returncode == 3
        assert "Error: Key file not found" in result.stderr

    def test_env_variable_localizes_error_message_end_to_end(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """実プロセス実行でVTOTP_LANG環境変数がエラーメッセージを日本語化することを確認する。"""
        missing_key_path = tmp_path / "does-not-exist.key"
        result = _run_cli(
            ["generate", "github", "--key", str(missing_key_path)],
            home_dir,
            extra_env={"VTOTP_LANG": "ja"},
        )
        assert result.returncode == 3
        assert "エラー" in result.stderr

    def test_init_persists_language_and_later_commands_use_it_without_lang_option(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """`init -l ja`後、以降のコマンドは`-l`を省略してもconfig.jsonの言語設定で日本語表示になることを確認する。"""
        key_path = tmp_path / "master.key"
        result = _run_cli(["init", "--key", str(key_path), "-l", "ja"], home_dir)
        assert result.returncode == 0, result.stderr
        assert "鍵ファイルを作成しました" in result.stderr

        # `-l`もVTOTP_LANGも指定せず、config.jsonに保存された"ja"設定だけで
        # 実際に日本語表示になることを検証するため、あえてforce_lang=Noneで
        # 言語環境変数を注入しない（LC_ALL/LC_MESSAGES/LANGは通常どおり除去する）。
        result = _run_cli(
            ["generate", "unknown-service", "--key", str(key_path)],
            home_dir,
            force_lang=None,
        )
        assert result.returncode == 5
        assert "エラー: サービスが見つかりません" in result.stderr

    def test_config_set_language_updates_persisted_setting(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """`config set language ja`実行後、config.jsonのlanguageが更新されることを確認する。"""
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(["config", "set", "language", "ja"], home_dir)
        assert result.returncode == 0, result.stderr
        assert "言語を更新しました" in result.stdout

        config_path = home_dir / ".vtotp" / "config.json"
        saved = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved["language"] == "ja"

        # config.jsonの"ja"設定のみで解決されることを検証するため、
        # ここでもVTOTP_LANGを注入しない。
        result = _run_cli(
            ["generate", "unknown-service", "--key", str(key_path)],
            home_dir,
            force_lang=None,
        )
        assert result.returncode == 5
        assert "エラー" in result.stderr

    def test_leading_option_before_subcommand_is_rejected_end_to_end(
        self, home_dir: Path
    ) -> None:
        """実プロセス実行でも、サブコマンドより前に置かれたオプションが終了コード2で拒否されることを確認する。"""
        result = _run_cli(["-l", "ja", "list"], home_dir)
        assert result.returncode == 2
        assert "Traceback" not in result.stderr

    @pytest.mark.parametrize(
        "extra_args",
        [
            ["--key", "PATH", "github"],
            ["-l", "ja", "github"],
        ],
    )
    def test_option_before_service_is_rejected_end_to_end(
        self, home_dir: Path, tmp_path: Path, extra_args: list[str]
    ) -> None:
        """実プロセス実行でも、`SERVICE`より前に置かれたオプションが終了コード2で
        拒否されることを確認する（DESIGN.md 20.1。`vtotp get --key PATH github`は
        非サポートの明示例）。
        """
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        resolved_args = [
            str(key_path) if token == "PATH" else token for token in extra_args
        ]
        result = _run_cli(["get", *resolved_args], home_dir)
        assert result.returncode == 2
        assert "Traceback" not in result.stderr
