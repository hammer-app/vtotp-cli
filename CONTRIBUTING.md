# vtotp 開発者ガイド

このドキュメントは、開発者向けの構築・テスト・静的解析手順をまとめたものです。一般利用者向けの説明は [README.md](README.md) を参照してください。

## 開発環境のセットアップ

### 依存パッケージのインストール

```bash
pip install -e ".[dev]"
```

開発依存には、テスト実行、カバレッジ計測、フォーマットチェック、静的解析が含まれます。

## テスト実行

### 基本実行

```bash
python -m pytest
```

### カバレッジ付き実行

```bash
python -m pytest --cov=src/vtotp --cov-report=term-missing
```

このコマンドはユニットテスト・統合テストを実行し、カバレッジ率と不足行を端末出力へ表示します。

## 静的解析

### flake8

```bash
python -m flake8 src tests
```

`flake8` はリポジトリ直下の `.flake8` 設定と整合するように実行してください。設定は `max-line-length = 88` と `extend-ignore = E203, W503` を想定し、Black との競合がないように保守します。

### mypy

```bash
python -m mypy src
```

`mypy` は型の整合性と未使用のコードを検出し、型安全性を担保します。

### black --check

```bash
python -m black --check src tests
```

フォーマットが未整合の場合は、`python -m black src tests` を実行して修正してください。

## 検証基準

- テストカバレッジ 100% を維持する
- `flake8`、`mypy`、`black --check` を警告なしで通過する
- CI での品質ゲートを維持し、テスト失敗や静的解析エラーが発生しないことを確認する
- 重大なセキュリティ要件（Zero Leakage Rule、AES-256-GCM、Windows パス安全性）に違反しないことを確認する

## 参考リンク

- [README.md](README.md)
- [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
- [docs/DESIGN.md](docs/DESIGN.md)
