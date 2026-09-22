# vtotp ビルドガイド

このドキュメントは、配布用バイナリの構築・検証・CI 自動化の手順をまとめたものです。一般利用者向けの説明は [../README.md](../README.md) を参照してください。

## 概要

vtotp の配布バイナリは、Nuitka を用いてビルドされます。配布形態は主に2種類です。

- Standalone ZIP 版: 高速起動、低リスクな実行ファイル一式を ZIP 圧縮した形式
- Onefile EXE 版: 単一ファイルで持ち運びやすい形式

Nuitka を使うことで、Python ソースコードを C 言語相当の中間コードへ変換し、ネイティブ機械語へコンパイルし、リバースエンジニアリング耐性を高めます。設計上の背景は [DESIGN.md](DESIGN.md) の Section 18 と Section 22 を参照してください。

## ビルド用依存のインストール

```bash
pip install -e ".[build]"
```

`[build]` には Nuitka と必要な補助ライブラリが含まれます。

## ビルド手順

### 1. Standalone 版（ZIP 配布）

```bash
python -m nuitka --standalone --assume-yes-for-downloads \
  --output-dir=dist/standalone --output-filename=vtotp \
  --include-package=vtotp --include-package=cryptography \
  --company-name="vtotp Project" --product-name="vtotp CLI" \
  --file-version=<VERSION> --product-version=<VERSION> \
  --file-description="Custom CLI TOTP Authenticator" \
  --copyright="Copyright (c) vtotp Project" \
  src/vtotp/__main__.py
```

この形式は、依存 DLL と Python ランタイムを含むフォルダ一式を ZIP で配布するため、起動が速く、実行時の一時展開が不要です。（※ ローカルでの動作検証時は PE メタデータ引数を省略可能です）

### 2. Onefile 版（単一 EXE）

```bash
python -m nuitka --standalone --onefile --assume-yes-for-downloads \
  --output-dir=dist/onefile --output-filename=vtotp \
  --include-package=vtotp --include-package=cryptography \
  --company-name="vtotp Project" --product-name="vtotp CLI" \
  --file-version=<VERSION> --product-version=<VERSION> \
  --file-description="Custom CLI TOTP Authenticator" \
  --copyright="Copyright (c) vtotp Project" \
  src/vtotp/__main__.py
```

Onefile 版は単一ファイルで持ち運びやすく、USB メモリや特定の作業フォルダへの配置に向いています。ただし、実行時に一時フォルダへ展開が発生するため、Standalone 版より待機時間が増える可能性があります。

## CI 自動化フロー

GitHub Actions の [../.github/workflows/release.yml](../.github/workflows/release.yml) を使い、タグ `v*` の push を契機に自動ビルドを行います。

### 主要な流れ

1. `pip install -e ".[build]"` でビルド依存を導入
2. Standalone ZIP 版をビルド
3. Standalone 版に対して `--version` / `--help` / `init` のスモークテストを実行
4. PE メタデータ（CompanyName / ProductName / FileDescription / ProductVersion）を検証
5. ZIP 圧縮と展開後の smoke test を実行
6. Onefile EXE 版をビルド後、`dist/onefile/vtotp.exe` を配布ルート `dist/vtotp.exe` へ配置
7. Onefile 版にも同じ smoke test を実行
8. SHA-256 sidecar の生成・検証
9. GitHub Release へ成果物をアップロード
10. 新規タグのリリースは Pre-release として公開し、AV 判定が通過後に Latest へ昇格

### PE メタデータ

ビルド時には次のメタデータを埋め込みます。

```text
--company-name="vtotp Project"
--product-name="vtotp CLI"
--file-version=<VERSION>
--product-version=<VERSION>
--file-description="Custom CLI TOTP Authenticator"
--copyright="Copyright (c) vtotp Project"
```

### スモークテスト

- `--version`
- `--help`
- `init` を使用した最小動作確認
- 実行後に生成物が正しいディレクトリ・ファイル配置になっているか確認

### SHA-256 検証

各成果物には `.sha256` サイドカーファイルを生成し、CI で再計算して一致確認を行います。

```powershell
foreach ($file in @("dist\vtotp.exe", "dist\vtotp-windows-x64.zip")) {
    $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
    $name = Split-Path $file -Leaf
    "$hash  $name" | Set-Content -NoNewline "$file.sha256"
}
```

### Pre-release から Latest への昇格

新規タグの公開は最初に Pre-release として行います。その後、AV などの検知・審査が完了したあと、次のコマンドを使って正式公開へ昇格します。

```bash
gh release edit <tag> --latest --prerelease=false
```

この手順により、バイナリを再コンパイルせずに、既存のリリースをそのまま「Latest」に昇格できます。

## 参考リンク

- [../README.md](../README.md)
- [REQUIREMENTS.md](REQUIREMENTS.md)
- [DESIGN.md](DESIGN.md)
