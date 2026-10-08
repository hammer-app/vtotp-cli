# vtotp ビルドガイド

このドキュメントは、配布用バイナリの構築・検証・CI 自動化の手順をまとめたものです。一般利用者向けの説明は [../README.md](../README.md) を参照してください。

## 概要

vtotp の配布バイナリは、Nuitka を用いてビルドされます。配布形態は主に3種類です。

- MSIX パッケージ版: Microsoft Store / winget 経由で配布する形式（ストア自動署名により SmartScreen / SAC を回避。Windows 推奨）
- Standalone ZIP 版: 高速起動、低リスクな実行ファイル一式を ZIP 圧縮した形式
- Onefile EXE 版: 単一ファイルで持ち運びやすい形式

Nuitka を使うことで、Python ソースコードを C 言語相当の中間コードへ変換し、ネイティブ機械語へコンパイルし、リバースエンジニアリング耐性を高めます。設計上の背景は [DESIGN.md](DESIGN.md) の Section 18 と Section 22、MSIX 版の詳細は Section 25 を参照してください。

## ビルド用依存のインストール

```bash
pip install -e ".[build]"
```

`[build]` には Nuitka と必要な補助ライブラリが含まれます。

## ビルド手順

> **Note**: 以下の複数行コマンド例は Bash/POSIX 形式（`\`）で記載しています。Windows の PowerShell から直接実行する場合は、改行を削除して 1 行にまとめるか、行継続文字をバッククォート（`` ` ``）に置き換えて実行してください。

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

### 3. MSIX パッケージ版（Microsoft Store 配布用）

MSIX 版は、Nuitka の Standalone 成果物を MSIX レイアウトディレクトリへ配置してパッケージ化します。マニフェスト仕様とパッケージ構成の詳細は [DESIGN.md](DESIGN.md) の Section 25 を参照してください。

#### 前提ツール

- Windows 10/11 SDK に含まれる以下のツール（既定では `C:\Program Files (x86)\Windows Kits\10\bin\<SDKバージョン>\x64\` 配下にインストールされます）
  - `makeappx.exe`（パッケージ化）
  - `signtool.exe`（ローカル検証用の署名）

#### パッケージ作成手順

マニフェストとロゴ資産はリポジトリ内の `msix-layout/`（`AppxManifest.xml`、`Assets/`）として管理済みです。このディレクトリに Nuitka Standalone 成果物を配置してからパッケージ化します。

1. 手順 1 と同じ Nuitka コマンドで Standalone 版をビルドします（`--onefile` は付けません）
2. Standalone 成果物一式（`vtotp.exe` および依存 DLL / Python ランタイム）を `msix-layout/` 直下へコピーします

    ```powershell
    Copy-Item .\dist\standalone\__main__.dist\* .\msix-layout\ -Recurse -Force
    ```

3. `makeappx pack` でパッケージ化します

```powershell
makeappx pack /d .\msix-layout /p .\dist\vtotp_<VERSION>_x64.msix
```

`/d` はレイアウトディレクトリ、`/p` は出力 `.msix` パスを指定します。パッケージ内容のセマンティック検証は有効なままとし、マニフェスト不備を早期に検知できるようにします。生成された `.msix` は無署名のため、ローカル検証を行う場合は次章の自己署名手順を、ストア公開時は無署名のまま Partner Center へ提出します（署名はストア審査時に自動付与されます）。

## MSIX のローカル自己署名・インストール検証

ストア提出前に、ローカル環境でパッケージの健全性と AppExecutionAlias の動作を検証します。ここでの署名は検証専用であり、ストア提出用の成果物には適用しません。以下はすべて PowerShell で実行します。

### 1. 検証用証明書の生成

`AppxManifest.xml` の `Publisher` と一致する CN を持つコード署名用の自己署名証明書を生成し、信頼ストアへ登録します（信頼ストアへの登録には管理者権限が必要です）。

```powershell
# Publisher は AppxManifest.xml の Identity/@Publisher と完全一致させる
$cert = New-SelfSignedCertificate `
    -Type Custom `
    -Subject "<AppxManifest.xml の Publisher 値（CN=...）>" `
    -KeyUsage DigitalSignature `
    -FriendlyName "vtotp MSIX Dev Cert" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

# 信頼チェーン確立のため TrustedPeople へ登録（要管理者権限）
Export-Certificate -Cert $cert -FilePath "$env:TEMP\vtotp-msix-dev.cer"
Import-Certificate -FilePath "$env:TEMP\vtotp-msix-dev.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPeople
```

### 2. パッケージへの署名

`signtool` で MSIX パッケージへ署名します。ハッシュアルゴリズムは SHA256 を指定します。

```powershell
signtool sign /fd SHA256 /sha1 $($cert.Thumbprint) dist\vtotp_<VERSION>_x64.msix
```

### 3. ローカルインストールと起動確認

```powershell
Add-AppxPackage .\dist\vtotp_<VERSION>_x64.msix
```

インストール後、AppExecutionAlias の PATH 反映のため**新しいターミナルを開き**、以下で動作を確認します。

```powershell
vtotp --version
vtotp.exe --help
```

`vtotp` と `vtotp.exe` の双方が等価に起動すれば、AppExecutionAlias は設計通りです。検証終了後は次のコマンドでアンインストールできます。

```powershell
Remove-AppxPackage (Get-AppxPackage -Name "ToramimiNetwork.vtotp").PackageFullName
```

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
