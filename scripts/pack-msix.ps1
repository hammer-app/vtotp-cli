<#
.SYNOPSIS
    vtotp の ZIP パッケージを展開し、MSIX パッケージのビルドおよび署名を行います。

.PARAMETER ZipPath
    展開する Standalone ZIP パッケージのパス。省略時は実行時に入力を求められます。
    相対パスはスクリプト実行時のカレントディレクトリを基準に解決します。

.PARAMETER SkipSign
    指定した場合、自己署名をスキップして未署名の MSIX を出力します（Partner Center 提出用）。

.EXAMPLE
    .\scripts\pack-msix.ps1 -ZipPath .\dist\vtotp-windows-x64.zip
    .\scripts\pack-msix.ps1 -SkipSign
#>
param(
    [Parameter(Position = 0)]
    [string]$ZipPath,

    [switch]$SkipSign
)

# エラー発生時は即座に停止
$ErrorActionPreference = "Stop"

# エラーメッセージを stderr へ出力して終了
function Exit-WithError {
    param(
        [string]$Message,
        [int]$Code = 1
    )
    $Host.UI.WriteErrorLine("エラー: $Message")
    exit $Code
}

# 入力パスの前後の空白・引用符を除去し、基準ディレクトリからの絶対パスへ解決
function Resolve-InputPath {
    param(
        [string]$Path,
        [string]$BaseDir
    )
    $trimmed = $Path.Trim().Trim('"', "'")
    if (-not [System.IO.Path]::IsPathRooted($trimmed)) {
        $trimmed = Join-Path $BaseDir $trimmed
    }
    return [System.IO.Path]::GetFullPath($trimmed)
}

# Windows SDK のツールを検索（バージョンの新しい SDK から順に、見つからなければ PATH）
function Find-SdkTool {
    param([string]$Name)
    $sdkBinRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $tool = Get-ChildItem -Path $sdkBinRoot -Directory -Filter "10.*" -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\$Name" } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if (-not $tool) {
        $tool = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty Source
    }
    if (-not $tool) {
        Exit-WithError "$Name が見つかりません。Windows SDK がインストールされているか確認してください。"
    }
    return $tool
}

# 相対パス解決用に、移動前のカレントディレクトリを保持
$callerDir = (Get-Location -PSProvider FileSystem).Path

# 1. リポジトリ直下へ移動（スクリプトは scripts\ 配下に置くため親ディレクトリ。終了時に元の場所へ戻す）
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    Write-Host "作業ディレクトリ: $repoRoot" -ForegroundColor Cyan

    # マニフェストパスの検証
    $manifestPath = ".\msix-layout\AppxManifest.xml"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Exit-WithError "msix-layout\AppxManifest.xml が見つかりません。"
    }

    # マニフェスト情報の読み込み
    [xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    $publisher = $manifest.Package.Identity.Publisher
    $version   = $manifest.Package.Identity.Version

    Write-Host "検出バージョン : $version" -ForegroundColor Cyan
    Write-Host "対象 Publisher : $publisher" -ForegroundColor Cyan

    # 2. 検証用証明書の検索（未署名オプション指定時はスキップ可能）
    $cert = $null
    if (-not $SkipSign) {
        # 署名に使用可能な証明書（秘密鍵あり・有効期限内）に限定
        $now = Get-Date
        $certs = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
            $_.Subject -eq $publisher -and $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now
        })
        if ($certs.Count -eq 0) {
            Exit-WithError "Publisher と一致する有効な検証用証明書が見つかりませんでした (Subject: $publisher)。`n先に scripts\install-msix-cert.ps1 で作成してください。"
        }
        if ($certs.Count -gt 1) {
            $thumbprints = ($certs | ForEach-Object { $_.Thumbprint }) -join ", "
            Exit-WithError "Publisher と一致する有効な証明書が複数あります ($thumbprints)。`nscripts\remove-msix-cert.ps1 で削除し、scripts\install-msix-cert.ps1 で作り直してください。"
        }
        $cert = $certs[0]
        Write-Host "使用する証明書 : $($cert.Thumbprint) ($($cert.Subject))" -ForegroundColor Green
    }

    # SDK ツール（makeappx / signtool）のパス解決
    $makeappx = Find-SdkTool "makeappx.exe"
    $signtool = if (-not $SkipSign) { Find-SdkTool "signtool.exe" } else { $null }

    # 3. マニフェストとロゴ資産以外をクリーンアップ
    Write-Host "`nmsix-layout をクリーンアップ中..." -ForegroundColor Yellow
    Get-ChildItem .\msix-layout -Exclude "AppxManifest.xml", "Assets" -Force | Remove-Item -Recurse -Force

    # 4. ZIP パッケージの指定確認と展開
    if ([string]::IsNullOrWhiteSpace($ZipPath)) {
        $ZipPath = Read-Host "展開する ZIP パッケージのパスを入力してください"
        if ([string]::IsNullOrWhiteSpace($ZipPath)) {
            Exit-WithError "ZIP パッケージのパスが入力されませんでした。"
        }
    }
    $zipFullPath = Resolve-InputPath -Path $ZipPath -BaseDir $callerDir

    if (-not (Test-Path -LiteralPath $zipFullPath -PathType Leaf)) {
        Exit-WithError "指定された ZIP パッケージが見つかりません: $zipFullPath"
    }

    $tempExtractDir = Join-Path ([System.IO.Path]::GetTempPath()) "vtotp_msix_extract_$(Get-Random)"
    try {
        Write-Host "ZIP を展開中: $zipFullPath -> $tempExtractDir" -ForegroundColor Yellow
        Expand-Archive -LiteralPath $zipFullPath -DestinationPath $tempExtractDir -Force

        # 5. 新しい成果物をコピー（vtotp.exe が存在するディレクトリを自動検出してコピー）
        $exeFile = Get-ChildItem -LiteralPath $tempExtractDir -Filter "vtotp.exe" -Recurse | Select-Object -First 1
        if (-not $exeFile) {
            Exit-WithError "ZIP パッケージ内に vtotp.exe が見つかりませんでした。"
        }

        $sourceDir = $exeFile.DirectoryName
        Write-Host "成果物をコピー中: $sourceDir -> .\msix-layout\" -ForegroundColor Yellow
        Copy-Item -Path (Join-Path $sourceDir "*") -Destination ".\msix-layout\" -Recurse -Force
    }
    finally {
        # 一時フォルダの削除（失敗しても処理は継続し、警告のみ表示）
        if (Test-Path -LiteralPath $tempExtractDir) {
            try {
                Remove-Item -LiteralPath $tempExtractDir -Recurse -Force
            }
            catch {
                Write-Warning "一時フォルダを削除できませんでした: $tempExtractDir ($($_.Exception.Message))"
            }
        }
    }

    # 出力先ディレクトリの確保
    $distDir = ".\dist\msix"
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
    $outputMsix = Join-Path $distDir "vtotp-$version.msix"

    # 6. makeappx pack でパッケージ化
    Write-Host "`nMSIX パッケージを作成中: $outputMsix" -ForegroundColor Yellow
    & $makeappx pack /d .\msix-layout /p $outputMsix /o
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "makeappx によるパッケージ作成に失敗しました。" $LASTEXITCODE
    }
    Write-Host "パッケージ作成成功: $outputMsix" -ForegroundColor Green

    # 7. ローカル検証用の自己署名（SkipSign が指定されていない場合）
    if (-not $SkipSign) {
        Write-Host "`nMSIX パッケージに署名中..." -ForegroundColor Yellow
        & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $outputMsix
        if ($LASTEXITCODE -ne 0) {
            Exit-WithError "signtool による署名に失敗しました。" $LASTEXITCODE
        }
        Write-Host "署名完了: $outputMsix" -ForegroundColor Green
    } else {
        Write-Host "`n-SkipSign が指定されたため、未署名のまま完了しました（ストア提出用）。" -ForegroundColor Cyan
    }

    Write-Host "`n完了しました！" -ForegroundColor Green
}
finally {
    Pop-Location
}
