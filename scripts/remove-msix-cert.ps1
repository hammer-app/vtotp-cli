<#
.SYNOPSIS
    MSIX ローカル検証用の自己署名証明書と、検証用にインストールしたパッケージを削除します。

.DESCRIPTION
    AppxManifest.xml の Identity (Name / Publisher) をもとに、以下を削除します。
      - 検証用にインストールしたパッケージ（Microsoft Store からインストールしたものは対象外）
      - Publisher と一致する証明書（CurrentUser\My の秘密鍵を含む、TrustedPeople / Root の登録）
    削除前に対象ごとに確認を求めます（-Confirm:$false で省略、-WhatIf で対象の確認のみ）。
    LocalMachine の証明書ストアを変更する場合は管理者権限が必要です。
    CurrentUser\Root からの削除時は、Windows の確認ダイアログが表示されます。

.EXAMPLE
    .\scripts\remove-msix-cert.ps1 -WhatIf
    .\scripts\remove-msix-cert.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param()

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

function Test-Administrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 削除対象とする証明書ストア（LocalMachine を先に処理し、CurrentUser 側の重複表示を解消する）
$certStores = @(
    "Cert:\LocalMachine\TrustedPeople",
    "Cert:\LocalMachine\Root",
    "Cert:\CurrentUser\TrustedPeople",
    "Cert:\CurrentUser\Root",
    "Cert:\CurrentUser\My"
)

# スクリプトは scripts\ 配下に置くため、親ディレクトリ（リポジトリ直下）を作業ディレクトリとする
$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    # マニフェストから Identity を取得
    $manifestPath = ".\msix-layout\AppxManifest.xml"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Exit-WithError "msix-layout\AppxManifest.xml が見つかりません。"
    }
    [xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    $packageName = $manifest.Package.Identity.Name
    $publisher   = $manifest.Package.Identity.Publisher
    Write-Host "対象パッケージ : $packageName" -ForegroundColor Cyan
    Write-Host "対象 Publisher : $publisher" -ForegroundColor Cyan

    # 削除対象の列挙（-WhatIf 指定時にモジュール読み込み時のエイリアス設定まで WhatIf 表示されるのを抑止）
    $savedWhatIf = $WhatIfPreference
    $WhatIfPreference = $false
    Import-Module Appx
    $WhatIfPreference = $savedWhatIf
    $packages = @(Get-AppxPackage -Name $packageName | Where-Object { $_.SignatureKind -ne "Store" })
    $certs = @(foreach ($storePath in $certStores) {
        Get-ChildItem $storePath | Where-Object { $_.Subject -eq $publisher }
    })

    if ($packages.Count -eq 0 -and $certs.Count -eq 0) {
        Write-Host "`n削除対象はありません。" -ForegroundColor Green
        exit 0
    }

    Write-Host "`n削除対象:" -ForegroundColor Yellow
    foreach ($pkg in $packages) {
        Write-Host "  [パッケージ] $($pkg.PackageFullName) ($($pkg.SignatureKind))"
    }
    foreach ($cert in $certs) {
        Write-Host "  [証明書] $($cert.PSParentPath -replace '^.*::', '')\$($cert.Thumbprint) (有効期限: $($cert.NotAfter))"
    }

    # LocalMachine を変更する場合は管理者権限を確認（-WhatIf 時は不要）
    $needsAdmin = @($certs | Where-Object { $_.PSParentPath -like "*LocalMachine*" }).Count -gt 0
    if ($needsAdmin -and -not $WhatIfPreference -and -not (Test-Administrator)) {
        Exit-WithError "LocalMachine の証明書ストアを変更するには管理者権限が必要です。管理者として起動した PowerShell で実行してください。"
    }

    # 1. パッケージのアンインストール
    foreach ($pkg in $packages) {
        if ($PSCmdlet.ShouldProcess($pkg.PackageFullName, "パッケージのアンインストール")) {
            Remove-AppxPackage -Package $pkg.PackageFullName
            Write-Host "アンインストールしました: $($pkg.PackageFullName)" -ForegroundColor Green
        }
    }

    # 2. 証明書の削除（CurrentUser\My は秘密鍵も削除）
    foreach ($cert in $certs) {
        $location = "$($cert.PSParentPath -replace '^.*::', '')\$($cert.Thumbprint)"
        # LocalMachine 側の削除により、CurrentUser 側の表示から消えている場合はスキップ
        if (-not (Test-Path -LiteralPath $cert.PSPath)) {
            continue
        }
        if ($PSCmdlet.ShouldProcess($location, "証明書の削除")) {
            if ($cert.PSParentPath -like "*CurrentUser\My") {
                Remove-Item -LiteralPath $cert.PSPath -DeleteKey
            } else {
                Remove-Item -LiteralPath $cert.PSPath
            }
            Write-Host "削除しました: $location" -ForegroundColor Green
        }
    }

    Write-Host "`n完了しました！" -ForegroundColor Green
}
finally {
    Pop-Location
}
