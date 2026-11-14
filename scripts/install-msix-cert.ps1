<#
.SYNOPSIS
    MSIX ローカル検証用の自己署名証明書を作成し、信頼済みユーザー (TrustedPeople) へ登録します。

.DESCRIPTION
    AppxManifest.xml の Publisher と一致する有効な証明書が CurrentUser\My に既にあれば再利用し、
    無ければ新規作成します。LocalMachine\TrustedPeople へ未登録の場合のみ登録します。
    何度実行しても同じ状態になります（冪等）。
    変更が必要な場合は管理者権限が必要です（管理者として起動した PowerShell で実行してください）。

.EXAMPLE
    .\scripts\install-msix-cert.ps1
#>

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

# スクリプトは scripts\ 配下に置くため、親ディレクトリ（リポジトリ直下）を作業ディレクトリとする
$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    # マニフェストから Publisher を取得
    $manifestPath = ".\msix-layout\AppxManifest.xml"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Exit-WithError "msix-layout\AppxManifest.xml が見つかりません。"
    }
    [xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    $publisher = $manifest.Package.Identity.Publisher
    Write-Host "対象 Publisher : $publisher" -ForegroundColor Cyan

    # 署名に使用可能な証明書（秘密鍵あり・有効期限内）を検索
    $now = Get-Date
    $certs = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $_.Subject -eq $publisher -and $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now
    })
    if ($certs.Count -gt 1) {
        $thumbprints = ($certs | ForEach-Object { $_.Thumbprint }) -join ", "
        Exit-WithError "Publisher と一致する有効な証明書が複数あります ($thumbprints)。`nscripts\remove-msix-cert.ps1 で削除してから再実行してください。"
    }
    $cert = $certs | Select-Object -First 1

    # 信頼済みユーザーへの登録状況を確認
    $isTrusted = $false
    if ($cert) {
        $isTrusted = Test-Path -LiteralPath "Cert:\LocalMachine\TrustedPeople\$($cert.Thumbprint)"
    }

    if ($cert -and $isTrusted) {
        Write-Host "登録済みの証明書があるため、何もしません: $($cert.Thumbprint) (有効期限: $($cert.NotAfter))" -ForegroundColor Green
        exit 0
    }

    # ここから先は変更を伴うため、管理者権限を確認
    if (-not (Test-Administrator)) {
        Exit-WithError "証明書の登録には管理者権限が必要です。管理者として起動した PowerShell で実行してください。"
    }

    # 1. 証明書の作成（BUILD.md「検証用証明書の生成」と同じ内容）
    if (-not $cert) {
        Write-Host "`n検証用証明書を作成中..." -ForegroundColor Yellow
        $cert = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $publisher `
            -KeyUsage DigitalSignature `
            -FriendlyName "vtotp MSIX Dev Cert" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
        Write-Host "作成しました: $($cert.Thumbprint) (有効期限: $($cert.NotAfter))" -ForegroundColor Green
    } else {
        Write-Host "既存の証明書を使用します: $($cert.Thumbprint) (有効期限: $($cert.NotAfter))" -ForegroundColor Green
    }

    # 2. LocalMachine\TrustedPeople へ公開鍵部分のみを登録
    Write-Host "`nLocalMachine\TrustedPeople へ登録中..." -ForegroundColor Yellow
    $publicCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPeople", "LocalMachine")
    try {
        $store.Open("ReadWrite")
        $store.Add($publicCert)
    }
    finally {
        $store.Close()
    }
    Write-Host "登録しました: $($cert.Thumbprint)" -ForegroundColor Green

    Write-Host "`n完了しました！ scripts\pack-msix.ps1 で署名付きパッケージを作成できます。" -ForegroundColor Green
}
finally {
    Pop-Location
}
