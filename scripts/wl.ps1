<#
.SYNOPSIS
    Helper script PowerShell untuk mendaftarkan atau menghapus IP publik dari remote-whitelist MikroTik.
.DESCRIPTION
    Mengambil IP publik lokal via https://ifconfig.me (timeout 5s), menampilkan IP,
    lalu mengirimkan POST (on) atau DELETE (off) ke endpoint whitelist.
.EXAMPLE
    .\wl.ps1 on
    .\wl.ps1 off
    .\wl.ps1 on -ServiceUrl "https://wl.contoh.co.id" -AuthToken "token-rahasia"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("on", "off")]
    [string]$Action,

    [Parameter(Mandatory = $false, Position = 1)]
    [string]$ServiceUrl = $env:WL_SERVICE_URL,

    [Parameter(Mandatory = $false, Position = 2)]
    [string]$AuthToken = $env:WL_AUTH_TOKEN
)

if ([string]::IsNullOrWhiteSpace($ServiceUrl)) {
    $ServiceUrl = "https://wl.contoh.co.id"
}

# Hapus trailing slash jika ada
$ServiceUrl = $ServiceUrl.TrimEnd('/')
$TargetEndpoint = "$ServiceUrl/v1/whitelist"

Write-Host "Mendeteksi IP publik via https://ifconfig.me (timeout 5s)..."

$ip = $null
try {
    # Coba menggunakan curl.exe bawaan Windows 10/11 jika tersedia, fallback ke Invoke-RestMethod
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        $ip = (& curl.exe -sS --max-time 5 https://ifconfig.me 2>$null)
    } else {
        $response = Invoke-RestMethod -Uri "https://ifconfig.me" -TimeoutSec 5 -UseBasicParsing
        $ip = $response
    }
} catch {
    $ip = $null
}

if ([string]::IsNullOrWhiteSpace($ip)) {
    Write-Error "ERROR: Gagal mengambil IP publik dari https://ifconfig.me (koneksi timeout atau gagal)."
    Write-Error "Permintaan ke whitelist service TIDAK dikirim."
    exit 1
}

$ip = $ip.Trim()
Write-Host "IP Publik terdeteksi: $ip"

$headers = @{}
if (-not [string]::IsNullOrWhiteSpace($AuthToken)) {
    $headers["Authorization"] = "Bearer $AuthToken"
}

if ($Action -eq "on") {
    Write-Host "Mengirim permintaan whitelist (POST)..."
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        if (-not [string]::IsNullOrWhiteSpace($AuthToken)) {
            & curl.exe -sS -H "Authorization: Bearer $AuthToken" -d "ip=$ip" "$TargetEndpoint"
        } else {
            & curl.exe -sS -d "ip=$ip" "$TargetEndpoint"
        }
    } else {
        $body = "ip=$([System.Uri]::EscapeDataString($ip))"
        $resp = Invoke-WebRequest -Uri $TargetEndpoint -Method POST -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing
        Write-Output $resp.Content
    }
} elseif ($Action -eq "off") {
    Write-Host "Mengirim permintaan penghapusan whitelist (DELETE)..."
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        if (-not [string]::IsNullOrWhiteSpace($AuthToken)) {
            & curl.exe -sS -H "Authorization: Bearer $AuthToken" -X DELETE -d "ip=$ip" "$TargetEndpoint"
        } else {
            & curl.exe -sS -X DELETE -d "ip=$ip" "$TargetEndpoint"
        }
    } else {
        $body = "ip=$([System.Uri]::EscapeDataString($ip))"
        $resp = Invoke-WebRequest -Uri $TargetEndpoint -Method DELETE -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing
        Write-Output $resp.Content
    }
}
