# 生成自签名证书 cert.pem / key.pem（有效期 1 年）
# 兼容 Windows PowerShell 5.1：优先用 Git 自带 openssl；仅当 openssl 不可用
# 且当前 PowerShell 支持 ExportCertificatePem（PS 7+）时才回退
# New-SelfSignedCertificate（PS 5.1 没有 PEM 导出 API）。
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$certPath = Join-Path $dir 'cert.pem'
$keyPath  = Join-Path $dir 'key.pem'
$ip = '192.168.1.100'   # 占位示例：请改成你本机的局域网 IP（或留空自动探测）

# 试跑一个 openssl.exe，确认它能真正启动（msys 版在受限环境可能起不来）
function Test-OpensslWorkable([string]$exe) {
  if ([string]::IsNullOrEmpty($exe) -or -not (Test-Path -LiteralPath $exe)) { return $false }
  cmd /c "`"$exe`" version >nul 2>&1"
  return ($LASTEXITCODE -eq 0)
}

# ---- 1) 主路径：openssl（Git for Windows 自带，无需安装）----
$candidates = @(
  'C:\Program Files\Git\usr\bin\openssl.exe',
  'C:\Program Files\Git\mingw64\bin\openssl.exe',
  'C:\Program Files (x86)\Git\usr\bin\openssl.exe'
)
$pathCmd = Get-Command openssl -ErrorAction SilentlyContinue
if ($pathCmd) { $candidates += $pathCmd.Source }

$openssl = $null
foreach ($c in $candidates) {
  if (Test-OpensslWorkable $c) { $openssl = $c; break }
}

if ($openssl) {
  # 自签 RSA 2048、有效期 1 年、无加密私钥（-nodes），SAN 覆盖本机 IP/DNS
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'   # openssl 进度输出走 stderr，避免 PS5.1 转成错误
  & $openssl req -x509 -newkey rsa:2048 -keyout $keyPath -out $certPath `
    -days 365 -nodes -subj "/CN=$ip" `
    -addext "subjectAltName=DNS:$ip,DNS:localhost,IP:127.0.0.1,IP:$ip" 2>&1 | Out-Null
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prevEap
  if ($rc -ne 0) { throw "openssl 生成证书失败（exit code $rc）" }

  $expire = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certPath)).NotAfter.ToString('yyyy-MM-dd')
  Write-Host "已用 openssl 生成 cert.pem / key.pem（$openssl），有效期至 $expire"
  exit 0
}

# ---- 2) PS 7+ 回退：New-SelfSignedCertificate + PEM 导出 ----
if (-not [System.Security.Cryptography.X509Certificates.X509Certificate2].GetMethod('ExportCertificatePem')) {
  Write-Host '错误：未找到可用的 openssl，且当前 PowerShell 不支持 ExportCertificatePem（需 PowerShell 7+）。'
  Write-Host '请安装 Git for Windows（自带 openssl）或 PowerShell 7 后重新运行本脚本。'
  exit 1
}

$cert = $null
try {
  $cert = New-SelfSignedCertificate -Subject "CN=$ip" `
    -DnsName @($ip, 'localhost', '127.0.0.1') `
    -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 `
    -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(1)
  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  [System.IO.File]::WriteAllText($certPath, $cert.ExportCertificatePem())
  [System.IO.File]::WriteAllText($keyPath, $rsa.ExportPkcs8PrivateKeyPem())
  Write-Host "已生成 cert.pem / key.pem，有效期至 $($cert.NotAfter.ToString('yyyy-MM-dd'))"
} finally {
  if ($cert) {
    Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
  }
}
