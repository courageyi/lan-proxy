# 生成自签名证书 cert.pem / key.pem（有效期 1 年）
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$dns = @('192.168.110.168', 'localhost', '127.0.0.1')
$cert = New-SelfSignedCertificate -Subject 'CN=192.168.110.168' -DnsName $dns `
  -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 `
  -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(1)
try {
  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  [System.IO.File]::WriteAllText((Join-Path $dir 'cert.pem'), $cert.ExportCertificatePem())
  [System.IO.File]::WriteAllText((Join-Path $dir 'key.pem'), $rsa.ExportPkcs8PrivateKeyPem())
  Write-Host "已生成 cert.pem / key.pem，有效期至 $($cert.NotAfter.ToString('yyyy-MM-dd'))"
} finally {
  Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
}
