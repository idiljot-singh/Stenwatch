# Build the Microsoft Store package: installer\Output\Stenwatch-<version>.msix (unsigned: the Store signs it).
# The three identity values come from Partner Center > the app > Product management > Product identity.
#   .\installer\build-msix.ps1 -Name "12345Publisher.Stenwatch" -Publisher "CN=XXXXXXXX-XXXX-..." -PublisherDisplayName "Diljot Singh Johal"
# -TestSign also signs it with a throwaway self-signed certificate, to install and try it on this machine first
# (installing needs that certificate in Local Machine > Trusted People, which asks for admin once).
param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Publisher, [Parameter(Mandatory)][string]$PublisherDisplayName,
      [string]$Version = "0.2.0.0", [switch]$TestSign)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot)
$kit = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
if (-not $kit) { throw "makeappx.exe not found: install the Windows SDK (winget install Microsoft.WindowsSDK.10.0.26100)" }
if ($Version -notmatch '^\d+\.\d+\.\d+\.0$') { throw "Store versions are four numbers ending in .0, for example 0.2.0.0" }

dotnet test src\Stenwatch.Tests; if ($LASTEXITCODE) { throw "tests failed" }
$dir = "dist\StenwatchMSIX"; if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
dotnet publish src\Stenwatch.App -c Release -r win-x64 --self-contained true -o $dir; if ($LASTEXITCODE) { throw "publish failed" }
dotnet publish src\Stenwatch.Cli -c Release -r win-x64 --self-contained true -o $dir; if ($LASTEXITCODE) { throw "publish failed" }
Copy-Item installer\msix\Assets "$dir\Assets" -Recurse
$esc = { param($s) [System.Security.SecurityElement]::Escape($s) }
(Get-Content installer\msix\AppxManifest.template.xml -Raw).Replace("__NAME__", (& $esc $Name)).Replace("__PUBLISHER__", (& $esc $Publisher)).
    Replace("__PUBLISHER_DISPLAY__", (& $esc $PublisherDisplayName)).Replace("__VERSION__", $Version) | Set-Content "$dir\AppxManifest.xml" -Encoding utf8

New-Item -ItemType Directory -Force installer\Output | Out-Null
$msix = "installer\Output\Stenwatch-$Version.msix"
& $kit.FullName pack /o /d $dir /p $msix; if ($LASTEXITCODE) { throw "makeappx failed" }
if ($TestSign) {
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq $Publisher | Select-Object -First 1
    if (-not $cert) { $cert = New-SelfSignedCertificate -Type Custom -Subject $Publisher -KeyUsage DigitalSignature -FriendlyName "Stenwatch MSIX test" -CertStoreLocation Cert:\CurrentUser\My -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}") }
    $signtool = Join-Path $kit.DirectoryName "signtool.exe"
    & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $msix; if ($LASTEXITCODE) { throw "signtool failed" }
    Export-Certificate -Cert $cert -FilePath installer\Output\Stenwatch-test.cer | Out-Null
    "Test-signed. To install here: import installer\Output\Stenwatch-test.cer into Local Machine > Trusted People (admin), then double-click the .msix."
}
Get-Item $msix | Select-Object Name, Length
(Get-FileHash $msix).Hash
