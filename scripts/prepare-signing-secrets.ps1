[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$P12Path,

    [Parameter(Mandatory = $true)]
    [string]$ProfilesFolder,

    [string]$OutputFolder = ".\signing-secrets",

    [switch]$CopyToClipboard
)

$ErrorActionPreference = "Stop"

function Convert-FileToBase64([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "File not found: $Path"
    }
    [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path)))
}

$p12 = (Resolve-Path -LiteralPath $P12Path).Path
$profiles = (Resolve-Path -LiteralPath $ProfilesFolder).Path
if (-not (Get-ChildItem -LiteralPath $profiles -Recurse -File -Filter "*.mobileprovision")) {
    throw "No .mobileprovision files found in $profiles"
}

$out = [IO.Path]::GetFullPath($OutputFolder)
New-Item -ItemType Directory -Force -Path $out | Out-Null

$zipPath = Join-Path $out "ios-provisioning-profiles.zip"
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

$profileFiles = Get-ChildItem -LiteralPath $profiles -Recurse -File -Filter "*.mobileprovision"
$tempProfiles = Join-Path $env:TEMP ("chromium-ios-profiles-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempProfiles | Out-Null
try {
    foreach ($file in $profileFiles) {
        $targetName = $file.Name
        $target = Join-Path $tempProfiles $targetName
        if (Test-Path -LiteralPath $target) {
            $targetName = "{0}-{1}{2}" -f $file.BaseName, ([guid]::NewGuid().ToString("N").Substring(0,8)), $file.Extension
            $target = Join-Path $tempProfiles $targetName
        }
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
    Compress-Archive -Path (Join-Path $tempProfiles "*") -DestinationPath $zipPath -CompressionLevel Optimal
}
finally {
    Remove-Item -LiteralPath $tempProfiles -Recurse -Force -ErrorAction SilentlyContinue
}

$certificateB64 = Convert-FileToBase64 $p12
$profilesB64 = Convert-FileToBase64 $zipPath

$certificateSecretPath = Join-Path $out "APPLE_CERTIFICATE_P12_BASE64.txt"
$profilesSecretPath = Join-Path $out "IOS_PROVISIONING_PROFILES_ZIP_BASE64.txt"
[IO.File]::WriteAllText($certificateSecretPath, $certificateB64, [Text.Encoding]::ASCII)
[IO.File]::WriteAllText($profilesSecretPath, $profilesB64, [Text.Encoding]::ASCII)

Write-Host ""
Write-Host "Created GitHub secret value files:"
Write-Host "  $certificateSecretPath"
Write-Host "  $profilesSecretPath"
Write-Host ""
Write-Host "Add these repository secrets:"
Write-Host "  APPLE_CERTIFICATE_P12_BASE64  <- contents of the first file"
Write-Host "  IOS_PROVISIONING_PROFILES_ZIP_BASE64 <- contents of the second file"
Write-Host "  APPLE_CERTIFICATE_PASSWORD <- password used when exporting the P12"
Write-Host ""
Write-Warning "These files contain private signing material. Do not commit them, upload them, or share them. Delete the output folder after adding the GitHub secrets."

if ($CopyToClipboard) {
    Set-Clipboard -Value $certificateB64
    Write-Host "Certificate Base64 copied to clipboard. Paste it into APPLE_CERTIFICATE_P12_BASE64 first."
    Write-Host "The profile ZIP Base64 is saved in $profilesSecretPath; copy it separately."
}
