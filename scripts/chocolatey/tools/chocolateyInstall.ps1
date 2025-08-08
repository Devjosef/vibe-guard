# Chocolatey installation script for Vibe-Guard
# This script handles the installation process on Windows systems

# Stop on any error
$ErrorActionPreference = 'Stop'

# Package configuration
$packageName = 'vibe-guard'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url = 'https://github.com/Devjosef/vibe-guard/releases/download/v1.1.2/vibe-guard-windows-x64.exe'
$checksum = 'c20fcee47fab199c98d1242a452435558c9270290c9f26c4f7eb389d24167356'
$checksumType = 'sha256'

# Download and install the executable
$packageArgs = @{
    packageName    = $packageName
    fileType       = 'exe'
    url            = $url
    checksum       = $checksum
    checksumType   = $checksumType
    validExitCodes = @(0)
}

# Install the package using Chocolatey's file installer
Install-ChocolateyPackage @packageArgs

# Create a shim for the executable
# This makes the command available system-wide
$binPath = Join-Path $toolsDir "vibe-guard.exe"
Install-BinFile -Name "vibe-guard" -Path $binPath 