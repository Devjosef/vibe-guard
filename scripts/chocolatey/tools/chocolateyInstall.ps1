# Chocolatey installation script for Vibe-Guard
# This script handles the installation process on Windows systems

# Stop on any error
$ErrorActionPreference = 'Stop'

# Package configuration
$packageName = 'vibe-guard'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url = 'https://github.com/Devjosef/vibe-guard/releases/download/v1.2.1/vibe-guard-windows-x64.exe'
$checksum = '033dc0a9be1d108b480a35f075ae18cee96585fe1972f6384980894571dcfa1a'
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