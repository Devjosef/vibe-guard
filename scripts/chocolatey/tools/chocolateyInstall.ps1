# Chocolatey installation script for Vibe-Guard
# This script handles the installation process on Windows systems

# Stop on any error
$ErrorActionPreference = 'Stop'

# Package configuration
$packageName = 'vibe-guard'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url = 'https://github.com/Devjosef/vibe-guard/releases/download/v1.0.0/vibe-guard-windows-amd64.zip'
$checksum = 'YOUR_SHA256_HERE' # Replace with actual SHA256 after release
$checksumType = 'sha256'

# Package installation arguments
$packageArgs = @{
    packageName    = $packageName
    unzipLocation  = $toolsDir
    url            = $url
    checksum       = $checksum
    checksumType   = $checksumType
}

# Install the package using Chocolatey's zip package installer
Install-ChocolateyZipPackage @packageArgs

# Create a shim for the executable
# This makes the command available system-wide
$binPath = Join-Path $toolsDir "vibe-guard.exe"
Install-BinFile -Name "vibe-guard" -Path $binPath 