# RPM package specification for Vibe-Guard
# This file defines how to build the RPM package for RHEL/CentOS systems

# Basic package information
Name:           vibe-guard
Version:        1.0.0
Release:        1%{?dist}  # Distribution-specific release number
Summary:        Security scanner for developers who code fast
Vendor:         Vibe-Guard
Packager:       Josef <devjosef@github.com>

# License and source information
License:        MIT
URL:            https://github.com/Devjosef/vibe-guard
Source0:        https://github.com/Devjosef/vibe-guard/releases/download/v%{version}/vibe-guard-linux-%{arch}.tar.gz

# Build and runtime dependencies
BuildRequires:  systemd-rpm-macros  # Required for systemd integration
Requires:       systemd             # Runtime dependency

# Package description
%description
Vibe-Guard is a security scanner designed for developers who code fast.
It helps identify security vulnerabilities in your codebase.

This is an open source project maintained by Josef and the Vibe-Guard community.

# Preparation phase
%prep
%autosetup  # Automatically extract and patch the source

# Build phase
%build
# No build step needed as we're packaging pre-built binaries

# Installation phase
%install
# Create the binary directory
mkdir -p %{buildroot}%{_bindir}
# Install the binary with proper permissions
install -m 755 vibe-guard %{buildroot}%{_bindir}/

# Files to include in the package
%files
%{_bindir}/vibe-guard

# Changelog
%changelog
* %(date "+%a %b %d %Y") Josef <devjosef@github.com> - 1.0.0-1
- Initial release 