# RPM package specification for Vibe-Guard
# This file defines how to build the RPM package for RHEL/CentOS systems

# Basic package information
Name:           vibe-guard
Version:        1.2.1
Release:        1%{?dist}
# Distribution-specific release number
Summary:        Security scanner for developers who code fast
Vendor:         Vibe-Guard
Packager:       Josef <devjosef@github.com>

# License and source information
License:        MIT
URL:            https://github.com/Devjosef/vibe-guard
%ifarch x86_64
Source0:        https://github.com/Devjosef/vibe-guard/releases/download/v%{version}/vibe-guard-linux-x64
%endif
%ifarch aarch64
Source0:        https://github.com/Devjosef/vibe-guard/releases/download/v%{version}/vibe-guard-linux-arm64
%endif

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
# No source archive to extract — we package pre-built binaries from the release assets.
# CI downloads the appropriate binary into the SOURCES directory before rpmbuild.

# Build phase
%build
# No build step needed as we're packaging pre-built binaries

# Installation phase
%install
# Create the binary directory
mkdir -p %{buildroot}%{_bindir}
%ifarch x86_64
install -m 755 vibe-guard-linux-x64 %{buildroot}%{_bindir}/vibe-guard
%endif
%ifarch aarch64
install -m 755 vibe-guard-linux-arm64 %{buildroot}%{_bindir}/vibe-guard
%endif

# Files to include in the package
%files
%{_bindir}/vibe-guard

# Changelog
%changelog
* %(date "+%a %b %d %Y") Josef <devjosef@github.com> - 1.2.1-1
- Version 1.2.1: Enhanced CLI, modular frontend, rule updates, improved docs, clean up of bad code.
* %(date "+%a %b %d %Y") Josef <devjosef@github.com> - 1.0.0-1
- Initial release 