# RPM package specification for Vibe-Guard
# Includes support for Arch

Name:           vibe-guard
Version:        1.2.1
Release:        1%{?dist}
Summary:        Security scanner for developers who code fast
Vendor:         Vibe-Guard
Packager:       Josef <devjosef@github.com>

License:        MIT
URL:            github.com/Devjosef/vibe-guard

Source0:        vibe-guard-linux-x64
Source1:        vibe-guard-linux-arm64
Source2:        vibe-guard.service

Requires:       systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Vibe-Guard is a security scanner designed for developers who code fast.

%prep

%build

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_unitdir}

%ifarch x86_64
install -m 755 vibe-guard-linux-x64 %{buildroot}%{_bindir}/vibe-guard
%endif
%ifarch aarch64
install -m 755 vibe-guard-linux-arm64 %{buildroot}%{_bindir}/vibe-guard
%endif

install -m 644 vibe-guard.service %{buildroot}%{_unitdir}/vibe-guard.service

%post
%systemd_post vibe-guard.service

%preun
%systemd_preun vibe-guard.service

%postun
%systemd_postun_with_restart vibe-guard.service

%files
%{_bindir}/vibe-guard
%{_unitdir}/vibe-guard.service

%changelog
* Thu Mar 12 2026 Josef <devjosef@github.com> - 1.2.1-1
- Added multi-arch support
