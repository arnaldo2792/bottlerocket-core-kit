%global goproject github.com/opencontainers
%global gorepo runc
%global goimport %{goproject}/%{gorepo}
%global commit 4144b63817ebcc5b358fc2c8ef95f7cddd709aa7
%global shortcommit 4144b63
%global gover 1.0.1

%global _dwz_low_mem_die_limit 0

Name: %{_cross_os}%{gorepo}
Version: %{gover}
Release: 1.%{shortcommit}%{?dist}
Summary: CLI for running Open Containers
License: Apache-2.0
URL: https://%{goimport}
Source0: https://%{goimport}/releases/download/v%{gover}/%{gorepo}.tar.xz#/%{gorepo}-v%{gover}.tar.xz

BuildRequires: git
BuildRequires: %{_cross_os}glibc-devel
BuildRequires: %{_cross_os}libseccomp-devel
Requires: %{_cross_os}libseccomp

%description
%{summary}.

%prep
%autosetup -Sgit -n %{gorepo}-%{gover} -p1
%cross_go_setup %{gorepo}-%{gover} %{goproject} %{goimport}

%build
%cross_go_configure %{goimport}
export LD_VERSION="-X main.version=%{gover}+bottlerocket"
export LD_COMMIT="-X main.gitCommit=%{commit}"
export BUILDTAGS="ambient seccomp selinux"
go build \
  -buildmode=pie \
  -ldflags="-linkmode=external ${LD_VERSION} ${LD_COMMIT}" \
  -tags="${BUILDTAGS}" \
  -o bin/runc .

%install
install -d %{buildroot}%{_cross_bindir}
install -p -m 0755 bin/runc %{buildroot}%{_cross_bindir}

%cross_scan_attribution go-vendor vendor

%files
%license LICENSE NOTICE
%{_cross_attribution_file}
%{_cross_attribution_vendor_dir}
%{_cross_bindir}/runc

%changelog
