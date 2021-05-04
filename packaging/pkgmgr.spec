Name:       pkgmgr
Summary:    Packager Manager client library package
Version:    0.12.9
Release:    0
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: %{name}.manifest
Source1002: %{name}-client.manifest
Source1003: %{name}-client-devel.manifest
Source1004: %{name}-installer.manifest
Source1005: %{name}-installer-devel.manifest
Source1006: %{name}-types-devel.manifest
Source1007: %{name}.conf
Source1008: %{name}-installer-signal-agent.service
Source1009: %{name}-installer-signal-agent.socket
Requires(post): /usr/sbin/useradd
Requires(post): capi-system-info

BuildRequires:  cmake
BuildRequires:  unzip
BuildRequires:  gettext-tools
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(xdgmime)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(minizip)
BuildRequires:  pkgmgr-info-parser-devel
BuildRequires:  pkgmgr-info-parser
BuildRequires:  fdupes

%description
Packager Manager client library package for packaging


%package client
Summary:    Package Manager client library develpoment package
Requires:   %{name} = %{version}-%{release}
Requires: shared-mime-info
Requires(post): pkgmgr

%description client
Package Manager client library develpoment package for packaging


%package client-devel
Summary:    Package Manager client library develpoment package
Requires:   %{name} = %{version}-%{release}
Requires: pkgmgr-client

%description client-devel
Package Manager client library develpoment package for packaging


%package installer
Summary:    Library for installer frontend/backend
Requires:   %{name} = %{version}-%{release}

%description installer
Library for installer frontend/backend for packaging.


%package installer-devel
Summary:    Dev package for libpkgmgr-installer
Requires:   %{name} = %{version}-%{release}
Requires:   pkgmgr-installer = %{version}-%{release}

%description installer-devel
Dev package for libpkgmgr-installer for packaging.


%package types-devel
Summary:    Package Manager manifest parser develpoment package
Requires:   %{name} = %{version}-%{release}

%description types-devel
Package Manager client types develpoment package for packaging

%prep
%setup -q
cp %{SOURCE1001} %{SOURCE1002} %{SOURCE1003} %{SOURCE1004} %{SOURCE1005} %{SOURCE1006} .

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER}

%__make %{?_smp_mflags}

%install
%make_install
rm -f  %{buildroot}%{_bindir}/pkgmgr_backend_sample
rm -f %{buildroot}%{_libdir}/libpkgmgr_backend_lib_sample.so
rm -f %{buildroot}%{_libdir}/libpkgmgr_parser_lib_sample.so

mkdir -p %{buildroot}%{_tmpfilesdir}/
install -m 0644 %{SOURCE1007} %{buildroot}%{_tmpfilesdir}/pkgmgr.conf

mkdir -p %{buildroot}%{_unitdir_user}/sockets.target.wants
install -m 0644 %{SOURCE1008} %{buildroot}%{_unitdir_user}/pkgmgr-installer-signal-agent.service
install -m 0644 %{SOURCE1009} %{buildroot}%{_unitdir_user}/pkgmgr-installer-signal-agent.socket
ln -sf ../pkgmgr-installer-signal-agent.socket %{buildroot}%{_unitdir_user}/sockets.target.wants/pkgmgr-installer-signal-agent.socket

mkdir -p %{buildroot}%{_sysconfdir}/package-manager/backend
mkdir -p %{buildroot}%{_sysconfdir}/package-manager/backendlib
mkdir -p %{buildroot}%{_sysconfdir}/opt/upgrade

touch  %{buildroot}%{_sysconfdir}/package-manager/backend/default
chmod 755 %{buildroot}%{_sysconfdir}/package-manager/backend/default
touch  %{buildroot}%{_sysconfdir}/package-manager/backend/pkgtool
chmod 755 %{buildroot}%{_sysconfdir}/package-manager/backend/pkgtool


%fdupes %{buildroot}

%post
/sbin/ldconfig

# Create tizenglobalapp user needed for global installation
useradd %TZ_SYS_GLOBALAPP_USER -r -c "system user for common applications" -g root -u 201

# change owner of TZ_USER_APP (/etc/skel/apps_rw) to tizenglobalapp
saveHOME="$HOME"
HOME="%{_sysconfdir}/skel"
. "%{_sysconfdir}/tizen-platform.conf"

chown %TZ_SYS_GLOBALAPP_USER:root $TZ_USER_APP

# add .shared and .shared_tmp at skel
mkdir -p $TZ_USER_APP/.shared
mkdir -p $TZ_USER_APP/.shared_tmp
chsmack -a User::Home $TZ_USER_APP/.shared
chsmack -a User::Home $TZ_USER_APP/.shared_tmp
chmod 755 $TZ_USER_APP/.shared
chmod 755 $TZ_USER_APP/.shared_tmp

HOME="$saveHOME"

%post -n pkgmgr-client -p /sbin/ldconfig

%postun -n pkgmgr-client -p /sbin/ldconfig

%post -n pkgmgr-installer -p /sbin/ldconfig

%postun -n pkgmgr-installer -p /sbin/ldconfig

%posttrans
if [ ! -f %{TZ_SYS_DB}/.pkgmgr_parser.db ]; then
  pkg_initdb --ro
  install_preload_pkg
  if [ -f /tmp/.preload_install_error ]; then
    if [ ! -d /tmp/.postscript/error ]; then
      mkdir -p /tmp/.postscript/error
    fi
    echo "preload install failed" > /tmp/.postscript/error/%{name}_error
  else
    pkgcmd -l --global 1>&2
  fi
  %{_sysconfdir}/package-manager/pkgmgr-label-initial-image.sh
fi
rm -rf %{_sysconfdir}/package-manager/pkgmgr-label-initial-image.sh

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%dir %{_sysconfdir}/package-manager/backend
%dir %{_sysconfdir}/package-manager/backendlib
%{_sysconfdir}/package-manager/backend/*
%{_tmpfilesdir}/pkgmgr.conf

%files client
%manifest %{name}-client.manifest
%license LICENSE
%defattr(-,root,root,-)
%dir %{_sysconfdir}/package-manager
%config %{_sysconfdir}/package-manager/pkg_path.conf
%{_libdir}/libpkgmgr-client.so.*

%files client-devel
%manifest %{name}-client-devel.manifest
%defattr(-,root,root,-)
%{_includedir}/*.h
%{_libdir}/pkgconfig/pkgmgr.pc
%{_libdir}/libpkgmgr-client.so

%files installer
%manifest %{name}-installer.manifest
%license LICENSE
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_installer.so.*
%{_bindir}/pkgmgr-installer-signal-agent
%{_unitdir_user}/pkgmgr-installer-signal-agent.service
%{_unitdir_user}/pkgmgr-installer-signal-agent.socket
%{_unitdir_user}/sockets.target.wants/pkgmgr-installer-signal-agent.socket

%files installer-devel
%manifest %{name}-installer-devel.manifest
%defattr(-,root,root,-)
%dir %{_includedir}/pkgmgr
%{_includedir}/pkgmgr/*.h
%{_libdir}/pkgconfig/pkgmgr-installer.pc
%{_libdir}/libpkgmgr_installer.so

%files types-devel
%manifest %{name}-types-devel.manifest
%defattr(-,root,root,-)
%{_includedir}/package-manager-*.h
%{_libdir}/pkgconfig/pkgmgr-types.pc
