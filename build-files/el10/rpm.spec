# Sobek Nginx module

# Version and Release should come from command line, e.g.: --define '_sobek_version 0.32.0' --define '_sobek_release 1'
# If they do not, assume some generic defaults
%{!?_sobek_version:%define _sobek_version 0.0.0}
%{!?_sobek_release:%define _sobek_release 0}

Summary: Sobek Nginx module
Name: %{_sobek_name}
Version: %{_sobek_version}
%if "%{?dist:%{dist}}%{!?dist:0}" == ".rel"
Release: %{_sobek_release}%{?dist}.el%{rhel}
%else
Release: 0.%{_sobek_release}%{?dist}.el%{rhel}
%endif
URL: http://www.zavedil.com
Packager: Assen Totin <assen.totin@gmail.com>
Group: Applications
License: Proprietary
BuildArch: x86_64
BuildRequires: libxslt-devel, gd-devel, perl-ExtUtils-Embed, gcc, make, openssl-devel
Requires: nginx openssl

%description
Sobek Nginx module

%prep

%build

%install

mkdir -p $RPM_BUILD_ROOT/etc/nginx/conf.d
cp -r ${RPM_SOURCE_DIR}/support-files/nginx/conf.d/* $RPM_BUILD_ROOT/etc/nginx/conf.d

mkdir -p $RPM_BUILD_ROOT/usr/share/nginx/modules
cp -r ${RPM_SOURCE_DIR}/support-files/nginx/modules/* $RPM_BUILD_ROOT/usr/share/nginx/modules

mkdir -p $RPM_BUILD_ROOT/usr/lib64/nginx/modules
cp -r ${RPM_SOURCE_DIR}/lib/* $RPM_BUILD_ROOT/usr/lib64/nginx/modules

mkdir -p $RPM_BUILD_ROOT/usr/share/sobek
cp -r ${RPM_SOURCE_DIR}/www $RPM_BUILD_ROOT/usr/share/sobek

mkdir -p $RPM_BUILD_ROOT/var/www/sobek

mkdir -p $RPM_BUILD_ROOT/var/log/nginx/sobek

%clean
rm -rf $RPM_BUILD_ROOT

%files

%defattr(-, root, root)
/etc/nginx/conf.d/*
/usr/share/sobek
/usr/share/nginx/modules/*
/usr/lib64/nginx/modules/*
/var/www/sobek
/var/log/nginx/sobek

%pre

%post

if [ $1 == 1 ] ; then
	cp -r /usr/share/sobek/www/* /var/www/sobek
fi

systemctl restart nginx

%preun

%postun

# NB: Changelog records the changes in this spec file. For changes in the packaged product, use the ChangeLog file.
%changelog
* Wed Apr 1 2026 Assen Totin <assen.totin@gmail.com>
- Release 0.0.1

