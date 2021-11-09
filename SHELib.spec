Name:       {{{ git_dir_name }}}
Version:    {{{ git_dir_version }}}
Release:    1%{?dist}
Summary:    Simple Homomorphic Encryption Library

License:    MIT License
URL:        https://someurl.org
VCS:        {{{ git_dir_vcs }}}

Source: {{{ git_dir_pack }}}

BuildRequires: HElib > 2.0.0
BuildRequires: gmp-devel
BuildRequires: gcc-c++
BuildRequires: make
%if 0%{?rhel} != 9
BuildRequires: pandoc
%endif
Requires: HELib > 2.0.0

%description
Homomorphic Encryption allows you to send encrypted data to a third party
and that third party can do computations on the data and return it to you
will all the computations happening on the encrypted data itself. This
library uses the HElib's binArithmetic library to implement as full a C++
semantic as possible. HElib uses the BGV homomorphic encryption system. This
system can do primitive operations of bit level addition and bit level
multiplication. Each operation adds some noise to the result, so only
a limited number of operations can be done before the noise overwhelms our
actual data. Part of BGV is a way to set the noise level to a lower value
by decrypting our the encrypted value homophorphically. The details aren't
important for the use of SHELib, but this affects the performance of any
calculations you do.


%prep
{{{ git_dir_setup_macro }}}

%build
export TARGET_INCLUDE=%{_includedir}
export TARGET_LIB=%{_libdir}
export TARGET_BIN=%{_bindir}
export TARGET_MAN=%{_mandir}
export TARGET_DOC=%{_datadir}/doc
export VERSION=%{version}
make

%install
export DESTDIR=$RPM_BUILD_ROOT
export TARGET_INCLUDE=%{_includedir}
export TARGET_LIB=%{_libdir}
export TARGET_BIN=%{_bindir}
export TARGET_MAN=%{_mandir}
export TARGET_DOC=%{_datadir}/doc
export VERSION=%{version}
%if 0%{?rhel} != 9
make install
%else
make install-nodoc
%endif

%files
%{_libdir}/libSHELib.a
%{_libdir}/pkgconfig/SHELib.pc
%{_bindir}/SHETest
%{_bindir}/SHEPerf
%{_bindir}/SHEEval
%{_includedir}/SHELib
%if 0%{?rhel} != 9
%doc %{_mandir}/man3/*
%doc %{_datadir}/doc/SHELib
%endif

%check
# do a reasonable test: use float, but skip div, log and trig tests.
# use the smallest security level
./SHETest --no-trig --float --no-log --no-div 19 600

%changelog
{{{ git_dir_changelog }}}
* Fri Oct 29 2021 Bob Relyea <rrelyea@redhat.com> - 0.0.0-0
- initial import
#EOF
