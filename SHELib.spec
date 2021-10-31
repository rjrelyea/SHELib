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

%description
Homomorphic Encryption allows you to send encrypted data to a third party
and that third party can do computations on the data and return it to you
will all the computations happenning on the encrypted data itself. This
library uses the helib's binArithmetic library to implement as full a C++
semantic as possible. Helib uses the BGV homomorphic encryption system. This
system can do primitive operations of bit level addition and bit level
multiplication. Each operation adds some noise to the result, so only
a limitted number of operations can be done before the noise overwhelms our
actual data. Part of BGV is a way to set the noise level to a lower value
by decrypting our the encrypted value homophorphically. The details aren't
important for the use of SHE, but this affects the performance of any
calculations you do.


%prep
{{{ git_dir_setup_macro }}}

%build
make

%install
make install

%files
%{_libdir}
%{_includedir}
%{_datadir}

%check

%changelog
* Fri Oct 29 2021 Bob Relyea <rrelyea@redhat.com> - 2.2.1-1
- initial import

#{{{ git_dir_changelog }}}
#EOF
