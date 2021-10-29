Name:       {{{ git_dir_name }}}
Version:    {{{ git_dir_version }}}
Release:    1%{?dist}
Summary:    This is a test package.

License:    MIT License
URL:        https://someurl.org
VCS:        {{{ git_dir_vcs }}}

Source: {{{ git_dir_pack }}}

%description
This is a test package.

%prep
{{{ git_dir_setup_macro }}}

%changelog
{{{ git_dir_changelog }}}
EOF
