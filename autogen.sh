#!/bin/bash -e

# The addition of the glibtoolize command is for macOS users
libtoolize 2>/dev/null || glibtoolize 2>/dev/null \
&& aclocal \
&& autoheader \
&& automake --add-missing \
&& autoconf
