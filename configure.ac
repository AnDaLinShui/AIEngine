AC_INIT([aiengine],[1.9.0],[me@ryadpasha.com],[],[https://ryadpasha.com])

AM_INIT_AUTOMAKE([subdir-objects])
AM_PROG_LIBTOOL

AM_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])
m4_include([m4/ax_compare_version.m4])
m4_include([m4/ax_python_devel.m4])
m4_include([m4/ax_boost_base.m4])
m4_include([m4/ax_boost_python.m4])
m4_include([m4/ax_boost_asio.m4])
m4_include([m4/ax_boost_filesystem.m4])
m4_include([m4/ax_boost_regex.m4])
m4_include([m4/ax_boost_system.m4])
m4_include([m4/ax_boost_unit_test_framework.m4])
m4_include([m4/ax_boost_program_options.m4])
m4_include([m4/ax_cxx_compile_stdcxx.m4])
m4_include([m4/ax_pkg_swig.m4])
m4_include([m4/ax_swig_enable_cxx.m4])
m4_include([m4/ax_swig_multi_module_support.m4])
m4_include([m4/ax_prog_javah.m4])
m4_include([m4/ax_prog_java_cc.m4])
m4_include([m4/ax_lua.m4])
m4_include([m4/ax_code_coverage.m4])
m4_include([m4/ax_check_compile_flag.m4])

AC_PREREQ(2.59)

AC_PROG_INSTALL

AC_CANONICAL_HOST
AM_CONDITIONAL([__OPENBSD__],false)
AM_CONDITIONAL([__FREEBSD__],false)
AM_CONDITIONAL([__LINUX__],false)
AM_CONDITIONAL([__DARWIN__],false)

AC_LANG([C++])
AC_PROG_CXX([g++ c++])
AC_PROG_MAKE_SET
AC_HEADER_STDC

AX_CXX_COMPILE_STDCXX(14, [noext], [mandatory])
#AC_COMPILE_STDCXX_11([noext],[mandatory])

#if test "$ac_cv_cxx_compile_cxx11_cxx" = no ||
#    test "$ac_cv_cxx_compile_cxx11_gxx" = no; then
#    AC_MSG_ERROR([C++11 support is an essential dependency for AIEngine, install it.])
#else
#    AM_CXXFLAGS="$AM_CXXFLAGS -std=c++14"
#fi

case $host in
    *free*)
    	AC_DEFINE([__FREEBSD__],[1],[FreeBSD Host])
    	AM_CONDITIONAL([__FREEBSD__],true)
# The macro ax_boost_python is not working properly on freebsd
# in order to fix the problem I just updated the BOOST_PYTHON_LIB
# and if something is wrong will explode later :D
	BOOST_PYTHON_LIB="boost_python"
        ax_cv_cxx_compiler_version=$($CXX --version | head -n 1 | cut -d " " -f 4)
    ;;
    *openbsd*)
    	AC_DEFINE([__OPENBSD__],[1],[OpenBSD Host])
    	AM_CONDITIONAL([__OPENBSD__],true)
        ax_cv_cxx_compiler_version=$($CXX --version | head -n 1 | cut -d " " -f 4)
    ;;
    *linux*)
	AC_DEFINE([__LINUX__],[1],[Linux Host])
    	AM_CONDITIONAL([__LINUX__],true)
        ax_cv_cxx_compiler_version="`$CXX -dumpversion`"
    ;;
    *darwin*)
	AC_DEFINE([__DARWIN__],[1],[Mac OS Darwin Host])
    	AM_CONDITIONAL([__DARWIN__],true)
        ax_cv_cxx_compiler_version=$($CXX --version | head -n 1 | cut -d " " -f 4)
    ;;
esac

AC_SUBST([cxx_version],[$($CXX --version|head -n 1)])

AM_CXXFLAGS="$AM_CXXFLAGS -Wno-write-strings"
# Dont use it unless you know what you are doing
# CXXFLAGS="-std=c++11"
# CXXFLAGS="-std=c++0x"

# Verify the c++ compiler version, needs 5.x up
AC_MSG_CHECKING(for c++ versions higher than 5.x)
AX_COMPARE_VERSION([$ax_cv_cxx_compiler_version], [ge], [5.0],
    [is_ge_gxx50=yes], [is_ge_gxx50=no])

if test "x$is_ge_gxx50" != "xyes"; then
    AC_MSG_ERROR([G++ 5.x or higher required (found $ax_cv_cxx_compiler_version)])
fi
AC_MSG_RESULT([$is_ge_gxx50])

##########################################################################
# Pcap support
##########################################################################
#AC_CHECK_HEADER([pcap.h])
#AC_CHECK_LIB(pcap,main,,AC_MSG_ERROR([Pcap support is an essential dependency for AIEngine, install it.]))
have_libpcap=no
AC_CHECK_HEADER(pcap.h,
      AC_CHECK_LIB(pcap, main,
      [have_libpcap=yes LIBS="-lpcap $LIBS"]))

if test "$have_libpcap" = no; then
    AC_MSG_ERROR([Libpcap support is an essential dependency for AIEngine, install it.])
fi

##########################################################################
# Boost support
##########################################################################

AX_BOOST_BASE([1.50.0])
AX_BOOST_ASIO
AX_BOOST_SYSTEM
AX_BOOST_REGEX
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS

AM_PATH_PYTHON

# If want a specific python version change the value
# but allways with the commas!!!
AX_PYTHON_DEVEL([>= '2.7'])
AX_BOOST_PYTHON

##########################################################################
# Log4cxx support
##########################################################################
AC_CHECK_HEADER([log4cxx/logger.h])
AC_CHECK_LIB([log4cxx],[main],have_log4cxx=yes,have_log4cxx=no)

if test x"$have_log4cxx" = x"yes"; then
    AC_DEFINE([HAVE_LIBLOG4CXX],[1],[Log4cxx support])
    AM_CONDITIONAL([HAVE_LIBLOG4CXX],true)
else
    # AC_DEFINE([HAVE_LIBLOG4CXX],[0],[No Log4cxx support])
    AM_CONDITIONAL([HAVE_LIBLOG4CXX],false)
fi

##########################################################################
# Pcre++ support
##########################################################################

AC_MSG_CHECKING(for perl regular expressions support)
AC_ARG_WITH(pcre, AC_HELP_STRING([--with-pcre],[Enable pcre support (default yes)]),
    [WITH_PCRE=$withval],[WITH_PCRE=yes])
AC_MSG_RESULT([$WITH_PCRE])

if test "$WITH_PCRE" != "no"; then
  AC_PATH_PROG(PCRECONFIG, pcre-config)

  if test x"$PCRECONFIG" != x; then
    PCRE_LIB=`$PCRECONFIG --libs`
    CPPFLAGS="$CPPFLAGS `$PCRECONFIG --cflags`"
    AC_DEFINE([HAVE_LIBPCRE], [1], [libpcre])
    AC_DEFINE([HAVE_PCRE_H], [1], [pcre.h])
  else
     AC_MSG_ERROR([pcre-config not found, install the pcre-devel package or build with --without-pcre])
  fi
fi

AC_SUBST(PCRE_LIB)
    AC_MSG_CHECKING(for PCRE JIT support)
    AC_TRY_COMPILE([ #include <pcre.h> ],
        [
        int jit = 0;
        pcre_config(PCRE_CONFIG_JIT, &jit);
        ],
        [ pcre_jit_available=yes ], [ pcre_jit_available=no ]
        )

    if test "x$pcre_jit_available" = "xyes"; then
       AC_MSG_RESULT(yes)
       AC_DEFINE([PCRE_HAVE_JIT], [1], [Pcre with JIT compiler support enabled])

       AC_MSG_CHECKING(for PCRE JIT support usability)
       AC_TRY_COMPILE([ #include <pcre.h> ],
           [
           const char* regexstr = "(a|b|c|d)";
           pcre *re;
           const char *error;
           pcre_extra *extra;
           int err_offset;
           re = pcre_compile(regexstr,0, &error, &err_offset,NULL);
           extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &error);
           if (extra == NULL)
               exit(EXIT_FAILURE);
           int jit = 0;
           int ret = pcre_fullinfo(re, extra, PCRE_INFO_JIT, &jit);
           if (ret != 0 || jit != 1)
               exit(EXIT_FAILURE);
           exit(EXIT_SUCCESS);
           ],
           [ pcre_jit_works=yes ], [:]
       )
       if test "x$pcre_jit_works" != "xyes"; then
           AC_MSG_RESULT(no)
           echo
           echo "   PCRE JIT support detection worked but testing it failed"
           echo "   something odd is going on, please file a bug report."
           echo
           exit 1
       else
           AC_MSG_RESULT(yes)
       fi
    fi

##########################################################################
# Debug compilation support
##########################################################################

AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable debug data generation (def=no)])],
    [debugit="$enableval"],
    [debugit=no])
AC_MSG_RESULT([$debugit])

if test x"$debugit" = x"yes"; then
    AC_DEFINE([DEBUG],[],[Debug Mode])
    AM_CXXFLAGS="-O0 $AM_CXXFLAGS -g -Wall -Wno-uninitialized "
fi

##########################################################################
# TCP QoS Metrics support
##########################################################################

AC_MSG_CHECKING([whether to build with TCP QoS Metrics information])
AC_ARG_ENABLE([tcpqos],
    [AS_HELP_STRING([--enable-tcpqos],
        [enable TCP QoS Metrics support (def=no)])],
    [tcpqos="$enableval"],
    [tcpqos=no])
AC_MSG_RESULT([$tcpqos])

if test x"$tcpqos" = x"yes"; then
    AC_DEFINE([HAVE_TCP_QOS_METRICS],[],[TCP Qos Metrics support])
fi

##########################################################################
# bloom filter support
##########################################################################

AC_MSG_CHECKING([whether to build bloom filters])
AC_ARG_ENABLE([bloomfilter],
    [AS_HELP_STRING([--enable-bloomfilter],
        [enable bloom filter support (def=no)])],
    [bloom_support=yes],
    [bloom_support=no])
AC_MSG_RESULT([$bloom_support])

if test x"$bloom_support" = x"yes"; then
    AC_CHECK_HEADER([boost/bloom_filter/basic_bloom_filter.hpp],[have_bloom_support=yes],
        [have_bloom_support=no])

    if test x"$have_bloom_support" = x"no"; then
        AC_MSG_ERROR([Boost Bloom filter headers not present on the system.])
    fi
    AC_DEFINE([HAVE_BLOOMFILTER],[1],[Bloom filter support])
fi

##########################################################################
# Swig ruby support
##########################################################################

AM_CONDITIONAL([HAVE_RUBY_SUPPORT],false)

have_ruby_support=no
AC_PATH_PROGS([SWIG],[swig swig2.0 swig3.0])
if test -z "$SWIG" ; then
    enable_swig=no
else
    enable_swig=yes
    AX_PKG_SWIG(3.0.0, , AC_MSG_ERROR("Swig is required."))
    AX_SWIG_ENABLE_CXX
    AX_SWIG_MULTI_MODULE_SUPPORT
    AC_CHECK_HEADER(ruby.h,[have_ruby_support=yes],[have_ruby_support=no])

    if test x"$have_ruby_support" = x"yes"; then
        AM_CONDITIONAL([HAVE_RUBY_SUPPORT],true)
    fi
fi


##########################################################################
# Swig Java support
##########################################################################

AM_CONDITIONAL([HAVE_JAVA_SUPPORT],false)

AC_SUBST([AM_JAVAFLAGS],[hola])

# The m4 macros of java modify the variable CPPFLAGS
# and the project shares this variable so we modify to the previous value
temp_cpp_flags="$CPPFLAGS"

have_java_support=no
AX_PROG_JAVA_CC(javac, gcj)

if test -z "$JAVA_CC" ; then
    enable_swig_java=no
else
    enable_swig_java=yes
    AX_PROG_JAVAH
    AC_CHECK_HEADER(jni.h,[have_java_support=yes],[have_java_support=no])

    if test x"$have_java_support" = x"yes"; then
        AM_CONDITIONAL([HAVE_JAVA_SUPPORT],true)
    fi
fi
AM_JAVAFLAGS="$CPPFLAGS"
CPPFLAGS="$temp_cpp_flags"

##########################################################################
# Swig Lua support
##########################################################################

AM_CONDITIONAL([HAVE_LUA_SUPPORT],false)

enable_lua_support=no
have_lua_support=no
AX_PROG_LUA(5.1, [], [enable_lua_support=yes], [enable_lua_support=no])

if test x"$enable_lua_support" = x"yes"; then
    AX_LUA_HEADERS([have_lua_support=yes], [have_lua_support=no])

    if test x"$have_lua_support" = x"yes"; then
        AM_CONDITIONAL([HAVE_LUA_SUPPORT], true)
    fi
fi

LUA_INCLUDE="$LUA_INCLUDE"

##########################################################################
# Swig Go support
##########################################################################

AM_CONDITIONAL([HAVE_GO_SUPPORT],false)
have_go_support=no
if test x"$enable_swig" = x"yes"; then
    AM_CONDITIONAL([HAVE_GO_SUPPORT], true)
    have_go_support=yes
fi

##########################################################################
# TCP/UDP reject connection support
##########################################################################

AC_MSG_CHECKING([whether to reject TCP/UDP connections support])
AC_ARG_ENABLE([reject],
    [AS_HELP_STRING([--enable-reject],
        [enable TCP/UDP reject connection support (def=no)])],
    [reject_support=yes],
    [reject_support=no])
AC_MSG_RESULT([$reject_support])

if test x"$reject_support" = x"yes"; then
    AC_DEFINE([HAVE_REJECT_FLOW],[1],[TCP/UDP reject flow support])
#else
#    AC_DEFINE([HAVE_REJECT_FLOW],[0],[TCP/UDP reject flow support])
fi

##########################################################################
# Python GIL lock support for multithread enviroments
##########################################################################

AC_MSG_CHECKING([whether to build with python threads support (GIL lock)])
AC_ARG_ENABLE([pythongil],
    [AS_HELP_STRING([--enable-pythongil],
        [enable Python Gil support for multithreading environtments (def=no)])],
    [pythongil_support=yes],
    [pythongil_support=no])
AC_MSG_RESULT([$pythongil_support])

if test x"$pythongil_support" = x"yes"; then
    AC_DEFINE([HAVE_PYTHON_GIL],[1],[Python GIL support])
fi

##########################################################################
# Enable for static memory for caches
##########################################################################

AC_MSG_CHECKING([whether to build with static memory blocks (256) bytes])
AC_ARG_ENABLE([static-memory],
    [AS_HELP_STRING([--enable-static-memory],
        [enable static/fixed memory support (def=no)])],
    [static_memory=yes],
    [static_memory=no])
AC_MSG_RESULT([$static_memory])

if test x"$static_memory" = x"yes"; then
    AC_DEFINE([HAVE_STATIC_MEMORY_CACHE], [1], [Static memory support])
fi

##########################################################################
# Enable gcov and lcov coverage
##########################################################################

AX_CODE_COVERAGE
if test x"enable_code_coverage" = x"yes"; then
    AM_CXXFLAGS="$AM_CXXFLAGS -O0"
fi

##########################################################################
# Enable address sanatizer
##########################################################################

AC_MSG_CHECKING([whether to build tests with sanatizer checks])
AC_ARG_ENABLE([sanatizer],
    [AS_HELP_STRING([--enable-sanatizer],
        [enable sanatizer tests support (def=no)])],
    [sanatizer=yes],
    [sanatizer=no])
AC_MSG_RESULT([$sanatizer])

EXTRA_TEST_CPPFLAGS=""
EXTRA_TEST_LDFLAGS=""

if test x"$sanatizer" = x"yes"; then
    AX_CHECK_COMPILE_FLAG([-fsanitize=address],
        [EXTRA_TEST_CPPFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer" EXTRA_TEST_LDFLAGS="-g -fsanitize=address"], [], [])
    AX_CHECK_COMPILE_FLAG([-fsanitize=memory],
        [EXTRA_TEST_CPPFLAGS="$EXTRA_TEST_CPPFLAGS -fsanitize=memory" EXTRA_TEST_LDFLAGS="$EXTRA_TEST_LDFLAGS -fsanitize=memory"], [], [])
    AX_CHECK_COMPILE_FLAG([-fsanitize=leak],
        [EXTRA_TEST_CPPFLAGS="$EXTRA_TEST_CPPFLAGS -fsanitize=leak" EXTRA_TEST_LDFLAGS="$EXTRA_TEST_LDFLAGS -fsanitize=leak"], [], [])
#    AX_CHECK_COMPILE_FLAG([-fsanitize=undefined],
#        [EXTRA_TEST_CPPFLAGS="$EXTRA_TEST_CPPFLAGS -fsanitize=undefined" EXTRA_TEST_LDFLAGS="$EXTRA_TEST_LDFLAGS -fsanitize=undefined"], [], [])
fi

AC_SUBST(EXTRA_TEST_CPPFLAGS)
AC_SUBST(EXTRA_TEST_LDFLAGS)

##########################################################################

CXXFLAGS=$AM_CXXFLAGS

##########################################################################

AC_CONFIG_FILES([
Makefile
man/Makefile
utils/Makefile
examples/Makefile
pcapfiles/Makefile
src/Makefile
src/ipset/Makefile
src/regex/Makefile
src/user/Makefile
src/learner/Makefile
src/names/Makefile
src/flow/Makefile
src/protocols/ethernet/Makefile
src/protocols/vlan/Makefile
src/protocols/mpls/Makefile
src/protocols/pppoe/Makefile
src/protocols/ip/Makefile
src/protocols/ip6/Makefile
src/protocols/gprs/Makefile
src/protocols/vxlan/Makefile
src/protocols/openflow/Makefile
src/protocols/gre/Makefile
src/protocols/icmp/Makefile
src/protocols/icmp6/Makefile
src/protocols/udp/Makefile
src/protocols/tcp/Makefile
src/protocols/http/Makefile
src/protocols/ssl/Makefile
src/protocols/smtp/Makefile
src/protocols/imap/Makefile
src/protocols/pop/Makefile
src/protocols/modbus/Makefile
src/protocols/bitcoin/Makefile
src/protocols/mqtt/Makefile
src/protocols/dns/Makefile
src/protocols/sip/Makefile
src/protocols/dhcp/Makefile
src/protocols/ntp/Makefile
src/protocols/snmp/Makefile
src/protocols/ssdp/Makefile
src/protocols/coap/Makefile
src/protocols/rtp/Makefile
src/protocols/netbios/Makefile
src/protocols/quic/Makefile
src/protocols/tcpgeneric/Makefile
src/protocols/udpgeneric/Makefile
src/protocols/frequency/Makefile
src/protocols/smb/Makefile
src/protocols/dhcp6/Makefile
src/protocols/ssh/Makefile
src/protocols/dcerpc/Makefile
docs/Makefile
])


AC_OUTPUT

echo "
  aiengine
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Host..................: $host
  Prefix................: $prefix
  Debug Build...........: $debugit
  C++ version...........: $cxx_version
  C++ compiler..........: $CXX $AM_CXXFLAGS $CPPFLAGS
  Linker................: $LD $LDFLAGS $LIBS
  Boost include.........: $BOOST_CPPFLAGS/boost
  Boost.................: $boost_lib_version_req
  Boost python lib......: $BOOST_PYTHON_LIB
  Python................: $PYTHON_VERSION $ax_python_bin
  Python include path...: $python_path
  Log4cxx...............: $ac_cv_lib_log4cxx_main
  Libpcap...............: $ac_cv_lib_pcap_main
  Pcre..................: $WITH_PCRE
  Pcre JIT..............: $pcre_jit_works
  Bloom filter support..: $bloom_support
  Swig support..........: $enable_swig
  Swig/Ruby support.....: $have_ruby_support
  Swig/Java support.....: $have_java_support
  Swig/Lua support......: $have_lua_support
  Swig/Go support.......: $have_go_support
  TCP Qos support.......: $tcpqos
  TCP/UDP reject support: $reject_support
  Python GIL support....: $pythongil_support
  Static memory support.: $static_memory
  Code coverage.........: $enable_code_coverage
"
