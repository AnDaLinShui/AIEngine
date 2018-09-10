AUTOMAKE_OPTIONS = gnu

TEST = test_regex

check_PROGRAMS = test_regex

noinst_HEADERS =	Regex.h RegexManager.h 

test_regex_SOURCES =		../Packet.cc Regex.cc RegexManager.cc \
				test_regex.cc

test_regex_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST -I..
test_regex_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_regex_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework $(PCRE_LIB) 

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

