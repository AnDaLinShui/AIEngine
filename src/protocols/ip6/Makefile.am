include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS = 	IPv6Protocol.h IPv6HdrIncl.h IPv6Header.h test_ip6.h

TEST = test_ip6

check_PROGRAMS = test_ip6

test_ip6_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../../Protocol.cc \
			$(TEST_FLOW_OBJECTS) \
			../ethernet/EthernetProtocol.cc \
			IPv6Protocol.cc test_ip6.cc

test_ip6_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -I../../test -DSTAND_ALONE_TEST
test_ip6_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_ip6_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

