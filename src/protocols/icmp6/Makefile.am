include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	ICMPv6Protocol.h ICMPv6Header.h test_icmp6.h

TEST = test_icmp

check_PROGRAMS = test_icmp6

test_icmp6_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../StringCache.cc \
			../../Protocol.cc \
			../../AnomalyManager.cc \
			$(TEST_FLOW_OBJECTS) \
			../ethernet/EthernetProtocol.cc \
			../ip6/IPv6Protocol.cc ICMPv6Header.cc \
			ICMPv6Protocol.cc test_icmp6.cc

test_icmp6_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_icmp6_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_icmp6_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

