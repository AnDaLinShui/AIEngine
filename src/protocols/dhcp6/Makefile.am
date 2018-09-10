include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_dhcpv6.h DHCPv6Protocol.h DHCPv6Info.h

TEST = test_dhcpv6

check_PROGRAMS = test_dhcpv6

test_dhcpv6_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Protocol.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip6/IPv6Protocol.cc \
                        $(TEST_FLOW_OBJECTS) \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			DHCPv6Protocol.cc test_dhcpv6.cc

test_dhcpv6_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_dhcpv6_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_dhcpv6_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

