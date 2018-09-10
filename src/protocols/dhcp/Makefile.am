include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_dhcp.h DHCPProtocol.h DHCPInfo.h

TEST = test_dhcp

check_PROGRAMS = test_dhcp

test_dhcp_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Protocol.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
                        $(TEST_FLOW_OBJECTS) \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			DHCPProtocol.cc test_dhcp.cc

test_dhcp_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_dhcp_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_dhcp_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

