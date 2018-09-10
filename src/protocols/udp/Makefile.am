include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	UDPProtocol.h test_udp.h

TEST = test_udp

check_PROGRAMS = test_udp

test_udp_SOURCES = 	../../Multiplexer.cc \
			../../StringCache.cc \
			../../Protocol.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../AnomalyManager.cc \
			../../flow/FlowManager.cc \
			../../FlowForwarder.cc \
			../vlan/VLanProtocol.cc \
			../ip/IPProtocol.cc \
                        $(TEST_FLOW_OBJECTS) \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../ip6/IPv6Protocol.cc \
			UDPProtocol.cc \
			test_udp.cc

test_udp_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_udp_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_udp_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

