include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	NetbiosProtocol.h NetbiosInfo.h test_netbios.h

TEST = test_netbios

check_PROGRAMS = test_netbios

test_netbios_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Protocol.cc \
			../ethernet/EthernetProtocol.cc \
			../../StringCache.cc \
			../../Flow.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
                        $(TEST_FLOW_OBJECTS) \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			NetbiosProtocol.cc test_netbios.cc

test_netbios_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_netbios_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_netbios_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

