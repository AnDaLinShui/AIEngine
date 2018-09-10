include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	SNMPProtocol.h test_snmp.h

TEST = test_snmp

check_PROGRAMS = test_snmp

test_snmp_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Flow.cc \
			../../StringCache.cc \
			../../Protocol.cc \
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
			SNMPProtocol.cc test_snmp.cc

test_snmp_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_snmp_LDFLAGS = $(EXTRA_TEST_LDFLAGS) 
test_snmp_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

