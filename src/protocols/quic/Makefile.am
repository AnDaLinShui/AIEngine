include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	QuicProtocol.h test_quic.h

TEST = test_quic

check_PROGRAMS = test_quic

test_quic_SOURCES = 	../../Multiplexer.cc \
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
			QuicProtocol.cc test_quic.cc

test_quic_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_quic_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_quic_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

