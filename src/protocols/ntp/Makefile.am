include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	NTPProtocol.h test_ntp.h

TEST = test_ntp

check_PROGRAMS = test_ntp

test_ntp_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../Packet.cc \
			../../IPAddress.cc \
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
			NTPProtocol.cc test_ntp.cc

test_ntp_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_ntp_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_ntp_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

