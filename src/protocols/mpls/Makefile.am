include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	MPLSProtocol.h test_mpls.h

TEST = test_mpls

check_PROGRAMS = test_mpls

test_mpls_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../StringCache.cc \
			../../Protocol.cc \
			../../AnomalyManager.cc \
			$(TEST_FLOW_OBJECTS) \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../icmp/ICMPProtocol.cc \
			MPLSProtocol.cc test_mpls.cc

test_mpls_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_mpls_LDFLAGS = $(EXTRA_TEST_LDFLAGS) 
test_mpls_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

