include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_pppoe.h PPPoEProtocol.h

TEST = test_pppoe

check_PROGRAMS = test_pppoe

test_pppoe_SOURCES = 	../../Multiplexer.cc \
			../../StringCache.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../AnomalyManager.cc \
			$(TEST_FLOW_OBJECTS) \
			../../Protocol.cc \
			../ip/IPProtocol.cc \
			../ip6/IPv6Protocol.cc \
			../ethernet/EthernetProtocol.cc \
			PPPoEProtocol.cc test_pppoe.cc

test_pppoe_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_pppoe_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_pppoe_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

