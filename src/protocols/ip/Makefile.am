include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	IPv4Header.h IPv4HdrIncl.h IPProtocol.h test_ip.h

TEST = test_ip

check_PROGRAMS = test_ip

test_ip_SOURCES = 	../../Multiplexer.cc \
			../../Protocol.cc \
			../../StringCache.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../AnomalyManager.cc \
			$(TEST_FLOW_OBJECTS) \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			IPProtocol.cc test_ip.cc

test_ip_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../../ $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_ip_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_ip_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

