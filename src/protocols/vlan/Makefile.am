include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_vlan.h VLanProtocol.h

TEST = test_vlan

check_PROGRAMS = test_vlan

test_vlan_SOURCES = 	../../Multiplexer.cc \
			../../StringCache.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../AnomalyManager.cc \
			$(TEST_FLOW_OBJECTS) \
			../../Protocol.cc \
			../ethernet/EthernetProtocol.cc \
			VLanProtocol.cc test_vlan.cc

test_vlan_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_vlan_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_vlan_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

