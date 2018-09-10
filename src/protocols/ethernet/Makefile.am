AUTOMAKE_OPTIONS = gnu

TEST = test_ethernet

check_PROGRAMS = test_ethernet

test_ethernet_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST

test_ethernet_SOURCES = ../../Multiplexer.cc \
			../../StringCache.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../AnomalyManager.cc \
			../../Protocol.cc \
			EthernetProtocol.cc test_ethernet.cc

test_ethernet_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_ethernet_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

