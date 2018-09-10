include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	DNSProtocol.h test_dns.h DNSInfo.h DNSQueryTypes.h

TEST = test_dns

check_PROGRAMS = test_dns

test_dns_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Protocol.cc \
			../../FlowForwarder.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../ethernet/EthernetProtocol.cc \
			../../protocols/ip/IPProtocol.cc \
			../../protocols/ip6/IPv6Protocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../protocols/udp/UDPProtocol.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainNode.cc \
			../../names/DomainName.cc \
                        $(TEST_FLOW_OBJECTS) \
			DNSProtocol.cc test_dns.cc

test_dns_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_dns_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_dns_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

