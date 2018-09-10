include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	CoAPProtocol.h CoAPInfo.h test_coap.h

TEST = test_coap

check_PROGRAMS = test_coap

test_coap_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Flow.cc \
			../../Protocol.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../ip6/IPv6Protocol.cc \
                        $(TEST_FLOW_OBJECTS) \
                        ../http/HTTPUriSet.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
                        ../../names/DomainNameManager.cc \
                        ../../names/DomainNode.cc \
                        ../../names/DomainName.cc \
			CoAPProtocol.cc test_coap.cc

test_coap_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST 
test_coap_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_coap_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework $(LOG4CXX_FLAGS)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

