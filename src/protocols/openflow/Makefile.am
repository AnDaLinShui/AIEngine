include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	OpenFlowProtocol.h test_openflow.h

TEST = test_openflow

check_PROGRAMS = test_openflow

test_openflow_SOURCES =	../../Multiplexer.cc \
			../../Protocol.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../StringCache.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../AnomalyManager.cc \
			../../FlowRegexEvaluator.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			$(TEST_FLOW_OBJECTS) \
			../udpgeneric/UDPGenericProtocol.cc \
			../tcpgeneric/TCPGenericProtocol.cc \
			../tcp/TCPProtocol.cc \
			../../regex/RegexManager.cc \
			../../regex/Regex.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainNode.cc \
			../../names/DomainName.cc \
			../dns/DNSProtocol.cc \
			../icmp/ICMPProtocol.cc \
			OpenFlowProtocol.cc test_openflow.cc

test_openflow_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_openflow_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_openflow_LDADD   = $(BOOST_LDFLAGS) $(PCRE_LIB) $(LOG4CXX_FLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

