include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	VxLanProtocol.h test_vxlan.h

TEST = test_vxlan

check_PROGRAMS = test_vxlan

test_vxlan_SOURCES = 	../../Multiplexer.cc \
			../../Protocol.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../StringCache.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../FlowRegexEvaluator.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../ipset/IPSetManager.cc \
			../../regex/Regex.cc \
			../../regex/RegexManager.cc \
			../udp/UDPProtocol.cc \
			$(TEST_FLOW_OBJECTS) \
			../tcp/TCPProtocol.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainNode.cc \
			../../names/DomainName.cc \
			../dns/DNSProtocol.cc \
			../tcpgeneric/TCPGenericProtocol.cc \
			../icmp/ICMPProtocol.cc \
			VxLanProtocol.cc test_vxlan.cc

test_vxlan_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. -g $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_vxlan_LDFLAGS = $(EXTRA_TEST_LDFLAGS) 
test_vxlan_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) $(PCRE_LIB) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

