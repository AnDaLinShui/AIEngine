include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

TEST = test_sip

check_PROGRAMS = test_sip

noinst_HEADERS = 	SIPProtocol.h SIPInfo.h test_sip.h

test_sip_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Protocol.cc \
			../../FlowForwarder.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../ip6/IPv6Protocol.cc \
			../udp/UDPProtocol.cc \
			$(TEST_FLOW_OBJECTS) \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainNode.cc \
			../../names/DomainName.cc \
			../../regex/Regex.cc \
			SIPProtocol.cc test_sip.cc

test_sip_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_sip_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_sip_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework $(LOG4CXX_FLAGS) $(PCRE_LIB)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

