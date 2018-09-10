include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	TCPGenericProtocol.h test_tcpgeneric.h

TEST = test_tcpgeneric

check_PROGRAMS = test_tcpgeneric

test_tcpgeneric_SOURCES = 	../../Multiplexer.cc \
				../../Packet.cc \
				../../IPAddress.cc \
				../../StringCache.cc \
				../../Protocol.cc \
				../../FlowForwarder.cc \
				../../AnomalyManager.cc \
				../../FlowRegexEvaluator.cc \
				../ethernet/EthernetProtocol.cc \
				../ip/IPProtocol.cc \
				../../ipset/IPSetManager.cc \
				../../ipset/IPSet.cc \
				../../ipset/IPBloomSet.cc \
				../../ipset/IPRadixTree.cc \
				../ip6/IPv6Protocol.cc \
				../tcp/TCPProtocol.cc \
                        	$(TEST_FLOW_OBJECTS) \
				../../Flow.cc \
				../../flow/FlowManager.cc \
				../../regex/RegexManager.cc \
				../../regex/Regex.cc \
				TCPGenericProtocol.cc test_tcpgeneric.cc

test_tcpgeneric_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_tcpgeneric_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_tcpgeneric_LDADD   = $(BOOST_LDFLAGS) $(PCRE_LIB) $(LOG4CXX_FLAGS) -lboost_system -lboost_unit_test_framework 

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

