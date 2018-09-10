include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	POPProtocol.h test_pop.h POPInfo.h

TEST = test_pop

check_PROGRAMS = test_pop

test_pop_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Protocol.cc \
			../../FlowForwarder.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../../protocols/ethernet/EthernetProtocol.cc \
			../../protocols/ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../protocols/tcp/TCPProtocol.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNode.cc \
			../../names/DomainName.cc \
			../../names/DomainNameManager.cc \
			$(TEST_FLOW_OBJECTS) \
			POPProtocol.cc test_pop.cc

test_pop_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_pop_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_pop_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

