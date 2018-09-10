include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	DCERPCProtocol.h DCERPCInfo.h test_dcerpc.h

TEST = test_dcerpc

check_PROGRAMS = test_dcerpc

test_dcerpc_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../Protocol.cc \
			../../Packet.cc \
			../../IPAddress.cc \
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
			../tcp/TCPProtocol.cc \
			DCERPCProtocol.cc test_dcerpc.cc

test_dcerpc_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_dcerpc_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_dcerpc_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework $(LOG4CXX_FLAGS)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

