include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	IMAPProtocol.h test_imap.h IMAPInfo.h

TEST = test_imap

check_PROGRAMS = test_imap

test_imap_SOURCES = 	../../Multiplexer.cc \
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
			../tcp/TCPProtocol.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNode.cc \
			../../names/DomainName.cc \
			../../names/DomainNameManager.cc \
                        $(TEST_FLOW_OBJECTS) \
			IMAPProtocol.cc test_imap.cc

test_imap_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_imap_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_imap_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework $(LOG4CXX_FLAGS)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

