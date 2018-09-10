include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	SMTPProtocol.h test_smtp.h SMTPInfo.h

TEST = test_smtp

check_PROGRAMS = test_smtp

test_smtp_SOURCES = 	../../Multiplexer.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Protocol.cc \
			../../FlowForwarder.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../../FlowRegexEvaluator.cc \
			../../protocols/ethernet/EthernetProtocol.cc \
			../../protocols/ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../tcp/TCPProtocol.cc \
			$(TEST_FLOW_OBJECTS) \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainNode.cc \
			../../names/DomainName.cc \
                        ../../regex/RegexManager.cc \
                        ../../regex/Regex.cc \
			SMTPProtocol.cc test_smtp.cc

test_smtp_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_smtp_LDFLAGS = $(EXTRA_TEST_LDFLAGS) 
test_smtp_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) $(PCRE_LIB) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

