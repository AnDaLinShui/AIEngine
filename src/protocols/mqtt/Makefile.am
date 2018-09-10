include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	MQTTProtocol.h test_mqtt.h MQTTInfo.h

TEST = test_mqtt

check_PROGRAMS = test_mqtt

test_mqtt_SOURCES = 	../../Multiplexer.cc \
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
                       	$(TEST_FLOW_OBJECTS) \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainNode.cc \
			../../names/DomainName.cc \
			MQTTProtocol.cc test_mqtt.cc

test_mqtt_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_mqtt_LDFLAGS = $(EXTRA_TEST_LDFLAGS) 
test_mqtt_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

