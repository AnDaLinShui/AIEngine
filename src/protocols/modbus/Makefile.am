include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	ModbusProtocol.h test_modbus.h

TEST = test_modbus

check_PROGRAMS = test_modbus

test_modbus_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Packet.cc \
			../../IPAddress.cc \
			../../Flow.cc \
			../../StringCache.cc \
			../../Protocol.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPBloomSet.cc \
			../../ipset/IPRadixTree.cc \
			../../ipset/IPSetManager.cc \
			../tcp/TCPProtocol.cc \
                        $(TEST_FLOW_OBJECTS) \
			ModbusProtocol.cc test_modbus.cc

test_modbus_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE_TEST
test_modbus_LDFLAGS = $(EXTRA_TEST_LDFLAGS)
test_modbus_LDADD   = $(BOOST_LDFLAGS) -lboost_system -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

