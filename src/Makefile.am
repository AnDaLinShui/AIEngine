AUTOMAKE_OPTIONS = gnu

all: aiengine

full: aiengine python lua ruby java go

@CODE_COVERAGE_RULES@
CODE_COVERAGE_LCOV_OPTIONS_DEFAULT = $(CODE_COVERAGE_LCOV_OPTIONS_GCOVPATH) --directory . --no-external 

AM_CPPFLAGS= -g -fprofile-arcs -ftest-coverage

GOPATHDIR=gopath/src/goaiengine
GOPATH=/home/luis/c++/tmp/aiengine/src/gopath
GO=/usr/bin/go
# CGO_CPPFLAGS="-I `pwd`" 
CGO_CXXFLAGS="-DHAVE_CONFIG -DGO_BINDING -std=c++11"
CGO_LDFLAGS="-lstdc++ -lboost_system -lboost_iostreams -lm -lpcap -lpcre"
LUA_INCLUDE=@LUA_INCLUDE@
AM_JAVAFLAGS=@AM_JAVAFLAGS@
# EXTRA_FLAGS = -flto not supported on the freebsd compiler
# EXTRA_FLAGS = -O3 '-fprofile-arcs -ftest-coverage -g' For enable gcov tool
EXTRA_FLAGS = -O3 

EXTRA_DIST = 	pyai_tests.py __init__.py python_wrapper.cc python_help.h ruby_wrapper.i setup.py MANIFEST.in \
		ruai_tests.rb java_wrapper.i JavaAiengineTestsStackLan.java JavaAiengineTestsStackLanIPv6.java \
		JavaAiengineTestsStackVirtual.java JunitTestSuite.java \
		luai_tests.lua lua_wrapper.i go_wrapper.i goai.go go_compile.sh	

noinst_HEADERS =        Packet.h Pointer.h RawPacket.h \
			Protocol.h AnomalyManager.h RejectManager.h \
			PacketDispatcher.h EvidenceManager.h \
			NetworkStack.h FlowRegexEvaluator.h \
			StackLan.h OutputManager.h Message.h Color.h \
			StackLanIPv6.h \
			Cache.h Cache_Impl.h IPAddress.h \
			StackMobile.h StackVirtual.h StackMobileIPv6.h \
			StackOpenFlow.h \
			Multiplexer.h TimerManager.h Timer.h \
			FlowForwarder.h \
			Signature.h Callback.h JaiCallback.h \
			Interpreter.h PyGilContext.h \
                        flow/FlowCache.h \
                        flow/FlowManager.h \
                        Flow.h FlowInfo.h FlowDirection.h StringCache.h \
			ipset/IPAbstractSet.h \
			ipset/IPBloomSet.h \
			ipset/IPSet.h \
			ipset/IPSetManager.h \
			learner/LearnerEngine.h \
			names/DomainName.h \
			names/DomainNode.h \
			names/DomainNameManager.h \
			protocols/ethernet/EthernetProtocol.h \
			protocols/vlan/VLanProtocol.h \
			protocols/mpls/MPLSProtocol.h \
			protocols/pppoe/PPPoEProtocol.h \
			protocols/ip/IPProtocol.h \
			protocols/ip6/IPv6Protocol.h \
			protocols/icmp/ICMPProtocol.h \
			protocols/icmp6/ICMPv6Header.h \
			protocols/icmp6/ICMPv6Protocol.h \
			protocols/udp/UDPProtocol.h \
			protocols/tcp/TCPHeader.h \
			protocols/tcp/TCPProtocol.h \
			protocols/tcpgeneric/TCPGenericProtocol.h \
			protocols/udpgeneric/UDPGenericProtocol.h \
			protocols/gprs/GPRSProtocol.h \
			protocols/vxlan/VxLanProtocol.h \
			protocols/openflow/OpenFlowProtocol.h \
			protocols/gre/GREProtocol.h \
			protocols/http/HTTPProtocol.h \
			protocols/ssl/SSLProtocol.h \
			protocols/smtp/SMTPProtocol.h \
			protocols/imap/IMAPProtocol.h \
			protocols/pop/POPProtocol.h \
			protocols/bitcoin/BitcoinProtocol.h \
			protocols/modbus/ModbusProtocol.h \
			protocols/dns/DNSProtocol.h \
			protocols/dns/DNSInfo.h \
			protocols/sip/SIPProtocol.h \
			protocols/sip/SIPInfo.h \
			protocols/dhcp/DHCPProtocol.h \
			protocols/ntp/NTPProtocol.h \
			protocols/snmp/SNMPProtocol.h \
			protocols/ssdp/SSDPProtocol.h \
			protocols/ssdp/SSDPInfo.h \
			protocols/coap/CoAPProtocol.h \
			protocols/coap/CoAPInfo.h \
			protocols/rtp/RTPProtocol.h \
			protocols/mqtt/MQTTProtocol.h \
			protocols/netbios/NetbiosProtocol.h \
			protocols/quic/QuicProtocol.h \
			protocols/smb/SMBProtocol.h \
			protocols/smb/SMBInfo.h \
			protocols/dhcp6/DHCPv6Protocol.h \
			protocols/dhcp6/DHCPv6Info.h \
			protocols/ssh/SSHProtocol.h \
			protocols/ssh/SSHInfo.h \
			protocols/dcerpc/DCERPCInfo.h \
			protocols/dcerpc/DCERPCProtocol.h \
			protocols/frequency/Frequencies.h \
			protocols/frequency/PacketFrequencies.h \
			protocols/frequency/FrequencyProtocol.h \
			System.h CounterMap.h \
			StackTest.h StackLanTest.h \
			Serializable.h JsonFlow.h \
			DatabaseAdaptor.h json.hpp GoaiCallback.h 

aiengine_core_sources =	Multiplexer.cc \
			FlowForwarder.cc \
			PacketDispatcher.cc \
			Packet.cc IPAddress.cc \
			Flow.cc \
			Protocol.cc AnomalyManager.cc \
			Callback.cc StringCache.cc \
			FlowRegexEvaluator.cc Interpreter.cc \
			flow/FlowManager.cc \
			protocols/ethernet/EthernetProtocol.cc \
			protocols/vlan/VLanProtocol.cc \
			protocols/mpls/MPLSProtocol.cc \
			protocols/pppoe/PPPoEProtocol.cc \
			protocols/ip/IPProtocol.cc \
			ipset/IPAbstractSet.cc \
			ipset/IPSet.cc \
			ipset/IPBloomSet.cc \
			ipset/IPRadixTree.cc \
			ipset/IPSetManager.cc \
			protocols/ip6/IPv6Protocol.cc \
			protocols/icmp/ICMPProtocol.cc \
			protocols/icmp6/ICMPv6Header.cc \
			protocols/icmp6/ICMPv6Protocol.cc \
			protocols/udp/UDPProtocol.cc \
			protocols/tcp/TCPInfo.cc \
			protocols/tcp/TCPHeader.cc \
			protocols/tcp/TCPProtocol.cc \
			protocols/tcpgeneric/TCPGenericProtocol.cc \
			protocols/udpgeneric/UDPGenericProtocol.cc \
			protocols/gprs/GPRSInfo.cc \
			protocols/gprs/GPRSProtocol.cc \
			protocols/vxlan/VxLanProtocol.cc \
			protocols/openflow/OpenFlowProtocol.cc \
			protocols/gre/GREProtocol.cc \
			protocols/http/HTTPInfo.cc \
			protocols/http/HTTPProtocol.cc \
			protocols/http/HTTPUriSet.cc \
			protocols/ssl/SSLInfo.cc \
			protocols/ssl/SSLProtocol.cc \
			protocols/smtp/SMTPProtocol.cc \
			protocols/smtp/SMTPInfo.cc \
			protocols/imap/IMAPProtocol.cc \
			protocols/imap/IMAPInfo.cc \
			protocols/pop/POPProtocol.cc \
			protocols/pop/POPInfo.cc \
			protocols/bitcoin/BitcoinProtocol.cc \
			protocols/bitcoin/BitcoinInfo.cc \
			protocols/modbus/ModbusProtocol.cc \
			protocols/dns/DNSInfo.cc \
			protocols/dns/DNSProtocol.cc \
			protocols/sip/SIPInfo.cc \
			protocols/sip/SIPProtocol.cc \
			protocols/dhcp/DHCPProtocol.cc \
			protocols/dhcp/DHCPInfo.cc \
			protocols/ntp/NTPProtocol.cc \
			protocols/snmp/SNMPProtocol.cc \
			protocols/ssdp/SSDPProtocol.cc \
			protocols/ssdp/SSDPInfo.cc \
			protocols/coap/CoAPProtocol.cc \
			protocols/coap/CoAPInfo.cc \
			protocols/rtp/RTPProtocol.cc \
			protocols/mqtt/MQTTProtocol.cc \
			protocols/mqtt/MQTTInfo.cc \
			protocols/netbios/NetbiosProtocol.cc \
			protocols/netbios/NetbiosInfo.cc \
			protocols/quic/QuicProtocol.cc \
			protocols/smb/SMBProtocol.cc \
			protocols/smb/SMBInfo.cc \
			protocols/dhcp6/DHCPv6Protocol.cc \
			protocols/dhcp6/DHCPv6Info.cc \
			protocols/ssh/SSHProtocol.cc \
			protocols/ssh/SSHInfo.cc \
			protocols/dcerpc/DCERPCInfo.cc \
			protocols/dcerpc/DCERPCProtocol.cc \
			regex/Regex.cc \
			regex/RegexManager.cc RejectManager.cc \
			protocols/frequency/Frequencies.cc \
			protocols/frequency/PacketFrequencies.cc \
			protocols/frequency/FrequencyProtocol.cc \
			protocols/frequency/FrequencyCounter.cc \
			learner/LearnerEngine.cc \
			names/DomainNameManager.cc \
			names/DomainNode.cc \
			names/DomainName.cc \
			System.cc \
			NetworkStack.cc \
			StackMobile.cc StackLan.cc \
			StackLanIPv6.cc StackVirtual.cc \
			StackOpenFlow.cc StackMobileIPv6.cc \
			EvidenceManager.cc TimerManager.cc 

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS = 
endif

BOOST_LINK_CORE = -lboost_system -lboost_iostreams 

# On certain versions of gdb the symbol table are not shown properly
# add the flags -gdwarf-3 on the CPPFLAGS variable to see the tables.
aiengine_SOURCES =      $(aiengine_core_sources) main.cc
aiengine_CPPFLAGS = 	$(EXTRA_FLAGS) $(BOOST_CPPFLAGS) $(EXTRA_TEST_CPPFLAGS)
aiengine_LDFLAGS = 	-DBOOST_ASIO_DISABLE_EPOLL -lpthread -lstdc++ \
			$(BOOST_LDFLAGS) $(BOOST_LINK_CORE) $(PCRE_LIB) \
			-lboost_program_options $(EXTRA_TEST_LDFLAGS) \
			-lboost_filesystem -lpcap $(LOG4CXX_FLAGS) 

aiengine_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = aiengine

TEST = tests 

check_PROGRAMS = tests 

tests_SOURCES = $(aiengine_core_sources) \
		protocols/ethernet/test_ethernet.cc \
		protocols/vlan/test_vlan.cc \
		protocols/mpls/test_mpls.cc \
		protocols/pppoe/test_pppoe.cc \
		flow/test_flows.cc \
		ipset/test_ipset.cc \
		protocols/ip/test_ip.cc \
		protocols/ip6/test_ip6.cc \
		protocols/udp/test_udp.cc \
		protocols/tcp/test_tcp.cc \
		protocols/tcpgeneric/test_tcpgeneric.cc \
		protocols/udpgeneric/test_udpgeneric.cc \
		protocols/dns/test_dns.cc \
		protocols/gprs/test_gprs.cc \
		protocols/vxlan/test_vxlan.cc \
		protocols/openflow/test_openflow.cc \
		protocols/gre/test_gre.cc \
		protocols/http/test_http.cc \
		protocols/icmp/test_icmp.cc \
		protocols/icmp6/test_icmp6.cc \
		protocols/frequency/test_frequency.cc \
		protocols/ssl/test_ssl.cc \
		protocols/smtp/test_smtp.cc \
		protocols/imap/test_imap.cc \
		protocols/pop/test_pop.cc \
		protocols/bitcoin/test_bitcoin.cc \
		protocols/modbus/test_modbus.cc \
		protocols/sip/test_sip.cc \
		protocols/dhcp/test_dhcp.cc \
		protocols/ntp/test_ntp.cc \
		protocols/snmp/test_snmp.cc \
		protocols/ssdp/test_ssdp.cc \
		protocols/coap/test_coap.cc \
		protocols/rtp/test_rtp.cc \
		protocols/mqtt/test_mqtt.cc \
		protocols/netbios/test_netbios.cc \
		protocols/quic/test_quic.cc \
		protocols/smb/test_smb.cc \
		protocols/dhcp6/test_dhcpv6.cc \
		protocols/ssh/test_ssh.cc \
		protocols/dcerpc/test_dcerpc.cc \
		regex/test_regex.cc \
		user/test_users.cc \
		learner/test_learner.cc \
		names/test_names.cc \
		tests.cc 

tests_LDFLAGS = 	-DBOOST_ASIO_DISABLE_EPOLL -lpthread -lstdc++ $(EXTRA_TEST_LDFLAGS) \
			$(BOOST_LDFLAGS) $(BOOST_LINK_CORE) $(PCRE_LIB) \
			-lboost_program_options \
			-lboost_filesystem -lpcap $(LOG4CXX_FLAGS) $(CODE_COVERAGE_LDFLAGS) 

ruby_objects = 	NetworkStack.o Protocol.o EthernetProtocol.o \
		AnomalyManager.o Multiplexer.o FlowForwarder.o PacketDispatcher.o \
		Packet.o IPAddress.o Flow.o Callback.o StringCache.o FlowRegexEvaluator.o \
		RegexManager.o Regex.o \
		VLanProtocol.o MPLSProtocol.o PPPoEProtocol.o \
		IPProtocol.o IPv6Protocol.o \
		TCPInfo.o TCPHeader.o TCPProtocol.o UDPProtocol.o \
		TCPGenericProtocol.o UDPGenericProtocol.o \
		HTTPProtocol.o HTTPInfo.o \
		SSLProtocol.o SSLInfo.o \
		DNSProtocol.o DNSInfo.o \
		GPRSInfo.o GPRSProtocol.o \
		NTPProtocol.o SNMPProtocol.o \
		SMTPProtocol.o SMTPInfo.o \
		IMAPProtocol.o IMAPInfo.o \
		DHCPProtocol.o DHCPInfo.o \
		DHCPv6Protocol.o DHCPv6Info.o \
		SIPProtocol.o SIPInfo.o \
		SSDPProtocol.o SSDPInfo.o \
		POPProtocol.o POPInfo.o \
		SSHProtocol.o SSHInfo.o \
		GREProtocol.o \
		OpenFlowProtocol.o VxLanProtocol.o \
		BitcoinProtocol.o BitcoinInfo.o \
		ModbusProtocol.o \
		RTPProtocol.o \
		CoAPProtocol.o CoAPInfo.o \
		MQTTProtocol.o MQTTInfo.o \
		NetbiosProtocol.o NetbiosInfo.o \
		QuicProtocol.o \
		SMBProtocol.o SMBInfo.o \
		DCERPCProtocol.o DCERPCInfo.o \
		Frequencies.o PacketFrequencies.o FrequencyProtocol.o LearnerEngine.o \
		ICMPProtocol.o ICMPv6Protocol.o ICMPv6Header.o \
		StackLan.o StackMobile.o StackLanIPv6.o StackVirtual.o StackOpenFlow.o StackMobileIPv6.o \
		FlowManager.o Interpreter.o System.o \
		IPSetManager.o IPAbstractSet.o IPSet.o IPBloomSet.o IPRadixTree.o HTTPUriSet.o \
		DomainNameManager.o DomainNode.o DomainName.o \
		RejectManager.o EvidenceManager.o TimerManager.o

java_objects = 	RegexManager.o Regex.o Packet.o IPAddress.o FlowRegexEvaluator.o \
		NetworkStack.o Protocol.o EthernetProtocol.o \
		FlowManager.o Flow.o Callback.o StringCache.o \
                AnomalyManager.o Multiplexer.o FlowForwarder.o PacketDispatcher.o \
                VLanProtocol.o MPLSProtocol.o PPPoEProtocol.o \
                IPProtocol.o IPv6Protocol.o \
		TCPInfo.o TCPHeader.o TCPProtocol.o UDPProtocol.o \
                TCPGenericProtocol.o UDPGenericProtocol.o \
                HTTPProtocol.o HTTPInfo.o SSLProtocol.o SSLInfo.o \
                DNSProtocol.o DNSInfo.o \
		GPRSInfo.o GPRSProtocol.o \
                NTPProtocol.o SNMPProtocol.o \
                SMTPProtocol.o SMTPInfo.o \
		IMAPProtocol.o IMAPInfo.o \
                DHCPProtocol.o DHCPInfo.o \
                DHCPv6Protocol.o DHCPv6Info.o \
		SIPProtocol.o SIPInfo.o \
		SSDPProtocol.o SSDPInfo.o \
                POPProtocol.o POPInfo.o \
                SSHProtocol.o SSHInfo.o \
		GREProtocol.o \
		RTPProtocol.o \
		CoAPProtocol.o CoAPInfo.o \
		BitcoinProtocol.o BitcoinInfo.o ModbusProtocol.o \
		MQTTProtocol.o MQTTInfo.o \
		NetbiosProtocol.o NetbiosInfo.o \
		QuicProtocol.o \
		SMBProtocol.o SMBInfo.o \
		DCERPCProtocol.o DCERPCInfo.o \
                OpenFlowProtocol.o VxLanProtocol.o \
                Frequencies.o PacketFrequencies.o FrequencyProtocol.o LearnerEngine.o \
                ICMPProtocol.o ICMPv6Protocol.o ICMPv6Header.o \
                StackLan.o StackMobile.o StackLanIPv6.o StackVirtual.o StackOpenFlow.o StackMobileIPv6.o \
                Interpreter.o System.o \
                IPSetManager.o IPAbstractSet.o IPSet.o IPBloomSet.o IPRadixTree.o HTTPUriSet.o \
                DomainNameManager.o DomainNode.o DomainName.o \
		RejectManager.o EvidenceManager.o TimerManager.o

lua_objects =  	NetworkStack.o Protocol.o EthernetProtocol.o \
                AnomalyManager.o Multiplexer.o FlowForwarder.o PacketDispatcher.o \
                Packet.o IPAddress.o Flow.o Callback.o StringCache.o \
                RegexManager.o Regex.o FlowRegexEvaluator.o \
                VLanProtocol.o MPLSProtocol.o PPPoEProtocol.o \
                IPProtocol.o IPv6Protocol.o \
                TCPInfo.o TCPHeader.o TCPProtocol.o UDPProtocol.o \
                TCPGenericProtocol.o UDPGenericProtocol.o \
                HTTPProtocol.o HTTPInfo.o \
                SSLProtocol.o SSLInfo.o \
                DNSProtocol.o DNSInfo.o \
                GPRSInfo.o GPRSProtocol.o \
                NTPProtocol.o SNMPProtocol.o \
                SMTPProtocol.o SMTPInfo.o \
                IMAPProtocol.o IMAPInfo.o \
                DHCPProtocol.o DHCPInfo.o \
                DHCPv6Protocol.o DHCPv6Info.o \
                SIPProtocol.o SIPInfo.o \
                SSDPProtocol.o SSDPInfo.o \
                POPProtocol.o POPInfo.o \
                SSHProtocol.o SSHInfo.o \
                GREProtocol.o \
                OpenFlowProtocol.o VxLanProtocol.o \
                BitcoinProtocol.o BitcoinInfo.o \
                ModbusProtocol.o \
                RTPProtocol.o \
		NetbiosProtocol.o NetbiosInfo.o \
		QuicProtocol.o \
                CoAPProtocol.o CoAPInfo.o \
                MQTTProtocol.o MQTTInfo.o \
		SMBProtocol.o SMBInfo.o \
		DCERPCProtocol.o DCERPCInfo.o \
                Frequencies.o PacketFrequencies.o FrequencyProtocol.o LearnerEngine.o \
                ICMPProtocol.o ICMPv6Protocol.o ICMPv6Header.o \
                StackLan.o StackMobile.o StackLanIPv6.o StackVirtual.o StackOpenFlow.o StackMobileIPv6.o \
                FlowManager.o Interpreter.o System.o \
                IPSetManager.o IPAbstractSet.o IPSet.o IPBloomSet.o IPRadixTree.o HTTPUriSet.o \
                DomainNameManager.o DomainNode.o DomainName.o \
		RejectManager.o EvidenceManager.o TimerManager.o

tests_CPPFLAGS = $(EXTRA_TEST_CPPFLAGS) -DTESTING $(BOOST_CPPFLAGS) $(CODE_COVERAGE_CXXFLAGS)
tests_LDADD   = $(BOOST_LIBS) $(BOOST_LINK_CORE) -lboost_unit_test_framework -lpcap -lpthread $(LOG4CXX_FLAGS) $(CODE_COVERAGE_LDFLAGS)

CLEANFILES = *.o *.lo *.so *.class *_wrap.cxx *_wrap.h swigluarun.h goaiengine.go goaiengine.a \
		python.coverage.info binary.coverage.info coverage.info temp.coverage.info \
		`rm -rf $(srcdir)/buildjava` goai_test \
		`rm -rf $(srcdir)/gopath`

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

lua-coverage:
	@echo "Making lua coverage report"
	@if [ ! -f luaiengine.so ]; then\
		make lua;\
	fi
	lua luai_tests.lua
	lcov -t "Lua coverage results" -o temp.coverage.info -c -d . 1>/dev/null
	lcov -t "Coverage results" --remove temp.coverage.info '/usr/include/*' 'json.hpp' 'radix*.hpp' -o lua.coverage.info  -d .

python-coverage:
	@echo "Making python coverage report"
	@if [ ! -f pyaiengine.so ]; then\
		make python;\
	fi
	python pyai_tests.py
	lcov -t "Python coverage results" -o temp.coverage.info -c -d . 1>/dev/null
	lcov -t "Coverage results" --remove temp.coverage.info '/usr/include/*' 'json.hpp' 'radix*.hpp' -o python.coverage.info  -d .

binary-coverage:
	@echo "Making binary coverage report"
	@if [ ! -f tests ]; then\
		make check;\
	fi
	./tests
	lcov -t "Binary coverage results" -o temp.coverage.info -c -d . 1>/dev/null
	lcov -t "Coverage results" --remove temp.coverage.info '/usr/include/*' 'json.hpp' 'radix*.hpp' -o binary.coverage.info  -d .
	genhtml -o coverage_results binary.coverage.info

coverage:
	@echo "Making coverage report"
	make binary-coverage
	make python-coverage
	lcov --derive-func-data --directory ./ -a binary.coverage.info -a python.coverage.info -o coverage.info
	genhtml -o coverage_results coverage.info

python:
	@echo "**************************************************************************************"
	@echo "* Depending on your machine this compilation could take some time, please be patient.*"
	@echo "* You can use alternatively the setup.py script (python setup.py build_ext -i).      *"
	@echo "**************************************************************************************"

	$(CXX) -fPIC $(EXTRA_FLAGS) $(CODE_COVERAGE_CXXFLAGS) -DHAVE_CONFIG_H -DBINDING -DPYTHON_BINDING \
		-I. -I.. $(BOOST_CPPFLAGS) $(BOOST_CPPFLAGS)/boost/python \
		`pkg-config --cflags python-$(PYTHON_VERSION)` \
		$(aiengine_core_sources) python_wrapper.cc \
		$(CXXFLAGS) -lpthread -lstdc++ \
		$(BOOST_LDFLAGS) $(BOOST_LINK_CORE) \
		-l$(BOOST_PYTHON_LIB) \
		`pkg-config --libs python-$(PYTHON_VERSION)` -lpcap \
		$(LOG4CXX_FLAGS) $(CODE_COVERAGE_LDFLAGS) $(PCRE_LIB) -o pyaiengine.so -shared

ruby:
if HAVE_RUBY_SUPPORT
	@echo "**************************************************************************************"
	@echo "* Compiling Ruby extension.                                                          *"
	@echo "**************************************************************************************"
	@echo "Generating Ruby interface" $(SWIG)	
	swig -DHAVE_CONFIG_H -DBINDING -DRUBY_BINDING -globalmodule -c++ -ruby ruby_wrapper.i 	
	@echo "Compiling Ruby interface"
	$(CXX) -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DBINDING -DRUBY_BINDING -I.. -I. -I/usr/include/ruby \
		$(CXXFLAGS) -c $(aiengine_core_sources) ruby_wrapper_wrap.cxx 
	@echo "Linking Ruby interface"
	$(CXX) -g -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DBINDING -DRUBY_BINDING -I.. \
		-shared $(CXXFLAGS) $(ruby_objects) ruby_wrapper_wrap.o -o ruaiengine.so $(BOOST_LINK_CORE) \
		$(LOG4CXX_FLAGS) -lpcap -lruby -lpcre
endif
java:
if HAVE_JAVA_SUPPORT
	@echo "**************************************************************************************"
	@echo "* Compiling Java extension.                                                          *"
	@echo "**************************************************************************************"
	@echo "Generating Java interface" 
	$(MKDIR_P) buildjava 2>/dev/null
	swig -DBINDING -DJAVA_BINDING -DHAVE_CONFIG_H -outdir buildjava -c++ -java java_wrapper.i 	
	@echo "Compiling Java interface"
	$(CXX) -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DBINDING -DJAVA_BINDING -I./buildjava -I.. -I. $(CPPFLAGS) $(AM_JAVAFLAGS) \
		$(CXXFLAGS) -c $(aiengine_core_sources) java_wrapper_wrap.cxx 
	@echo "Linking Java interface"
	$(CXX) -g -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DBINDING -DJAVA_BINDING -I.. -I./buildjava  \
		-shared $(CXXFLAGS) $(java_objects) java_wrapper_wrap.o -o jaaiengine.so -lpcap \
		$(LOG4CXX_FLAGS) $(BOOST_LINK_CORE) -lpcre 
	@echo "Compiling Java Unit tests"
	$(JAVA_CC) -d buildjava/ -sourcepath buildjava/ -cp /usr/share/java/junit.jar  *.java
endif
lua:
if HAVE_LUA_SUPPORT
	@echo "**************************************************************************************"
	@echo "* Compiling Lua extension.                                                           *"
	@echo "**************************************************************************************"
	@echo "Generating Lua interface" 
	swig -lua -external-runtime 
	swig -DBINDING -DLUA_BINDING -DHAVE_CONFIG_H -c++ -lua lua_wrapper.i 
	@echo "Compiling Lua interface"
	$(CXX) -fPIC $(EXTRA_FLAGS) $(CODE_COVERAGE_CXXFLAGS) -DSWIG_TYPE_TABLE=luaiengine -DHAVE_CONFIG_H -DBINDING -DLUA_BINDING \
		-I.. -I. $(CPPFLAGS) $(LUA_INCLUDE) -I/usr/include \
		$(CXXFLAGS) -c $(aiengine_core_sources) lua_wrapper_wrap.cxx 
	@echo "Linking Lua interface"
	$(CXX) -g -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DBINDING -DLUA_BINDING -I.. \
		-shared $(CXXFLAGS) $(lua_objects) lua_wrapper_wrap.o -o luaiengine.so $(BOOST_LINK_CORE) \
		$(LOG4CXX_FLAGS) $(CODE_COVERAGE_LDFLAGS) -lpcap $(LUA_LIB) -lpcre -L/lib64/liblua.so
endif
go:
if HAVE_GO_SUPPORT
	@echo "**************************************************************************************"
	@echo "* Compiling Go extension.                                                            *"
	@echo "**************************************************************************************"
	@echo "Generating Go interface"
	swig -DBINDING -DGO_BINDING -DHAVE_CONFIG_H -intgosize 64 -go -c++ -cgo go_wrapper.i
	@echo "Generating Go source tree"
	@mkdir -p $(GOPATHDIR)/regex && cp regex/Regex* $(GOPATHDIR)/regex && cp regex/Regex* $(GOPATHDIR) 
	@mkdir -p $(GOPATHDIR)/flow && cp flow/Flow* $(GOPATHDIR)/flow && cp flow/Flow* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/ipset && cp ipset/*.hpp ipset/IP* $(GOPATHDIR)/ipset && cp ipset/IP* ipset/*.hpp $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/names && cp names/Domain* $(GOPATHDIR)/names && cp names/Domain* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/protocols/frequency 
	@cp protocols/frequency/Packet* protocols/frequency/Frequen* $(GOPATHDIR)/protocols/frequency
	@cp protocols/frequency/Packet* protocols/frequency/Frequen* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/protocols/dns 
	@cp protocols/dns/DNS* $(GOPATHDIR)/protocols/dns && cp protocols/dns/DNS* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/protocols/http 
	@cp protocols/http/HTTP* $(GOPATHDIR)/protocols/http 
	@cp protocols/http/HTTP* $(GOPATHDIR) 
	@mkdir -p $(GOPATHDIR)/protocols/ssl 
	@cp protocols/ssl/SSL* $(GOPATHDIR)/protocols/ssl
	@cp protocols/ssl/SSL* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/protocols/ssh 
	@cp protocols/ssh/SSH* $(GOPATHDIR)/protocols/ssh
	@cp protocols/ssh/SSH* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/protocols/gprs 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/gprs | xargs -n 1 cp protocols/gprs/GPRS* 
	@mkdir -p $(GOPATHDIR)/protocols/tcp 
	@cp protocols/tcp/TCP* $(GOPATHDIR)/protocols/tcp && cp protocols/tcp/TCP* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/protocols/tcpgeneric 
	@cp protocols/tcpgeneric/TCP* $(GOPATHDIR)/protocols/tcpgeneric 
	@cp protocols/tcpgeneric/TCP* $(GOPATHDIR) 
	@mkdir -p $(GOPATHDIR)/protocols/udp 
	@cp protocols/udp/UDP* $(GOPATHDIR)/protocols/udp
	@cp protocols/udp/UDP* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/protocols/udpgeneric
	@cp protocols/udpgeneric/UDP* $(GOPATHDIR)/protocols/udpgeneric 
	@cp protocols/udpgeneric/UDP* $(GOPATHDIR)
	@mkdir -p $(GOPATHDIR)/protocols/smtp 2>/dev/null
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/smtp | xargs -n 1 cp protocols/smtp/SMTP*
	@mkdir -p $(GOPATHDIR)/protocols/pop 2>/dev/null
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/pop | xargs -n 1 cp protocols/pop/POP* 
	@mkdir -p $(GOPATHDIR)/protocols/imap 2>/dev/null
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/imap | xargs -n 1 cp protocols/imap/IMAP* 
	@mkdir -p $(GOPATHDIR)/protocols/sip 2>/dev/null
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/sip | xargs -n 1 cp protocols/sip/SIP*
	@mkdir -p $(GOPATHDIR)/protocols/bitcoin 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/bitcoin | xargs -n 1 cp protocols/bitcoin/Bitcoin* 
	@mkdir -p $(GOPATHDIR)/protocols/ssdp 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/ssdp | xargs -n 1 cp protocols/ssdp/SSDP*
	@mkdir -p $(GOPATHDIR)/protocols/coap 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/coap | xargs -n 1 cp protocols/coap/CoAP*
	@mkdir -p $(GOPATHDIR)/protocols/mqtt 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/mqtt | xargs -n 1 cp protocols/mqtt/MQTT*
	@mkdir -p $(GOPATHDIR)/protocols/snmp 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/snmp | xargs -n 1 cp protocols/snmp/SNMP*
	@mkdir -p $(GOPATHDIR)/protocols/netbios 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/netbios | xargs -n 1 cp protocols/netbios/Netbios*
	@mkdir -p $(GOPATHDIR)/protocols/ip 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/ip | xargs -n 1 cp protocols/ip/IP* 
	@mkdir -p $(GOPATHDIR)/protocols/ip6 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/ip6 | xargs -n 1 cp protocols/ip6/IP* 
	@mkdir -p $(GOPATHDIR)/protocols/dhcp 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/dhcp | xargs -n 1 cp protocols/dhcp/DHCP* 
	@mkdir -p $(GOPATHDIR)/protocols/dhcp6 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/dhcp6 | xargs -n 1 cp protocols/dhcp6/DHCP* 
	@mkdir -p $(GOPATHDIR)/protocols/smb 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/smb | xargs -n 1 cp protocols/smb/SMB*
	@mkdir -p $(GOPATHDIR)/protocols/ethernet 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/ethernet | xargs -n 1 cp protocols/ethernet/Ether* 
	@mkdir -p $(GOPATHDIR)/protocols/vlan 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/vlan | xargs -n 1 cp protocols/vlan/VLan*
	@mkdir -p $(GOPATHDIR)/protocols/vxlan 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/vxlan | xargs -n 1 cp protocols/vxlan/VxLan*
	@mkdir -p $(GOPATHDIR)/protocols/mpls 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/mpls | xargs -n 1 cp protocols/mpls/MPLS*
	@mkdir -p $(GOPATHDIR)/protocols/pppoe 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/pppoe | xargs -n 1 cp protocols/pppoe/PPPoE*
	@mkdir -p $(GOPATHDIR)/protocols/gre 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/gre | xargs -n 1 cp protocols/gre/GRE*
	@mkdir -p $(GOPATHDIR)/protocols/ntp 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/ntp | xargs -n 1 cp protocols/ntp/NTP*
	@mkdir -p $(GOPATHDIR)/protocols/snmp && cp protocols/snmp/SNMP* $(GOPATHDIR)/protocols/snmp 
	@mkdir -p $(GOPATHDIR)/protocols/rtp 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/rtp | xargs -n 1 cp protocols/rtp/RTP* 
	@mkdir -p $(GOPATHDIR)/protocols/dcerpc 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/dcerpc | xargs -n 1 cp protocols/dcerpc/DCERPC* 
	@mkdir -p $(GOPATHDIR)/protocols/quic 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/quic | xargs -n 1 cp protocols/quic/Quic*
	@mkdir -p $(GOPATHDIR)/protocols/modbus 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/modbus | xargs -n 1 cp protocols/modbus/Modbus*
	@mkdir -p $(GOPATHDIR)/protocols/icmp 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/icmp | xargs -n 1 cp protocols/icmp/ICMP*  
	@mkdir -p $(GOPATHDIR)/protocols/icmp6 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/icmp6 | xargs -n 1 cp protocols/icmp6/ICMP*  
	@mkdir -p $(GOPATHDIR)/protocols/openflow 
	@echo $(GOPATHDIR) $(GOPATHDIR)/protocols/openflow | xargs -n 1 cp protocols/openflow/OpenFlow*  
	@mkdir -p $(GOPATHDIR)/learner && cp learner/Learner* $(GOPATHDIR)/learner 
	@mkdir -p $(GOPATHDIR)/user && cp user/User* $(GOPATHDIR)/user 
	@cp go_wrapper_wrap.h go_wrapper_wrap.cxx goaiengine.go $(GOPATHDIR)
	@cp *.h *.hpp $(GOPATHDIR)
	@cp *.cc $(GOPATHDIR)
	@rm $(GOPATHDIR)/python_wrapper.cc
	@rm $(GOPATHDIR)/main.cc
	@rm $(GOPATHDIR)/tests.cc
	bash go_compile.sh
endif
