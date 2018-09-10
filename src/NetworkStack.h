/*
 * AIEngine a new generation network intrusion detection system.
 *
 * Copyright (C) 2013-2018  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Ryadnology Team; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Ryadnology Team, 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <me@ryadpasha.com> 
 *
 */
#ifndef SRC_NETWORKSTACK_H_
#define SRC_NETWORKSTACK_H_

#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include "Multiplexer.h"
#include "names/DomainNameManager.h"
#include "regex/RegexManager.h"
#include "flow/FlowManager.h"
#include "DatabaseAdaptor.h"
#include "ipset/IPSetManager.h"
#include "protocols/ethernet/EthernetProtocol.h"
#include "protocols/vlan/VLanProtocol.h"
#include "protocols/mpls/MPLSProtocol.h"
#include "protocols/pppoe/PPPoEProtocol.h"
#include "protocols/tcp/TCPProtocol.h"
#include "protocols/udp/UDPProtocol.h"
#include "protocols/tcpgeneric/TCPGenericProtocol.h"
#include "protocols/udpgeneric/UDPGenericProtocol.h"
#include "protocols/dns/DNSProtocol.h"
#include "protocols/sip/SIPProtocol.h"
#include "protocols/dhcp/DHCPProtocol.h"
#include "protocols/ntp/NTPProtocol.h"
#include "protocols/snmp/SNMPProtocol.h"
#include "protocols/ssdp/SSDPProtocol.h"
#include "protocols/ssl/SSLProtocol.h"
#include "protocols/http/HTTPProtocol.h"
#include "protocols/smtp/SMTPProtocol.h"
#include "protocols/imap/IMAPProtocol.h"
#include "protocols/pop/POPProtocol.h"
#include "protocols/bitcoin/BitcoinProtocol.h"
#include "protocols/modbus/ModbusProtocol.h"
#include "protocols/coap/CoAPProtocol.h"
#include "protocols/rtp/RTPProtocol.h"
#include "protocols/mqtt/MQTTProtocol.h"
#include "protocols/netbios/NetbiosProtocol.h"
#include "protocols/quic/QuicProtocol.h"
#include "protocols/smb/SMBProtocol.h"
#include "protocols/ssh/SSHProtocol.h"
#include "protocols/dcerpc/DCERPCProtocol.h"
#include "protocols/frequency/FrequencyProtocol.h"
#include "OutputManager.h"
#include "Color.h"

namespace aiengine {

typedef std::pair<std::string,ProtocolPtr> ProtocolPair;
typedef std::map<std::string,ProtocolPtr> ProtocolMap;
typedef std::vector<ProtocolPair> ProtocolVector;

class NetworkStack {
public:
    	NetworkStack();
    	virtual ~NetworkStack();

	void showFlows();
	void showFlows(int limit);
	void showFlows(const std::string &protoname);
	void showFlows(const std::string &protoname, int limit);
	void showFlows(std::basic_ostream<char> &out) { showFlows(out, std::numeric_limits<int>::max()); }

	// Specific for derived classes
        virtual void statistics(std::basic_ostream<char> &out) const = 0;

        void statistics() const;
	void statistics(const std::string &name) const;
	void statistics(int level) const;
	void statistics(const std::string &name, int level) const;

	const char* getName() const { return name_.c_str(); }
	void setName(const std::string &name) { name_ = name; }

	virtual MultiplexerPtrWeak getLinkLayerMultiplexer() = 0; 

	virtual void setTotalTCPFlows(int value) = 0;
	virtual int getTotalTCPFlows() const = 0;
	virtual void setTotalUDPFlows(int value) = 0;
	virtual int getTotalUDPFlows() const = 0;

       	virtual void enableFrequencyEngine(bool enable) = 0;
       	virtual void enableNIDSEngine(bool enable) = 0;
       	virtual bool isEnableFrequencyEngine() const = 0;
       	virtual bool isEnableNIDSEngine() const = 0;

	void enableLinkLayerTagging(const std::string &type); 
	const std::string &getLinkLayerTagging() const { return link_layer_tag_name_; } 

	virtual void setFlowsTimeout(int timeout) = 0;
	virtual int getFlowsTimeout() const = 0;

	// Release the memory of the caches of every protocol on the stack
	void releaseCache(const std::string &name);
	void releaseCaches();

        void increaseAllocatedMemory(const std::string &name, int value);
        void decreaseAllocatedMemory(const std::string &name, int value);

	void setDomainNameManager(const SharedPointer<DomainNameManager> &dnm, const std::string &name);
	void setDomainNameManager(const SharedPointer<DomainNameManager> &dnm, const std::string &name, bool allow);
	
#if defined(BINDING) // common for all the bindings
	
	void enableProtocol(const std::string &name);
	void disableProtocol(const std::string &name);

	void showAnomalies() const { anomaly_->statistics(OutputManager::getInstance()->out()); }
	void showProtocolSummary() const { showProtocolSummary(OutputManager::getInstance()->out()); }

	virtual FlowManager& getTCPFlowManager() = 0;
	virtual FlowManager& getUDPFlowManager() = 0;

#else
	virtual FlowManagerPtrWeak getTCPFlowManager() = 0;
	virtual FlowManagerPtrWeak getUDPFlowManager() = 0;
#endif

#if defined(RUBY_BINDING) || defined(LUA_BINDING) || defined(JAVA_BINDING) || defined(GO_BINDING)
	void setDomainNameManager(const DomainNameManager &dnm, const std::string &name);
	void setDomainNameManager(const DomainNameManager &dnm, const std::string &name, bool allow);
#endif

#if defined(RUBY_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
	virtual void setTCPRegexManager(RegexManager &sig) { setTCPRegexManager(std::make_shared<RegexManager>(sig)); } 
	virtual void setUDPRegexManager(RegexManager &sig) { setUDPRegexManager(std::make_shared<RegexManager>(sig)); } 
	
	RegexManager &getTCPRegexManager() const { return *tcp_regex_mng_.get(); }
	RegexManager &getUDPRegexManager() const { return *udp_regex_mng_.get(); }

	IPSetManager &getTCPIPSetManager() const { return *tcp_ipset_mng_.get(); }
	IPSetManager &getUDPIPSetManager() const { return *udp_ipset_mng_.get(); }

#elif defined(JAVA_BINDING)
	virtual void setTCPRegexManager(RegexManager *sig);
	virtual void setUDPRegexManager(RegexManager *sig); 
#endif
	// The Python API sends an empty shared_ptr for the None assignment
	virtual void setTCPRegexManager(const SharedPointer<RegexManager> &sig) { tcp_regex_mng_ = sig; } 
	virtual void setUDPRegexManager(const SharedPointer<RegexManager> &sig) { udp_regex_mng_ = sig; } 
	
	virtual void setTCPIPSetManager(const SharedPointer<IPSetManager> &ipset_mng) { tcp_ipset_mng_ = ipset_mng; }
	virtual void setUDPIPSetManager(const SharedPointer<IPSetManager> &ipset_mng) { udp_ipset_mng_ = ipset_mng; }

#if defined(PYTHON_BINDING)
	void showCache(const std::string &name);

	void setTCPDatabaseAdaptor(boost::python::object &dbptr);
	void setTCPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling);
	void setUDPDatabaseAdaptor(boost::python::object &dbptr);
	void setUDPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling);

	boost::python::dict getCounters(const std::string &name);
	boost::python::dict getCache(const std::string &name);

	SharedPointer<RegexManager> getTCPRegexManager() const { return tcp_regex_mng_; }
	SharedPointer<RegexManager> getUDPRegexManager() const { return udp_regex_mng_; }

	SharedPointer<IPSetManager> getTCPIPSetManager() const { return tcp_ipset_mng_; }
	SharedPointer<IPSetManager> getUDPIPSetManager() const { return udp_ipset_mng_; }

	const char *getLinkLayerTag() const { return link_layer_tag_name_.c_str(); } 

	void setAnomalyCallback(PyObject *callback, const std::string &proto_name);

#elif defined(RUBY_BINDING)
	void setTCPDatabaseAdaptor(VALUE dbptr); 
	void setTCPDatabaseAdaptor(VALUE dbptr, int packet_sampling); 
	void setUDPDatabaseAdaptor(VALUE dbptr);
	void setUDPDatabaseAdaptor(VALUE dbptr, int packet_sampling);

	VALUE getCounters(const std::string &name);
	VALUE getCache(const std::string &name);

	void setAnomalyCallback(VALUE callback, const std::string &proto_name);

#elif defined(JAVA_BINDING)
	void setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr);
	void setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling);
	void setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr);
	void setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling);
	
	std::map<std::string, int32_t> getCounters(const std::string &name);
	
	void setAnomalyCallback(JaiCallback *callback, const std::string &proto_name);
#elif defined(LUA_BINDING)
	void setTCPDatabaseAdaptor(lua_State *L, const char *obj_name);
	void setTCPDatabaseAdaptor(lua_State *L, const char *obj_name, int packet_sampling);
	void setUDPDatabaseAdaptor(lua_State *L, const char *obj_name);
	void setUDPDatabaseAdaptor(lua_State *L, const char *obj_name, int packet_sampling);

	void setAnomalyCallback(lua_State *L, const std::string &callback, const std::string &proto_name);

	std::map<std::string, int> getCounters(const char *name);

#elif defined(GO_BINDING)
        void setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr);
        void setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling);
        void setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr);
        void setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling);
	
	void setAnomalyCallback(GoaiCallback *callback, const std::string &proto_name);
	
	std::map<std::string, int32_t> getCounters(const std::string &name);
#endif

	void setStatisticsLevel(int level); 
	int getStatisticsLevel() const { return stats_level_; }

	int64_t getAllocatedMemory() const;
	int64_t getTotalAllocatedMemory() const;

	void setDynamicAllocatedMemory(const std::string &name, bool value);
	void setDynamicAllocatedMemory(bool value); 

	virtual std::tuple<Flow*, Flow*> getCurrentFlows() const = 0;
	virtual void setAsioService(boost::asio::io_service &io_service) {}

	void showProtocolSummary(std::basic_ostream<char> &out) const;

	friend std::ostream& operator<< (std::ostream &out, const NetworkStack &ns);

protected:
	void infoMessage(const std::string &msg);
	
	void enableFlowForwarders(const std::initializer_list<SharedPointer<FlowForwarder>> &ffs);
	void disableFlowForwarders(const std::initializer_list<SharedPointer<FlowForwarder>> &ffs);

	virtual void showFlows(std::basic_ostream<char> &out, int limit) = 0;
	virtual void showFlows(std::basic_ostream<char> &out, const std::string &protoname, int limit) = 0;

	void addProtocol(ProtocolPtr proto); 
	void addProtocol(ProtocolPtr proto, bool active); 

	void setTCPDefaultForwarder(const SharedPointer<FlowForwarder> &ff) { ff_tcp_current_ = ff; }
	void setUDPDefaultForwarder(const SharedPointer<FlowForwarder> &ff) { ff_udp_current_ = ff; }

	// Multiplexers of low layer parts (vlan, mpls, ethernet, etc....)
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_vlan;
        MultiplexerPtr mux_mpls;
        MultiplexerPtr mux_pppoe;
        MultiplexerPtr mux_ip;

	// Protocols shared with all the stacks at link layer
	EthernetProtocolPtr eth;
        VLanProtocolPtr vlan;
        MPLSProtocolPtr mpls;
	PPPoEProtocolPtr pppoe;
	
	// Protocols shared with all the stacks, layer 7
        HTTPProtocolPtr http;
        SSLProtocolPtr ssl;
        DNSProtocolPtr dns;
        SIPProtocolPtr sip;
        DHCPProtocolPtr dhcp;
        NTPProtocolPtr ntp;
        SNMPProtocolPtr snmp;
        SSDPProtocolPtr ssdp;
        SMTPProtocolPtr smtp;
        IMAPProtocolPtr imap;
        POPProtocolPtr pop;
        BitcoinProtocolPtr bitcoin;
        ModbusProtocolPtr modbus;
        CoAPProtocolPtr coap;
        RTPProtocolPtr rtp;
        MQTTProtocolPtr mqtt;
	NetbiosProtocolPtr netbios;
	QuicProtocolPtr quic;
	SMBProtocolPtr smb;
	SSHProtocolPtr ssh;
	DCERPCProtocolPtr dcerpc;
        TCPGenericProtocolPtr tcp_generic;
        UDPGenericProtocolPtr udp_generic;
        FrequencyProtocolPtr freqs_tcp;
        FrequencyProtocolPtr freqs_udp;

        SharedPointer<FlowForwarder> ff_http;
        SharedPointer<FlowForwarder> ff_ssl;
        SharedPointer<FlowForwarder> ff_dns;
        SharedPointer<FlowForwarder> ff_sip;
        SharedPointer<FlowForwarder> ff_dhcp;
        SharedPointer<FlowForwarder> ff_ntp,ff_snmp,ff_ssdp;
        SharedPointer<FlowForwarder> ff_smtp;
        SharedPointer<FlowForwarder> ff_imap;
        SharedPointer<FlowForwarder> ff_pop,ff_bitcoin;
	SharedPointer<FlowForwarder> ff_ssh;
        SharedPointer<FlowForwarder> ff_modbus;
        SharedPointer<FlowForwarder> ff_coap;
        SharedPointer<FlowForwarder> ff_rtp;
	SharedPointer<FlowForwarder> ff_mqtt;
	SharedPointer<FlowForwarder> ff_netbios;
	SharedPointer<FlowForwarder> ff_quic;
	SharedPointer<FlowForwarder> ff_smb;
	SharedPointer<FlowForwarder> ff_dcerpc;
        SharedPointer<FlowForwarder> ff_tcp_generic;
        SharedPointer<FlowForwarder> ff_udp_generic;
        SharedPointer<FlowForwarder> ff_tcp_freqs;
        SharedPointer<FlowForwarder> ff_udp_freqs;

	SharedPointer<AnomalyManager> anomaly_;
private:
	void enable_protocol(const ProtocolPtr &proto, const SharedPointer<FlowForwarder> &ff);
	void disable_protocol(const ProtocolPtr &proto, const SharedPointer<FlowForwarder> &ff);

	void statistics(std::basic_ostream<char> &out, int level) const;
#if defined(BINDING)
        static const int default_update_frequency = 32;
#endif
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
	ProtocolPtr get_protocol(const std::string &name) const;

	int stats_level_;
	std::string name_;
	ProtocolVector proto_vector_;
	std::vector<DomainNameManagerPtr> domain_mng_list_;

	SharedPointer<RegexManager> tcp_regex_mng_;
	SharedPointer<RegexManager> udp_regex_mng_;
	SharedPointer<IPSetManager> tcp_ipset_mng_;
	SharedPointer<IPSetManager> udp_ipset_mng_;
        SharedPointer<FlowForwarder> ff_udp_current_;
        SharedPointer<FlowForwarder> ff_tcp_current_;
	std::string link_layer_tag_name_;
};

typedef std::shared_ptr <NetworkStack> NetworkStackPtr;

} // namespace aiengine

#endif  // SRC_NETWORKSTACK_H_
