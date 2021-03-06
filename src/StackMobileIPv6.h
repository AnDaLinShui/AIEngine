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
 * Configuration diagram of this stack
 *
 *                         +--------------------+
 *                         | TCPGenericProtocol |                    
 *                         +-------+------------+                    
 *                                 |                                 
 *          +--------------------+ |              +--------------------+
 *          |     SSLProtocol    | |              | UDPGenericProtocol |
 *          +--------------+-----+ |              +-----------+--------+
 *                         |       |                          |      
 * +--------------------+  |       |  +--------------------+  |      
 * |    HTTPProtocol    |  |       |  |    DNSProtocol     |  |      
 * +------------------+-+  |       |  +------------+-------+  |      
 *                    |    |       |               |          |      
 *                 +--+----+-------+----+    +-----+----------+---+  
 *                 |    TCPProtocol     |    |    UDPProtocol     |  
 *                 +------------------+-+    +-+------------------+  
 *                                    |        |                     
 *      +--------------------+        |        |                     
 *      |   ICMPProtocol     +-----+  |        |                     
 *      +--------------------+     |  |        |                     
 *                               +-+--+--------+------+              
 *                               |     IPProtocol     |              
 *                               +---------+----------+              
 *                                         |                         
 *                               +---------+----------+              
 *                               |   GPRSProtocol     |              
 *                               +---------+----------+              
 *                                         |                         
 *                               +---------+----------+              
 *                               |    UDPProtocol     |              
 *                               +---------+----------+              
 *                                         |                         
 *                               +---------+----------+              
 *                         +---> |    IPv6Protocol    | <---+        
 *                         |     +---------+----------+     |        
 *                         |               |                |        
 *                +--------+-----------+   |   +------------+-------+
 *                |    VLANProtocol    |   |   |    MPLSProtocol    |
 *                +--------+-----------+   |   +------------+-------+
 *                         |               |                |        
 *                         |     +---------+----------+     |        
 *                         +-----+  EthernetProtocol  +-----+        
 *                               +--------------------+              
 *
 */
#ifndef SRC_STACKMOBILEIPV6_H_
#define SRC_STACKMOBILEIPV6_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <chrono>
#include <string>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "protocols/ip/IPProtocol.h"
#include "protocols/ip6/IPv6Protocol.h"
#include "protocols/udp/UDPProtocol.h"
#include "protocols/gprs/GPRSProtocol.h"
#include "protocols/tcp/TCPProtocol.h"
#include "protocols/icmp6/ICMPv6Protocol.h"
#include "flow/FlowManager.h"
#include "flow/FlowCache.h"
#include "NetworkStack.h"

namespace aiengine {

class StackMobileIPv6: public NetworkStack {
public:
	explicit StackMobileIPv6();
        virtual ~StackMobileIPv6() {}

        MultiplexerPtrWeak getLinkLayerMultiplexer() override { return mux_eth; }

        void statistics(std::basic_ostream<char> &out) const override;

	void showFlows(std::basic_ostream<char> &out, const std::string &protoname, int limit) override; 
	void showFlows(std::basic_ostream<char> &out, int limit) override;

        void setTotalTCPFlows(int value) override;
        void setTotalUDPFlows(int value) override;
        int getTotalTCPFlows() const override;
        int getTotalUDPFlows() const override;

	void enableNIDSEngine(bool value) override;
	void enableFrequencyEngine(bool value) override;
        bool isEnableFrequencyEngine() const override { return enable_frequency_engine_; }
        bool isEnableNIDSEngine() const override { return enable_nids_engine_; }

	void setFlowsTimeout(int timeout) override;
	int getFlowsTimeout() const override { return flow_table_tcp_->getTimeout(); }

#if defined(BINDING)
        FlowManager &getTCPFlowManager() override { return *flow_table_tcp_.get(); }
        FlowManager &getUDPFlowManager() override { return *flow_table_udp_high_.get(); }
#else
        FlowManagerPtrWeak getTCPFlowManager() override { return flow_table_tcp_; }
        FlowManagerPtrWeak getUDPFlowManager() override { return flow_table_udp_high_; }
#endif

	void setTCPRegexManager(const SharedPointer<RegexManager> &rm) override;
        void setUDPRegexManager(const SharedPointer<RegexManager> &rm) override;

        void setTCPIPSetManager(const SharedPointer<IPSetManager> &ipset_mng) override;
        void setUDPIPSetManager(const SharedPointer<IPSetManager> &ipset_mng) override;

#if defined(RUBY_BINDING) || defined(LUA_BINDING) || defined(GO_BINDING)
        void setTCPRegexManager(RegexManager &rm) { setTCPRegexManager(std::make_shared<RegexManager>(rm)); }
        void setUDPRegexManager(RegexManager &rm) { setUDPRegexManager(std::make_shared<RegexManager>(rm)); }

        void setTCPIPSetManager(IPSetManager &ipset_mng) { setTCPIPSetManager(std::make_shared<IPSetManager>(ipset_mng)); }
        void setUDPIPSetManager(IPSetManager &ipset_mng) { setUDPIPSetManager(std::make_shared<IPSetManager>(ipset_mng)); }
#elif defined(JAVA_BINDING)
        void setTCPRegexManager(RegexManager *sig);
        void setUDPRegexManager(RegexManager *sig); 
        
	void setTCPIPSetManager(IPSetManager *ipset_mng); 
        void setUDPIPSetManager(IPSetManager *ipset_mng);
#endif

	std::tuple<Flow*, Flow*> getCurrentFlows() const override; 

private:
	typedef NetworkStack super_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
        //Protocols
        IPProtocolPtr ip_low_;
	IPv6ProtocolPtr ip6_high_;
        UDPProtocolPtr udp_low_;
	UDPProtocolPtr udp_high_;
        TCPProtocolPtr tcp_;
        GPRSProtocolPtr gprs_;
        ICMPv6ProtocolPtr icmp6_;
	
        // Specific Multiplexers
        MultiplexerPtr mux_ip6_high_;
        MultiplexerPtr mux_udp_low_;
	MultiplexerPtr mux_udp_high_;
        MultiplexerPtr mux_gprs_;
        MultiplexerPtr mux_tcp_;
        MultiplexerPtr mux_icmp6_;

        // FlowManager and FlowCache
        FlowManagerPtr flow_table_tcp_;
        FlowManagerPtr flow_table_udp_high_;
        FlowManagerPtr flow_table_udp_low_;
        FlowCachePtr flow_cache_tcp_;
        FlowCachePtr flow_cache_udp_low_;
        FlowCachePtr flow_cache_udp_high_;

        // FlowForwarders
        SharedPointer<FlowForwarder> ff_udp_low_;
        SharedPointer<FlowForwarder> ff_gprs_;
        SharedPointer<FlowForwarder> ff_tcp_;
        SharedPointer<FlowForwarder> ff_udp_high_;

       	bool enable_frequency_engine_;
       	bool enable_nids_engine_;
};

} // namespace aiengine

#endif  // SRC_STACKMOBILEIPV6_H_
