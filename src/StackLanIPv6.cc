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
#include "StackLanIPv6.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackLanIPv6::logger(log4cxx::Logger::getLogger("aiengine.stacklan6"));
#endif

StackLanIPv6::StackLanIPv6():
	/* LCOV_EXCL_START Looks that coverage dont like this */
	ip6_(IPv6ProtocolPtr(new IPv6Protocol())),
	udp_(UDPProtocolPtr(new UDPProtocol())),
	tcp_(TCPProtocolPtr(new TCPProtocol())),
	icmp6_(ICMPv6ProtocolPtr(new ICMPv6Protocol())),
	dhcp6_(DHCPv6ProtocolPtr(new DHCPv6Protocol())),
        // Multiplexers
        mux_udp_(MultiplexerPtr(new Multiplexer())),
        mux_tcp_(MultiplexerPtr(new Multiplexer())),
        mux_icmp_(MultiplexerPtr(new Multiplexer())),
        // FlowManagers and FlowCaches
        flow_table_udp_(FlowManagerPtr(new FlowManager())),
        flow_table_tcp_(FlowManagerPtr(new FlowManager())),
        flow_cache_udp_(FlowCachePtr(new FlowCache())),
        flow_cache_tcp_(FlowCachePtr(new FlowCache())),
        // FlowForwarders
        ff_tcp_(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_udp_(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_dhcp6_(SharedPointer<FlowForwarder>(new FlowForwarder())),
        rj_mng_(),
        enable_frequency_engine_(false),
        enable_nids_engine_(false) {
	/* LCOV_EXCL_STOP */

	setName("Lan IPv6 network stack");

	// Add the specific Protocol objects
	addProtocol(eth, true);
	addProtocol(vlan, false);
	addProtocol(mpls, false);
	addProtocol(pppoe, false);
	addProtocol(ip6_, true);
	addProtocol(tcp_, true);
	addProtocol(udp_, true);
	addProtocol(icmp6_, true);

	// Layer7 protocols 
        addProtocol(http);
        addProtocol(ssl);
        addProtocol(smtp);
        addProtocol(imap);
        addProtocol(pop);
        addProtocol(ssh);
        addProtocol(bitcoin);
        addProtocol(mqtt);
        addProtocol(tcp_generic);
        addProtocol(freqs_tcp, false);
        addProtocol(dns);
        addProtocol(sip);
        addProtocol(ntp);
        addProtocol(snmp);
        addProtocol(ssdp);
	addProtocol(netbios);
        addProtocol(coap);
        addProtocol(rtp);
        addProtocol(quic);
        addProtocol(dhcp6_);
        addProtocol(udp_generic);
        addProtocol(freqs_udp, false);
 
        // Link the FlowCaches to their corresponding FlowManager for timeouts
        flow_table_udp_->setFlowCache(flow_cache_udp_);
        flow_table_tcp_->setFlowCache(flow_cache_tcp_);

	// configure the IP Layer 
	ip6_->setMultiplexer(mux_ip);
	mux_ip->setProtocol(static_cast<ProtocolPtr>(ip6_));
	mux_ip->setProtocolIdentifier(ETHERTYPE_IPV6);
	mux_ip->setHeaderSize(ip6_->getHeaderSize());
	mux_ip->addChecker(std::bind(&IPv6Protocol::ip6Checker, ip6_, std::placeholders::_1));
	mux_ip->addPacketFunction(std::bind(&IPv6Protocol::processPacket, ip6_, std::placeholders::_1));

	//configure the ICMPv6 Layer 
	icmp6_->setMultiplexer(mux_icmp_);
	mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp6_));
	mux_icmp_->setProtocolIdentifier(IPPROTO_ICMPV6);
	mux_icmp_->setHeaderSize(icmp6_->getHeaderSize());
	mux_icmp_->addChecker(std::bind(&ICMPv6Protocol::icmp6Checker, icmp6_, std::placeholders::_1));
	mux_icmp_->addPacketFunction(std::bind(&ICMPv6Protocol::processPacket, icmp6_, std::placeholders::_1));

	//configure the UDP Layer 
	udp_->setMultiplexer(mux_udp_);
	mux_udp_->setProtocol(static_cast<ProtocolPtr>(udp_));
	ff_udp_->setProtocol(static_cast<ProtocolPtr>(udp_));
	mux_udp_->setProtocolIdentifier(IPPROTO_UDP);
	mux_udp_->setHeaderSize(udp_->getHeaderSize());
	mux_udp_->addChecker(std::bind(&UDPProtocol::udpChecker, udp_, std::placeholders::_1));
	mux_udp_->addPacketFunction(std::bind(&UDPProtocol::processPacket, udp_, std::placeholders::_1));

	//configure the TCP Layer
	tcp_->setMultiplexer(mux_tcp_);
	mux_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	ff_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	mux_tcp_->setProtocolIdentifier(IPPROTO_TCP);
	mux_tcp_->setHeaderSize(tcp_->getHeaderSize());
	mux_tcp_->addChecker(std::bind(&TCPProtocol::tcpChecker, tcp_, std::placeholders::_1));
	mux_tcp_->addPacketFunction(std::bind(&TCPProtocol::processPacket, tcp_, std::placeholders::_1));

	// configure the dhcp
        dhcp6_->setFlowForwarder(ff_dhcp6_);
        ff_dhcp6_->setProtocol(static_cast<ProtocolPtr>(dhcp6_));
        ff_dhcp6_->addChecker(std::bind(&DHCPv6Protocol::dhcpv6Checker, dhcp6_, std::placeholders::_1));
        ff_dhcp6_->addFlowFunction(std::bind(&DHCPv6Protocol::processFlow, dhcp6_, std::placeholders::_1));

	// configure the multiplexers
	mux_eth->addUpMultiplexer(mux_ip, ETHERTYPE_IPV6);
	mux_ip->addDownMultiplexer(mux_eth);
	mux_ip->addUpMultiplexer(mux_udp_, IPPROTO_UDP);
	mux_udp_->addDownMultiplexer(mux_ip);
	mux_ip->addUpMultiplexer(mux_tcp_, IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip);
	mux_ip->addUpMultiplexer(mux_icmp_, IPPROTO_ICMPV6);
	mux_icmp_->addDownMultiplexer(mux_ip);
	
	// Connect the FlowManager and FlowCache
	tcp_->setFlowCache(flow_cache_tcp_);
	tcp_->setFlowManager(flow_table_tcp_);
	flow_table_tcp_->setProtocol(tcp_);
			
	udp_->setFlowCache(flow_cache_udp_);
	udp_->setFlowManager(flow_table_udp_);
	flow_table_udp_->setProtocol(udp_);

        // Connect to upper layers the FlowManager
        http->setFlowManager(flow_table_tcp_);
        ssl->setFlowManager(flow_table_tcp_);
        smtp->setFlowManager(flow_table_tcp_);
        imap->setFlowManager(flow_table_tcp_);
        pop->setFlowManager(flow_table_tcp_);
        mqtt->setFlowManager(flow_table_tcp_);
        ssh->setFlowManager(flow_table_tcp_);

        dns->setFlowManager(flow_table_udp_);
        sip->setFlowManager(flow_table_udp_);
        ssdp->setFlowManager(flow_table_udp_);
        coap->setFlowManager(flow_table_udp_);
        netbios->setFlowManager(flow_table_udp_);
        dhcp6_->setFlowManager(flow_table_udp_);

        freqs_tcp->setFlowManager(flow_table_tcp_);
        freqs_udp->setFlowManager(flow_table_udp_);

	// Connect the AnomalyManager with the protocols that may have anomalies
        ip6_->setAnomalyManager(anomaly_);
        tcp_->setAnomalyManager(anomaly_);
        udp_->setAnomalyManager(anomaly_);

	// Configure the FlowForwarders
	tcp_->setFlowForwarder(ff_tcp_);	
	udp_->setFlowForwarder(ff_udp_);	

        setTCPDefaultForwarder(ff_tcp_);
        setUDPDefaultForwarder(ff_udp_);

	enableFlowForwarders({ff_tcp_,
		ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin, ff_mqtt, ff_ssh, ff_tcp_generic});
        enableFlowForwarders({ff_udp_,
		ff_dns, ff_sip, ff_ntp, ff_snmp, ff_ssdp, ff_netbios, ff_coap, ff_rtp, ff_quic, ff_dhcp6_, ff_udp_generic});

        std::ostringstream msg;
        msg << getName() << " ready.";

        infoMessage(msg.str());
}

void StackLanIPv6::showFlows(std::basic_ostream<char> &out, int limit) {

	int total = flow_table_tcp_->getTotalFlows() + flow_table_udp_->getTotalFlows();
        out << "Flows on memory " << total << std::endl;
	flow_table_tcp_->showFlows(out, limit);
	flow_table_udp_->showFlows(out, limit);
}

void StackLanIPv6::showFlows(std::basic_ostream<char> &out, const std::string &protoname, int limit) {

	int total = flow_table_tcp_->getTotalFlows() + flow_table_udp_->getTotalFlows();
        out << "Flows on memory " << total << std::endl;
	flow_table_tcp_->showFlows(out, protoname, limit);
	flow_table_udp_->showFlows(out, protoname, limit);
}

void StackLanIPv6::enableFrequencyEngine(bool enable) {

	int tcp_flows_created = flow_cache_tcp_->getTotalFlows();
	int udp_flows_created = flow_cache_udp_->getTotalFlows();

	if (enable) {
        	std::ostringstream msg;
        	msg << "Enable FrequencyEngine on " << getName();

        	infoMessage(msg.str());

        	disableFlowForwarders({ff_tcp_, ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin, ff_mqtt, ff_ssh, ff_tcp_generic});
        	disableFlowForwarders({ff_udp_,
			ff_dns, ff_sip, ff_ntp, ff_snmp, ff_ssdp, ff_netbios, ff_coap, ff_rtp, ff_quic, ff_dhcp6_, ff_udp_generic});

		freqs_tcp->setActive(true);
		freqs_udp->setActive(true);

		freqs_tcp->createFrequencies(tcp_flows_created);	
		freqs_udp->createFrequencies(udp_flows_created);	

		ff_tcp_->insertUpFlowForwarder(ff_tcp_freqs);	
		ff_udp_->insertUpFlowForwarder(ff_udp_freqs);
	} else {
		freqs_tcp->destroyFrequencies(tcp_flows_created);	
		freqs_udp->destroyFrequencies(udp_flows_created);	
		
		freqs_tcp->setActive(false);
		freqs_udp->setActive(false);

		ff_tcp_->removeUpFlowForwarder(ff_tcp_freqs);
		ff_udp_->removeUpFlowForwarder(ff_udp_freqs);
	}
	enable_frequency_engine_ = enable;
}

void StackLanIPv6::enableNIDSEngine(bool enable) {

	if (enable) {
        	disableFlowForwarders({ff_tcp_, ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin, ff_mqtt, ff_ssh});
        	disableFlowForwarders({ff_udp_,
			ff_dns, ff_sip, ff_ntp, ff_snmp, ff_ssdp, ff_netbios, ff_coap, ff_rtp, ff_quic, ff_dhcp6_});

	        std::ostringstream msg;
       		msg << "Enable NIDSEngine on " << getName(); 

        	infoMessage(msg.str());
	} else {
        	disableFlowForwarders({ff_tcp_, ff_tcp_generic});
        	disableFlowForwarders({ff_udp_, ff_udp_generic});

        	enableFlowForwarders({ff_tcp_,
			ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin, ff_mqtt, ff_ssh, ff_tcp_generic});
        	enableFlowForwarders({ff_udp_,
			ff_dns, ff_sip, ff_ntp, ff_snmp, ff_ssdp, ff_netbios, ff_coap, ff_rtp, ff_quic, ff_dhcp6_, ff_udp_generic});
	}
	enable_nids_engine_ = enable;
}

void StackLanIPv6::setTotalTCPFlows(int value) {

	flow_cache_tcp_->createFlows(value);
	tcp_->createTCPInfos(value);

	// The vast majority of the traffic of internet is HTTP
	// so create 75% of the value received for the http caches
	http->increaseAllocatedMemory(value * 0.75);

        // The 40% of the traffic is SSL
        ssl->increaseAllocatedMemory(value * 0.4);

	// 5% of the traffic could be SMTP/IMAP, im really positive :D
	smtp->increaseAllocatedMemory(value * 0.05);
	imap->increaseAllocatedMemory(value * 0.05);
	pop->increaseAllocatedMemory(value * 0.05);
	bitcoin->increaseAllocatedMemory(value * 0.05);
	mqtt->increaseAllocatedMemory(value * 0.05);
	ssh->increaseAllocatedMemory(value * 0.05);
}

void StackLanIPv6::setTotalUDPFlows(int value) {

	flow_cache_udp_->createFlows(value);

	dns->increaseAllocatedMemory(value/ 2);
        sip->increaseAllocatedMemory(value * 0.2);
        ssdp->increaseAllocatedMemory(value * 0.2);
        coap->increaseAllocatedMemory(value * 0.2);
}

int StackLanIPv6::getTotalTCPFlows() const { return flow_cache_tcp_->getTotalFlows(); }

int StackLanIPv6::getTotalUDPFlows() const { return flow_cache_udp_->getTotalFlows(); }

void StackLanIPv6::setFlowsTimeout(int timeout) {

        flow_table_udp_->setTimeout(timeout);
        flow_table_tcp_->setTimeout(timeout);
}

void StackLanIPv6::setTCPRegexManager(const SharedPointer<RegexManager> &rm) {

        tcp_->setRegexManager(rm);
        tcp_generic->setRegexManager(rm);
	super_::setTCPRegexManager(rm);
}

void StackLanIPv6::setUDPRegexManager(const SharedPointer<RegexManager> &rm) {

        udp_->setRegexManager(rm);
        udp_generic->setRegexManager(rm);
	super_::setUDPRegexManager(rm);
}

void StackLanIPv6::setTCPIPSetManager(const SharedPointer<IPSetManager> &ipset_mng) { 

	tcp_->setIPSetManager(ipset_mng);
	super_::setTCPIPSetManager(ipset_mng);
}

void StackLanIPv6::setUDPIPSetManager(const SharedPointer<IPSetManager> &ipset_mng) { 

	udp_->setIPSetManager(ipset_mng);
	super_::setUDPIPSetManager(ipset_mng);
}

void StackLanIPv6::setAsioService(boost::asio::io_service &io_service) {

        // Create a new RejectManager with their corresponding sockets
#ifdef HAVE_REJECT_FLOW
        if (geteuid() == 0) { // The process have rights on raw sockets
                rj_mng_ = SharedPointer<RejectManager<StackLanIPv6>>(new RejectManager<StackLanIPv6>(io_service));
                if (rj_mng_->ready()) {
                        // Attach the reject function to the corresponding protocols tcp/udp
                        tcp_->addRejectFunction(std::bind(&RejectManager<StackLanIPv6>::rejectTCPFlow, rj_mng_, std::placeholders::_1));
                        udp_->addRejectFunction(std::bind(&RejectManager<StackLanIPv6>::rejectUDPFlow, rj_mng_, std::placeholders::_1));
                }
        }
#endif

}

void StackLanIPv6::statistics(std::basic_ostream<char> &out) const {

        super_::statistics(out);
#ifdef HAVE_REJECT_FLOW
        if (geteuid() == 0) { // The process have rights on raw sockets
                if (rj_mng_) {
                        rj_mng_->statistics(out);
                        out << std::endl;
                }
        }
#endif
}

#if defined(JAVA_BINDING)

void StackLanIPv6::setTCPRegexManager(RegexManager *sig) {

        SharedPointer<RegexManager> rm;

        if (sig != nullptr) {
                rm.reset(sig);
        }
        setTCPRegexManager(rm);
}

void StackLanIPv6::setUDPRegexManager(RegexManager *sig) {

        SharedPointer<RegexManager> rm;

        if (sig != nullptr) {
                rm.reset(sig);
        }
        setUDPRegexManager(rm);
}

void StackLanIPv6::setTCPIPSetManager(IPSetManager *ipset_mng) {

        SharedPointer<IPSetManager> im;

        if (ipset_mng != nullptr) {
                im.reset(ipset_mng);
        }
        setTCPIPSetManager(im);
}

void StackLanIPv6::setUDPIPSetManager(IPSetManager *ipset_mng) {

        SharedPointer<IPSetManager> im;

        if (ipset_mng != nullptr) {
                im.reset(ipset_mng);
        }
        setUDPIPSetManager(im);
}

#endif

std::tuple<Flow*, Flow*> StackLanIPv6::getCurrentFlows() const {

        Flow *flow = nullptr;
	uint16_t proto = ip6_->getL7Protocol();

        if (proto == IPPROTO_TCP)
                flow = tcp_->getCurrentFlow();
        else if (proto == IPPROTO_UDP)
                flow = udp_->getCurrentFlow();

#if GCC_VERSION < 50500
        return std::tuple<Flow*, Flow*>(flow, nullptr);
#else
        return {flow, nullptr};
#endif
}

} // namespace aiengine
