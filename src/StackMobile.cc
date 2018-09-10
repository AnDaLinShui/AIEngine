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
#include "StackMobile.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackMobile::logger(log4cxx::Logger::getLogger("aiengine.stackmobile"));
#endif

StackMobile::StackMobile(): 
	/* LCOV_EXCL_START Looks that coverage dont like this */
        ip_low_(IPProtocolPtr(new IPProtocol())),
        ip_high_(IPProtocolPtr(new IPProtocol())),
        udp_low_(UDPProtocolPtr(new UDPProtocol("UDPProtocol GPRS", "udp gprs"))),
        udp_high_(UDPProtocolPtr(new UDPProtocol())),
        tcp_(TCPProtocolPtr(new TCPProtocol())),
	gprs_(GPRSProtocolPtr(new GPRSProtocol())),
        icmp_(ICMPProtocolPtr(new ICMPProtocol())),
	// Multiplexers
        mux_ip_high_(MultiplexerPtr(new Multiplexer())),
        mux_udp_low_(MultiplexerPtr(new Multiplexer())),
        mux_udp_high_(MultiplexerPtr(new Multiplexer())),
        mux_gprs_(MultiplexerPtr(new Multiplexer())),
        mux_tcp_(MultiplexerPtr(new Multiplexer())),
        mux_icmp_(MultiplexerPtr(new Multiplexer())),
	// FlowManager and FlowCache
        flow_table_tcp_(FlowManagerPtr(new FlowManager())),
        flow_table_udp_high_(FlowManagerPtr(new FlowManager())),
        flow_table_udp_low_(FlowManagerPtr(new FlowManager())),
        flow_cache_tcp_(FlowCachePtr(new FlowCache())),
        flow_cache_udp_low_(FlowCachePtr(new FlowCache())),
        flow_cache_udp_high_(FlowCachePtr(new FlowCache())),
	// FlowForwarders
        ff_udp_low_(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_gprs_(SharedPointer<FlowForwarder>(new FlowForwarder())), 
        ff_tcp_(SharedPointer<FlowForwarder>(new FlowForwarder())), 
        ff_udp_high_(SharedPointer<FlowForwarder>(new FlowForwarder())),
        enable_frequency_engine_(false),
        enable_nids_engine_(false) { 
	/* LCOV_EXCL_STOP */

	setName("Mobile Network Stack");

	// Add the Protocol objects
	addProtocol(eth, true);
	addProtocol(vlan, false);
	addProtocol(mpls, false);
	addProtocol(pppoe, false);
	addProtocol(ip_low_, true);
	addProtocol(udp_low_, true);
	addProtocol(gprs_, true);
	addProtocol(ip_high_, true);
	addProtocol(udp_high_, true);
	addProtocol(tcp_, true);
	addProtocol(icmp_, true);

	// Add the L7 protocols
	addProtocol(http);
	addProtocol(ssl);
	addProtocol(smtp);
	addProtocol(imap);
	addProtocol(pop);
	addProtocol(bitcoin);
	addProtocol(tcp_generic);
	addProtocol(freqs_tcp, false);
	addProtocol(dns);
	addProtocol(sip);
	addProtocol(ntp);
	addProtocol(snmp);
	addProtocol(ssdp);
	addProtocol(rtp);
	addProtocol(quic);
	addProtocol(udp_generic);
	addProtocol(freqs_udp, false);

        // Link the FlowCaches to their corresponding FlowManager for timeouts
        flow_table_udp_low_->setFlowCache(flow_cache_udp_low_);
        flow_table_udp_high_->setFlowCache(flow_cache_udp_high_);
        flow_table_tcp_->setFlowCache(flow_cache_tcp_);

	// configure the low IP Layer 
	ip_low_->setMultiplexer(mux_ip);
	mux_ip->setProtocol(static_cast<ProtocolPtr>(ip_low_));
	mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
	mux_ip->setHeaderSize(ip_low_->getHeaderSize());
	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker, ip_low_, std::placeholders::_1));
	mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket, ip_low_, std::placeholders::_1));

	//configure the low UDP Layer 
	udp_low_->setMultiplexer(mux_udp_low_);
	mux_udp_low_->setProtocol(static_cast<ProtocolPtr>(udp_low_));
	ff_udp_low_->setProtocol(static_cast<ProtocolPtr>(udp_low_));
	mux_udp_low_->setProtocolIdentifier(IPPROTO_UDP);
	mux_udp_low_->setHeaderSize(udp_low_->getHeaderSize());
	mux_udp_low_->addChecker(std::bind(&UDPProtocol::udpChecker, udp_low_, std::placeholders::_1));
	mux_udp_low_->addPacketFunction(std::bind(&UDPProtocol::processPacket, udp_low_, std::placeholders::_1));

	//configure the gprs
	gprs_->setFlowForwarder(ff_gprs_);
	gprs_->setMultiplexer(mux_gprs_);
	mux_gprs_->setProtocol(static_cast<ProtocolPtr>(gprs_));
	mux_gprs_->setHeaderSize(gprs_->getHeaderSize());
	mux_gprs_->setProtocolIdentifier(0);
	ff_gprs_->setProtocol(static_cast<ProtocolPtr>(gprs_));
	ff_gprs_->addChecker(std::bind(&GPRSProtocol::gprsChecker, gprs_, std::placeholders::_1));
	ff_gprs_->addFlowFunction(std::bind(&GPRSProtocol::processFlow, gprs_, std::placeholders::_1));

     	// configure the high ip handler
        ip_high_->setMultiplexer(mux_ip_high_);
        mux_ip_high_->setProtocol(static_cast<ProtocolPtr>(ip_high_));
        mux_ip_high_->setProtocolIdentifier(ETHERTYPE_IP);
        mux_ip_high_->setHeaderSize(ip_high_->getHeaderSize());
        mux_ip_high_->addChecker(std::bind(&IPProtocol::ipChecker, ip_high_, std::placeholders::_1));
        mux_ip_high_->addPacketFunction(std::bind(&IPProtocol::processPacket, ip_high_, std::placeholders::_1));

        // Create the HIGH UDP layer
        udp_high_->setMultiplexer(mux_udp_high_);
        mux_udp_high_->setProtocol(static_cast<ProtocolPtr>(udp_high_));
        ff_udp_high_->setProtocol(static_cast<ProtocolPtr>(udp_high_));
        mux_udp_high_->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_high_->setHeaderSize(udp_high_->getHeaderSize());
        mux_udp_high_->addChecker(std::bind(&UDPProtocol::udpChecker, udp_high_, std::placeholders::_1));
        mux_udp_high_->addPacketFunction(std::bind(&UDPProtocol::processPacket, udp_high_, std::placeholders::_1));

	//configure the TCP Layer
	tcp_->setMultiplexer(mux_tcp_);
	mux_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	ff_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	mux_tcp_->setProtocolIdentifier(IPPROTO_TCP);
	mux_tcp_->setHeaderSize(tcp_->getHeaderSize());
	mux_tcp_->addChecker(std::bind(&TCPProtocol::tcpChecker, tcp_, std::placeholders::_1));
	mux_tcp_->addPacketFunction(std::bind(&TCPProtocol::processPacket, tcp_, std::placeholders::_1));

        //configure the ICMP Layer
        icmp_->setMultiplexer(mux_icmp_);
        mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp_));
        mux_icmp_->setProtocolIdentifier(IPPROTO_ICMP);
        mux_icmp_->setHeaderSize(icmp_->getHeaderSize());
        mux_icmp_->addChecker(std::bind(&ICMPProtocol::icmpChecker, icmp_, std::placeholders::_1));
	mux_icmp_->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp_, std::placeholders::_1));

	// configure the multiplexers
	mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
	mux_ip->addDownMultiplexer(mux_eth);
	mux_ip->addUpMultiplexer(mux_udp_low_,IPPROTO_UDP);
	mux_udp_low_->addDownMultiplexer(mux_ip);

	// configure the multiplexers of the second part
	mux_gprs_->addUpMultiplexer(mux_ip_high_, ETHERTYPE_IP);
        mux_ip_high_->addDownMultiplexer(mux_gprs_);
        mux_ip_high_->addUpMultiplexer(mux_icmp_, IPPROTO_ICMP);
	mux_icmp_->addDownMultiplexer(mux_ip_high_);
	mux_ip_high_->addUpMultiplexer(mux_tcp_, IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip_high_);
	mux_ip_high_->addUpMultiplexer(mux_udp_high_, IPPROTO_UDP);
	mux_udp_high_->addDownMultiplexer(mux_ip_high_);

	// Connect the FlowManager and FlowCache
	tcp_->setFlowCache(flow_cache_tcp_);
	tcp_->setFlowManager(flow_table_tcp_);
	flow_table_tcp_->setProtocol(tcp_);
			
	udp_low_->setFlowCache(flow_cache_udp_low_);
	udp_low_->setFlowManager(flow_table_udp_low_);
	
	udp_high_->setFlowCache(flow_cache_udp_high_);
	udp_high_->setFlowManager(flow_table_udp_high_);
	flow_table_udp_high_->setProtocol(udp_high_);

        // Connect to upper layers the FlowManager
        http->setFlowManager(flow_table_tcp_);
        ssl->setFlowManager(flow_table_tcp_);
        smtp->setFlowManager(flow_table_tcp_);
        imap->setFlowManager(flow_table_tcp_);
        pop->setFlowManager(flow_table_tcp_);
        bitcoin->setFlowManager(flow_table_tcp_);
        dns->setFlowManager(flow_table_udp_high_);
        sip->setFlowManager(flow_table_udp_high_);
        ssdp->setFlowManager(flow_table_udp_high_);
        gprs_->setFlowManager(flow_table_udp_low_);

        freqs_tcp->setFlowManager(flow_table_tcp_);
        freqs_udp->setFlowManager(flow_table_udp_high_);

        // Connect the AnomalyManager with the protocols that may have anomalies
        ip_low_->setAnomalyManager(anomaly_);
        ip_high_->setAnomalyManager(anomaly_);
        tcp_->setAnomalyManager(anomaly_);
        udp_low_->setAnomalyManager(anomaly_);
        udp_high_->setAnomalyManager(anomaly_);
      
	// The low FlowManager have a 24 hours timeout to keep the Context on memory
        flow_table_udp_low_->setTimeout(86400);

	// Configure the FlowForwarders
	udp_low_->setFlowForwarder(ff_udp_low_);
	ff_udp_low_->addUpFlowForwarder(ff_gprs_);

	tcp_->setFlowForwarder(ff_tcp_);	
	udp_high_->setFlowForwarder(ff_udp_high_);	

	setTCPDefaultForwarder(ff_tcp_);
        setUDPDefaultForwarder(ff_udp_high_);

	enableFlowForwarders(
		{ff_tcp_, ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin, ff_tcp_generic});
        enableFlowForwarders( {ff_udp_high_,
		ff_sip, ff_dhcp, ff_ntp, ff_snmp, ff_ssdp, ff_rtp, ff_quic, ff_udp_generic});

        std::ostringstream msg;
        msg << getName() << " ready.";

        infoMessage(msg.str());
}

void StackMobile::showFlows(std::basic_ostream<char> &out, const std::string &protoname, int limit) {

        int total = flow_table_tcp_->getTotalFlows() + flow_table_udp_low_->getTotalFlows();
        total += flow_table_udp_high_->getTotalFlows();

        out << "Flows on memory " << total << std::endl;
        flow_table_udp_low_->showFlows(out, protoname, limit);
        flow_table_tcp_->showFlows(out,protoname, limit);
        flow_table_udp_high_->showFlows(out,protoname, limit);
}

void StackMobile::showFlows(std::basic_ostream<char> &out, int limit) {

        int total = flow_table_tcp_->getTotalFlows() + flow_table_udp_low_->getTotalFlows();
	total += flow_table_udp_high_->getTotalFlows();

        out << "Flows on memory " << total << std::endl;
	flow_table_udp_low_->showFlows(out, limit);
	flow_table_tcp_->showFlows(out, limit);
	flow_table_udp_high_->showFlows(out, limit);
}

void StackMobile::statistics(std::basic_ostream<char> &out) const {

        super_::statistics(out);
}

void StackMobile::setTotalTCPFlows(int value) {

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
}

void StackMobile::setTotalUDPFlows(int value) {

	flow_cache_udp_high_->createFlows(value);
        flow_cache_udp_low_->createFlows(value/8);
        gprs_->increaseAllocatedMemory(value/8);
        dns->increaseAllocatedMemory(value / 2);
        sip->increaseAllocatedMemory(value * 0.2);
        ssdp->increaseAllocatedMemory(value * 0.2);
}

int StackMobile::getTotalTCPFlows() const { return flow_cache_tcp_->getTotalFlows(); }

int StackMobile::getTotalUDPFlows() const { return flow_cache_udp_high_->getTotalFlows(); }

void StackMobile::enableFrequencyEngine(bool enable) {

        int tcp_flows_created = flow_cache_tcp_->getTotalFlows();
        int udp_flows_created = flow_cache_udp_high_->getTotalFlows();

        if (enable) {
        	std::ostringstream msg;
        	msg << "Enable FrequencyEngine on " << getName();

        	infoMessage(msg.str());

		disableFlowForwarders( {ff_tcp_, 
			ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin, ff_tcp_generic});
        	disableFlowForwarders( {ff_udp_high_,
			ff_dns, ff_sip, ff_dhcp, ff_ntp, ff_snmp, ff_ssdp, ff_rtp, ff_quic, ff_udp_generic});

                freqs_tcp->createFrequencies(tcp_flows_created);
                freqs_udp->createFrequencies(udp_flows_created);

                freqs_tcp->setActive(true);
                freqs_udp->setActive(true);

                ff_tcp_->insertUpFlowForwarder(ff_tcp_freqs);
                ff_udp_high_->insertUpFlowForwarder(ff_udp_freqs);
        } else {
                freqs_tcp->destroyFrequencies(tcp_flows_created);
                freqs_udp->destroyFrequencies(udp_flows_created);

		enableFlowForwarders( {ff_tcp_, 
			ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin, ff_tcp_generic});
        	enableFlowForwarders( {ff_udp_high_,
			ff_dns, ff_sip, ff_dhcp, ff_ntp, ff_snmp, ff_ssdp, ff_rtp, ff_quic, ff_udp_generic});

                freqs_tcp->setActive(false);
                freqs_udp->setActive(false);

                ff_tcp_->removeUpFlowForwarder(ff_tcp_freqs);
                ff_udp_high_->removeUpFlowForwarder(ff_udp_freqs);
        }
	enable_frequency_engine_ = enable;
}

void StackMobile::enableNIDSEngine(bool enable) {

        if (enable) {
		disableFlowForwarders( {ff_tcp_, ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin});
        	disableFlowForwarders( {ff_udp_high_,
			ff_dns, ff_sip, ff_dhcp, ff_ntp, ff_snmp, ff_ssdp, ff_rtp, ff_quic});

	        std::ostringstream msg;
        	msg << "Enable NIDSEngine on " << getName(); 

        	infoMessage(msg.str());
        } else {
		disableFlowForwarders( {ff_tcp_, ff_tcp_generic});
        	disableFlowForwarders( {ff_udp_high_, ff_udp_generic});

		enableFlowForwarders( {ff_tcp_, ff_http, ff_ssl, ff_smtp, ff_imap, ff_pop, ff_bitcoin, ff_tcp_generic});
        	enableFlowForwarders( {ff_udp_high_,
			ff_dns, ff_sip, ff_dhcp, ff_ntp, ff_snmp, ff_ssdp, ff_rtp, ff_quic, ff_udp_generic});
        }
	enable_nids_engine_ = enable;
}

void StackMobile::setFlowsTimeout(int timeout) {

        flow_table_tcp_->setTimeout(timeout);
        flow_table_udp_high_->setTimeout(timeout);
}

void StackMobile::setTCPRegexManager(const SharedPointer<RegexManager> &rm) {

        tcp_->setRegexManager(rm);
        tcp_generic->setRegexManager(rm);
	super_::setTCPRegexManager(rm);
}

void StackMobile::setUDPRegexManager(const SharedPointer<RegexManager> &rm) {

        udp_high_->setRegexManager(rm);
        udp_generic->setRegexManager(rm);
	super_::setUDPRegexManager(rm);
}

void StackMobile::setTCPIPSetManager(const SharedPointer<IPSetManager> &ipset_mng) {

        tcp_->setIPSetManager(ipset_mng);
        super_::setTCPIPSetManager(ipset_mng);
}

void StackMobile::setUDPIPSetManager(const SharedPointer<IPSetManager> &ipset_mng) {

        udp_high_->setIPSetManager(ipset_mng);
        super_::setUDPIPSetManager(ipset_mng);
}

#if defined(JAVA_BINDING)

void StackMobile::setTCPRegexManager(RegexManager *sig) {

        SharedPointer<RegexManager> rm;

        if (sig != nullptr) {
                rm.reset(sig);
        }
        setTCPRegexManager(rm);
}

void StackMobile::setUDPRegexManager(RegexManager *sig) {

        SharedPointer<RegexManager> rm;

        if (sig != nullptr) {
                rm.reset(sig);
        }
        setUDPRegexManager(rm);
}

void StackMobile::setTCPIPSetManager(IPSetManager *ipset_mng) {

        SharedPointer<IPSetManager> im;

        if (ipset_mng != nullptr) {
                im.reset(ipset_mng);
        }
        setTCPIPSetManager(im);
}

void StackMobile::setUDPIPSetManager(IPSetManager *ipset_mng) {

        SharedPointer<IPSetManager> im;

        if (ipset_mng != nullptr) {
                im.reset(ipset_mng);
        }
        setUDPIPSetManager(im);
}

#endif

std::tuple<Flow*, Flow*> StackMobile::getCurrentFlows() const {

        Flow *low_flow = udp_low_->getCurrentFlow();
        Flow *high_flow = nullptr;
	uint16_t proto = ip_high_->getProtocol();

        if (proto == IPPROTO_TCP)
                high_flow = tcp_->getCurrentFlow();
        else if (proto == IPPROTO_UDP)
                high_flow = udp_high_->getCurrentFlow();

#if GCC_VERSION < 50500
        return std::tuple<Flow*, Flow*>(low_flow, high_flow);
#else
        return {low_flow, high_flow};
#endif
}

} // namespace aiengine
