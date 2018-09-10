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
#include "test_gprs.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE gprstest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(test_suite_gprs, Stack3Gtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

       	BOOST_CHECK(gprs->getTotalBytes() == 0);
       	BOOST_CHECK(gprs->getTotalValidPackets() == 0);
       	BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
       	BOOST_CHECK(gprs->getTotalPackets() == 0);
	BOOST_CHECK(gprs->processPacket(packet) == true);

        BOOST_CHECK(gprs->getTotalCreatePDPContextRequests() == 0);
        BOOST_CHECK(gprs->getTotalCreatePDPContextResponses() == 0);
        BOOST_CHECK(gprs->getTotalUpdatePDPContextRequests() == 0);
        BOOST_CHECK(gprs->getTotalUpdatePDPContextResponses() == 0);
        BOOST_CHECK(gprs->getTotalDeletePDPContextRequests() == 0);
        BOOST_CHECK(gprs->getTotalDeletePDPContextResponses() == 0); 
        BOOST_CHECK(gprs->getTotalPdus() == 0);
        BOOST_CHECK(gprs->getTotalEchoRequets() == 0);
        BOOST_CHECK(gprs->getTotalEchoResponses() == 0); 
	
	CounterMap c = gprs->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../gprs/packets/packet01.pcap");

	inject(packet);

	// check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet.getLength());
	BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!! 

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IP);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        // check the integrity of the first ip header
        BOOST_CHECK(mux_ip_low->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip_low->getTotalFailPackets() == 0);

        BOOST_CHECK(ip_low->getTTL() == 254);
        BOOST_CHECK(ip_low->getIPHeaderLength() == 20);
        BOOST_CHECK(ip_low->getProtocol() == IPPROTO_UDP);
        BOOST_CHECK(ip_low->getPacketLength() == packet.getLength() - 14);
       	BOOST_CHECK(ip_low->getTotalBytes() == 72);

	std::string localip("208.64.30.124");
        std::string remoteip("164.20.62.30");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation())==0);

	// Check the UDP layer
	BOOST_CHECK(udp_low->getTotalBytes() == 52);
       	BOOST_CHECK(udp_low->getLength() == 52);
       	BOOST_CHECK(udp_low->getTotalValidPackets() == 1);
       	BOOST_CHECK(udp_low->getTotalInvalidPackets() == 0);
       	BOOST_CHECK(udp_low->getTotalPackets() == 1);

	BOOST_CHECK(ff_udp_low->getTotalForwardFlows()  == 1);
	BOOST_CHECK(ff_udp_low->getTotalReceivedFlows()  == 1);
	BOOST_CHECK(ff_udp_low->getTotalFailFlows()  == 0);

	// check the GPRS layer;
       	BOOST_CHECK(gprs->getTotalBytes() == 44);// Im not sure of this value, check!!!
       	BOOST_CHECK(gprs->getTotalValidPackets() == 1);
       	BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
       	BOOST_CHECK(gprs->getTotalPackets() == 1);
	BOOST_CHECK(gprs->haveSequenceNumber() == false);

        BOOST_CHECK(mux_gprs->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_gprs->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_gprs->getTotalFailPackets() == 0);

	// check the HIGH IP layer
       	BOOST_CHECK(ip_high->getTotalBytes() == 36);
       	BOOST_CHECK(ip_high->getTotalValidPackets() == 1);
       	BOOST_CHECK(ip_high->getTotalInvalidPackets() == 0);
       	BOOST_CHECK(ip_high->getTotalPackets() == 1);

        BOOST_CHECK(mux_ip_high->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip_high->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_ip_high->getTotalFailPackets() == 0);
	
	std::string localip_h("12.19.126.226");
        std::string remoteip_h("30.225.92.1");

        BOOST_CHECK(localip_h.compare(ip_high->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip_h.compare(ip_high->getDstAddrDotNotation())==0);

	// check the ICMP layer
       	BOOST_CHECK(icmp->getTotalValidPackets() == 1);
       	BOOST_CHECK(icmp->getTotalInvalidPackets() == 0);
       	BOOST_CHECK(icmp->getTotalPackets() == 0); // Because the packet function is not set!!!
        
	BOOST_CHECK(mux_icmp_high->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_icmp_high->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_icmp_high->getTotalFailPackets() == 1);

	BOOST_CHECK(icmp->getType() == 8);
	BOOST_CHECK(icmp->getCode() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../gprs/packets/packet02.pcap");

	// Allocate the UDP high part
        auto mux_udp_high = MultiplexerPtr(new Multiplexer());
	auto udp_high = UDPProtocolPtr(new UDPProtocol());
	auto ff_udp_high = SharedPointer<FlowForwarder>(new FlowForwarder());

	// Create the new UDP 
        udp_high->setMultiplexer(mux_udp_high);
        mux_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        ff_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        mux_udp_high->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_high->setHeaderSize(udp_high->getHeaderSize());
        mux_udp_high->addChecker(std::bind(&UDPProtocol::udpChecker, udp_high, std::placeholders::_1));
        mux_udp_high->addPacketFunction(std::bind(&UDPProtocol::processPacket, udp_high, std::placeholders::_1));

	// Plug the Multiplexer and the forwarder on the stack
       	mux_ip_high->addUpMultiplexer(mux_udp_high, IPPROTO_UDP);
        mux_udp_high->addDownMultiplexer(mux_ip_high);

        udp_high->setFlowCache(flow_cache);
        udp_high->setFlowManager(flow_mng);

        // Configure the FlowForwarders
        udp_high->setFlowForwarder(ff_udp_high);

	inject(packet);

	// Check the integrity of the highest IP 
	std::string localip_h("28.102.6.36");
        std::string remoteip_h("212.190.178.154");

        BOOST_CHECK(localip_h.compare(ip_high->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip_h.compare(ip_high->getDstAddrDotNotation())==0);

	// The flow cache should have two entries as well as the flow manager
	BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
	BOOST_CHECK(flow_mng->getTotalFlows() == 2);
	BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../gprs/packets/packet03.pcap");

        // Allocate the UDP high part
        MultiplexerPtr mux_udp_high = MultiplexerPtr(new Multiplexer());
        UDPProtocolPtr udp_high = UDPProtocolPtr(new UDPProtocol());
        SharedPointer<FlowForwarder> ff_udp_high = SharedPointer<FlowForwarder>(new FlowForwarder());

        // Create the new UDP
        udp_high->setMultiplexer(mux_udp_high);
        mux_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        ff_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        mux_udp_high->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_high->setHeaderSize(udp_high->getHeaderSize());
        mux_udp_high->addChecker(std::bind(&UDPProtocol::udpChecker,udp_high,std::placeholders::_1));
        mux_udp_high->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_high,std::placeholders::_1));

        // Plug the Multiplexer and the forwarder on the stack
        mux_ip_high->addUpMultiplexer(mux_udp_high,IPPROTO_UDP);
        mux_udp_high->addDownMultiplexer(mux_ip_high);

	FlowCachePtr f_cache = FlowCachePtr(new FlowCache());
	FlowManagerPtr f_mng = FlowManagerPtr(new FlowManager());

	f_cache->createFlows(10);

        udp_high->setFlowCache(f_cache);
        udp_high->setFlowManager(f_mng);

        // Configure the FlowForwarders
        udp_high->setFlowForwarder(ff_udp_high);
       
	inject(packet); 

	// Check the integrity of the first IP header
        std::string localip("192.168.62.200");
        std::string remoteip("192.168.62.16");

	BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation())==0);

        // Check the integrity of the second IP
        std::string localip_h("193.190.200.98");
        std::string remoteip_h("193.206.206.32");

	BOOST_CHECK(localip_h.compare(ip_high->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip_h.compare(ip_high->getDstAddrDotNotation())==0);

        // The first cache 
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

      	// Check the second cache 
        BOOST_CHECK(f_cache->getTotalAcquires() == 1);
        BOOST_CHECK(f_mng->getTotalFlows() == 1);
        BOOST_CHECK(f_cache->getTotalFails() == 0);

	BOOST_CHECK(gprs->haveSequenceNumber() == false);
}

BOOST_AUTO_TEST_CASE (test05) // with the DNSProtocol 
{
	Packet packet("../gprs/packets/packet02.pcap");

        // Allocate the UDP high part
        auto mux_udp_high = MultiplexerPtr(new Multiplexer());
        auto udp_high = UDPProtocolPtr(new UDPProtocol());
        auto ff_udp_high = SharedPointer<FlowForwarder>(new FlowForwarder());
        auto ff_dns_ = SharedPointer<FlowForwarder>(new FlowForwarder());

        // Create the new UDP
        udp_high->setMultiplexer(mux_udp_high);
        mux_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        ff_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        mux_udp_high->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_high->setHeaderSize(udp_high->getHeaderSize());
        mux_udp_high->addChecker(std::bind(&UDPProtocol::udpChecker,udp_high,std::placeholders::_1));
        mux_udp_high->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_high,std::placeholders::_1));

        // Plug the Multiplexer and the forwarder on the stack
        mux_ip_high->addUpMultiplexer(mux_udp_high,IPPROTO_UDP);
        mux_udp_high->addDownMultiplexer(mux_ip_high);

        udp_high->setFlowCache(flow_cache);
        udp_high->setFlowManager(flow_mng);

        // configure the DNS Layer
	DNSProtocolPtr dns_ = DNSProtocolPtr(new DNSProtocol());
        dns_->setFlowForwarder(ff_dns_);
        ff_dns_->setProtocol(static_cast<ProtocolPtr>(dns_));
        ff_dns_->addChecker(std::bind(&DNSProtocol::dnsChecker,dns_,std::placeholders::_1));
        ff_dns_->addFlowFunction(std::bind(&DNSProtocol::processFlow,dns_,std::placeholders::_1));

        // Configure the FlowForwarders
        udp_high->setFlowForwarder(ff_udp_high);
	ff_udp_high->addUpFlowForwarder(ff_dns_);

	inject(packet);
	inject(packet);

        // Check the integrity of the highest IP
        std::string localip_h("28.102.6.36");
        std::string remoteip_h("212.190.178.154");

        BOOST_CHECK(localip_h.compare(ip_high->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip_h.compare(ip_high->getDstAddrDotNotation())==0);

        // The flow cache should have two entries as well as the flow manager
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

	// check the DNSProtocol values
	BOOST_CHECK(dns_->getTotalPackets() == 2);
	BOOST_CHECK(dns_->getTotalValidPackets() == 1);
	BOOST_CHECK(dns_->getTotalBytes() == 68);
}

BOOST_AUTO_TEST_CASE (test06) // Process a pdp context creation
{
	Packet packet("../gprs/packets/packet04.pcap");

	gprs->increaseAllocatedMemory(1);

	inject(packet);

        // check the GPRS layer;
        BOOST_CHECK(gprs->getTotalBytes() == 159);
        BOOST_CHECK(gprs->getTotalValidPackets() == 1);
        BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
        BOOST_CHECK(gprs->getTotalPackets() == 1);

	int64_t a = gprs->getCurrentUseMemory();

	BOOST_CHECK(gprs->getTotalCacheMisses() == 0);

	// A pdp create dont forward nothing
        BOOST_CHECK(mux_gprs->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_gprs->getTotalReceivedPackets() == 0);
        BOOST_CHECK(mux_gprs->getTotalFailPackets() == 0);

	// Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info != nullptr);
        SharedPointer<GPRSInfo> info = flow->getGPRSInfo();

	{
		RedirectOutput r;
        
		r.cout << *info.get();
		flow->serialize(r.cout);
		flow->showFlowInfo(r.cout);
	}

	JsonFlow j;
	info->serialize(j);

	std::ifstream is("/dev/null");
	flow->deserialize(is);

	std::string imsi("234308256005467");
	BOOST_CHECK(imsi.compare(info->getIMSIString()) == 0);
	BOOST_CHECK(info->getPdpTypeNumber() == PDP_END_USER_TYPE_IPV4); // IPv4 

	// Just for execute at least one
	flow->setReject(false);
	flow->setEvidence(false);

	// Force a release
	gprs->releaseFlowInfo(flow);
	// Check the values of the flow
}

BOOST_AUTO_TEST_CASE (test07) // Process a pdp context creation
{
	Packet packet("../gprs/packets/packet05.pcap");

        gprs->increaseAllocatedMemory(1);

	inject(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info != nullptr);
        SharedPointer<GPRSInfo> info = flow->getGPRSInfo();

        std::string imsi("460004100000101");
        BOOST_CHECK(imsi.compare(info->getIMSIString()) == 0);
	BOOST_CHECK(info->getPdpTypeNumber() == PDP_END_USER_TYPE_IPV4); // IPv4 
}

BOOST_AUTO_TEST_CASE (test08) // Process a pdp context creation
{
	Packet packet("../gprs/packets/packet06.pcap");

        gprs->increaseAllocatedMemory(1);

	inject(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info != nullptr);
        SharedPointer<GPRSInfo> info = flow->getGPRSInfo();

        BOOST_CHECK(info->getPdpTypeNumber() == PDP_END_USER_TYPE_IPV6); // IPv6

	gprs->decreaseAllocatedMemory(1);
}

BOOST_AUTO_TEST_CASE (test09) // Process a pdp context creation with ipv6 and extension header and release the flows 
{
	Packet packet("../gprs/packets/packet07.pcap");

        gprs->increaseAllocatedMemory(1);

	inject(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info != nullptr);
        SharedPointer<GPRSInfo> info = flow->getGPRSInfo();

        std::string imsi("262026201608297");
        BOOST_CHECK(imsi.compare(info->getIMSIString()) == 0);
        BOOST_CHECK(info->getPdpTypeNumber() == PDP_END_USER_TYPE_IPV6); // IPv6

	gprs->releaseCache();

        BOOST_CHECK(flow->layer4info == nullptr);
}

BOOST_AUTO_TEST_CASE (test10) // Process a pdp context response
{
	Packet packet("../gprs/packets/packet08.pcap");

        gprs->increaseAllocatedMemory(1);

	inject(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info == nullptr);

	gprs->releaseCache();

        BOOST_CHECK(flow->layer4info == nullptr);
}

BOOST_AUTO_TEST_CASE (test11) // echo request
{
	Packet packet("../gprs/packets/packet09.pcap");

        gprs->increaseAllocatedMemory(1);

	inject(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info == nullptr);

        BOOST_CHECK(gprs->getTotalEchoRequets() == 1);
        BOOST_CHECK(gprs->getTotalEchoResponses() == 0);
}

BOOST_AUTO_TEST_CASE (test12) // echo response
{
	Packet packet("../gprs/packets/packet10.pcap");

        gprs->increaseAllocatedMemory(1);

	inject(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info == nullptr);
        
	BOOST_CHECK(gprs->getTotalEchoRequets() == 0);
        BOOST_CHECK(gprs->getTotalEchoResponses() == 1);
}

BOOST_AUTO_TEST_CASE (test13) // malformed gprs packet length
{
	Packet packet("../gprs/packets/packet05.pcap");

	packet.setPayloadLength(14 + 20 + 8 + 4);

        gprs->increaseAllocatedMemory(1);

        inject(packet);

        // Verify the integrity of the flow
        //Flow *flow = udp_low->getCurrentFlow();

        //BOOST_CHECK(flow == nullptr);

        BOOST_CHECK(gprs->getTotalBytes() == 0);
        BOOST_CHECK(gprs->getTotalValidPackets() == 0);
        BOOST_CHECK(gprs->getTotalInvalidPackets() == 1);
        BOOST_CHECK(gprs->getTotalPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test14) // update pdp 
{
	Packet packet("../gprs/packets/packet11.pcap");

	enableVlan();

        gprs->increaseAllocatedMemory(1);

        inject(packet);

        // Check the integrity of the first IP header
        std::string localip("172.16.132.21");
        std::string remoteip("172.16.150.197");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation()) == 0);

        BOOST_CHECK(gprs->getTotalBytes() == 73);
        BOOST_CHECK(gprs->getTotalValidPackets() == 1);
        BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
        BOOST_CHECK(gprs->getTotalPackets() == 1);
	BOOST_CHECK(gprs->getType() == UPDATE_PDP_CONTEXT_REQUEST);
	BOOST_CHECK(gprs->haveSequenceNumber() == true);
}

BOOST_AUTO_TEST_CASE (test15) // delete pdp request
{
	Packet packet("../gprs/packets/packet12.pcap");

        gprs->increaseAllocatedMemory(1);

        inject(packet);

        // Check the integrity of the first IP header
        std::string localip("59.64.183.202");
        std::string remoteip("59.64.183.203");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation()) == 0);

        BOOST_CHECK(gprs->getTotalBytes() == 16);
        BOOST_CHECK(gprs->getTotalValidPackets() == 1);
        BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
        BOOST_CHECK(gprs->getTotalPackets() == 1);
	BOOST_CHECK(gprs->getType() == DELETE_PDP_CONTEXT_REQUEST);
	BOOST_CHECK(gprs->haveSequenceNumber() == true);
}

BOOST_AUTO_TEST_CASE (test16) // delete pdp response
{
	Packet packet("../gprs/packets/packet13.pcap");

        gprs->increaseAllocatedMemory(1);

        inject(packet);

        // Check the integrity of the first IP header
        std::string localip("59.64.183.203");
        std::string remoteip("59.64.183.202");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation()) == 0);

        BOOST_CHECK(gprs->getTotalBytes() == 14 + 4);
        BOOST_CHECK(gprs->getTotalValidPackets() == 1);
        BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
        BOOST_CHECK(gprs->getTotalPackets() == 1);
	BOOST_CHECK(gprs->getType() == DELETE_PDP_CONTEXT_RESPONSE);
	BOOST_CHECK(gprs->haveSequenceNumber() == true);
}

BOOST_AUTO_TEST_CASE (test17) // delete pdp response with seq number
{
	Packet packet("../gprs/packets/packet14.pcap");

        gprs->increaseAllocatedMemory(1);

        inject(packet);

        // Check the integrity of the first IP header
        std::string localip("74.216.254.230");
        std::string remoteip("74.216.254.160");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation()) == 0);

        BOOST_CHECK(gprs->getTotalBytes() == 14 );
        BOOST_CHECK(gprs->getTotalValidPackets() == 1);
        BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
        BOOST_CHECK(gprs->getTotalPackets() == 1);
	BOOST_CHECK(gprs->getType() == DELETE_PDP_CONTEXT_RESPONSE);
	BOOST_CHECK(gprs->haveSequenceNumber() == true);
	BOOST_CHECK(gprs->haveExtensionHeader() == false);
}

BOOST_AUTO_TEST_CASE (test18) // update pdp response with seq number
{
	Packet packet("../gprs/packets/packet15.pcap");

        gprs->increaseAllocatedMemory(1);

        inject(packet);

        // Check the integrity of the first IP header
        std::string localip("74.216.254.230");
        std::string remoteip("74.216.254.160");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation()) == 0);

        BOOST_CHECK(gprs->getTotalBytes() == 58);
        BOOST_CHECK(gprs->getTotalValidPackets() == 1);
        BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
        BOOST_CHECK(gprs->getTotalPackets() == 1);
	BOOST_CHECK(gprs->getType() == UPDATE_PDP_CONTEXT_RESPONSE);
	BOOST_CHECK(gprs->haveSequenceNumber() == true);
	BOOST_CHECK(gprs->haveExtensionHeader() == false);
}

BOOST_AUTO_TEST_CASE (test19) // user data pdu with torrent
{
	Packet packet("../gprs/packets/packet16.pcap");

        gprs->increaseAllocatedMemory(1);

        inject(packet);

        // Check the integrity of the first IP header
        std::string localip("212.129.65.23");
        std::string remoteip("212.129.65.81");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation()) == 0);

        BOOST_CHECK(gprs->getTotalBytes() == 146);
        BOOST_CHECK(gprs->getTotalValidPackets() == 1);
        BOOST_CHECK(gprs->getTotalInvalidPackets() == 0);
        BOOST_CHECK(gprs->getTotalPackets() == 1);
        BOOST_CHECK(gprs->getType() == T_PDU);
        BOOST_CHECK(gprs->haveSequenceNumber() == true);
        BOOST_CHECK(gprs->haveExtensionHeader() == false);
        
	localip = "192.168.111.20";
        remoteip = "99.226.206.120";

        BOOST_CHECK(localip.compare(ip_high->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip_high->getDstAddrDotNotation()) == 0);
}

BOOST_AUTO_TEST_CASE (test20) // Release the flow with l7 info on it
{
	Packet packet("../gprs/packets/packet02.pcap");

        gprs->increaseAllocatedMemory(1);
        dns->increaseAllocatedMemory(1);

        inject(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_high->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer4info == nullptr); // There is no PDP context 

        SharedPointer<DNSInfo> info = flow->getDNSInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->name != nullptr);
        std::string name("www.facebook.com");
        BOOST_CHECK(name.compare(info->name->getName()) == 0);

	// Release the flow
	gprs->releaseFlowInfo(flow);
	dns->releaseFlowInfo(flow);

        BOOST_CHECK(flow->layer4info == nullptr); 
	BOOST_CHECK(info->name == nullptr);
}

BOOST_AUTO_TEST_SUITE_END( )
