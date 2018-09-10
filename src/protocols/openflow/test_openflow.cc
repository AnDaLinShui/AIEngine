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
#include "test_openflow.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE openflowtest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(openflow_test_suite, StackTestOpenFlow)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(of->getTotalPackets() == 0);
        BOOST_CHECK(of->getTotalValidPackets() == 0);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 0);
	BOOST_CHECK(of->processPacket(packet) == true);

	of->releaseCache(); // nothing to do

	CounterMap c = of->getCounters();

	BOOST_CHECK(of->getCurrentUseMemory() == of->getTotalAllocatedMemory());
	of->setDynamicAllocatedMemory(true);
	BOOST_CHECK(of->isDynamicAllocatedMemory() == false);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet1("../openflow/packets/packet01.pcap");
	Packet packet2("../openflow/packets/packet02.pcap");
	Packet packet3("../openflow/packets/packet03.pcap");

	inject(packet1);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 60);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 8);
	BOOST_CHECK(of->getType() == OFP_HELLO); 
	BOOST_CHECK(of->getLength() == 8); 

        BOOST_CHECK(of->getTotalHellos() == 1);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0); 
        BOOST_CHECK(of->getTotalPacketsIn() == 0);
        BOOST_CHECK(of->getTotalPacketsOut() == 0);

	inject(packet2);

        BOOST_CHECK(of->getTotalPackets() == 2);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 20);
	BOOST_CHECK(of->getType() == OFP_SET_CONFIG); 
	BOOST_CHECK(of->getLength() == 12); 

        BOOST_CHECK(of->getTotalHellos() == 1);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 1); 
        BOOST_CHECK(of->getTotalPacketsIn() == 0);
        BOOST_CHECK(of->getTotalPacketsOut() == 0);

	inject(packet3);

        BOOST_CHECK(of->getTotalPackets() == 3);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 20 + 224);
	BOOST_CHECK(of->getType() == OFP_FEATURE_REPLY); 
	BOOST_CHECK(of->getLength() == 224); 
        
	BOOST_CHECK(of->getTotalHellos() == 1);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 1);
        BOOST_CHECK(of->getTotalSetConfigs() == 1); 
        BOOST_CHECK(of->getTotalPacketsIn() == 0);
        BOOST_CHECK(of->getTotalPacketsOut() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../openflow/packets/packet04.pcap");

	inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 78);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 78);

	BOOST_CHECK(eth_vir->getTotalPackets() == 1);
	BOOST_CHECK(eth_vir->getTotalBytes() == 60);
	BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
	BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_ARP);
	
	BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0); 
        BOOST_CHECK(of->getTotalPacketsIn() == 1);
        BOOST_CHECK(of->getTotalPacketsOut() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../openflow/packets/packet05.pcap");
	auto rm = RegexManagerPtr(new RegexManager());

        rm->addRegex("a signature", "^.{2}\\x77\\x59\\x44\\xa6.*\\x6c\\x6f\\x63$");
	udpg_vir->setRegexManager(rm);
	udp_vir->setRegexManager(rm);

	inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 146);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 146);

	BOOST_CHECK(eth_vir->getTotalPackets() == 1);
	BOOST_CHECK(eth_vir->getTotalBytes() == 128);
	BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
	BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_IP);

	BOOST_CHECK(ip_vir->getTotalPackets() == 1);
	BOOST_CHECK(ip_vir->getTotalBytes() == 114);
	
	BOOST_CHECK(udp_vir->getTotalPackets() == 1);
	BOOST_CHECK(udp_vir->getTotalBytes() == 94);
	BOOST_CHECK(udp_vir->getSourcePort() == 1044);
	BOOST_CHECK(udp_vir->getDestinationPort() == 8082);
        
	BOOST_CHECK(udpg_vir->getTotalPackets() == 1);
	BOOST_CHECK(udpg_vir->getTotalBytes() == 86);

	BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() != nullptr);
}

BOOST_AUTO_TEST_CASE (test05) 
{
	Packet packet1("../openflow/packets/packet06.pcap");
	Packet packet2("../openflow/packets/packet07.pcap");

        auto rm = RegexManagerPtr(new RegexManager());
	auto r = SharedPointer<Regex>(new Regex("a signature","^\\x26\\x01"));	

        rm->addRegex(r);
        tcpg_vir->setRegexManager(rm);
        tcp_vir->setRegexManager(rm);

	inject(packet1);

	// Verify the integrity of the path with the first packet injected

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2); // One the openflowtcp and other the real flow
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        std::string ip_a("192.168.2.4");
        std::string ip_b("192.168.2.14");

        BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_a.compare(ip->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_b.compare(ip->getDstAddrDotNotation())==0);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 132);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 132);

        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 114);
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_IP);

        std::string ip_va("192.168.2.4");
        std::string ip_vb("192.168.2.14");

        BOOST_CHECK(ip_vir->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_va.compare(ip_vir->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_vb.compare(ip_vir->getDstAddrDotNotation())==0);
        BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalBytes() == 100);

        BOOST_CHECK(tcp_vir->getTotalPackets() == 1);
        BOOST_CHECK(tcp_vir->getTotalBytes() == 48 + 32);
        BOOST_CHECK(tcp_vir->getSourcePort() == 46926);
        BOOST_CHECK(tcp_vir->getDestinationPort() == 22);

        BOOST_CHECK(tcpg_vir->getTotalPackets() == 1);
        BOOST_CHECK(tcpg_vir->getTotalBytes() == 48);

        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 0);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);
	BOOST_CHECK(r->getMatchs() == 0);
	BOOST_CHECK(r->getTotalEvaluates() == 1);

	inject(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2); // One the openflowtcp and other the real flow
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_a.compare(ip->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_b.compare(ip->getDstAddrDotNotation())==0);

        BOOST_CHECK(of->getTotalPackets() == 2);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 132 + 132);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 132);

        BOOST_CHECK(eth_vir->getTotalPackets() == 2);
        BOOST_CHECK(eth_vir->getTotalBytes() == 114 + 114);
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 2);
        BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_IP);

        BOOST_CHECK(ip_vir->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_vb.compare(ip_vir->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_va.compare(ip_vir->getDstAddrDotNotation())==0);
        BOOST_CHECK(ip_vir->getTotalPackets() == 2);
        BOOST_CHECK(ip_vir->getTotalBytes() == 100 + 100);

        BOOST_CHECK(tcp_vir->getTotalPackets() == 2);
        BOOST_CHECK(tcp_vir->getTotalBytes() == (48 + 32) * 2);
        BOOST_CHECK(tcp_vir->getSourcePort() == 22);
        BOOST_CHECK(tcp_vir->getDestinationPort() == 46926);

        BOOST_CHECK(tcpg_vir->getTotalPackets() == 2);
        BOOST_CHECK(tcpg_vir->getTotalBytes() == 48 + 48);

        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() == r);
        BOOST_CHECK(r->getMatchs() == 1);
        BOOST_CHECK(r->getTotalEvaluates() == 2);
}

BOOST_AUTO_TEST_CASE (test06) 
{
	Packet packet("../openflow/packets/packet08.pcap");

	inject(packet);

	// Verify the integrity of the path with the first packet injected

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1); // One the openflowtcp
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 2);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        std::string ip_a("192.168.56.1");
        std::string ip_b("192.168.56.101");

        BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_a.compare(ip->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_b.compare(ip->getDstAddrDotNotation())==0);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 122);
        BOOST_CHECK(of->getType() == OFP_PACKET_OUT);
        BOOST_CHECK(of->getLength() == 122);

	BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0); 
        BOOST_CHECK(of->getTotalPacketsIn() == 0);
        BOOST_CHECK(of->getTotalPacketsOut() == 1);

        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 14 + 20 + 64);
        BOOST_CHECK(eth_vir->getTotalInvalidPackets() == 0);
	BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_IP);

        std::string ip_va("10.0.0.2");
        std::string ip_vb("10.0.0.1");

        BOOST_CHECK(ip_vir->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(ip_va.compare(ip_vir->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_vb.compare(ip_vir->getDstAddrDotNotation())==0);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);

	// ICMP header
	BOOST_CHECK(icmp_vir->getType() == ICMP_ECHOREPLY);
	BOOST_CHECK(icmp_vir->getCode() == 0);
}
	
BOOST_AUTO_TEST_CASE (test07) // malformed packet 
{
	Packet packet("../openflow/packets/packet08.pcap");

	packet.setPayloadLength(14 + 20 + 20 + 4);

	inject(packet);

        std::string ip_a("192.168.56.1");
        std::string ip_b("192.168.56.101");

        BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_a.compare(ip->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_b.compare(ip->getDstAddrDotNotation())==0);

        BOOST_CHECK(of->getTotalPackets() == 0);
        BOOST_CHECK(of->getTotalValidPackets() == 0);
        BOOST_CHECK(of->getTotalInvalidPackets() == 1);
        BOOST_CHECK(of->getTotalBytes() == 0);
}

BOOST_AUTO_TEST_CASE (test08)
{
	Packet packet("../openflow/packets/packet09.pcap");

        inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 107);
        BOOST_CHECK(of->getType() == OFP_PACKET_OUT);
        BOOST_CHECK(of->getLength() == 107);

        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 67);
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getEthernetType() == 0x8999); // I dont have idea what the hell is this ethertype

        BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0);
        BOOST_CHECK(of->getTotalPacketsIn() == 0);
        BOOST_CHECK(of->getTotalPacketsOut() == 1);
}

BOOST_AUTO_TEST_CASE (test09)
{
	Packet packet("../openflow/packets/packet10.pcap");

        inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 321);
        BOOST_CHECK(of->getType() == OFP_PACKET_OUT);
        BOOST_CHECK(of->getLength() == 107);

        BOOST_CHECK(eth_vir->getTotalPackets() == 3);
        BOOST_CHECK(eth_vir->getTotalBytes() == 67 * 3);
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 3);
        BOOST_CHECK(eth_vir->getEthernetType() == 0x8999); // No idea

        BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0);
        BOOST_CHECK(of->getTotalPacketsIn() == 0);
        BOOST_CHECK(of->getTotalPacketsOut() == 1);
}

BOOST_AUTO_TEST_CASE (test10)
{
	Packet packet("../openflow/packets/packet11.pcap");

        inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 84);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 84);

        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 42);
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_ARP); 

        BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0);
        BOOST_CHECK(of->getTotalPacketsIn() == 1);
        BOOST_CHECK(of->getTotalPacketsOut() == 0);
}

BOOST_AUTO_TEST_CASE (test11) // corrupt the in packet
{
	Packet packet("../openflow/packets/packet11.pcap");

	packet.setPayloadLength(packet.getLength() - 44);

        inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 84 - 44);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 84); // The length of the oflow packet is correct

        BOOST_CHECK(eth_vir->getTotalPackets() == 0);
        BOOST_CHECK(eth_vir->getTotalBytes() == 0);
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 0);

        BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0);
        BOOST_CHECK(of->getTotalPacketsIn() == 1);
        BOOST_CHECK(of->getTotalPacketsOut() == 0);
}

BOOST_AUTO_TEST_CASE (test12) // Corrupt the thrird out packet
{
	Packet packet("../openflow/packets/packet10.pcap");

	packet.setPayloadLength(packet.getLength() - 30);

        inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 321 - 30);
        BOOST_CHECK(of->getType() == OFP_PACKET_OUT);
        BOOST_CHECK(of->getLength() == 107);

        BOOST_CHECK(eth_vir->getTotalPackets() == 2);
        BOOST_CHECK(eth_vir->getTotalBytes() == 67 * 2);
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 2);
        BOOST_CHECK(eth_vir->getEthernetType() == 0x8999); // No idea

        BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0);
        BOOST_CHECK(of->getTotalPacketsIn() == 0);
        BOOST_CHECK(of->getTotalPacketsOut() == 1);
}

BOOST_AUTO_TEST_CASE (test13) // Corrupt the second out packet
{
	Packet packet("../openflow/packets/packet10.pcap");

	packet.setPayloadLength(packet.getLength() - 117);

        inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 321 - 117);
        BOOST_CHECK(of->getType() == OFP_PACKET_OUT);
        BOOST_CHECK(of->getLength() == 107);

        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 67 );
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getEthernetType() == 0x8999); // No idea

        BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0);
        BOOST_CHECK(of->getTotalPacketsIn() == 0);
        BOOST_CHECK(of->getTotalPacketsOut() == 1);
}

BOOST_AUTO_TEST_CASE (test14) // dns response with bad length
{
	Packet packet("../openflow/packets/packet12.pcap");

        auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto d = SharedPointer<DomainName>(new DomainName("example", ".com"));

        dm->addDomainName(d);

        dns_vir->setDomainNameManager(dm);

        dns_vir->increaseAllocatedMemory(1);

        inject(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidPackets() == 1);
        BOOST_CHECK(of->getTotalInvalidPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 146);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 146);

        BOOST_CHECK(of->getTotalHellos() == 0);
        BOOST_CHECK(of->getTotalFeatureRequest() == 0);
        BOOST_CHECK(of->getTotalFeatureReplys() == 0);
        BOOST_CHECK(of->getTotalSetConfigs() == 0);
        BOOST_CHECK(of->getTotalPacketsIn() == 1);
        BOOST_CHECK(of->getTotalPacketsOut() == 0);

        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 14 + 20 + 8 + 86 );
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_IP);

        std::string ip_va("129.21.3.17");
        std::string ip_vb("192.168.2.7");

        BOOST_CHECK(ip_vir->getProtocol() == IPPROTO_UDP);
        BOOST_CHECK(ip_va.compare(ip_vir->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_vb.compare(ip_vir->getDstAddrDotNotation())==0);
        BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalInvalidPackets() == 0);

        // The real bytes are 114, but IP claims that there is more
        BOOST_CHECK(ip_vir->getTotalBytes() == 114);
        // IP claims that there is more bytes, but is not
        BOOST_CHECK(ip_vir->getPacketLength() == 128);

        BOOST_CHECK(udp_vir->getTotalPackets() == 1);
        BOOST_CHECK(udp_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(udp_vir->getTotalInvalidPackets() == 0);
        BOOST_CHECK(udp_vir->getTotalBytes() == 94); // Real length
        BOOST_CHECK(udp_vir->getLength() == 108); // UDP bad length

        BOOST_CHECK(dns_vir->getTotalPackets() == 1);
        BOOST_CHECK(dns_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(dns_vir->getTotalInvalidPackets() == 0);
        BOOST_CHECK(dns_vir->getTotalBytes() == 94 - 8); // Real length

        BOOST_CHECK(dns_vir->getTotalQueries() == 0);
        BOOST_CHECK(dns_vir->getTotalResponses() == 1);

        Flow *flow = udp_vir->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<DNSInfo> info = flow->getDNSInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(dns_vir->getTotalQuestions() == 1);
        BOOST_CHECK(dns_vir->getTotalAnswers() == 0);

        SharedPointer<StringCache> name = info->name;
        // The name is null because there is no answers so nothing to parse
        BOOST_CHECK(name == nullptr);
}
 
BOOST_AUTO_TEST_SUITE_END( )

