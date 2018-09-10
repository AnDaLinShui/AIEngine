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
#include "test_vxlan.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE vxlantest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(vxlan_test_suite, StackTestVxlan)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(vxlan->processPacket(packet) == true);

	BOOST_CHECK(vxlan->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(eth_vir->getTotalPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 0);

	CounterMap c = vxlan->getCounters();

	BOOST_CHECK(vxlan->getCurrentUseMemory() == vxlan->getTotalAllocatedMemory());
	vxlan->setDynamicAllocatedMemory(true);
	BOOST_CHECK(vxlan->isDynamicAllocatedMemory() == false);
}

// Ethernet with just one IP packet
BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../vxlan/packets/packet01.pcap");

        std::string localip("1.2.3.4");
        std::string remoteip("1.2.3.5");

	inject(packet);

	// Check the results

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 70);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_UDP);
        BOOST_CHECK(ip->isFragment() == false);
        BOOST_CHECK(ip->getTTL() == 127);
        BOOST_CHECK(localip.compare(ip->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip->getDstAddrDotNotation()) == 0);
	
        BOOST_CHECK(udp->getTotalPackets() == 1);
        BOOST_CHECK(udp->getTotalValidPackets() == 1);
        BOOST_CHECK(udp->getTotalBytes() == 50);
	BOOST_CHECK(udp->getSourcePort() == 9029);
	BOOST_CHECK(udp->getDestinationPort() == 9029);

        BOOST_CHECK(vxlan->getTotalPackets() == 1);
        BOOST_CHECK(vxlan->getTotalValidPackets() == 1);
        BOOST_CHECK(vxlan->getTotalInvalidPackets() == 0);
        BOOST_CHECK(vxlan->getTotalBytes() == 8 + 14 + 20);

        BOOST_CHECK(eth_vir->getTotalInvalidPackets() == 0);
        BOOST_CHECK(eth_vir->getTotalPackets() == 1);

	localip = "10.11.12.13";
	remoteip = "10.11.12.14";
        
	BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalBytes() == 20);
        BOOST_CHECK(localip.compare(ip_vir->getSrcAddrDotNotation()) == 0);
        BOOST_CHECK(remoteip.compare(ip_vir->getDstAddrDotNotation()) == 0);
}

// Ethernet with IP and ICMP reply 
BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../vxlan/packets/packet02.pcap");

	inject(packet);

        // Check the results of the virtual networks

        BOOST_CHECK(vxlan->getTotalPackets() == 1);
        BOOST_CHECK(vxlan->getTotalValidPackets() == 1);
        BOOST_CHECK(vxlan->getTotalInvalidPackets() == 0);
        BOOST_CHECK(vxlan->getTotalBytes() == 106);

        BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalInvalidPackets() == 0);
        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 98);

        BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalBytes() == 84);
	BOOST_CHECK(mux_ip_vir->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_ip_vir->getTotalReceivedPackets() == 1);

        BOOST_CHECK(icmp_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(icmp_vir->getTotalInvalidPackets() == 0);
        BOOST_CHECK(icmp_vir->getTotalPackets() == 1);
	BOOST_CHECK(icmp_vir->getType() == ICMP_ECHOREPLY);
	BOOST_CHECK(icmp_vir->getCode() == 0);

	BOOST_CHECK(mux_icmp_vir->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_icmp_vir->getTotalReceivedPackets() == 1);
	BOOST_CHECK(mux_icmp_vir->getTotalFailPackets() == 1);
}

// Ethernet IP UDP DNS to github.com
BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../vxlan/packets/packet03.pcap");

	dns_vir->increaseAllocatedMemory(1);

	inject(packet);

        // Check the results of the virtual networks

        BOOST_CHECK(vxlan->getTotalPackets() == 1);
        BOOST_CHECK(vxlan->getTotalValidPackets() == 1);
        BOOST_CHECK(vxlan->getTotalInvalidPackets() == 0);
        BOOST_CHECK(vxlan->getTotalBytes() == 78);

        BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalInvalidPackets() == 0);
        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 70);

        BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalBytes() == 56);
        BOOST_CHECK(mux_ip_vir->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip_vir->getTotalReceivedPackets() == 1);

        // Verify the integrity of the two udp flows
        Flow *flow_udp = udp->getCurrentFlow();
        Flow *flow_vir = udp_vir->getCurrentFlow();

        BOOST_CHECK(flow_udp != nullptr);
        BOOST_CHECK(flow_vir != nullptr);

	// The virtual flow is tagged to zero
	BOOST_CHECK(flow_vir->getTag() == 0);

	BOOST_CHECK(flow_udp->getSourcePort() == 32894);
	BOOST_CHECK(flow_udp->getDestinationPort() == 4789);
	BOOST_CHECK(flow_vir->getSourcePort() == 47864);
	BOOST_CHECK(flow_vir->getDestinationPort() == 53);

        SharedPointer<DNSInfo> dns_info = flow_vir->getDNSInfo();
	BOOST_CHECK(dns_info != nullptr);

	std::string domain("github.com");

	BOOST_CHECK(dns_info->name != nullptr);
	BOOST_CHECK(domain.compare(dns_info->name->getName()) == 0);
}

// Test the Tag functionatliy with two identical udp flows but in different vni networks
BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet1("../vxlan/packets/packet03.pcap");
	Packet packet2("../vxlan/packets/packet04.pcap");

        dns_vir->increaseAllocatedMemory(2);

	inject(packet1);

	// Verify the number of flows that should be on the cache and table
	BOOST_CHECK(flow_cache->getTotalFlows() == 1);
	BOOST_CHECK(flow_cache->getTotalAcquires() == 2); // One at physical layer and one virtual
	BOOST_CHECK(flow_cache->getTotalReleases() == 0); 
	BOOST_CHECK(flow_cache->getTotalFails() == 0);

	BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
	BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        
	Flow *flow_udp1 = udp_vir->getCurrentFlow();

	// Inject the second packet
	inject(packet2);
	
	Flow *flow_udp2 = udp_vir->getCurrentFlow();

        SharedPointer<DNSInfo> dns_info = flow_udp1->getDNSInfo();
	BOOST_CHECK(dns_info != nullptr);

	std::string domain("github.com");

	BOOST_CHECK(dns_info->name != nullptr);
	BOOST_CHECK(domain.compare(dns_info->name->getName()) == 0);
	
	BOOST_CHECK(flow_udp2->getDNSInfo() != nullptr);
        dns_info = flow_udp2->getDNSInfo();

	domain = "gitgit.com";
	BOOST_CHECK(dns_info->name != nullptr);
	BOOST_CHECK(domain.compare(dns_info->name->getName()) == 0);

	BOOST_CHECK(flow_udp1 != flow_udp2);

        // Verify again the number of flows that should be on the cache and table
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 3); // One at physical layer and one virtual
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 3);
        BOOST_CHECK(flow_mng->getTotalFlows() == 3);
}

// Inject to tcp packets of the same virtual flow
BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet1("../vxlan/packets/packet05.pcap");
	Packet packet2("../vxlan/packets/packet06.pcap");

	inject(packet1);

	BOOST_CHECK(tcp_vir->getTotalPackets() == 1);
	BOOST_CHECK(tcp_vir->getTotalBytes() == 28);
	BOOST_CHECK(tcp_vir->getTotalValidPackets() == 1);
	BOOST_CHECK(tcp_vir->getTotalInvalidPackets() == 0);

	BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
	BOOST_CHECK(flow_mng->getTotalFlows() == 2);

	BOOST_CHECK(flow_cache->getTotalFlows() == 1);
	BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
	BOOST_CHECK(flow_cache->getTotalReleases() == 0);
	BOOST_CHECK(flow_cache->getTotalFails() == 0);

	// Inject the second tcp packet
	inject(packet2); 

        BOOST_CHECK(tcp_vir->getTotalPackets() == 2);
        BOOST_CHECK(tcp_vir->getTotalBytes() == 56);
        BOOST_CHECK(tcp_vir->getTotalValidPackets() == 2);
        BOOST_CHECK(tcp_vir->getTotalInvalidPackets() == 0);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        Flow *flow = tcp_vir->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
	BOOST_CHECK( info != nullptr);

        BOOST_CHECK(info->syn == 1);
        BOOST_CHECK(info->fin == 0);
        BOOST_CHECK(info->syn_ack == 1);
        BOOST_CHECK(info->ack == 0);
        BOOST_CHECK(info->push == 0);
}

BOOST_AUTO_TEST_CASE (test07) // malformed vxlan packet
{
	Packet packet("../vxlan/packets/packet05.pcap");

	packet.setPayloadLength(14 + 20 + 8 + 2);

        inject(packet);

        BOOST_CHECK(udp->getTotalPackets() == 1);
        BOOST_CHECK(udp->getTotalBytes() == 10);
        BOOST_CHECK(udp->getTotalValidPackets() == 1);
        BOOST_CHECK(udp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(vxlan->getTotalPackets() == 0);
        BOOST_CHECK(vxlan->getTotalBytes() == 0);
        BOOST_CHECK(vxlan->getTotalValidPackets() == 0);
        BOOST_CHECK(vxlan->getTotalInvalidPackets() == 1);
}

BOOST_AUTO_TEST_CASE (test08)
{
	Packet packet("../vxlan/packets/packet07.pcap");
	auto re = SharedPointer<Regex>(new Regex("for hit", "^.*HTTP.*$"));
	auto rm = SharedPointer<RegexManager>(new RegexManager());

	re->setEvidence(true);

	rm->addRegex(re);
	tcp_vir->setRegexManager(rm); // sets the default regex manager

	inject(packet);

	BOOST_CHECK(tcp_vir->getTotalPackets() == 1);
	BOOST_CHECK(tcp_vir->getTotalBytes() == 166);
	BOOST_CHECK(tcp_vir->getTotalValidPackets() == 1);
	BOOST_CHECK(tcp_vir->getTotalInvalidPackets() == 0);

	BOOST_CHECK(tcpg_vir->getTotalPackets() == 1);
	BOOST_CHECK(tcpg_vir->getTotalBytes() == 134);
	BOOST_CHECK(tcpg_vir->getTotalValidPackets() == 1);
	BOOST_CHECK(tcpg_vir->getTotalInvalidPackets() == 0);

	// Verify the number of flows that should be on the cache and table
	BOOST_CHECK(flow_cache->getTotalFlows() == 1);
	BOOST_CHECK(flow_cache->getTotalAcquires() == 2); // One at physical layer and one virtual
	BOOST_CHECK(flow_cache->getTotalReleases() == 0); 
	BOOST_CHECK(flow_cache->getTotalFails() == 0);

	BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
	BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        
	Flow *flow_tcp = tcp_vir->getCurrentFlow();

	BOOST_CHECK(flow_tcp != nullptr);
	BOOST_CHECK(flow_tcp->regex.lock() == re);
}

BOOST_AUTO_TEST_SUITE_END( )

