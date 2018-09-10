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
#include "test_dhcp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE dhcptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(dhcp_test_suite, StackDHCPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(dhcp->getTotalPackets() == 0);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 0);
        BOOST_CHECK(dhcp->getTotalBytes() == 0);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcp->processPacket(packet) == true);

	CounterMap c = dhcp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../dhcp/packets/packet02.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 300 + 20 + 8);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 300);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0); 
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 1);
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name != nullptr);

	std::string host("ctrl006");
	BOOST_CHECK(host.compare(info->host_name->getName()) == 0);

        info->setLeaseTime(10);

        JsonFlow j;
        info->serialize(j);

	// Force a release
	dhcp->releaseFlowInfo(flow);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../dhcp/packets/packet03.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 338);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 310);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 1);
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name != nullptr);

	std::string host("TurboGrafx-16");
	BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../dhcp/packets/packet03.pcap", 42);
        auto flow = SharedPointer<Flow>(new Flow());

	// Reduce the packet size on 300 so the checks for anomalies are executed
	packet.setPayloadLength(packet.getLength() - 300);

        flow->packet = const_cast<Packet*>(&packet);
        dhcp->processFlow(flow.get());

        // Check the results
        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 0);
        BOOST_CHECK(dhcp->getTotalBytes() == 10);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 0); // No request
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	Flow *cflow = dhcp->getCurrentFlow();
	BOOST_CHECK(cflow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info == nullptr);

        PacketAnomalyType pa = flow->getPacketAnomaly();
        BOOST_CHECK(pa == PacketAnomalyType::DHCP_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../dhcp/packets/packet04.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 300 + 20 + 8);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 300);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 0);
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 1);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name == nullptr);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../dhcp/packets/packet05.pcap");

	inject(packet);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 548);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 0); 
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 1);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	BOOST_CHECK(dhcp->getType() == DHCP_BOOT_REPLY); 

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name == nullptr);
}

BOOST_AUTO_TEST_CASE (test07) // release
{
	Packet packet("../dhcp/packets/packet06.pcap");

	inject(packet);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 300);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 0); 
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 1);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name == nullptr);
}

BOOST_AUTO_TEST_CASE (test08) // inform
{
	Packet packet("../dhcp/packets/packet07.pcap");

	inject(packet);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 300);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 0); 
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 1);

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name != nullptr);
	
	std::string host("TSE-MANAGEMENT");
	BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test09) // offer
{
	Packet packet("../dhcp/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 300);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 1);
        BOOST_CHECK(dhcp->getTotalRequests() == 0); 
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name == nullptr);
	BOOST_CHECK(info->ip != nullptr);

	std::string ip("192.168.40.137");

	BOOST_CHECK(ip.compare(info->ip->getName()) == 0);

        JsonFlow j;
        info->serialize(j);

	dhcp->releaseCache();
}

BOOST_AUTO_TEST_CASE (test10)
{
	Packet packet("../dhcp/packets/packet03.pcap", 42);
        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

	dhcp->increaseAllocatedMemory(2);

        flow1->packet = const_cast<Packet*>(&packet);
        flow2->packet = const_cast<Packet*>(&packet);

        dhcp->processFlow(flow1.get());
        dhcp->processFlow(flow2.get());

        // Check the results
        BOOST_CHECK(dhcp->getTotalPackets() == 2);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 0);
        BOOST_CHECK(dhcp->getTotalBytes() == 620);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 2); 
        BOOST_CHECK(dhcp->getTotalDeclines() == 0);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

        BOOST_CHECK(flow1 != nullptr); 
        BOOST_CHECK(flow2 != nullptr); 
        SharedPointer<DHCPInfo> info1 = flow1->getDHCPInfo();
        SharedPointer<DHCPInfo> info2 = flow2->getDHCPInfo();
        BOOST_CHECK(info1 != info2);
        BOOST_CHECK(info1->host_name != nullptr);
        BOOST_CHECK(info2->host_name != nullptr);
        BOOST_CHECK(info1->host_name == info2->host_name);

        std::string host("TurboGrafx-16");
        BOOST_CHECK(host.compare(info1->host_name->getName()) == 0);
        BOOST_CHECK(host.compare(info2->host_name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test11) // Decline
{
	Packet packet("../dhcp/packets/packet08.pcap");

	inject(packet);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 265);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 0); 
        BOOST_CHECK(dhcp->getTotalDeclines() == 1);
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test12) // memory failure
{
	Packet packet("../dhcp/packets/packet08.pcap");

	dhcp->decreaseAllocatedMemory(10);

	inject(packet);

        BOOST_CHECK(dhcp->getTotalPackets() == 1);
        BOOST_CHECK(dhcp->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcp->getTotalBytes() == 265);
        BOOST_CHECK(dhcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcp->getTotalDiscovers() == 0);
        BOOST_CHECK(dhcp->getTotalOffers() == 0);
        BOOST_CHECK(dhcp->getTotalRequests() == 0); 
        BOOST_CHECK(dhcp->getTotalDeclines() == 0); // No decline
        BOOST_CHECK(dhcp->getTotalAcks() == 0);
        BOOST_CHECK(dhcp->getTotalNaks() == 0);
        BOOST_CHECK(dhcp->getTotalReleases() == 0);
        BOOST_CHECK(dhcp->getTotalInforms() == 0);

	Flow *flow = dhcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info == nullptr);
}

BOOST_AUTO_TEST_CASE (test13) // Sharing the same IP!
{
	Packet packet("../dhcp/packets/packet01.pcap", 42);

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        dhcp->increaseAllocatedMemory(2);

        flow1->packet = const_cast<Packet*>(&packet);
        flow2->packet = const_cast<Packet*>(&packet);

        dhcp->processFlow(flow1.get());
        dhcp->processFlow(flow2.get());

	SharedPointer<DHCPInfo> info1 = flow1->getDHCPInfo();
	SharedPointer<DHCPInfo> info2 = flow2->getDHCPInfo();
	BOOST_CHECK(info1 != nullptr);
	BOOST_CHECK(info2 != nullptr);
	BOOST_CHECK(info1->host_name == nullptr);
	BOOST_CHECK(info2->host_name == nullptr);
	BOOST_CHECK(info1->ip == info2->ip);

	std::string ip("192.168.40.137");

	BOOST_CHECK(ip.compare(info1->ip->getName()) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
