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
#include "test_netbios.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE netbiostest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(netbios_test_suite, StackNetbiostest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(netbios->getTotalPackets() == 0);
        BOOST_CHECK(netbios->getTotalValidPackets() == 0);
        BOOST_CHECK(netbios->getTotalBytes() == 0);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);
	BOOST_CHECK(netbios->processPacket(packet) == true);
	
	CounterMap c = netbios->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../netbios/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 78);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(netbios->getTotalPackets() == 1);
        BOOST_CHECK(netbios->getTotalValidPackets() == 1);
        BOOST_CHECK(netbios->getTotalBytes() == 50);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);

	Flow *flow = netbios->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<NetbiosInfo> info = flow->getNetbiosInfo();
	BOOST_CHECK(info != nullptr);

	std::string nbname("TEST");
	BOOST_CHECK(nbname.compare(info->netbios_name->getName()) == 0);
	BOOST_CHECK(netbios->getTotalEvents() == 0);

	// Force a release
	netbios->releaseFlowInfo(flow);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../netbios/packets/packet02.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 78);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(netbios->getTotalPackets() == 1);
        BOOST_CHECK(netbios->getTotalValidPackets() == 1);
        BOOST_CHECK(netbios->getTotalBytes() == 50);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);
	
	Flow *flow = netbios->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<NetbiosInfo> info = flow->getNetbiosInfo();
	BOOST_CHECK(info != nullptr);

	std::string nbname("ISATAP");
	BOOST_CHECK(nbname.compare(info->netbios_name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../netbios/packets/packet03.pcap");

        inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 78);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(netbios->getTotalPackets() == 1);
        BOOST_CHECK(netbios->getTotalValidPackets() == 1);
        BOOST_CHECK(netbios->getTotalBytes() == 50);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);

        Flow *flow = netbios->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<NetbiosInfo> info = flow->getNetbiosInfo();
        BOOST_CHECK(info != nullptr);

        std::string nbname("58CLV4J");
        BOOST_CHECK(nbname.compare(info->netbios_name->getName()) == 0);
}

// Verifying the anomaly on the netbios side
BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../netbios/packets/packet03.pcap");

	packet.setPayloadLength(packet.getLength() - 8);

        inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 70);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(netbios->getTotalPackets() == 1);
        BOOST_CHECK(netbios->getTotalValidPackets() == 1);
        BOOST_CHECK(netbios->getTotalBytes() == 42);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);

        Flow *flow = netbios->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<NetbiosInfo> info = flow->getNetbiosInfo();
        BOOST_CHECK(info != nullptr);

        PacketAnomalyType pa = flow->getPacketAnomaly();
        BOOST_CHECK(pa == PacketAnomalyType::UDP_BOGUS_HEADER);
	BOOST_CHECK(udp->getTotalEvents() == 1);
	BOOST_CHECK(netbios->getTotalEvents() == 1); // there is an anomaly also 
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../netbios/packets/packet04.pcap");

        inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 78);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(netbios->getTotalPackets() == 1);
        BOOST_CHECK(netbios->getTotalValidPackets() == 1);
        BOOST_CHECK(netbios->getTotalBytes() == 50);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);

        Flow *flow = netbios->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<NetbiosInfo> info = flow->getNetbiosInfo();
        BOOST_CHECK(info != nullptr);

	// std::cout << info->netbios_name->getName() << std::endl;
        std::string nbname("NAMESERVER.UM");
        BOOST_CHECK(nbname.compare(info->netbios_name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../netbios/packets/packet05.pcap");

        inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 78);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(netbios->getTotalPackets() == 1);
        BOOST_CHECK(netbios->getTotalValidPackets() == 1);
        BOOST_CHECK(netbios->getTotalBytes() == 50);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);

        Flow *flow = netbios->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        SharedPointer<NetbiosInfo> info = flow->getNetbiosInfo();
        BOOST_CHECK(info != nullptr);

        std::string nbname("__MSBROWSE__");
        BOOST_CHECK(nbname.compare(info->netbios_name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test08)
{
	Packet packet("../netbios/packets/packet05.pcap", 42);
	auto flow1 = SharedPointer<Flow>(new Flow());
	auto flow2 = SharedPointer<Flow>(new Flow());
	auto flow3 = SharedPointer<Flow>(new Flow());

	netbios->increaseAllocatedMemory(1);

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet);
        flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet);
        flow3->setFlowDirection(FlowDirection::FORWARD);
        flow3->packet = const_cast<Packet*>(&packet);

        netbios->processFlow(flow1.get());
        netbios->processFlow(flow2.get());
        netbios->processFlow(flow3.get());

        BOOST_CHECK(netbios->getTotalPackets() == 3);
        BOOST_CHECK(netbios->getTotalValidPackets() == 0);
        BOOST_CHECK(netbios->getTotalBytes() == 150);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);

        SharedPointer<NetbiosInfo> info1 = flow1->getNetbiosInfo();
        SharedPointer<NetbiosInfo> info2 = flow2->getNetbiosInfo();
        SharedPointer<NetbiosInfo> info3 = flow3->getNetbiosInfo();
        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info3 == nullptr);

	BOOST_CHECK(info1->netbios_name == info2->netbios_name);
}

BOOST_AUTO_TEST_CASE (test09)
{
	Packet packet("../netbios/packets/packet05.pcap", 42);
        auto flow = SharedPointer<Flow>(new Flow());

	packet.setPayloadLength(packet.getLength() - 20);

        netbios->increaseAllocatedMemory(1);

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);

        netbios->processFlow(flow.get());

        BOOST_CHECK(netbios->getTotalPackets() == 1);
        BOOST_CHECK(netbios->getTotalValidPackets() == 0);
        BOOST_CHECK(netbios->getTotalBytes() == 30);
        BOOST_CHECK(netbios->getTotalInvalidPackets() == 0);

        PacketAnomalyType pa = flow->getPacketAnomaly();
        BOOST_CHECK(pa == PacketAnomalyType::NETBIOS_BOGUS_HEADER);
	BOOST_CHECK(udp->getTotalEvents() == 0);
	BOOST_CHECK(netbios->getTotalEvents() == 1); // there is an anomaly also 
}

BOOST_AUTO_TEST_SUITE_END()

