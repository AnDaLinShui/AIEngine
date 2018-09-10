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
#include "test_dhcpv6.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE dhcpv6test
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(dhcpv6_test_suite, StackDHCPv6test)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(dhcpv6->getTotalPackets() == 0);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 0);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 0);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->processPacket(packet) == true);

	CounterMap c = dhcpv6->getCounters();

	auto v1 = dhcpv6->getCurrentUseMemory();
	auto v2 = dhcpv6->getTotalAllocatedMemory();
	auto v3 = dhcpv6->getTotalCacheMisses();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../dhcp6/packets/packet01.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 102 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 94);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_SOLICIT);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);

        std::string host("TSE-MANAGEMENT");
        BOOST_CHECK(host.compare(info->host_name->getName()) == 0);

	{
		RedirectOutput r;
        	
		flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
        	r.cout << *(info.get());
    	} 

	BOOST_CHECK(info->getT1() == 0);
	BOOST_CHECK(info->getT2() == 0);

	dhcpv6->releaseCache();
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../dhcp6/packets/packet02.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 134 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 126);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_ADVERTISE);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);

	dhcpv6->decreaseAllocatedMemory(10);
        dhcpv6->releaseFlowInfo(flow); 
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../dhcp6/packets/packet03.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 148 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 140);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_REQUEST);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
	
	dhcpv6->releaseCache();
        BOOST_CHECK(flow->getDHCPv6Info() == nullptr);
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../dhcp6/packets/packet04.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 134 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 126);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_REPLY);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
	
	BOOST_CHECK(info->getT1() == 1800);
	BOOST_CHECK(info->getT2() == 2880);

	BOOST_CHECK(info->ip6 != nullptr);

	std::string ip("2001:470:6803:731:1::1");
	BOOST_CHECK(ip.compare(info->ip6->getName()) == 0);

        JsonFlow j;
        info->serialize(j);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../dhcp6/packets/packet05.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 126 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 118);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_RELEASE);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../dhcp6/packets/packet06.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 252 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 244);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_RELAY_FORW);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test08) // two flows hiting the same name
{
	Packet packet("../dhcp6/packets/packet01.pcap", 62);

	auto flow1 = SharedPointer<Flow>(new Flow());
	auto flow2 = SharedPointer<Flow>(new Flow());

        dhcpv6->increaseAllocatedMemory(2);

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet);

        flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet);

        dhcpv6->processFlow(flow1.get());
        dhcpv6->processFlow(flow2.get());

        SharedPointer<DHCPv6Info> info1 = flow1->getDHCPv6Info();
        SharedPointer<DHCPv6Info> info2 = flow2->getDHCPv6Info();
        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info1 != info2);
	BOOST_CHECK(info1->host_name != nullptr);
	BOOST_CHECK(info2->host_name != nullptr);

	BOOST_CHECK(info1->host_name == info2->host_name);
}

BOOST_AUTO_TEST_CASE (test09) // Decline
{
	Packet packet("../dhcp6/packets/packet07.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 86 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 86);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_DECLINE);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test10) // Invalid packet
{
	Packet packet("../dhcp6/packets/packet07.pcap");
	packet.setPayloadLength(14 + 40 + 8 + 2);

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 2 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 0);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 0);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 0);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 1);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow == nullptr); 
}

BOOST_AUTO_TEST_CASE (test11) // Renew
{
	Packet packet("../dhcp6/packets/packet08.pcap");

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 92 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 92);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_RENEW);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
	
	BOOST_CHECK(info->getT1() == 1800);
	BOOST_CHECK(info->getT2() == 2880);

	std::string ip("::1");
	BOOST_CHECK(info->ip6 != nullptr);
	BOOST_CHECK(ip.compare(info->ip6->getName()) == 0);

	dhcpv6->releaseCache();
}

BOOST_AUTO_TEST_CASE (test12) // Relay reply
{
	Packet packet("../dhcp6/packets/packet09.pcap");

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 247 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 247);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_RELAY_REPL);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test13) // memory failure 
{
	Packet packet("../dhcp6/packets/packet09.pcap");

	dhcpv6->decreaseAllocatedMemory(100);

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 247 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 247);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info == nullptr);
}

BOOST_AUTO_TEST_CASE (test14) // Confirm
{
	Packet packet("../dhcp6/packets/packet10.pcap");

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 86 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 86);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_CONFIRM);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test15) // Rebind
{
	Packet packet("../dhcp6/packets/packet11.pcap");

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 74 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 74);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_REBIND);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test16) // Info request
{
	Packet packet("../dhcp6/packets/packet12.pcap");

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 30 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 30);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_INFO_REQUEST);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_CASE (test17) // Sharing the same ip!!!! 
{
	Packet packet("../dhcp6/packets/packet08.pcap", 62);

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        dhcpv6->increaseAllocatedMemory(2);

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet);

        flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet);

        dhcpv6->processFlow(flow1.get());
        dhcpv6->processFlow(flow2.get());

        SharedPointer<DHCPv6Info> info1 = flow1->getDHCPv6Info();
        SharedPointer<DHCPv6Info> info2 = flow2->getDHCPv6Info();
        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info1 != info2);
        BOOST_CHECK(info1->ip6 != nullptr);
        BOOST_CHECK(info2->ip6 != nullptr);

        BOOST_CHECK(info1->ip6 == info2->ip6);
}

BOOST_AUTO_TEST_CASE (test18) // Reconfigure with nothing more
{
	Packet packet("../dhcp6/packets/packet13.pcap");

        inject(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 4 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dhcpv6->getTotalPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalValidPackets() == 1);
        BOOST_CHECK(dhcpv6->getTotalBytes() == 4);
        BOOST_CHECK(dhcpv6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dhcpv6->getType() == DHCPV6_RECONFIGURE);

        Flow *flow = dhcpv6->getCurrentFlow();
        BOOST_CHECK(flow != nullptr); 
        SharedPointer<DHCPv6Info> info = flow->getDHCPv6Info();
        BOOST_CHECK(info != nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
