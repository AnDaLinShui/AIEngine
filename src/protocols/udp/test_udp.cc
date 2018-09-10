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
#include "test_udp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE udptest
#endif

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(udp_test_suite, StackUDPTest)

BOOST_AUTO_TEST_CASE (test01)
{
	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(udp->getTotalPackets() == 0);
	udp->processFlow(nullptr); // nothing to do

	CounterMap c = udp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../dhcp/packets/packet01.pcap"); // DHCP offer

	inject(packet);

	// Check the udp integrity
	BOOST_CHECK(udp->getSourcePort() == 67);
	BOOST_CHECK(udp->getDestinationPort() == 68);
	BOOST_CHECK(udp->getPayloadLength() == 300);
}

BOOST_AUTO_TEST_CASE(test03)
{
	Packet packet("../dhcp/packets/packet01.pcap"); // DHCP offer
	packet.setPayloadLength(14 + 20 + 6);

	inject(packet);

	BOOST_CHECK(udp->getTotalPackets() == 0);
	BOOST_CHECK(udp->getTotalValidPackets() == 0);
	BOOST_CHECK(udp->getTotalInvalidPackets() == 1);
}

BOOST_AUTO_TEST_CASE(test04)
{
	Packet packet("../gprs/packets/packet01.pcap");

	auto flow_cache = FlowCachePtr(new FlowCache());
	auto flow_mng = FlowManagerPtr(new FlowManager());
	auto ff_udp = SharedPointer<FlowForwarder>(new FlowForwarder());

	udp->setFlowCache(flow_cache);
	udp->setFlowManager(flow_mng);

	inject(packet);

	// ip
	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalValidPackets() == 1);
	BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 72);
}

BOOST_AUTO_TEST_CASE(test05) // Test timeout on UDP traffic 
{
	Packet packet1("../gprs/packets/packet17.pcap");
	Packet packet2("../dhcp/packets/packet01.pcap"); // DHCP offer

	packet2.setPacketTime(190);

        auto flow_cache = FlowCachePtr(new FlowCache());
        auto flow_mng = FlowManagerPtr(new FlowManager());

	flow_mng->setFlowCache(flow_cache);
        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

	udp->increaseAllocatedMemory(1);

	flow_cache->createFlows(1);

        inject(packet1);

	BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1);
	BOOST_CHECK(flow_mng->getTotalFlows() == 1);
	BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

	BOOST_CHECK(flow_cache->getTotalFlows() == 1);
	BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
	BOOST_CHECK(flow_cache->getTotalReleases() == 0);
	BOOST_CHECK(flow_cache->getTotalFails() == 0);

	inject(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 1);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE(test06) // Test timeout on UDP traffic, no expire flows
{
	Packet packet1("../gprs/packets/packet17.pcap");
	Packet packet2("../dhcp/packets/packet01.pcap"); // DHCP offer
	packet2.setPacketTime(120);

        auto flow_cache = FlowCachePtr(new FlowCache());
        auto flow_mng = FlowManagerPtr(new FlowManager());

        flow_mng->setFlowCache(flow_cache);
        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

        flow_cache->createFlows(2);

        inject(packet1);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        inject(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE(test07) // Test small packet udp , one byte packet
{
	Packet packet("../udp/packets/packet01.pcap");

        auto flow_cache = FlowCachePtr(new FlowCache());
        auto flow_mng = FlowManagerPtr(new FlowManager());

        flow_mng->setFlowCache(flow_cache);
        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

        flow_cache->createFlows(1);

        inject(packet);

	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalBytes() == 29);
	BOOST_CHECK(ip->getTotalValidPackets() == 1);
	BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

	BOOST_CHECK(udp->getTotalPackets() == 1);
	BOOST_CHECK(udp->getTotalBytes() == 9);
	BOOST_CHECK(udp->getTotalValidPackets() == 1);
	BOOST_CHECK(udp->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_CASE(test08) // Test timeout on UDP traffic with no release flows 
{
	Packet packet1("../gprs/packets/packet17.pcap");
	Packet packet2("../dhcp/packets/packet01.pcap"); // DHCP offer
	packet2.setPacketTime(190);

        auto flow_cache = FlowCachePtr(new FlowCache());
        auto flow_mng = FlowManagerPtr(new FlowManager());

        flow_mng->setFlowCache(flow_cache);
        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

        udp->increaseAllocatedMemory(1);

	// All the flows should be in the FlowManager memory zone
	flow_mng->setReleaseFlows(false);

        flow_cache->createFlows(1);

        inject(packet1);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        inject(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(udp_ipv6_test_suite, StackIPv6UDPTest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet("../dns/packets/packet32.pcap");

        auto flow_cache = FlowCachePtr(new FlowCache());
        auto flow_mng = FlowManagerPtr(new FlowManager());
        auto ff_udp = SharedPointer<FlowForwarder>(new FlowForwarder());

        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

        inject(packet);

        // ip6
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 2415);
        BOOST_CHECK(udp->getDestinationPort() == 53);

	BOOST_CHECK(udp->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )
