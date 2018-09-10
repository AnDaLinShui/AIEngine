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
#include "test_mpls.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE mplstest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mpls_test_suite, StackMPLStest)

BOOST_AUTO_TEST_CASE (test01)
{
	mpls->processFlow(nullptr); // nothing to do

	CounterMap c = mpls->getCounters();

	BOOST_CHECK(mpls->getCurrentUseMemory() == mpls->getTotalAllocatedMemory());
	BOOST_CHECK(mpls->isDynamicAllocatedMemory() == false);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../mpls/packets/packet01.pcap");

	inject(packet);

	// check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet.getLength());
	BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!! 

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

	BOOST_CHECK(ip->getTotalValidPackets()== 1);
	BOOST_CHECK(ip->getTotalPackets()== 1);
	BOOST_CHECK(ip->getTotalInvalidPackets()== 0);
	BOOST_CHECK(ip->getTotalBytes()== 100);

	BOOST_CHECK(icmp->getTotalValidPackets()== 1);

	BOOST_CHECK(icmp->getType() == 8);
	BOOST_CHECK(icmp->getCode() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../mpls/packets/packet02.pcap");

	inject(packet);

        // check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet.getLength());
        BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!!

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

	BOOST_CHECK(icmp->getType() == 8);
	BOOST_CHECK(icmp->getCode() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet1("../mpls/packets/packet01.pcap");
	Packet packet2("../mpls/packets/packet02.pcap");

	inject(packet1);

        // check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet1.getLength());
        BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!!

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);

	inject(packet2);

        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet2.getLength());

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 2);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

	BOOST_CHECK(mux_ip->getTotalForwardPackets() == 2);
	BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 2);
	BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 2);
	BOOST_CHECK(ip->getTotalValidPackets() == 2);
	BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 200);	

	BOOST_CHECK(icmp->getTotalValidPackets() == 2);	
        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);

	inject(packet1);

        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == packet1.getLength());

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 3);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 3);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 3);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 3);
        BOOST_CHECK(ip->getTotalValidPackets() == 3);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip->getTotalBytes() == 300);

        BOOST_CHECK(icmp->getTotalValidPackets() == 3);
        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);
        BOOST_CHECK(icmp->getTotalPackets() == 0); // ON this case the ICMPProtocol dont process the packets
        BOOST_CHECK(icmp->getTotalValidPackets() == 3);
        BOOST_CHECK(icmp->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test05) // malformed mpls packet
{
	Packet packet("../mpls/packets/packet02.pcap");
	packet.setPayloadLength(14 + 2);

	inject(packet);

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

	BOOST_CHECK(mpls->getTotalValidPackets() == 0);
	BOOST_CHECK(mpls->getTotalInvalidPackets() == 1);
	BOOST_CHECK(ip->getTotalValidPackets() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
