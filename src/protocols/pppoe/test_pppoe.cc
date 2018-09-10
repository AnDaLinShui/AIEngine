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
#include "test_pppoe.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE vlantest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(pppoe_test_suite, StackTestPPPoE)

BOOST_AUTO_TEST_CASE (test01)
{
	BOOST_CHECK(pppoe->getTotalPackets() == 0);
	BOOST_CHECK(pppoe->getTotalBytes() == 0);
	pppoe->processFlow(nullptr); // Nothing to do

	CounterMap c = pppoe->getCounters();
        
	pppoe->setDynamicAllocatedMemory(true);
        BOOST_CHECK(pppoe->isDynamicAllocatedMemory() == false);

	BOOST_CHECK(pppoe->getCurrentUseMemory() == pppoe->getAllocatedMemory());
	BOOST_CHECK(pppoe->getCurrentUseMemory() == pppoe->getTotalAllocatedMemory());
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../pppoe/packets/packet01.pcap");

	inject(packet);

	BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_PPPOE);
	BOOST_CHECK(pppoe->getTotalPackets() == 1);
	BOOST_CHECK(pppoe->getTotalBytes() == 46);
	BOOST_CHECK(eth->getTotalPackets() == 0);

	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(ip6->getTotalPackets() == 0);

        BOOST_CHECK(pppoe->getPayloadLength() == 12);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../pppoe/packets/packet02.pcap");

	inject(packet);

	BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_PPPOE);
	BOOST_CHECK(pppoe->getTotalPackets() == 1);
	BOOST_CHECK(pppoe->getTotalBytes() == 72);
	BOOST_CHECK(pppoe->getProtocol() == PPP_DLL_IPV6);
	BOOST_CHECK(eth->getTotalPackets() == 0);

	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 0);

	BOOST_CHECK(ip6->getTotalPackets() == 1);
	BOOST_CHECK(ip6->getTotalBytes() == 64);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../pppoe/packets/packet03.pcap");

	inject(packet);

	BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_PPPOE);
	BOOST_CHECK(pppoe->getTotalPackets() == 1);
	BOOST_CHECK(pppoe->getTotalBytes() == 56);
	BOOST_CHECK(pppoe->getProtocol() == PPP_DLL_IPV4);
	BOOST_CHECK(eth->getTotalPackets() == 0);

	std::string ipsrc("172.202.246.57");
	std::string ipdst("64.12.189.217");

	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalBytes() == 20 + 28);

	BOOST_CHECK(ipsrc.compare(ip->getSrcAddrDotNotation()) == 0);
	BOOST_CHECK(ipdst.compare(ip->getDstAddrDotNotation()) == 0);

	BOOST_CHECK(ip6->getTotalPackets() == 0);
	BOOST_CHECK(ip6->getTotalBytes() == 0);
}

BOOST_AUTO_TEST_CASE (test05) // malformed pppoe packet
{
	Packet packet("../pppoe/packets/packet03.pcap");
	packet.setPayloadLength(20);

	inject(packet);

	BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_PPPOE);
	BOOST_CHECK(pppoe->getTotalPackets() == 0);
	BOOST_CHECK(pppoe->getTotalValidPackets() == 0);
	BOOST_CHECK(pppoe->getTotalInvalidPackets() == 1);
}

BOOST_AUTO_TEST_SUITE_END()

