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
#include "test_udpgeneric.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE udpgenerictest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(udpgeneric_test_suite, StackUDPGenericTest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(gudp->getTotalPackets() == 0);
	BOOST_CHECK(gudp->getTotalValidPackets() == 0);
	BOOST_CHECK(gudp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(gudp->getTotalBytes() == 0);
	BOOST_CHECK(gudp->getTotalEvents() == 0);
	BOOST_CHECK(gudp->processPacket(packet) == true);
	
	CounterMap c = gudp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../udpgeneric/packets/packet01.pcap");

	inject(packet);

	BOOST_CHECK(ip->getPacketLength() == 86);

	BOOST_CHECK(udp->getSourcePort() == 51413);
	BOOST_CHECK(udp->getDestinationPort() == 6881);
	BOOST_CHECK(udp->getPayloadLength()== 58);
	BOOST_CHECK(gudp->getTotalPackets() == 1);
	BOOST_CHECK(gudp->getTotalValidPackets() == 1);
	BOOST_CHECK(gudp->getTotalBytes() == 58);
	BOOST_CHECK(gudp->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test03) // Same case as test1_genericudp but with a unmatched rule
{
	Packet packet("../udpgeneric/packets/packet01.pcap");

	auto rm = RegexManagerPtr(new RegexManager());

        rm->addRegex("a signature", "^hello");
	udp->setRegexManager(rm);
	gudp->setRegexManager(rm);

	inject(packet);

        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 0);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

	// Add another true signature that matchs the packet
	rm->addRegex("other", "^d1.*$");
        
	mux_eth->forwardPacket(packet);
        BOOST_CHECK(rm->getTotalRegexs()  == 2);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() != nullptr);

	Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->regex_mng == rm);
	BOOST_CHECK(gudp->getTotalEvents() == 1);

	{
		RedirectOutput r;

		gudp->statistics(r.cout, 5);
	}
}

BOOST_AUTO_TEST_SUITE_END( )

