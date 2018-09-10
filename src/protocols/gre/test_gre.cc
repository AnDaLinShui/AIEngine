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
#include "test_gre.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE gretest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(gre_suite, StackTestGre)

BOOST_AUTO_TEST_CASE (test01)
{
	BOOST_CHECK(gre->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(eth_vir->getTotalPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 0);

	BOOST_CHECK(gre->getCurrentUseMemory() == gre->getTotalAllocatedMemory());
	gre->setDynamicAllocatedMemory(true);
	BOOST_CHECK(gre->isDynamicAllocatedMemory() == false);

	gre->processFlow(nullptr); // Nothing to process

	CounterMap c = gre->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../gre/packets/packet01.pcap");        

	inject(packet);

	// Check the results over the stack
	BOOST_CHECK(gre->getTotalPackets() == 1);
	BOOST_CHECK(gre->getTotalBytes() == 102);
	BOOST_CHECK(gre->getTotalValidPackets() == 1);
	BOOST_CHECK(gre->getTotalInvalidPackets() == 0);

	BOOST_CHECK(eth_vir->getTotalPackets() == 1);
	BOOST_CHECK(eth_vir->getTotalBytes() == 98);
	BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
	BOOST_CHECK(eth_vir->getTotalInvalidPackets() == 0);

	BOOST_CHECK(ip_vir->getTotalPackets() == 1);
	BOOST_CHECK(ip_vir->getTotalBytes() == 84);
	BOOST_CHECK(ip_vir->getTotalValidPackets() == 1);
	BOOST_CHECK(ip_vir->getTotalInvalidPackets() == 0);
	
	BOOST_CHECK(icmp_vir->getTotalPackets() == 1);
	BOOST_CHECK(icmp_vir->getTotalValidPackets() == 1);
	BOOST_CHECK(icmp_vir->getTotalInvalidPackets() == 0);

	BOOST_CHECK(icmp_vir->getType() == ICMP_ECHO);
	BOOST_CHECK(icmp_vir->getCode() == 0);
}

BOOST_AUTO_TEST_CASE (test03) // malformed packet
{
	Packet packet("../gre/packets/packet01.pcap");        

	packet.setPayloadLength(14 + 20 + 2);

	inject(packet);

	// Check the results over the stack
	BOOST_CHECK(gre->getTotalPackets() == 0);
	BOOST_CHECK(gre->getTotalBytes() == 0);
	BOOST_CHECK(gre->getTotalValidPackets() == 0);
	BOOST_CHECK(gre->getTotalInvalidPackets() == 1);
}

BOOST_AUTO_TEST_CASE (test04)
{
        Packet packet("../gre/packets/packet02.pcap");
        
        inject(packet);
        
        // Check the results over the stack
        BOOST_CHECK(gre->getTotalPackets() == 1);
        BOOST_CHECK(gre->getTotalBytes() == 102);
        BOOST_CHECK(gre->getTotalValidPackets() == 1);
        BOOST_CHECK(gre->getTotalInvalidPackets() == 0);
        
        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 98);
        BOOST_CHECK(eth_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalInvalidPackets() == 0);
        
        BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalBytes() == 84);
        BOOST_CHECK(ip_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalInvalidPackets() == 0);
        
        BOOST_CHECK(icmp_vir->getTotalPackets() == 1);
        BOOST_CHECK(icmp_vir->getTotalValidPackets() == 1);
        BOOST_CHECK(icmp_vir->getTotalInvalidPackets() == 0);

        BOOST_CHECK(icmp_vir->getType() == ICMP_ECHOREPLY);
        BOOST_CHECK(icmp_vir->getCode() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )

