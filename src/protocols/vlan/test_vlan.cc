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
#include "test_vlan.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE vlantest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(vlan_test_suite,StackTestVlan)

BOOST_AUTO_TEST_CASE (test01)
{
	BOOST_CHECK(vlan->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);

	CounterMap c = vlan->getCounters();

	vlan->processFlow(nullptr); // nothing to do

	BOOST_CHECK(vlan->getCurrentUseMemory() == vlan->getTotalAllocatedMemory());
	BOOST_CHECK(vlan->isDynamicAllocatedMemory() == false);
}

BOOST_AUTO_TEST_CASE (test02)
{
	char *raw_packet = "\x00\x05\x47\x02\xa2\x5d\x00\x15\xc7\xee\x25\x98\x81\x00\x02\x5e\x08\x00";
	uint8_t *pkt = reinterpret_cast <uint8_t*> (raw_packet);
	int length = 18;
	Packet packet(pkt, length);

	inject(packet);	
        
	BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_VLAN);

	BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalFailPackets() == 1);

       	BOOST_CHECK(vlan->getEthernetType() == ETHERTYPE_IP);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../vlan/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);
        BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_vlan->getTotalFailPackets() == 1);

	BOOST_CHECK(vlan->getVlanId() == 104);
        BOOST_CHECK(vlan->getEthernetType() == ETHERTYPE_IP);
}

BOOST_AUTO_TEST_CASE (test04) // malformed vlan packet
{
	char *raw_packet = "\x00\x05\x47\x02\xa2\x5d\x00\x15\xc7\xee\x25\x98\x81\x00\x02\x5e\x08\x00";
	uint8_t *pkt = reinterpret_cast <uint8_t*> (raw_packet);
	int length = 16;
	Packet packet(pkt, length);

	inject(packet);	
        
       	BOOST_CHECK(vlan->getTotalPackets() == 0);
       	BOOST_CHECK(vlan->getTotalInvalidPackets() == 1);
}

BOOST_AUTO_TEST_SUITE_END()

