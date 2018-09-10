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
#include "test_snmp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE snmptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(snmp_test_suite, StackSNMPtest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet;

        BOOST_CHECK(snmp->getTotalPackets() == 0);
        BOOST_CHECK(snmp->getTotalValidPackets() == 0);
        BOOST_CHECK(snmp->getTotalBytes() == 0);
        BOOST_CHECK(snmp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(snmp->processPacket(packet) == true);
	
	CounterMap c = snmp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../snmp/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 48 + 8 + 20);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(snmp->getTotalPackets() == 1);
        BOOST_CHECK(snmp->getTotalValidPackets() == 1);
        BOOST_CHECK(snmp->getTotalBytes() == 48);
        BOOST_CHECK(snmp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(snmp->getTotalEvents() == 0);	
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../snmp/packets/packet02.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 42 + 8 + 20);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        
	BOOST_CHECK(snmp->getTotalPackets() == 1);
        BOOST_CHECK(snmp->getTotalValidPackets() == 1);
        BOOST_CHECK(snmp->getTotalBytes() == 42);
        BOOST_CHECK(snmp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(snmp->getTotalEvents() == 0);	
}

BOOST_AUTO_TEST_CASE (test04) // Corrupt the snmp packet
{
	Packet packet("../snmp/packets/packet02.pcap");
	packet.setPayloadLength(packet.getLength() - 12);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        snmp->processFlow(flow.get());

	// Verify the anomaly
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SNMP_BOGUS_HEADER);
	BOOST_CHECK(snmp->getTotalEvents() == 1);	
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../snmp/packets/packet03.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 136 + 8 + 20);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        
	BOOST_CHECK(snmp->getTotalPackets() == 1);
        BOOST_CHECK(snmp->getTotalValidPackets() == 1);
        BOOST_CHECK(snmp->getTotalBytes() == 136);
        BOOST_CHECK(snmp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(snmp->getTotalEvents() == 0);	
}

BOOST_AUTO_TEST_CASE (test06) // malformed community length
{
	snmp_header hsnmp;
	hsnmp.code = 0; 
	hsnmp.length = 8;
	hsnmp.type = SNMP_SET_REQ; 
	hsnmp.version_length = 2;
	uint8_t buffer[32];

        uint8_t *pkt = reinterpret_cast <uint8_t*> (&hsnmp);
	std::memcpy(&buffer, &hsnmp, sizeof(struct snmp_header));
	std::memcpy(&buffer[sizeof(struct snmp_header)], "\x00\xaa\x04\xfa", 4);

        int length = sizeof(snmp_header) + 4;

        Packet packet(buffer, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
	
        snmp->processFlow(flow.get());

	// Verify the anomaly
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SNMP_BOGUS_HEADER);
	BOOST_CHECK(snmp->getTotalEvents() == 1);	
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../snmp/packets/packet04.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 37 + 8 + 20);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        
	BOOST_CHECK(snmp->getTotalPackets() == 1);
        BOOST_CHECK(snmp->getTotalValidPackets() == 1);
        BOOST_CHECK(snmp->getTotalBytes() == 37);
        BOOST_CHECK(snmp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(snmp->getTotalEvents() == 0);	
}

BOOST_AUTO_TEST_SUITE_END()
