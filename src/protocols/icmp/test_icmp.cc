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
#include "test_icmp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE icmptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE (icmp_test_suite, StackIcmp) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test01)
{
	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 0);
	
	icmp->processFlow(nullptr); // nothing to do
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet1("../icmp/packets/packet01.pcap");
	Packet packet2("../icmp/packets/packet02.pcap");

	inject(packet1);

	BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
	BOOST_CHECK(icmp->getType() == ICMP_ECHO);
	BOOST_CHECK(icmp->getCode() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 0); // The function is not set!!!

	auto ipaddr1 = ip->getSrcAddr();
	auto ipaddr2 = ip->getDstAddr();
	auto id = icmp->getId();
	auto seq = icmp->getSequence();

	// Set the packet function
	mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

        // Inject second the packet
	inject(packet2);	

	BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
	BOOST_CHECK(icmp->getType() == ICMP_ECHOREPLY);
	BOOST_CHECK(icmp->getCode() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 1);

	BOOST_CHECK(icmp->getTotalBytes() == 28); // Header + data

	BOOST_CHECK(ipaddr1 == ip->getDstAddr());
	BOOST_CHECK(ipaddr2 == ip->getSrcAddr());
	BOOST_CHECK(seq == icmp->getSequence());
	BOOST_CHECK(id == icmp->getId());

	CounterMap c = icmp->getCounters();
}

// Test a router solicitation packet
BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../icmp/packets/packet03.pcap");

	mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

	inject(packet);

        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_ROUTERSOLICIT);
        BOOST_CHECK(icmp->getCode() == 0);
        BOOST_CHECK(icmp->getTotalPackets() == 1);
}

// Test a router redirection 
BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../icmp/packets/packet04.pcap");

        mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

	inject(packet);

        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_REDIRECT);
        BOOST_CHECK(icmp->getCode() == ICMP_REDIRECT_HOST);
        BOOST_CHECK(icmp->getTotalPackets() == 1);
}

BOOST_AUTO_TEST_CASE (test05) // malformed icmp packet
{
	Packet packet("../icmp/packets/packet04.pcap");
	packet.setPayloadLength(14 + 20 + 6);

        mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

	inject(packet);

        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getTotalPackets() == 0);
        BOOST_CHECK(icmp->getTotalInvalidPackets() == 1);
}

BOOST_AUTO_TEST_CASE (test06) // icmp time exceeded
{
	Packet packet("../icmp/packets/packet05.pcap");

        mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

	inject(packet);

        BOOST_CHECK(icmp->getTotalPackets() == 1);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_TIMXCEED);
        BOOST_CHECK(icmp->getCode() == ICMP_TIMXCEED_INTRANS);
}

BOOST_AUTO_TEST_CASE (test07) // icmp source quench
{
	Packet packet("../icmp/packets/packet06.pcap");

        mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

	inject(packet);

        BOOST_CHECK(icmp->getTotalPackets() == 1);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_SOURCEQUENCH);
        BOOST_CHECK(icmp->getCode() == ICMP_UNREACH_SRCFAIL);// ICMP_SR_FAILED);
}

BOOST_AUTO_TEST_CASE (test08) // icmp timestamp request and response
{
	Packet packet1("../icmp/packets/packet07.pcap");
	Packet packet2("../icmp/packets/packet08.pcap");

        mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

	inject(packet1);

        BOOST_CHECK(icmp->getTotalPackets() == 1);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_TSTAMP);
        BOOST_CHECK(icmp->getCode() == 0);

	inject(packet2);

        BOOST_CHECK(icmp->getTotalPackets() == 2);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_TSTAMPREPLY);
        BOOST_CHECK(icmp->getCode() == 0);
}

BOOST_AUTO_TEST_CASE (test09) // icmp malformed or whatever strange code types.
{
	Packet packet("../icmp/packets/packet09.pcap");

        mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

	inject(packet);

        BOOST_CHECK(icmp->getTotalPackets() == 1);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == 155);
        BOOST_CHECK(icmp->getCode() == 139);
	
	// May be a cover channel?
}

BOOST_AUTO_TEST_CASE (test10) // icmp router advertisement
{
	Packet packet("../icmp/packets/packet10.pcap");

        mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket, icmp, std::placeholders::_1));

	inject(packet);

        BOOST_CHECK(icmp->getTotalPackets() == 1);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_ROUTERADVERT);
        BOOST_CHECK(icmp->getCode() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )

