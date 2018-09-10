/*
IEgine a new generation network intrusion detection system.
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
#include "test_icmp6.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE icmptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE (icmp6_test_suite, StackIcmp6) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test01)
{
	BOOST_CHECK(ip6->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(icmp6->getTotalPackets() == 0);
	BOOST_CHECK(icmp6->getTotalBytes() == 0);

	BOOST_CHECK(icmp6->getCurrentUseMemory() == sizeof(ICMPv6Protocol));
	BOOST_CHECK(icmp6->getTotalAllocatedMemory() == sizeof(ICMPv6Protocol));
	BOOST_CHECK(icmp6->isDynamicAllocatedMemory() == false);

	icmp6->processFlow(nullptr); // nothing to do

	CounterMap c = icmp6->getCounters();
}

// Inject a icmp echo request
BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../icmp6/packets/packet01.pcap");

	inject(packet);

	BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
	BOOST_CHECK(icmp6->getType() == ICMP6_ECHO_REQUEST);
	BOOST_CHECK(icmp6->getCode() == 0);
	BOOST_CHECK(icmp6->getTotalPackets() == 1); 
	BOOST_CHECK(icmp6->getTotalValidPackets() == 1); 
	BOOST_CHECK(icmp6->getTotalInvalidPackets() == 0); 
	BOOST_CHECK(icmp6->getTotalBytes() == 64);
}

// Inject a icmp router advertisment
BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../icmp6/packets/packet02.pcap"); 

	inject(packet);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ND_ROUTER_ADVERT);
        BOOST_CHECK(icmp6->getCode() == 0);
        BOOST_CHECK(icmp6->getTotalPackets() == 1);
}

// time to live exceed and router solicitation 
BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet1("../icmp6/packets/packet03.pcap"); 
	Packet packet2("../icmp6/packets/packet04.pcap"); 

	inject(packet1);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ICMP6_TIME_EXCEEDED);
        BOOST_CHECK(icmp6->getCode() == ICMP6_TIME_EXCEED_TRANSIT);
        BOOST_CHECK(icmp6->getTotalPackets() == 1);

	inject(packet2);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ND_ROUTER_SOLICIT);
        BOOST_CHECK(icmp6->getCode() == 0);
        BOOST_CHECK(icmp6->getTotalPackets() == 2);
}

BOOST_AUTO_TEST_CASE (test05) // malformed packet
{
	Packet packet("../icmp6/packets/packet02.pcap");
	packet.setPayloadLength( 14 + 40 + 6); 

	inject(packet);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getTotalPackets() == 0);
        BOOST_CHECK(icmp6->getTotalInvalidPackets() == 1);
}

BOOST_AUTO_TEST_CASE (test06) // icmpv6 echo reply
{
	Packet packet("../icmp6/packets/packet05.pcap");

	inject(packet);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ICMP6_ECHO_REPLY);
        BOOST_CHECK(icmp6->getCode() == 0);
        BOOST_CHECK(icmp6->getTotalPackets() == 1);
        BOOST_CHECK(icmp6->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test07) // icmpv6 unreach port
{
	Packet packet("../icmp6/packets/packet06.pcap");

	inject(packet);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ICMP6_DST_UNREACH);
        BOOST_CHECK(icmp6->getCode() == ICMP6_DST_UNREACH_NOPORT);
        BOOST_CHECK(icmp6->getTotalPackets() == 1);
        BOOST_CHECK(icmp6->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test08) // icmpv6 redirect
{
	Packet packet("../icmp6/packets/packet07.pcap");

	inject(packet);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ND_REDIRECT);
        BOOST_CHECK(icmp6->getCode() == 0);
        BOOST_CHECK(icmp6->getTotalPackets() == 1);
        BOOST_CHECK(icmp6->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_SUITE_END()

