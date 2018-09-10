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
#include "test_rtp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE rtptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(rtp_test_suite, StackRTPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(rtp->getTotalBytes() == 0);
	BOOST_CHECK(rtp->getTotalPackets() == 0);
	BOOST_CHECK(rtp->getTotalValidPackets() == 0);
	BOOST_CHECK(rtp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(rtp->processPacket(packet) == true);
	
	CounterMap c = rtp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../rtp/packets/packet01.pcap");

	inject(packet);

        Flow *flow = rtp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

	BOOST_CHECK(rtp->getTotalBytes() == 167);
	BOOST_CHECK(rtp->getTotalPackets() == 1);
	BOOST_CHECK(rtp->getTotalValidPackets() == 1);
	BOOST_CHECK(rtp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(rtp->getPayloadType() == 99); //Clear mode
	BOOST_CHECK(rtp->getPadding() == false);

	CounterMap c = rtp->getCounters();
}

BOOST_AUTO_TEST_CASE (test03) // malformed packet
{
	Packet packet("../rtp/packets/packet01.pcap", 42);

	packet.setPayloadLength(10);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        rtp->processFlow(flow.get());

        BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::RTP_BOGUS_HEADER);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ipv6_rtp_test_suite, StackIPv6RTPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet("../rtp/packets/packet02.pcap");

	inject(packet);

        Flow *flow = rtp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

	BOOST_CHECK(ip6->getTotalBytes() == 40 + 44 + 8);

	BOOST_CHECK(rtp->getTotalBytes() == 44);
	BOOST_CHECK(rtp->getTotalPackets() == 1);
	BOOST_CHECK(rtp->getTotalValidPackets() == 1);
	BOOST_CHECK(rtp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(rtp->getVersion() == 2); 
	BOOST_CHECK(rtp->getPayloadType() == 102); // AMR mode
	BOOST_CHECK(rtp->getPadding() == false); 
}

BOOST_AUTO_TEST_SUITE_END()
