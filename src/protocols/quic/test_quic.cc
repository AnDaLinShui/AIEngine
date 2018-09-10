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
#include "test_quic.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE quictest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(quic_test_suite, StackQuictest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(quic->getTotalPackets() == 0);
        BOOST_CHECK(quic->getTotalValidPackets() == 0);
        BOOST_CHECK(quic->getTotalBytes() == 0);
        BOOST_CHECK(quic->getTotalInvalidPackets() == 0);
	BOOST_CHECK(quic->processPacket(packet) == true);

	CounterMap c = quic->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
        Packet packet("../quic/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 1378);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(quic->getTotalPackets() == 1);
        BOOST_CHECK(quic->getTotalValidPackets() == 1);
        BOOST_CHECK(quic->getTotalBytes() == 1350);
        BOOST_CHECK(quic->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_SUITE_END()

