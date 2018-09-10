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
#include "test_ntp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE ntptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(ntp_test_suite, StackNTPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(ntp->getTotalPackets() == 0);
        BOOST_CHECK(ntp->getTotalValidPackets() == 0);
        BOOST_CHECK(ntp->getTotalBytes() == 0);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ntp->processPacket(packet) == true);
	
	CounterMap c = ntp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../ntp/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 96);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 68);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ntp->getVersion() == 2);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_CLIENT);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../ntp/packets/packet02.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 96);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 68);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(ntp->getVersion() == 3);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_SERVER);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../ntp/packets/packet03.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 76);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 48);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getVersion() == 4);
        BOOST_CHECK(ntp->getMode() == NTP_MODE_CLIENT);
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../ntp/packets/packet04.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 76);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 48);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(ntp->getVersion() == 3);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_SYM_ACT);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../ntp/packets/packet05.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 76);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 48);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(ntp->getVersion() == 3);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_SYM_PAS);
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../ntp/packets/packet06.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 468);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 440);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(ntp->getVersion() == 2);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_RES2);
}

BOOST_AUTO_TEST_CASE (test08) // ntp broadcast
{
	Packet packet("../ntp/packets/packet07.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 76);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 48);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(ntp->getVersion() == 3);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_BROADCAST);
}

BOOST_AUTO_TEST_CASE (test09) // reserved unspec
{
	Packet packet("../ntp/packets/packet08.pcap");

	inject(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 76);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 48);
        BOOST_CHECK(ntp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(ntp->getVersion() == 3);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_UNSPEC);
}

BOOST_AUTO_TEST_SUITE_END()
