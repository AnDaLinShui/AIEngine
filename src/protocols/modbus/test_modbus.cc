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
#include "test_modbus.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE modbustest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(modbus_test_suite, StackModbustest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(modbus->getTotalPackets() == 0);
        BOOST_CHECK(modbus->getTotalValidPackets() == 0);
        BOOST_CHECK(modbus->getTotalBytes() == 0);
        BOOST_CHECK(modbus->getTotalInvalidPackets() == 0);
	BOOST_CHECK(modbus->processPacket(packet) == true);

	CounterMap c = modbus->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../modbus/packets/packet01.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 66);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(modbus->getTotalPackets() == 1);
        BOOST_CHECK(modbus->getTotalValidPackets() == 1);
        BOOST_CHECK(modbus->getTotalBytes() == 14);
        BOOST_CHECK(modbus->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../modbus/packets/packet02.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 52);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(modbus->getTotalPackets() == 1);
        BOOST_CHECK(modbus->getTotalValidPackets() == 1);
        BOOST_CHECK(modbus->getTotalBytes() == 12);
        BOOST_CHECK(modbus->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../modbus/packets/packet03.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 61);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(modbus->getTotalPackets() == 1);
        BOOST_CHECK(modbus->getTotalValidPackets() == 1);
        BOOST_CHECK(modbus->getTotalBytes() == 21);
        BOOST_CHECK(modbus->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../modbus/packets/packet04.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 53);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 13 + 20);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->isAck() == true);
        BOOST_CHECK(tcp->isPushSet()  == true);

        BOOST_CHECK(modbus->getTotalPackets() == 1);
        BOOST_CHECK(modbus->getTotalValidPackets() == 1);
        BOOST_CHECK(modbus->getTotalBytes() == 13);
        BOOST_CHECK(modbus->getTotalInvalidPackets() == 0);
}

BOOST_AUTO_TEST_SUITE_END()

