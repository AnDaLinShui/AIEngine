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
#include "test_bitcoin.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE bitcointest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(bitcoin_test_suite, StackBitcointest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(bitcoin->getTotalPackets() == 0);
        BOOST_CHECK(bitcoin->getTotalValidPackets() == 0);
        BOOST_CHECK(bitcoin->getTotalBytes() == 0);
        BOOST_CHECK(bitcoin->getTotalInvalidPackets() == 0);
       	 
	CounterMap c = bitcoin->getCounters();
	
	BOOST_CHECK(bitcoin->processPacket(packet) == true);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../bitcoin/packets/packet01.pcap");

	inject(packet);

        Flow *flow = bitcoin->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
        BOOST_CHECK(info != nullptr);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 145);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 105 + 20);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getDestinationPort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 105);
        BOOST_CHECK(bitcoin->getTotalInvalidPackets() == 0);
	
	BOOST_CHECK(bitcoin->getTotalBitcoinOperations() == 1);
	BOOST_CHECK(bitcoin->getPayloadLength() == 85);

	BOOST_CHECK(info->getTotalTransactions() == 0);
	BOOST_CHECK(info->getTotalBlocks() == 0);
	BOOST_CHECK(info->getTotalRejects() == 0);

	bitcoin->releaseFlowInfo(flow);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../bitcoin/packets/packet02.pcap");

	inject(packet);

        Flow *flow = bitcoin->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
        BOOST_CHECK(info != nullptr);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 345);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 325);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getSourcePort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 305);
        BOOST_CHECK(bitcoin->getTotalInvalidPackets() == 0);

	BOOST_CHECK( bitcoin->getTotalBitcoinOperations() == 4);
	BOOST_CHECK( bitcoin->getPayloadLength() == 31);

	BOOST_CHECK(info->getTotalTransactions() == 0);
	BOOST_CHECK(info->getTotalBlocks() == 0);
	BOOST_CHECK(info->getTotalRejects() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../bitcoin/packets/packet04.pcap");

	inject(packet);

        Flow *flow = bitcoin->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
        BOOST_CHECK(info != nullptr);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 1492);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 1472);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getDestinationPort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 1452);
        BOOST_CHECK(bitcoin->getTotalInvalidPackets() == 0);

	BOOST_CHECK(bitcoin->getTotalBitcoinOperations() == 6);
	BOOST_CHECK(bitcoin->getPayloadLength() == 215);

	BOOST_CHECK(info->getTotalTransactions() == 0);
	BOOST_CHECK(info->getTotalBlocks() == 6);
	BOOST_CHECK(info->getTotalRejects() == 0);

	info->incRejects();
	BOOST_CHECK(info->getTotalRejects() == 1);

	bitcoin->releaseCache();
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../bitcoin/packets/packet03.pcap");

	inject(packet);

        Flow *flow = bitcoin->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
        BOOST_CHECK(info != nullptr);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 322);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 302);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getDestinationPort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 282);
        BOOST_CHECK(bitcoin->getTotalInvalidPackets() == 0);

	BOOST_CHECK(bitcoin->getTotalBitcoinOperations() == 1);
	BOOST_CHECK(bitcoin->getPayloadLength() == 258);

	BOOST_CHECK(info->getTotalTransactions() == 1);
	BOOST_CHECK(info->getTotalBlocks() == 0);
	BOOST_CHECK(info->getTotalRejects() == 0);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../bitcoin/packets/packet01.pcap");

	bitcoin->setDynamicAllocatedMemory(false);
	bitcoin->decreaseAllocatedMemory(1);

        inject(packet);

        Flow *flow = bitcoin->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
        BOOST_CHECK(info == nullptr);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 145);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 105 + 20);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getDestinationPort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 105);
        BOOST_CHECK(bitcoin->getTotalInvalidPackets() == 0);

        BOOST_CHECK( bitcoin->getTotalBitcoinOperations() == 0);
        BOOST_CHECK( bitcoin->getPayloadLength() == 85);
}

BOOST_AUTO_TEST_CASE (test07) // Corrupted or wrong bitcoin packet or whatever
{
        char *header =  "This is a corrupted bitcoin packet or whatever";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);

        Packet packet(pkt, length);
        auto flow = SharedPointer<Flow>(new Flow());

        bitcoin->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        bitcoin->processFlow(flow.get());

        SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
        BOOST_CHECK(info != nullptr);

        BOOST_CHECK(info->getTotalTransactions()  == 0);
        BOOST_CHECK(info->getTotalRejects()  == 0);
        BOOST_CHECK(info->getTotalBlocks()  == 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ipv6_bitcoin_test_suite, StackIPv6Bitcointest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet("../bitcoin/packets/packet05.pcap");

        inject(packet);

        Flow *flow = bitcoin->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
        BOOST_CHECK(info != nullptr);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 1472 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 1472);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getDestinationPort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 1452);
        BOOST_CHECK(bitcoin->getTotalInvalidPackets() == 0);

        BOOST_CHECK(bitcoin->getTotalBitcoinOperations() == 6);
        BOOST_CHECK(bitcoin->getPayloadLength() == 215);

        BOOST_CHECK(info->getTotalTransactions() == 0);
        BOOST_CHECK(info->getTotalBlocks() == 6);
        BOOST_CHECK(info->getTotalRejects() == 0);

        bitcoin->releaseFlowInfo(flow);
}

BOOST_AUTO_TEST_SUITE_END()
