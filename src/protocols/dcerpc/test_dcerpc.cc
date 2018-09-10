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
#include "test_dcerpc.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE dcerpctest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(dcerpc_test_suite, StackDCERPCtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(dcerpc->getTotalBytes() == 0);
	BOOST_CHECK(dcerpc->getTotalPackets() == 0);
	BOOST_CHECK(dcerpc->getTotalValidPackets() == 0);
	BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dcerpc->processPacket(packet) == true);
	
	CounterMap c = dcerpc->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../dcerpc/packets/packet02.pcap");

	inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

	BOOST_CHECK(dcerpc->getTotalBytes() == 105);
	BOOST_CHECK(dcerpc->getTotalPackets() == 1);
	BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
	BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

	BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes()); 
	BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_ALTER_CONTEXT_RESP); 
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../dcerpc/packets/packet03.pcap");

	dcerpc->increaseAllocatedMemory(1);

	inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

	BOOST_CHECK(dcerpc->getTotalBytes() == 160);
	BOOST_CHECK(dcerpc->getTotalPackets() == 1);
	BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
	BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

	BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes()); 
	BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_BIND); // Bind

	SharedPointer<DCERPCInfo> info = flow->getDCERPCInfo();
	BOOST_CHECK(info != nullptr);

	dcerpc->releaseFlowInfo(flow);
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../dcerpc/packets/packet05.pcap");

	inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

	BOOST_CHECK(dcerpc->getTotalBytes() == 72);
	BOOST_CHECK(dcerpc->getTotalPackets() == 1);
	BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
	BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

	BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes()); 
	BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_BIND_ACK); // Bind ack
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../dcerpc/packets/packet06.pcap");

	inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

	BOOST_CHECK(dcerpc->getTotalBytes() == 16);
	BOOST_CHECK(dcerpc->getTotalPackets() == 1);
	BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
	BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

	BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes()); 
	BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_ORPHANED);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../dcerpc/packets/packet01.pcap");

        inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(dcerpc->getTotalBytes() == 220);
        BOOST_CHECK(dcerpc->getTotalPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes()); 
        BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_ALTER_CONTEXT);
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../dcerpc/packets/packet07.pcap");

        inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(dcerpc->getTotalBytes() == 32);
        BOOST_CHECK(dcerpc->getTotalPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes());
        BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_FAULT);
}

BOOST_AUTO_TEST_CASE (test08)
{
	Packet packet("../dcerpc/packets/packet08.pcap");

        inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(dcerpc->getTotalBytes() == 168);
        BOOST_CHECK(dcerpc->getTotalPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes());
        BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_REQUEST);
}

BOOST_AUTO_TEST_CASE (test09)
{
	Packet packet("../dcerpc/packets/packet09.pcap");

        inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(dcerpc->getTotalBytes() == 172);
        BOOST_CHECK(dcerpc->getTotalPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes());
        BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_RESPONSE);
}

BOOST_AUTO_TEST_CASE (test10)
{
	Packet packet("../dcerpc/packets/packet10.pcap");

        inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(dcerpc->getTotalBytes() == 190);
        BOOST_CHECK(dcerpc->getTotalPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes());
        BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_AUTH3);
}

BOOST_AUTO_TEST_CASE (test11)
{
	Packet packet("../dcerpc/packets/packet04.pcap");

        dcerpc->increaseAllocatedMemory(1);

        inject(packet);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(dcerpc->getTotalBytes() == 160);
        BOOST_CHECK(dcerpc->getTotalPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes());
        BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_BIND); // Bind

        SharedPointer<DCERPCInfo> info = flow->getDCERPCInfo();
        BOOST_CHECK(info != nullptr);

	std::string uuid("e1af8308-5d1f-11c9-91a4-08002b14a0fa");
	BOOST_CHECK(info->uuid != nullptr);

	BOOST_CHECK(uuid.compare(info->uuid->getName()) == 0);

	{
		RedirectOutput r;

        	flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
        	r.cout << *(info.get());
	}

        JsonFlow j;
        info->serialize(j);

        dcerpc->releaseCache();
        BOOST_CHECK(flow->getDCERPCInfo() == nullptr);
       
	dcerpc->decreaseAllocatedMemory(1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ipv6_dcerpc_test_suite, StackIPv6DCERPCtest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet("../dcerpc/packets/packet11.pcap");

        tcp->increaseAllocatedMemory(1);
        dcerpc->increaseAllocatedMemory(1);

        inject(packet);

        BOOST_CHECK(ip6->getTotalBytes() == 220);
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp->getTotalBytes() == 180);
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

        Flow *flow = dcerpc->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(dcerpc->getTotalBytes() == 160);
        BOOST_CHECK(dcerpc->getTotalPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalValidPackets() == 1);
        BOOST_CHECK(dcerpc->getTotalInvalidPackets() == 0);

        BOOST_CHECK(dcerpc->getFragmentLength() == dcerpc->getTotalBytes());
        BOOST_CHECK(dcerpc->getPacketType() == DCERPC_UNIT_BIND); // Bind

        SharedPointer<DCERPCInfo> info = flow->getDCERPCInfo();
        BOOST_CHECK(info != nullptr);

        std::string uuid("e1af8308-5d1f-11c9-91a4-08002b14a0fa");
        BOOST_CHECK(info->uuid != nullptr);

        BOOST_CHECK(uuid.compare(info->uuid->getName()) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
