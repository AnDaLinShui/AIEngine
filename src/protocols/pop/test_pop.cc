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
#include "test_pop.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE poptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(pop_test_suite, StackPOPtest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet;

	BOOST_CHECK(pop->getTotalPackets() == 0);
        BOOST_CHECK(pop->getTotalValidPackets() == 0);
        BOOST_CHECK(pop->getTotalInvalidPackets() == 0);
        BOOST_CHECK(pop->getTotalBytes() == 0);
	BOOST_CHECK(pop->getTotalEvents() == 0);
	BOOST_CHECK(pop->processPacket(packet) == true);
	
	CounterMap c = pop->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../pop/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(pop->getTotalPackets() == 1);
        BOOST_CHECK(pop->getTotalValidPackets() == 1);
        BOOST_CHECK(pop->getTotalBytes() == 47);

        std::string cad("+OK ready  <2906.1258886954@viste-family.net>");
	std::string header((char*)pop->getPayload(), cad.length());

        BOOST_CHECK(cad.compare(header) == 0);
	BOOST_CHECK(pop->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet1("../pop/packets/packet02.pcap");
	Packet packet2("../pop/packets/packet03.pcap");

	inject(packet1);
	inject(packet2);
       
	BOOST_CHECK(pop->getTotalPackets() == 2);
        BOOST_CHECK(pop->getTotalValidPackets() == 1);
        BOOST_CHECK(pop->getTotalBytes() == 110 + 26);
	BOOST_CHECK(pop->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
        char *header =  "USER im_a_bad_user@";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        pop->processFlow(flow.get());

        BOOST_CHECK(pop->getTotalBytes() == 19);
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::POP_BOGUS_HEADER);
        BOOST_CHECK(pop->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_CASE (test05)
{
        char *header =  "USER im_a_bad_user@\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        pop->processFlow(flow.get());

        BOOST_CHECK(pop->getTotalBytes() == 21);

	SharedPointer<POPInfo> info = flow->getPOPInfo();

	BOOST_CHECK(info != nullptr);
        std::string user("im_a_bad_user");

	BOOST_CHECK(user.compare(info->user_name->getName()) == 0);

        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);
        BOOST_CHECK(pop->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test06)
{
        char *header =  "USER im_a_bad_user@a\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

	auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
	auto d = SharedPointer<DomainName>(new DomainName("example","a"));

	dm->addDomainName(d);

	pop->setDomainNameManager(dm);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        pop->processFlow(flow.get());

        BOOST_CHECK(pop->getTotalBytes() == 22);

        SharedPointer<POPInfo> info = flow->getPOPInfo();

        BOOST_CHECK(info != nullptr);
        std::string user("im_a_bad_user");

        BOOST_CHECK(user.compare(info->user_name->getName()) == 0);

        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);
        BOOST_CHECK(pop->getTotalEvents() == 1);
	BOOST_CHECK(d->getMatchs() == 1);
}

BOOST_AUTO_TEST_CASE (test07)
{
        char *header =  "USER jack@domain.com\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto d = SharedPointer<DomainName>(new DomainName("example","domain.com"));

        dm->addDomainName(d);

        pop->setDomainNameBanManager(dm);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        pop->processFlow(flow.get());

        BOOST_CHECK(pop->getTotalBytes() == 22);

        SharedPointer<POPInfo> info = flow->getPOPInfo();

        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->user_name == nullptr);

        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);
        BOOST_CHECK(pop->getTotalEvents() == 0);
        BOOST_CHECK(d->getMatchs() == 1);
}

BOOST_AUTO_TEST_CASE (test08)
{
        char *header =  "USER jack_the_ripper@domain.com\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet);
        flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet);

        pop->processFlow(flow1.get());
        pop->processFlow(flow2.get());

        SharedPointer<POPInfo> info1 = flow1->getPOPInfo();
        SharedPointer<POPInfo> info2 = flow2->getPOPInfo();

        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info1->user_name != nullptr);
        BOOST_CHECK(info2->user_name != nullptr);
        BOOST_CHECK(info1->user_name == info2->user_name);
}

BOOST_AUTO_TEST_CASE (test09) // memory failure
{
	Packet packet("../pop/packets/packet02.pcap");
        
	pop->decreaseAllocatedMemory(10);

	inject(packet);
       
	BOOST_CHECK(pop->getTotalPackets() == 1);
        BOOST_CHECK(pop->getTotalValidPackets() == 1);
        BOOST_CHECK(pop->getTotalBytes() == 110);
	BOOST_CHECK(pop->getTotalEvents() == 0);

	Flow *flow = pop->getCurrentFlow();
	BOOST_CHECK(flow == nullptr);
}

BOOST_AUTO_TEST_CASE (test10) // ban domain and 
{
        char *header =  "USER jack@domain.com\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto d = SharedPointer<DomainName>(new DomainName("example","domain.com"));

        dm->addDomainName(d);

        pop->setDomainNameBanManager(dm);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        pop->processFlow(flow.get());

        BOOST_CHECK(pop->getTotalBytes() == 22);

        SharedPointer<POPInfo> info = flow->getPOPInfo();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->user_name == nullptr);
        BOOST_CHECK(info->isBanned() == true);

        BOOST_CHECK(d->getMatchs() == 1);

        flow->packet = const_cast<Packet*>(&packet);
        pop->processFlow(flow.get());

        BOOST_CHECK(pop->getTotalBytes() == 44);
}

BOOST_AUTO_TEST_SUITE_END()

