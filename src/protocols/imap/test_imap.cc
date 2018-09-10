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
#include "test_imap.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE imaptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(test_suite_imap, StackIMAPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(imap->getTotalPackets() == 0);
        BOOST_CHECK(imap->getTotalValidPackets() == 0);
        BOOST_CHECK(imap->getTotalInvalidPackets() == 0);
        BOOST_CHECK(imap->getTotalBytes() == 0);
	BOOST_CHECK(imap->processPacket(packet) == true);
	BOOST_CHECK(imap->getTotalClientCommands() == 0);
	BOOST_CHECK(imap->getTotalServerResponses() == 0);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../imap/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(imap->getTotalPackets() == 1);
        BOOST_CHECK(imap->getTotalValidPackets() == 1);
        BOOST_CHECK(imap->getTotalBytes() == 42);

        std::string cad("* OK IMAP4Rev1 Server Version 4.9.04.012");
	std::string header((char*)imap->getPayload(), cad.length());
	
        BOOST_CHECK(cad.compare(header) == 0);
	
	Flow *flow = imap->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	auto info = flow->getIMAPInfo();
	BOOST_CHECK(info != nullptr);

	BOOST_CHECK(info->getClientCommands() == 0);
	BOOST_CHECK(info->getServerCommands() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
        char *header =  "C00000 CAPABILITY\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        imap->processFlow(flow.get());

        BOOST_CHECK(imap->getTotalBytes() == 19);

        std::string cad("C00000 CAPABILITY");
        std::ostringstream h;

        h << imap->getPayload();
        BOOST_CHECK(cad.compare(0, cad.length(), h.str(), 0, cad.length()) == 0);
	BOOST_CHECK(imap->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
        char *header =  "00001 LOGIN pepe mypassword\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        imap->processFlow(flow.get());

        BOOST_CHECK(imap->getTotalBytes() == length);
}

BOOST_AUTO_TEST_CASE (test05)
{
        char *header =  "00001 LOGIN pepe@meneame.net mypassword\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

	imap->increaseAllocatedMemory(1);
        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        imap->processFlow(flow.get());

        BOOST_CHECK(imap->getTotalBytes() == length);

	auto info = flow->getIMAPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->user_name != nullptr);
}

BOOST_AUTO_TEST_CASE (test06)
{
        char *header =  "00001 LOGIN pepe@meneameandsomebigggbuerferexc.netmypassword";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        imap->processFlow(flow.get());

        BOOST_CHECK(imap->getTotalBytes() == length);
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::IMAP_BOGUS_HEADER);
	BOOST_CHECK(imap->getTotalEvents() == 1);

	CounterMap c = imap->getCounters();
}

BOOST_AUTO_TEST_CASE (test07)
{
	auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
	auto d = SharedPointer<DomainName>(new DomainName("bu","meneame.net"));

	dm->addDomainName(d);

        char *header1 =  "00001 LOGIN pepe@meneame.net mypassword\r\n";
        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1, length1);

	imap->increaseAllocatedMemory(1);
	imap->setDomainNameBanManager(dm);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
        imap->processFlow(flow.get());

	// Not interested on meneame users
	BOOST_CHECK(d->getMatchs() == 1);
	auto info = flow->getIMAPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->user_name == nullptr);
	BOOST_CHECK(info->isBanned() == true);
        
	char *header2 =  "00001 OK LOGIN completed\r\n";
        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2, length2);
        
	flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        imap->processFlow(flow.get());

	BOOST_CHECK(d->getMatchs() == 1);
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->user_name == nullptr);
	BOOST_CHECK(info->isBanned() == true);
}

BOOST_AUTO_TEST_CASE (test08)
{
        auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto d = SharedPointer<DomainName>(new DomainName("bogus domain","snowden.ru"));

        dm->addDomainName(d);

        char *header =  "00001 LOGIN letmein@snowden.ru mypassword\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        imap->increaseAllocatedMemory(1);
        imap->setDomainNameManager(dm);

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet);
        flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet);

        imap->processFlow(flow1.get());
        imap->processFlow(flow2.get());

        auto info1 = flow1->getIMAPInfo();
        auto info2 = flow2->getIMAPInfo();
        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info1->user_name != nullptr);
        BOOST_CHECK(info1->isBanned() == false);
        BOOST_CHECK(info2->user_name != nullptr);
        BOOST_CHECK(info2->isBanned() == false);

        BOOST_CHECK(info1->user_name == info2->user_name);

        BOOST_CHECK(d->getMatchs() == 2);
}

BOOST_AUTO_TEST_CASE (test09) // memory failure
{
	Packet packet("../imap/packets/packet01.pcap");

	imap->decreaseAllocatedMemory(100);

	inject(packet);

        BOOST_CHECK(imap->getTotalPackets() == 1);
        BOOST_CHECK(imap->getTotalValidPackets() == 1);
        BOOST_CHECK(imap->getTotalBytes() == 42);

	Flow *flow = imap->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getIMAPInfo() == nullptr);
}

BOOST_AUTO_TEST_CASE (test10)
{
        Packet packet1("../imap/packets/packet01.pcap");
        Packet packet2("../imap/packets/packet02.pcap");

        inject(packet1);
        inject(packet2);

        BOOST_CHECK(imap->getTotalPackets() == 2);
        BOOST_CHECK(imap->getTotalValidPackets() == 1);
        BOOST_CHECK(imap->getTotalBytes() == 19 + 42);

	Flow *flow = imap->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	auto info = flow->getIMAPInfo();
	BOOST_CHECK(info != nullptr);

        std::string cad("C00000 CAPABILITY");
        std::string header((char*)imap->getPayload(), cad.length());

        BOOST_CHECK(cad.compare(header) == 0);

	BOOST_CHECK(info->getClientCommands() == 0);
	BOOST_CHECK(info->getServerCommands() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
