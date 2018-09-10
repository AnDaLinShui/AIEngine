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
#include "test_smtp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE smtptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(smtp_test_suite, StackSMTPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(smtp->getTotalPackets() == 0);
        BOOST_CHECK(smtp->getTotalValidPackets() == 0);
        BOOST_CHECK(smtp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(smtp->getTotalBytes() == 0);
	BOOST_CHECK(smtp->processPacket(packet) == true);
	
	CounterMap c = smtp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../smtp/packets/packet01.pcap");

	inject(packet);

        BOOST_CHECK(smtp->getTotalPackets() == 1);
        BOOST_CHECK(smtp->getTotalValidPackets() == 1);
        BOOST_CHECK(smtp->getTotalBytes() == 181);

        std::string cad("220-xc90.websitewelcome.com ESMTP Exim 4.69");
	std::string header((char*)smtp->getPayload(), cad.length());

	BOOST_CHECK(cad.compare(header) == 0);	
	BOOST_CHECK(smtp->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
        char *header =  "EHLO GP\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(smtp->getTotalBytes() == 9);

        std::string cad("EHLO GP");
	std::string header1((char*)smtp->getPayload(), cad.length());

	BOOST_CHECK(cad.compare(header1) == 0);	
}

BOOST_AUTO_TEST_CASE (test04)
{
        char *header =  "MAIL FROM: <gurpartap@patriots.in>\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(smtp->getTotalBytes() == length);
	BOOST_CHECK(flow->getSMTPInfo() != nullptr);

	SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
	SharedPointer<StringCache> from = info->from;
	SharedPointer<StringCache> to = info->to;

	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(from != nullptr);
	BOOST_CHECK(to == nullptr);
	
        std::string cad("gurpartap@patriots.in");

        BOOST_CHECK(cad.compare(from->getName()) == 0);
	BOOST_CHECK(smtp->getTotalEvents() == 0);
	BOOST_CHECK(info->getCommand() == (int8_t)SMTPCommandTypes::SMTP_CMD_MAIL); 
}

BOOST_AUTO_TEST_CASE (test05)
{
        char *header =  "RCPT TO: <mike_andersson@yahoo.me>\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(smtp->getTotalBytes() == length);
        BOOST_CHECK(flow->getSMTPInfo() != nullptr);

        SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
        SharedPointer<StringCache> from = info->from;
        SharedPointer<StringCache> to = info->to;

        BOOST_CHECK(from == nullptr);
        BOOST_CHECK(to != nullptr);

        std::string cad("mike_andersson@yahoo.me");

        BOOST_CHECK(cad.compare(to->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test06)
{
        char *header =  "MAIL FROM: <billy_the_kid@yahoo.com>\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto domain_ban_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto domain_name = SharedPointer<DomainName>(new DomainName("unwanted domain", "yahoo.com"));

        smtp->setDomainNameBanManager(domain_ban_mng);
        domain_ban_mng->addDomainName(domain_name);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(flow->getSMTPInfo() != nullptr);

        SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
        SharedPointer<StringCache> from = info->from;
        SharedPointer<StringCache> to = info->to;

	BOOST_CHECK(domain_name->getMatchs() == 1);
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(from == nullptr);
        BOOST_CHECK(to == nullptr);
	BOOST_CHECK(info->isBanned() == true);
	BOOST_CHECK(smtp->getTotalEvents() == 0);
}

BOOST_AUTO_TEST_CASE (test07)
{
        char *header =  "MAIL FROM: <billy_the_kid@yahoo.com>\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto domain_ban_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto domain_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto domain_name_ban = SharedPointer<DomainName>(new DomainName("unwanted domain", "google.com"));
        auto domain_name = SharedPointer<DomainName>(new DomainName("unwanted domain", "yahoo.com"));

        smtp->setDomainNameBanManager(domain_ban_mng);
        smtp->setDomainNameManager(domain_mng);
        domain_ban_mng->addDomainName(domain_name_ban);
        domain_mng->addDomainName(domain_name);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(flow->getSMTPInfo() != nullptr);

        SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
        SharedPointer<StringCache> from = info->from;
        SharedPointer<StringCache> to = info->to;

        BOOST_CHECK(domain_name_ban->getMatchs() == 0);
        BOOST_CHECK(domain_name->getMatchs() == 1);
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(from != nullptr);
        BOOST_CHECK(to == nullptr);
        BOOST_CHECK(info->isBanned() == false);
	BOOST_CHECK(smtp->getTotalEvents() == 1);
        
	smtp->setDomainNameManager(nullptr);
}

BOOST_AUTO_TEST_CASE (test08)
{
        char *header =  "MAIL FROM: <myaexploityahoo.com\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SMTP_BOGUS_HEADER);
	BOOST_CHECK(smtp->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_CASE (test09)
{
        char *header =  "MAIL FROM: <myuseryahoo.com>\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SMTP_BOGUS_HEADER);
	BOOST_CHECK(smtp->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_CASE (test10)
{
	Packet packet("../smtp/packets/packet04.pcap");

        inject(packet);

        BOOST_CHECK(smtp->getTotalPackets() == 1);
        BOOST_CHECK(smtp->getTotalValidPackets() == 1);
        BOOST_CHECK(smtp->getTotalBytes() == 67);
        BOOST_CHECK(smtp->getTotalEvents() == 0);

        std::string cad("220 ubuntu ESMTP Exim 4.82 Ubuntu Fri, 30 Jan 2015 22:53:30 +0100");
	std::string header((char*)smtp->getPayload(), cad.length());

	BOOST_CHECK(cad.compare(header) == 0);	
}

BOOST_AUTO_TEST_CASE (test11)
{
        char *header1 =  "MAIL FROM: <billy_the_kid@yahoo.com>\r\n";
        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1, length1);
        
	char *header2 =  "RCPT TO: <lovely_mayer@yahoo.co.uk>\r\n";
        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2, length2);
        
        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet1);
        
	flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet1);
       
	// Inject two times 
        smtp->processFlow(flow1.get());
        smtp->processFlow(flow2.get());

        SharedPointer<SMTPInfo> info2 = flow2->getSMTPInfo();
        SharedPointer<SMTPInfo> info1 = flow1->getSMTPInfo();

	BOOST_CHECK(info2 != nullptr);
	BOOST_CHECK(info1 != nullptr);

	BOOST_CHECK(info1->from != nullptr);
	BOOST_CHECK(info2->from != nullptr);
	BOOST_CHECK(info1->to == nullptr);
	BOOST_CHECK(info2->to == nullptr);

	std::string from("billy_the_kid@yahoo.com");
	std::string to("lovely_mayer@yahoo.co.uk");

	BOOST_CHECK(from.compare(info2->from->getName()) == 0);

	flow1->packet = const_cast<Packet*>(&packet2);
	flow2->packet = const_cast<Packet*>(&packet2);

	// Inject two times 
        smtp->processFlow(flow1.get());

	BOOST_CHECK(info1->to != nullptr);
	BOOST_CHECK(info2->to == nullptr);

        smtp->processFlow(flow2.get());
	
	BOOST_CHECK(info1->to == info2->to);

	BOOST_CHECK(to.compare(info1->to->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test12) // Test incorrect server responses
{
        char *header =  "XXXX this is not a response\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet);

        smtp->processFlow(flow.get());

        SharedPointer<SMTPInfo> info = flow->getSMTPInfo();

	// TODO verify the error
	
}

BOOST_AUTO_TEST_CASE (test13) // No memory and banned flow
{
        char *header1 =  "MAIL FROM: <billy_the_kid@yahoo.co.uk>\r\n";
        uint8_t *pkt1 = reinterpret_cast <uint8_t*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1, length1);

        char *header2 =  "MAIL FROM: <lovely_mayer@yahoo.co.uk>\r\n";
        uint8_t *pkt2 = reinterpret_cast <uint8_t*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2, length2);

        auto domain_ban_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto domain_name_ban = SharedPointer<DomainName>(new DomainName("unwanted domain","yahoo.co.uk"));

        smtp->setDomainNameBanManager(domain_ban_mng);
        domain_ban_mng->addDomainName(domain_name_ban);

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        flow1->setFlowDirection(FlowDirection::FORWARD);
        flow1->packet = const_cast<Packet*>(&packet1);

        flow2->setFlowDirection(FlowDirection::FORWARD);
        flow2->packet = const_cast<Packet*>(&packet1);

	smtp->decreaseAllocatedMemory(10);
	// Inject the first flow
        smtp->processFlow(flow1.get());

        SharedPointer<SMTPInfo> info = flow1->getSMTPInfo();
	BOOST_CHECK(info == nullptr);
	
	smtp->increaseAllocatedMemory(1);
        smtp->processFlow(flow2.get());
        
	info = flow2->getSMTPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->isBanned() == true);

        smtp->processFlow(flow2.get());
        
	info = flow2->getSMTPInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->isBanned() == true);
}

BOOST_AUTO_TEST_CASE (test14)
{
	Packet packet("../smtp/packets/packet05.pcap");

        inject(packet);

        BOOST_CHECK(smtp->getTotalPackets() == 1);
        BOOST_CHECK(smtp->getTotalValidPackets() == 1);
        BOOST_CHECK(smtp->getTotalBytes() == 38);
        BOOST_CHECK(smtp->getTotalEvents() == 0);

	Flow *flow = smtp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
        SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
	BOOST_CHECK(info != nullptr);

        std::string cad("220 smtp001.mail.xxx.xxxxx.com ESMTP");
	std::string header((char*)smtp->getPayload(), cad.length());

	BOOST_CHECK(cad.compare(header) == 0);	
	BOOST_CHECK(info->getCommand() == (int8_t)SMTPCommandTypes::SMTP_CMD_EHLO); 
}

BOOST_AUTO_TEST_CASE (test15)
{
        char *header =  "RCPT TO: ITvN3@VrVzGAJkFDLNEpcMMFQvyLrLhxPyl.us\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(smtp->getTotalBytes() == length);
        BOOST_CHECK(flow->getSMTPInfo() != nullptr);

        SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
        SharedPointer<StringCache> from = info->from;
        SharedPointer<StringCache> to = info->to;

        BOOST_CHECK(from == nullptr);
        BOOST_CHECK(to != nullptr);

        std::string cad("ITvN3@VrVzGAJkFDLNEpcMMFQvyLrLhxPyl.us");
	BOOST_CHECK(cad.compare(to->getName()) == 0);

	BOOST_CHECK(info->getCommand() == (int8_t)SMTPCommandTypes::SMTP_CMD_RCPT); 
}

BOOST_AUTO_TEST_CASE (test16)
{
        char *header =  "MAIL FROM: jZKFVyEtXjmyp4zHxuu0@bEYuzxsYMWHIBOclrTBkjWQWDElrcIDfu.net\r\n";
        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(smtp->getTotalBytes() == length);
        BOOST_CHECK(flow->getSMTPInfo() != nullptr);

        SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
        SharedPointer<StringCache> from = info->from;
        SharedPointer<StringCache> to = info->to;

        BOOST_CHECK(from != nullptr);
        BOOST_CHECK(to == nullptr);

        std::string cad("jZKFVyEtXjmyp4zHxuu0@bEYuzxsYMWHIBOclrTBkjWQWDElrcIDfu.net");
	BOOST_CHECK(cad.compare(from->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test17) // Long RCPT 
{
	char *header = 	"RCPT TO: qLRwNVmgQWLLqZ9nZ9QQrqBm5PxB7NoFgnK0baZ8RS91DRmjb2Rx1oTcmZXUhGzlQHB0FQ9JeQay8"
			"ux8FaHvArlPcCK0wZRTs347IY8UtWx66CRFXKyY7HeeTFgiBxnR2Mb7jXqg5h0alL1ERzDmuUAi4eQyfvJAnjo"
			"qpZjZWnqNDtKC7E3iLEgew16MxMDg7rRayUjY9YvY3Y2JrJTERe4L4d3NjbayzzI9yKrpSpvtRj9TWUqLzmcFs"
			"eVOHFVAy82dQUBCbfMVVrDEibF40FOEumLsXO09VXN4gY3Ny7GskSLHONRDmde5JtVgKpLc1x8xDGxar51t8m2"
			"5O5LpOlpl9AkaDqNN0rG2usZmF7ed5sdE31tsDJMBlQO6lKw5YwXbF2pz0bOZEeToXG85tTqF71c8KvFtCAhZW"
			"ImwgxaWG967tBabBx49kZNQIn2jbrmK60jwVDwgs8Q3FdGjwXR6CNd8n1KEkumplOTXCn5OjHHeGmoPRxPl8hG"
			"oz6qnre04kqTEsxIgKNeSyyJLL91EyQgTzekFEwd2kzrQOCwSXpZoxwzQG0pR9wWjyUqTcjZxRWpu0WMErGD3J"
			"K2xFf4fNjF43clwaz71dqOnE1V27g8nlpIp7zyJk7Oaol73z01r1BH9oQW5vKeTCEscb7cPZR9DZWkHIBFhZ34"
			"WtaRsBAPh8WbxacrNZeEDK02TTxiyhSplSrJBoy1l63BQePcEk2SRDAcUtZgq5Gxj4MmjWNk7HDI26xt6ySuiE"
			"yBeidLM5z7s9V8S6lBVLsS4hNn4J74DgL5nb0UtMzmT1yxDZFob5KYJPPHCs1MrUP4tieKTILJrid6kFhXi76q"
			"BlsH6nNRKdnFozzzcQ4UWH9qRgEmgCztFOnRhEOd1QuUbprseX3Wp13IFQeHY4AF7tFNM2HMEPhJUJnOrZ8U7B\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SMTP_LONG_EMAIL);
        BOOST_CHECK(smtp->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_CASE (test18) // Long mail from
{
	char *header = 	"MAIL FROM: RwNVmgQWLLqZ9nZ9QQrqBm5PxB7NoFgnK0baZ8RS91DRmjb2Rx1oTcmZXUhGzlQHB0FQ9JeQay8"
			"ux8FaHvArlPcCK0wZRTs347IY8UtWx66CRFXKyY7HeeTFgiBxnR2Mb7jXqg5h0alL1ERzDmuUAi4eQyfvJAnjo"
			"qpZjZWnqNDtKC7E3iLEgew16MxMDg7rRayUjY9YvY3Y2JrJTERe4L4d3NjbayzzI9yKrpSpvtRj9TWUqLzmcFs"
			"eVOHFVAy82dQUBCbfMVVrDEibF40FOEumLsXO09VXN4gY3Ny7GskSLHONRDmde5JtVgKpLc1x8xDGxar51t8m2"
			"ImwgxaWG967tBabBx49kZNQIn2jbrmK60jwVDwgs8Q3FdGjwXR6CNd8n1KEkumplOTXCn5OjHHeGmoPRxPl8hG"
			"oz6qnre04kqTEsxIgKNeSyyJLL91EyQgTzekFEwd2kzrQOCwSXpZoxwzQG0pR9wWjyUqTcjZxRWpu0WMErGD3J"
			"K2xFf4fNjF43clwaz71dqOnE1V27g8nlpIp7zyJk7Oaol73z01r1BH9oQW5vKeTCEscb7cPZR9DZWkHIBFhZ34"
			"WtaRsBAPh8WbxacrNZeEDK02TTxiyhSplSrJBoy1l63BQePcEk2SRDAcUtZgq5Gxj4MmjWNk7HDI26xt6ySuiE"
			"yBeidLM5z7s9V8S6lBVLsS4hNn4J74DgL5nb0UtMzmT1yxDZFob5KYJPPHCs1MrUP4tieKTILJrid6kFhXi76q"
			"BlsH6nNRKdnFozzzcQ4UWH9qRgEmgCztFOnRhEOd1QuUbprseX3Wp13IFQeHY4AF7tFNM2HMEPhJUJnOrZ8U7B\r\n";

        uint8_t *pkt = reinterpret_cast <uint8_t*> (header);
        int length = strlen(header);
        Packet packet(pkt, length);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SMTP_LONG_EMAIL);
        BOOST_CHECK(smtp->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
