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
#include "test_coap.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE coaptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(coap_test_suite, StackCoAPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

       	BOOST_CHECK(coap->getTotalPackets() == 0);
        BOOST_CHECK(coap->getTotalValidPackets() == 0);
        BOOST_CHECK(coap->getTotalBytes() == 0);
        BOOST_CHECK(coap->getTotalInvalidPackets() == 0);
	BOOST_CHECK(coap->processPacket(packet) == true);

	CounterMap c = coap->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../coap/packets/packet01.pcap");

	inject(packet);

        Flow *flow = coap->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
        BOOST_CHECK(info != nullptr);

        // Check the results
       	BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 53);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
       
        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 58541);
        BOOST_CHECK(udp->getDestinationPort() == 5683);
        BOOST_CHECK(udp->getPayloadLength() == 25);
	
	BOOST_CHECK(coap->getTotalValidPackets() == 1);
	BOOST_CHECK(coap->getVersion() == COAP_VERSION);
	BOOST_CHECK(coap->getTokenLength() == 2);
	BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
	BOOST_CHECK(coap->getCode() == COAP_CODE_GET); 
	BOOST_CHECK(coap->getMessageId() == 33408); 

	std::string uri("/1/1/768/core.power");
	
        std::string hostname("localhost");

        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../coap/packets/packet02.pcap");

        inject(packet);

        // Check the results
       	BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 227);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
       
        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 5683);
        BOOST_CHECK(udp->getDestinationPort() == 58541);
        BOOST_CHECK(udp->getPayloadLength() == 207 - 8);
	
	BOOST_CHECK(coap->getTotalValidPackets() == 1);
	BOOST_CHECK(coap->getVersion() == COAP_VERSION);
	BOOST_CHECK(coap->getTokenLength() == 2);
	BOOST_CHECK(coap->getType() == COAP_TYPE_ACKNOWLEDGEMENT);
	BOOST_CHECK(coap->getCode() == 64); 
	BOOST_CHECK(coap->getMessageId() == 33408); 
}

BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../coap/packets/packet03.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 56);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 5683);
        BOOST_CHECK(udp->getDestinationPort() == 5683);
        BOOST_CHECK(udp->getPayloadLength() == 36 - 8);

        BOOST_CHECK(coap->getTotalValidPackets() == 1);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 5);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_GET);
        BOOST_CHECK(coap->getMessageId() == 35444);
}

BOOST_AUTO_TEST_CASE (test05)
{
	Packet packet("../coap/packets/packet04.pcap");

        inject(packet);

        Flow *flow = coap->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
        BOOST_CHECK(info != nullptr);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 51);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 33564);
        BOOST_CHECK(udp->getDestinationPort() == 5683);
        BOOST_CHECK(udp->getPayloadLength() == 31 - 8);

        BOOST_CHECK(coap->getTotalValidPackets() == 1);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 4);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_GET);
        BOOST_CHECK(coap->getMessageId() == 8434);
	
	std::string hostname("localhost");
	BOOST_CHECK(hostname.compare(info->host_name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test06)
{
	Packet packet("../coap/packets/packet05.pcap");

        inject(packet);

        Flow *flow = coap->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
        BOOST_CHECK(info != nullptr);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 110);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 46025);
        BOOST_CHECK(udp->getDestinationPort() == 5683);
        BOOST_CHECK(udp->getPayloadLength() == 90 - 8);

        BOOST_CHECK(coap->getTotalValidPackets() == 1);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 4);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_GET);
        BOOST_CHECK(coap->getMessageId() == 33043);

	std::string uri("/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time");
	std::string hostname("localhost");
	BOOST_CHECK(hostname.compare(info->host_name->getName()) == 0);
	BOOST_CHECK(uri.compare(info->uri->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test07)
{
	Packet packet("../coap/packets/packet06.pcap");

        inject(packet);

        Flow *flow = coap->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 1092);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 58928);
        BOOST_CHECK(udp->getDestinationPort() == 5683);
        BOOST_CHECK(udp->getPayloadLength() == 1072 - 8);

        BOOST_CHECK(coap->getTotalValidPackets() == 1);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 4);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_PUT);
        BOOST_CHECK(coap->getMessageId() == 45900);

	std::string uri_str("/other/block");
	std::string hostname("somedomain.com");
	BOOST_CHECK(hostname.compare(info->host_name->getName()) == 0);
	BOOST_CHECK(uri_str.compare(info->uri->getName()) == 0);

	// Verify the caches
	SharedPointer<StringCache> host = info->host_name;
	SharedPointer<StringCache> uri = info->uri;

	// 3 references: 1 from the flow, 1 from the variables and 1 for the map
	BOOST_CHECK(host.use_count() == 3);
	BOOST_CHECK(uri.use_count() == 3);

	coap->releaseCache();
	
	BOOST_CHECK(host.use_count() == 2);
	BOOST_CHECK(uri.use_count() == 2);

	BOOST_CHECK(info->host_name == nullptr);
	BOOST_CHECK(info->uri == nullptr);
        BOOST_CHECK(flow->getCoAPInfo() == nullptr);
}

BOOST_AUTO_TEST_CASE (test08) // malformed coap packet
{
	Packet packet("../coap/packets/packet05.pcap", 42);

	packet.setPayloadLength(3);

        auto flow = SharedPointer<Flow>(new Flow());

        coap->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        coap->processFlow(flow.get());

        BOOST_CHECK(flow != nullptr); 
        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
        BOOST_CHECK(info == nullptr);

        // Check the results
        BOOST_CHECK(coap->getTotalEvents() == 1);
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::COAP_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test09)
{
	Packet packet("../coap/packets/packet05.pcap", 42);

        auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

        coap->increaseAllocatedMemory(2);

        flow1->packet = const_cast<Packet*>(&packet);
        flow2->packet = const_cast<Packet*>(&packet);

        coap->processFlow(flow1.get());
        coap->processFlow(flow2.get());

        SharedPointer<CoAPInfo> info1 = flow1->getCoAPInfo();
        SharedPointer<CoAPInfo> info2 = flow2->getCoAPInfo();

        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);

	BOOST_CHECK(info1->host_name != nullptr);
	BOOST_CHECK(info2->host_name != nullptr);
	BOOST_CHECK(info1->uri != nullptr);
	BOOST_CHECK(info2->uri != nullptr);
	BOOST_CHECK(info1->host_name == info2->host_name);
	BOOST_CHECK(info1->uri == info2->uri);
}

BOOST_AUTO_TEST_CASE (test10) // matched domain name and uri sets
{
	Packet packet("../coap/packets/packet05.pcap");

	auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
	auto d = SharedPointer<DomainName>(new DomainName("example", "localhost"));
	auto us = SharedPointer<HTTPUriSet>(new HTTPUriSet());

	us->addURI("/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time");

        // Attach the HTTPUriSet to the DomainName
        d->setHTTPUriSet(us);
	dm->addDomainName(d);

	// Just exercise the virtual methods of Protocol
	ip->setDomainNameManager(dm);
	ip->setDomainNameBanManager(dm);

	coap->setDomainNameManager(dm);

        coap->increaseAllocatedMemory(1);

	inject(packet);

        Flow *flow = coap->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(info->uri != nullptr);

	BOOST_CHECK(info->matched_domain_name == d);

	BOOST_CHECK(us->getTotalURIs() == 1);
	BOOST_CHECK(us->getTotalLookups() == 1);
	BOOST_CHECK(us->getTotalLookupsIn() == 1);
	BOOST_CHECK(us->getTotalLookupsOut() == 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ipv6_coap_test_suite, StackIPv6CoAPtest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet("../coap/packets/packet07.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 32 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 61046);
        BOOST_CHECK(udp->getDestinationPort() == 5683);
        BOOST_CHECK(udp->getPayloadLength() == 32 - 8);

        BOOST_CHECK(coap->getTotalValidPackets() == 1);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 3);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_DELETE);
        BOOST_CHECK(coap->getMessageId() == 18020);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../coap/packets/packet08.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 23 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(coap->getTotalValidPackets() == 1);
        BOOST_CHECK(coap->getTotalBytes() == 23);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 0);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_POST);
        BOOST_CHECK(coap->getMessageId() == 52896);

        Flow *flow = coap->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri != nullptr);
	
	std::string uri_str("/storage");
	BOOST_CHECK(uri_str.compare(info->uri->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../coap/packets/packet09.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 23 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(coap->getTotalValidPackets() == 1);
        BOOST_CHECK(coap->getTotalBytes() == 23);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 0);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_DELETE);
        BOOST_CHECK(coap->getMessageId() == 38180);

        Flow *flow = coap->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri != nullptr);

	std::string uri_str("/storage/myresource");
	BOOST_CHECK(uri_str.compare(info->uri->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test04) // failing memory
{
	Packet packet("../coap/packets/packet09.pcap");

	coap->decreaseAllocatedMemory(10);

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 23 + 8 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(coap->getTotalValidPackets() == 1);
        BOOST_CHECK(coap->getTotalBytes() == 23);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 0);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_DELETE);
        BOOST_CHECK(coap->getMessageId() == 38180);

        Flow *flow = coap->getCurrentFlow();
        BOOST_CHECK(flow == nullptr);
        flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getCoAPInfo() == nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
