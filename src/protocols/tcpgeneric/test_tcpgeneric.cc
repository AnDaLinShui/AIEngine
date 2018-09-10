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
#include "test_tcpgeneric.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE tcpgenerictest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tcpgeneric_test_suite, StackTCPGenericTest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

	BOOST_CHECK(gtcp6->getTotalPackets() == 0);
	BOOST_CHECK(gtcp6->getTotalBytes() == 0);
	BOOST_CHECK(gtcp6->getTotalValidPackets() == 0);
	BOOST_CHECK(gtcp6->getTotalInvalidPackets() == 0);
	BOOST_CHECK(gtcp6->processPacket(packet) == true);

	CounterMap c = gtcp->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
        Packet packet("../tcpgeneric/packets/packet01.pcap");

        auto rm = RegexManagerPtr(new RegexManager());
	auto r = SharedPointer<Regex>(new Regex("bittorrent tcp", "^\\x13BitTorrent.*$"));

        rm->addRegex(r);
        gtcp->setRegexManager(rm);
        tcp->setRegexManager(rm);

	inject(packet);

        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() != nullptr);

	Flow *flow = tcp->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->regex_mng == rm);

	BOOST_CHECK(gtcp->getTotalEvents() == 1);

}

// Test case integrated with IPv6
BOOST_AUTO_TEST_CASE (test03)
{
        Packet packet("../ip6/packets/packet09.pcap");

	inject(packet);

	BOOST_CHECK(ip6->getTotalPackets() == 1);
	BOOST_CHECK(ip6->getTotalValidPackets() == 1);

	BOOST_CHECK(tcp6->getTotalPackets() == 1);
	BOOST_CHECK(tcp6->getTotalBytes() == 63);
	BOOST_CHECK(tcp6->getTotalValidPackets() == 1);
	BOOST_CHECK(tcp6->getSourcePort() == 40667);
	BOOST_CHECK(tcp6->getDestinationPort() == 6941);

	BOOST_CHECK(gtcp6->getTotalPackets() == 1);
	BOOST_CHECK(gtcp6->getTotalBytes() == 31);
	BOOST_CHECK(gtcp6->getTotalValidPackets() == 1);

	std::string message("its peanut butter & semem time");
	std::string header((char*)gtcp6->getPayload(), message.length());

        BOOST_CHECK(message.compare(header) == 0);
}

// Example of chaining regex
BOOST_AUTO_TEST_CASE (test04)
{
        Packet packet("../tcpgeneric/packets/packet01.pcap");

	auto r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1", "^\\x13BitTorrent.*$"));
	auto r2 = SharedPointer<Regex>(new Regex("bittorrent tcp 2", "^\\x13BitTorrent.*$"));
        auto rm = RegexManagerPtr(new RegexManager());

	r1->setNextRegex(r2);
        rm->addRegex(r1);
        gtcp->setRegexManager(rm);
        tcp->setRegexManager(rm);

	inject(packet);

	BOOST_CHECK(r1->getMatchs() == 1);
	BOOST_CHECK(r1->getTotalEvaluates() == 1);
	BOOST_CHECK(r2->getMatchs() == 0);
	BOOST_CHECK(r2->getTotalEvaluates() == 0);

        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() == r1);

	BOOST_CHECK(gtcp->getTotalEvents() == 1);

        mux_eth->forwardPacket(packet);

	BOOST_CHECK(r1->getMatchs() == 1);
	BOOST_CHECK(r1->getTotalEvaluates() == 1);
	BOOST_CHECK(r2->getMatchs() == 1);
	BOOST_CHECK(r2->getTotalEvaluates() == 1);

        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() == r1);

	BOOST_CHECK(gtcp->getTotalEvents() == 2);
}

// Example of chaining regex that fails
BOOST_AUTO_TEST_CASE (test05)
{
        Packet packet("../tcpgeneric/packets/packet01.pcap");

        auto r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1", "^\\x13BitTorrent.*$"));
        auto r2 = SharedPointer<Regex>(new Regex("bittorrent tcp 2", "^.*(hello paco).*$"));
        auto rm = RegexManagerPtr(new RegexManager());

        r1->setNextRegex(r2);
        rm->addRegex(r1);
        gtcp->setRegexManager(rm);
        tcp->setRegexManager(rm);
	
	inject(packet);

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 0);

        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() == r1);

	inject(packet);

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 1);

        BOOST_CHECK(rm->getTotalRegexs()  == 1);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() == r1);
	
	BOOST_CHECK(gtcp->getTotalEvents() == 1);
}

// Example of IPv4 and IPv6 matching regex 
BOOST_AUTO_TEST_CASE (test06)
{
        Packet packet1("../tcpgeneric/packets/packet01.pcap");
        Packet packet2("../ip6/packets/packet09.pcap");

        auto r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1", "^.*\\x13BitTorrent.*$"));
        auto r2 = SharedPointer<Regex>(new Regex("defcon20 regex", "^(its peanut butter).*$"));
        auto rm = RegexManagerPtr(new RegexManager());

	// Both tcp6 and tcp will point to one TCPGenericProtocol, so they will share the same RegexManager
	ff_tcp6->removeUpFlowForwarder(ff_gtcp6);
	ff_tcp6->addUpFlowForwarder(ff_gtcp);

        rm->addRegex(r1);
        rm->addRegex(r2);
        gtcp->setRegexManager(rm);
        tcp6->setRegexManager(rm);
        tcp->setRegexManager(rm);

	flow_cache->createFlows(2);

	inject(packet1);

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 0);

        BOOST_CHECK(rm->getTotalRegexs()  == 2);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(rm->getMatchedRegex() == r1);

	// Inject the second packet
	inject(packet2);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);

        BOOST_CHECK(tcp6->getTotalPackets() == 1);
        BOOST_CHECK(tcp6->getTotalBytes() == 63);
        BOOST_CHECK(tcp6->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp6->getSourcePort() == 40667);
        BOOST_CHECK(tcp6->getDestinationPort() == 6941);

        BOOST_CHECK(gtcp6->getTotalPackets() == 0);
        BOOST_CHECK(gtcp6->getTotalBytes() == 0);
        BOOST_CHECK(gtcp6->getTotalValidPackets() == 0);

        BOOST_CHECK(gtcp->getTotalPackets() == 2);
        BOOST_CHECK(gtcp->getTotalBytes() == 99);
        BOOST_CHECK(gtcp->getTotalValidPackets() == 2);

	// Recheck the regex status
        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 2);
        BOOST_CHECK(r2->getMatchs() == 1);
        BOOST_CHECK(r2->getTotalEvaluates() == 1);

        BOOST_CHECK(rm->getTotalRegexs()  == 2);
        BOOST_CHECK(rm->getTotalMatchingRegexs() == 2);
        BOOST_CHECK(rm->getMatchedRegex() == r2);
}

// One regex only can be matched on one flow once.
BOOST_AUTO_TEST_CASE (test07)
{
        Packet packet("../tcpgeneric/packets/packet01.pcap");

        auto r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1", "^\\x13BitTorrent.*$"));
        auto rm = RegexManagerPtr(new RegexManager());

        rm->addRegex(r1);
        gtcp->setRegexManager(rm);
        tcp->setRegexManager(rm);

	for (int i = 0; i < 5; ++i) inject(packet); 

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);

        BOOST_CHECK(tcp->getTotalPackets() == 5);
        BOOST_CHECK(tcp->getTotalBytes() == 88 * 5);
        BOOST_CHECK(tcp->getTotalValidPackets() == 5);
}

// Regex example
BOOST_AUTO_TEST_CASE (test08)
{
        Packet packet1("../tcpgeneric/packets/packet02.pcap");

        auto r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1", "^\\x13BitTorrent.*$"));
        auto r2 = SharedPointer<Regex>(new Regex("generic nop exploit tcp ", "^.*\\x90\\x90\\x90\x90.*$"));
        auto r3 = SharedPointer<Regex>(new Regex("clet tcp ", "^.*\\xe9\\xfe\\xff\\xff\xff.*$"));
        auto rm = RegexManagerPtr(new RegexManager());

        rm->addRegex(r1);
        rm->addRegex(r2);
        rm->addRegex(r3);
        gtcp->setRegexManager(rm);
        tcp->setRegexManager(rm);

	inject(packet1);

	// Check stack integrity
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 380);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);
        
	BOOST_CHECK(gtcp->getTotalPackets() == 1);
        BOOST_CHECK(gtcp->getTotalBytes() == 348);
        BOOST_CHECK(gtcp->getTotalValidPackets() == 1);

	// Check regex stuff
        BOOST_CHECK(r1->getMatchs() == 0);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 1);
        BOOST_CHECK(r3->getMatchs() == 1);
        BOOST_CHECK(r3->getTotalEvaluates() == 1);

	BOOST_CHECK(rm->getMatchedRegex() == r3);

	BOOST_CHECK(gtcp->getTotalEvents() == 1);
}

// Another Regex test case
BOOST_AUTO_TEST_CASE (test09)
{
        Packet packet1("../tcpgeneric/packets/packet03.pcap");
        Packet packet2("../tcpgeneric/packets/packet02.pcap");

        auto r1 = SharedPointer<Regex>(new Regex("generic nop exploit tcp ", "^.*\\x90\\x90\\x90\x90.*$"));
        auto rm = RegexManagerPtr(new RegexManager());

	flow_cache->createFlows(1); // allocate space for another flow

	// Shares the same generic tcp
        ff_tcp->removeUpFlowForwarder(ff_gtcp6);
        ff_tcp6->removeUpFlowForwarder(ff_gtcp6);
        ff_tcp6->addUpFlowForwarder(ff_gtcp);

        rm->addRegex(r1);
        gtcp->setRegexManager(rm);
        tcp6->setRegexManager(rm);
        tcp->setRegexManager(rm);

	inject(packet1);

        // Check stack integrity
        BOOST_CHECK(tcp6->getTotalPackets() == 1);
        BOOST_CHECK(tcp6->getTotalBytes() == 103+32);
        BOOST_CHECK(tcp6->getTotalValidPackets() == 1);

        BOOST_CHECK(gtcp->getTotalPackets() == 1);
        BOOST_CHECK(gtcp->getTotalBytes() == 103);
        BOOST_CHECK(gtcp->getTotalValidPackets() == 1);

        // Check regex stuff
        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(rm->getMatchedRegex() == r1);

	// Inject the second packet
	inject(packet2);

        // Check stack integrity
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 380);
        BOOST_CHECK(tcp->getTotalValidPackets() == 1);

        BOOST_CHECK(gtcp->getTotalPackets() == 2);
        BOOST_CHECK(gtcp->getTotalBytes() == 103 + 348);
        BOOST_CHECK(gtcp->getTotalValidPackets() == 2);

        // Check regex stuff
        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 2);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

	// Inject the last packet 5 times
	for (int i = 0; i< 5; ++i) inject(packet2);

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 7);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);

	for (int i = 0; i< 5; ++i) inject(packet1);

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 7);
        BOOST_CHECK(rm->getMatchedRegex() == nullptr);
}

BOOST_AUTO_TEST_CASE (test10) // IPv6 with auth header 
{
	Packet packet("../ip6/packets/packet02.pcap");

        auto r = SharedPointer<Regex>(new Regex("Bad http", "^GET.*$"));
        auto rm = RegexManagerPtr(new RegexManager());

        rm->addRegex(r);
        gtcp6->setRegexManager(rm);
        tcp6->setRegexManager(rm);

	inject(packet);

        // Check stack integrity
        BOOST_CHECK(tcp6->getTotalPackets() == 1);
        BOOST_CHECK(tcp6->getTotalBytes() == 35);
        BOOST_CHECK(tcp6->getTotalValidPackets() == 1);

	BOOST_CHECK(tcp6->getSourcePort() == 36951);
	BOOST_CHECK(tcp6->getDestinationPort() == 80);
	BOOST_CHECK(tcp6->isSyn() == false);
	BOOST_CHECK(tcp6->isAck() == true);
	BOOST_CHECK(tcp6->isFin() == false);
	BOOST_CHECK(tcp6->isRst() == false);
	BOOST_CHECK(tcp6->isPushSet() == true);

        BOOST_CHECK(r->getMatchs() == 1);
        BOOST_CHECK(r->getTotalEvaluates() == 1);

        BOOST_CHECK(gtcp6->getTotalPackets() == 1);
        BOOST_CHECK(gtcp6->getTotalBytes() == 15);
        BOOST_CHECK(gtcp6->getTotalValidPackets() == 1);

	Flow *flow = tcp6->getCurrentFlow();

	BOOST_CHECK( flow != nullptr);

	{
		RedirectOutput r;
        
		flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
	}

	BOOST_CHECK( flow->regex.lock() == r);
}

BOOST_AUTO_TEST_SUITE_END( )

