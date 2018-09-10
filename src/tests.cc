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

#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>
#include <string>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "PacketDispatcher.h"
#include "protocols/ethernet/EthernetProtocol.h"
#include "protocols/ip/IPProtocol.h"
#include "protocols/udp/UDPProtocol.h"
#include "protocols/tcp/TCPProtocol.h"
#include "protocols/ssl/SSLProtocol.h"
#include "protocols/http/HTTPProtocol.h"
#include "protocols/frequency/FrequencyGroup.h"
#include "learner/LearnerEngine.h"
#include "StackTest.h"
#include "StackLanTest.h"
#include "StackVirtual.h"
#include "StackOpenFlow.h"
#include "StackMobileIPv6.h"
#include "ipset/IPSet.h"
#include "ipset/IPRadixTree.h"
#include "ipset/IPBloomSet.h"
#include "EvidenceManager.h"
#include "System.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Main 
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_AUTO_TEST_SUITE (test_suite_1) 

BOOST_AUTO_TEST_CASE (test01)
{
	auto m1 = MultiplexerPtr(new Multiplexer());
	auto m2 = MultiplexerPtr(new Multiplexer());
	auto m3 = MultiplexerPtr(new Multiplexer());
	auto m4 = MultiplexerPtr(new Multiplexer());
	auto fw = SharedPointer<FlowForwarder>(new FlowForwarder());
	auto flow = SharedPointer<Flow>(new Flow());
	Packet pkt;

	flow->forwarder = fw;
	fw->forwardFlow(flow.get());

	auto value = m1->acceptPacket(pkt);

	BOOST_CHECK(m1->getNumberUpMultiplexers() == 0);
	BOOST_CHECK(m2->getNumberUpMultiplexers() == 0);
	BOOST_CHECK(m3->getNumberUpMultiplexers() == 0);
	BOOST_CHECK(m4->getNumberUpMultiplexers() == 0);

	BOOST_CHECK(m1->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m2->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m3->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m4->getDownMultiplexer().use_count() == 0);

	m1->addDownMultiplexer(m2);
	m1->addUpMultiplexer(m3, 1);	
	m1->addUpMultiplexer(m4, 2);	
	BOOST_CHECK(m1->getNumberUpMultiplexers() == 2);

	MultiplexerPtrWeak m5 = m1->getUpMultiplexer(1);
	BOOST_CHECK(m5.lock() == m3);

	m5 = m1->getUpMultiplexer(2);
	BOOST_CHECK(m5.lock() == m4);

	m5 = m1->getDownMultiplexer();
	BOOST_CHECK(m5.lock() == m2);
}

BOOST_AUTO_TEST_CASE (test02)
{
        auto m1 = MultiplexerPtr(new Multiplexer());
        auto m2 = MultiplexerPtr(new Multiplexer());
        auto m3 = MultiplexerPtr(new Multiplexer());
        auto m4 = MultiplexerPtr(new Multiplexer());

        m1->addUpMultiplexer(m2, 2);
        m2->addDownMultiplexer(m1);

        m2->addUpMultiplexer(m3, 3);
        m3->addDownMultiplexer(m2);

        m3->addUpMultiplexer(m4, 4);
        m4->addDownMultiplexer(m3);

        BOOST_CHECK(m1->getNumberUpMultiplexers() == 1);
        BOOST_CHECK(m2->getNumberUpMultiplexers() == 1);
        BOOST_CHECK(m3->getNumberUpMultiplexers() == 1);
        BOOST_CHECK(m4->getNumberUpMultiplexers() == 0);

        // Now check the position of the mux
        MultiplexerPtrWeak w_mux;

        // check positions from m1
        w_mux = m1->getUpMultiplexer(2);
        BOOST_CHECK(w_mux.lock() == m2);

        w_mux = m1->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m1->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == nullptr);

        // check positions from m2
        w_mux = m2->getUpMultiplexer(1);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m2->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == m3);

        w_mux = m2->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == nullptr);

        // check positions from m3
        w_mux = m3->getUpMultiplexer(2);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m3->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m3->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == m4);
}

BOOST_AUTO_TEST_CASE (test03)
{
	auto pd = PacketDispatcherPtr(new PacketDispatcher());

	pd->open("../pcapfiles/4udppackets.pcap");
	pd->status();
	pd->run();
	pd->close();

	// The packet dispatcher should process the packets without any stack 
	BOOST_CHECK(pd->getTotalPackets() == 4);
	BOOST_CHECK(pd->getTotalBytes() == 655);
}

BOOST_AUTO_TEST_CASE(test04)
{
	auto *eth = new EthernetProtocol();
	auto mux = MultiplexerPtr(new Multiplexer());
	auto pd = PacketDispatcherPtr(new PacketDispatcher());

	if (getuid() == 0) {
#if defined(__FREEBSD__) || defined(__OPENBSD__)
		pd->open("lo0");
#else	
		pd->open("lo");
#endif
		pd->close();
	}
	eth->setMultiplexer(mux);	

	delete eth;
}

BOOST_FIXTURE_TEST_CASE(test05, StackLanTest)
{
	auto pd = PacketDispatcherPtr(new PacketDispatcher());

	// connect with the stack
	pd->setDefaultMultiplexer(mux_eth);

	pd->open("../pcapfiles/4udppackets.pcap");
	pd->run();
	pd->close();

	BOOST_CHECK(pd->getTotalPackets() == 4);
	BOOST_CHECK(ip->getTotalValidPackets() == 4);
	BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 4);
	BOOST_CHECK(udp->getTotalPackets() == 4);
	BOOST_CHECK(udp->getTotalValidPackets() == 4);
	BOOST_CHECK(udp->getTotalInvalidPackets() == 0);
	BOOST_CHECK(tcp->getTotalPackets() == 0);
	BOOST_CHECK(tcp->getTotalValidPackets() == 0);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

	BOOST_CHECK(eth->getTotalBytes() == 655);
	BOOST_CHECK(ip->getTotalBytes() == 599); 
	BOOST_CHECK(udp->getTotalBytes() == 66 + 66 + 102 + 285); 
	BOOST_CHECK(tcp->getTotalBytes() == 0); 
}

BOOST_FIXTURE_TEST_CASE(test06, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/sslflow.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(pd->getTotalPackets() == 95);
        BOOST_CHECK(ip->getTotalValidPackets() == 95);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 95);
        BOOST_CHECK(udp->getTotalPackets() == 0);
        BOOST_CHECK(udp->getTotalValidPackets() == 0);
        BOOST_CHECK(udp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp->getTotalPackets() == 95);
        BOOST_CHECK(tcp->getTotalValidPackets() == 95);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);
}

BOOST_FIXTURE_TEST_CASE(test07, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
	auto flowmgr = FlowManagerPtr(new FlowManager());
	auto flowcache1 = FlowCachePtr(new FlowCache());
	auto flowcache2 = FlowCachePtr(new FlowCache());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	// Connect the flow manager and flow cache to their corresponding analyzer
	udp->setFlowManager(flowmgr);
	udp->setFlowCache(flowcache1);

        pd->open("../pcapfiles/4udppackets.pcap");
        pd->run();
        pd->close();
	
	//Checkers
        BOOST_CHECK(flowcache1->getTotalFlows() == 0);

	BOOST_CHECK(flowcache1->getTotalAcquires() == 0);
        BOOST_CHECK(flowcache1->getTotalReleases() == 0);
        BOOST_CHECK(flowcache1->getTotalFails() == 4);
	BOOST_CHECK(flowmgr->getTotalFlows() == 0);

	// One flow on the cache
	flowcache2->createFlows(1);
	udp->setFlowCache(flowcache2);

        pd->open("../pcapfiles/4udppackets.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(flowcache2->getTotalFlows() == 0);
        BOOST_CHECK(flowcache2->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache2->getTotalReleases() == 0);
        BOOST_CHECK(flowcache2->getTotalFails() == 0);
	BOOST_CHECK(flowmgr->getTotalFlows() == 1);

	// Add one flow on the cache
	flowcache2->createFlows(1);
	tcp->setFlowCache(flowcache2);
	tcp->setFlowManager(flowmgr);

        pd->open("../pcapfiles/sslflow.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(flowcache2->getTotalFlows() == 0);
        BOOST_CHECK(flowcache2->getTotalAcquires() == 2);
        BOOST_CHECK(flowcache2->getTotalReleases() == 0);
        BOOST_CHECK(flowcache2->getTotalFails() == 0);
        BOOST_CHECK(flowmgr->getTotalFlows() == 1);
}

BOOST_FIXTURE_TEST_CASE(test08, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto flowmgr = FlowManagerPtr(new FlowManager());
        auto flowcache = FlowCachePtr(new FlowCache());
	auto ff_tcp_aux = SharedPointer<FlowForwarder>(new FlowForwarder());	
	auto ff_ssl_aux = SharedPointer<FlowForwarder>(new FlowForwarder());	
	auto ssl_aux = SSLProtocolPtr(new SSLProtocol());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        flowcache->createFlows(1);
        tcp->setFlowCache(flowcache);
        tcp->setFlowManager(flowmgr);

	// configure the flow forwarder
	tcp->setFlowForwarder(ff_tcp_aux);
	ff_tcp_aux->setProtocol(static_cast<ProtocolPtr>(tcp));
	ff_tcp_aux->addUpFlowForwarder(ff_ssl_aux);

	ssl_aux->setFlowForwarder(ff_ssl_aux);
	ff_ssl_aux->setProtocol(static_cast<ProtocolPtr>(ssl_aux));
	
	//connect the ssl protocol on top of tcp
	ff_tcp_aux->addUpFlowForwarder(ff_ssl_aux);

	ff_ssl_aux->addChecker(std::bind(&SSLProtocol::sslChecker, ssl_aux, std::placeholders::_1));
        ff_ssl_aux->addFlowFunction(std::bind(&SSLProtocol::processFlow, ssl_aux, std::placeholders::_1));

	ssl_aux->increaseAllocatedMemory(4);

        pd->open("../pcapfiles/sslflow.pcap");
        pd->run();
        pd->close();

        //Checkers
        BOOST_CHECK(flowcache->getTotalFlows() == 0);
        BOOST_CHECK(flowcache->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache->getTotalReleases() == 0);
        BOOST_CHECK(flowcache->getTotalFails() == 0);
        BOOST_CHECK(flowmgr->getTotalFlows() == 1);

	//Checkers of the forwarders
	BOOST_CHECK(ff_tcp_aux->getTotalForwardFlows() == 1);
	BOOST_CHECK(ff_tcp_aux->getTotalReceivedFlows() == 56); // just 56 packets with payload;
	BOOST_CHECK(ff_tcp_aux->getTotalFailFlows() == 0);

	// Verify the SSLProtocol values
	BOOST_CHECK(ssl_aux->getTotalBytes() == 41821);
	BOOST_CHECK(ssl_aux->getTotalRecords() == 4);
	BOOST_CHECK(ssl_aux->getTotalClientHellos() == 1);
	BOOST_CHECK(ssl_aux->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl_aux->getTotalCertificates() == 1);
}

BOOST_FIXTURE_TEST_CASE(test09, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto ff_tcp_aux = SharedPointer<FlowForwarder>(new FlowForwarder());
        auto ff_ssl_aux = SharedPointer<FlowForwarder>(new FlowForwarder());
        auto ff_http_aux = SharedPointer<FlowForwarder>(new FlowForwarder());
        auto http_aux = HTTPProtocolPtr(new HTTPProtocol());
        auto ssl_aux = SSLProtocolPtr(new SSLProtocol());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        // configure the flow forwarder
        tcp->setFlowForwarder(ff_tcp_aux);
        ff_tcp_aux->setProtocol(static_cast<ProtocolPtr>(tcp));

        ssl_aux->setFlowForwarder(ff_ssl_aux);
        ff_ssl_aux->setProtocol(static_cast<ProtocolPtr>(ssl_aux));

        //connect the ssl protocol on top of tcp
        ff_tcp_aux->addUpFlowForwarder(ff_ssl_aux);
        ff_ssl_aux->addChecker(std::bind(&SSLProtocol::sslChecker, ssl_aux, std::placeholders::_1));
        ff_ssl_aux->addFlowFunction(std::bind(&SSLProtocol::processFlow, ssl_aux, std::placeholders::_1));

        http_aux->setFlowForwarder(ff_http_aux);
        ff_http_aux->setProtocol(static_cast<ProtocolPtr>(http_aux));

        //connect the http protocol on top of tcp
        ff_tcp_aux->addUpFlowForwarder(ff_http_aux);
        ff_http_aux->addChecker(std::bind(&HTTPProtocol::httpChecker, http_aux, std::placeholders::_1));
        ff_http_aux->addFlowFunction(std::bind(&HTTPProtocol::processFlow, http_aux, std::placeholders::_1));

        pd->open("../pcapfiles/accessgoogle.pcap");
        pd->run();
        pd->close();

        //Checkers of the forwarders
        BOOST_CHECK(ff_tcp_aux->getTotalForwardFlows() == 1);
        BOOST_CHECK(ff_tcp_aux->getTotalReceivedFlows() == 4); // just 56 packets with payload;
        BOOST_CHECK(ff_tcp_aux->getTotalFailFlows() == 0);

	// Verify the UDP part
	BOOST_CHECK(udp->getTotalPackets() == 4);
	BOOST_CHECK(udp->getTotalValidPackets() == 4);
	BOOST_CHECK(udp->getTotalBytes() == 40 + 40 + 136 + 68);

	BOOST_CHECK(mux_udp->getTotalReceivedPackets() == 4);
	BOOST_CHECK(mux_udp->getTotalForwardPackets() == 0);// nothing on top of UDP
	BOOST_CHECK(mux_udp->getTotalFailPackets() == 4);// nothing to forward

	// Verify the ICMP part
	BOOST_CHECK(icmp->getTotalPackets() == 0);
	BOOST_CHECK(icmp->getTotalValidPackets() == 0);

	BOOST_CHECK(mux_icmp->getTotalReceivedPackets() == 0);
	BOOST_CHECK(mux_icmp->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_icmp->getTotalFailPackets() == 0);

	// Verify the TCP part

	// verify the SSL Part
        BOOST_CHECK(ssl_aux->getTotalBytes() == 0);

	// verify the HTTP part
	BOOST_CHECK(http_aux->getTotalBytes() == 1826);
}

BOOST_FIXTURE_TEST_CASE(test10, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	this->enableLinkLayerTagging("vlan");

	// Enable VLan Tagging but packets dont have the VLAN tag

        pd->open("../pcapfiles/4udppackets.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(pd->getTotalPackets() == 4);
	BOOST_CHECK(mux_eth->getTotalForwardPackets() == 4);
	BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 4);
	BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);
	
	BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalReceivedPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalFailPackets() == 0);
        BOOST_CHECK(vlan->getTotalValidPackets() == 0);
        BOOST_CHECK(vlan->getTotalInvalidPackets() == 0);
        BOOST_CHECK(vlan->getTotalPackets() == 0);

        BOOST_CHECK(ip->getTotalValidPackets() == 4);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 4);

	// Now inject pcap with VLan Tagging and netbios
	// The trace contains 3 packets.
        
	pd->open("../pcapfiles/flow_vlan_netbios.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(pd->getTotalPackets() == 7);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 7);
        BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 7);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 3);
        BOOST_CHECK(mux_vlan->getTotalReceivedPackets() == 3);
        BOOST_CHECK(mux_vlan->getTotalFailPackets() == 0);
        BOOST_CHECK(vlan->getTotalValidPackets() == 3);
        BOOST_CHECK(vlan->getTotalInvalidPackets() == 0);
        BOOST_CHECK(vlan->getTotalPackets() == 3);

        BOOST_CHECK(ip->getTotalValidPackets() == 7);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 7);
}

BOOST_FIXTURE_TEST_CASE(test11, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        this->enableLinkLayerTagging("mpls");

        pd->open("../pcapfiles/mpls_icmp_tcp.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(pd->getTotalPackets() == 28);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 28);
        BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 28);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_mpls->getTotalForwardPackets() == 15);
        BOOST_CHECK(mux_mpls->getTotalReceivedPackets() == 15);
        BOOST_CHECK(mux_mpls->getTotalFailPackets() == 0);
        BOOST_CHECK(mpls->getTotalValidPackets() == 15);
        BOOST_CHECK(mpls->getTotalInvalidPackets() == 0);
        BOOST_CHECK(mpls->getTotalPackets() == 15);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 28);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 28);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);
        BOOST_CHECK(ip->getTotalValidPackets() == 28);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 28);

        BOOST_CHECK(mux_icmp->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_icmp->getTotalReceivedPackets() == 10);
        BOOST_CHECK(mux_icmp->getTotalFailPackets() == 10);
        BOOST_CHECK(icmp->getTotalValidPackets() == 10);
        BOOST_CHECK(icmp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(icmp->getTotalPackets() == 0);
}

BOOST_FIXTURE_TEST_CASE(test12, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/ipv6_tcp_stream.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(pd->getTotalPackets() == 13);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 13);
        BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 13);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_ip6->getTotalForwardPackets() == 13);
        BOOST_CHECK(mux_ip6->getTotalReceivedPackets() == 13);
        BOOST_CHECK(mux_ip6->getTotalFailPackets() == 0);

        BOOST_CHECK(ip6->getTotalValidPackets() == 13);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalPackets() == 13);

        BOOST_CHECK(tcp6->getTotalValidPackets() == 13);
        BOOST_CHECK(tcp6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp6->getTotalPackets() == 13);

        BOOST_CHECK(tcp_generic6->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp_generic6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp_generic6->getTotalPackets() == 4);
        BOOST_CHECK(tcp_generic6->getTotalBytes() == 213);
}

// test a chaining regex with one flow that matchs on the first and
// on the last packet
BOOST_FIXTURE_TEST_CASE(test13, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_head = SharedPointer<Regex>(new Regex("r1", "^(its peanut).*$"));
        auto r_tail = SharedPointer<Regex>(new Regex("r2", "^(invalid command).*$"));

        r_head->setNextRegex(r_tail);

        rm->addRegex(r_head);

        tcp_generic6->setRegexManager(rm);
        tcp6->setRegexManager(rm);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/ipv6_tcp_stream.pcap");
        pd->run();
        pd->close();

	// Check pcap file for see the results
	BOOST_CHECK(r_head->getMatchs() == 1);
	BOOST_CHECK(r_head->getTotalEvaluates() == 1);

	BOOST_CHECK(r_tail->getMatchs() == 1);
	BOOST_CHECK(r_tail->getTotalEvaluates() == 3);
        
	tcp_generic6->setRegexManager(nullptr);
	tcp6->setRegexManager(nullptr);
}

// Test with a generic ipv6 exploit
BOOST_FIXTURE_TEST_CASE(test14, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("generic exploit", "^.*\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90.*$"));

        rm->addRegex(r_generic);

        tcp_generic6->setRegexManager(rm);
        tcp6->setRegexManager(rm);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        pd->run();
        pd->close();

        // Check pcap file for see the results
        BOOST_CHECK(r_generic->getMatchs() == 1);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

	BOOST_CHECK(tcp6->getTotalPackets() == 86);
	BOOST_CHECK(tcp6->getTotalBytes() == 68823);
	BOOST_CHECK(tcp6->getTotalValidPackets() == 86);
	BOOST_CHECK(tcp6->getTotalInvalidPackets() == 0);

	BOOST_CHECK(flow_table_tcp->getTotalFlows() == 0); // The flow is on the cache

	BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 1);
	BOOST_CHECK(flow_cache_tcp->getTotalAcquires() == 1);
	BOOST_CHECK(flow_cache_tcp->getTotalFails() == 0);

        BOOST_CHECK(tcp_generic6->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp_generic6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp_generic6->getTotalPackets() == 49);
        BOOST_CHECK(tcp_generic6->getTotalBytes() == 66067);
}

// A true negative test 
BOOST_FIXTURE_TEST_CASE(test15, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("generic exploit", "^.*\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90.*$"));

        rm->addRegex(r_generic);

        tcp_generic->setRegexManager(rm);
        tcp->setRegexManager(rm);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/polymorphic_clet32bits_port1986.pcap");
        pd->run();
        pd->close();

        // Check pcap file for see the results
        BOOST_CHECK(r_generic->getMatchs() == 0);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

        BOOST_CHECK(tcp->getTotalPackets() == 8);
        BOOST_CHECK(tcp->getTotalBytes() == 620);
        BOOST_CHECK(tcp->getTotalValidPackets() == 8);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

       	BOOST_CHECK(tcp_generic->getTotalBytes() == 348);
        BOOST_CHECK(tcp_generic->getTotalPackets() == 1);
}

// Test dual stack 
// use the same TCPGenericProtocol for IPv4 and IPv6
BOOST_FIXTURE_TEST_CASE(test16, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("generic exploit", "^.*\\x90\\x90\\x90\\x90.*$"));

        ff_tcp->removeUpFlowForwarder(ff_tcp_generic6);
        ff_tcp6->removeUpFlowForwarder(ff_tcp_generic6);
        ff_tcp6->addUpFlowForwarder(ff_tcp_generic);

        rm->addRegex(r_generic);
        tcp_generic->setRegexManager(rm);
        tcp->setRegexManager(rm);
        tcp6->setRegexManager(rm);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        pd->run();
        pd->close();

        // Check pcap file for see the results
        BOOST_CHECK(r_generic->getMatchs() == 1);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

        BOOST_CHECK(tcp->getTotalPackets() == 0);
        BOOST_CHECK(tcp->getTotalBytes() == 0);
        BOOST_CHECK(tcp->getTotalValidPackets() == 0);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp6->getTotalPackets() == 86);
        BOOST_CHECK(tcp6->getTotalBytes() == 68823);
        BOOST_CHECK(tcp6->getTotalValidPackets() == 86);
        BOOST_CHECK(tcp6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache_tcp->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache_tcp->getTotalFails() == 0);

        BOOST_CHECK(tcp_generic->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp_generic->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp_generic->getTotalPackets() == 49);
        BOOST_CHECK(tcp_generic->getTotalBytes() == 66067);

	// Inject IPv4 pcap file
	// polymorphic_clet32bits_port1986.pcap
        pd->open("../pcapfiles/polymorphic_clet32bits_port1986.pcap");
        pd->run();
        pd->close();

        // Check pcap file for see the results
        BOOST_CHECK(r_generic->getMatchs() == 1);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 2);

        BOOST_CHECK(tcp->getTotalPackets() == 8);
        BOOST_CHECK(tcp->getTotalBytes() == 620);
        BOOST_CHECK(tcp->getTotalValidPackets() == 8);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

        BOOST_CHECK(tcp6->getTotalPackets() == 86);
        BOOST_CHECK(tcp6->getTotalBytes() == 68823);
        BOOST_CHECK(tcp6->getTotalValidPackets() == 86);
        BOOST_CHECK(tcp6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache_tcp->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache_tcp->getTotalFails() == 0);

        BOOST_CHECK(tcp_generic->getTotalValidPackets() == 2);
        BOOST_CHECK(tcp_generic->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp_generic->getTotalPackets() == 49 + 1);
        BOOST_CHECK(tcp_generic->getTotalBytes() == 66067 + 348);
}

BOOST_FIXTURE_TEST_CASE(test17, StackLanTest) // Test a IPv6 flow with  authentication header
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/ipv6_ah.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(pd->getTotalPackets() == 10);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 10);
        BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 10);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(ip6->getTotalValidPackets() == 10);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ip6->getTotalPackets() == 10);
        BOOST_CHECK(ip6->getTotalBytes() == 947);
        
        BOOST_CHECK(tcp6->getTotalValidPackets() == 10);
        BOOST_CHECK(tcp6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp6->getTotalPackets() == 10);

        BOOST_CHECK(tcp_generic6->getTotalValidPackets() == 1);
        BOOST_CHECK(tcp_generic6->getTotalInvalidPackets() == 0);
        BOOST_CHECK(tcp_generic6->getTotalPackets() == 2);
        BOOST_CHECK(tcp_generic6->getTotalBytes() == 103);
}

BOOST_FIXTURE_TEST_CASE(test18, StackLanTest) // Tests timeouts with two different pcap files 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/accessgoogle.pcap");
        pd->run();
        pd->close();
	
	BOOST_CHECK(flow_table_udp->getTotalProcessFlows() == 1);
	BOOST_CHECK(flow_table_udp->getTotalFlows() == 1);
	BOOST_CHECK(flow_table_udp->getTotalTimeoutFlows() == 0);

	BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 1);
	BOOST_CHECK(flow_table_tcp->getTotalFlows() == 1);
	BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 0);

        pd->open("../pcapfiles/amazon_4ssl_flows.pcap");
        pd->run();
        pd->close();

	BOOST_CHECK(flow_table_udp->getTotalProcessFlows() == 1);
	BOOST_CHECK(flow_table_udp->getTotalFlows() == 1);

	// There is no timeout for udp because there is no udp traffic
	// on the second pcapfile
	BOOST_CHECK(flow_table_udp->getTotalTimeoutFlows() == 0);

	BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 5);
	BOOST_CHECK(flow_table_tcp->getTotalFlows() == 4);
	BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 1);
}

BOOST_FIXTURE_TEST_CASE(test19, StackLanTest) // Tests timeouts with two different pcap files, timeout of one year
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	flow_table_udp->setTimeout(60 * 60 * 24 * 365);
	flow_table_tcp->setTimeout(60 * 60 * 24 * 365);

        pd->open("../pcapfiles/accessgoogle.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(flow_table_udp->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_table_udp->getTotalFlows() == 1);
        BOOST_CHECK(flow_table_udp->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 1);
        BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 0);

        pd->open("../pcapfiles/amazon_4ssl_flows.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(flow_table_udp->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_table_udp->getTotalFlows() == 1);
        BOOST_CHECK(flow_table_udp->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 5);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 5);
        BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 0);
}

BOOST_FIXTURE_TEST_CASE(test20, StackLanTest) // Tests for release the caches
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	ssl->increaseAllocatedMemory(4);

        pd->open("../pcapfiles/amazon_4ssl_flows.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 4);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 4); 
        BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 0);

	releaseCaches();

	for (auto &f: flow_table_tcp->getFlowTable()) {
		BOOST_CHECK(f->getSSLInfo() == nullptr);
	}
	flow_table_tcp->flush();

	tcp->decreaseAllocatedMemory(1000);
	ssl->decreaseAllocatedMemory(4);
}

// Test Regex linked with a generic ipv6 exploit
BOOST_FIXTURE_TEST_CASE(test21, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r1 = SharedPointer<Regex>(new Regex("generic exploit1", "^(No hacker).*$"));
        auto r2 = SharedPointer<Regex>(new Regex("generic exploit2", "^(Upgrade Your Liquor Cabinet).*$"));
        auto r3 = SharedPointer<Regex>(new Regex("generic exploit3", "^\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90.*$"));
        auto r4 = SharedPointer<Regex>(new Regex("generic exploit4", "^(Upgrade Your Liquor Cabinet).*$"));

	r1->setNextRegex(r2);
	r2->setNextRegex(r3);
	r3->setNextRegex(r4);

        rm->addRegex(r1);

        tcp_generic6->setRegexManager(rm);
        tcp6->setRegexManager(rm);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        pd->run();
        pd->close();

        // Check the regex for results
        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);

        BOOST_CHECK(r2->getMatchs() == 1);
        BOOST_CHECK(r2->getTotalEvaluates() == 46);
        
	BOOST_CHECK(r3->getMatchs() == 1);
        BOOST_CHECK(r3->getTotalEvaluates() == 1);
        
	BOOST_CHECK(r4->getMatchs() == 1);
        BOOST_CHECK(r4->getTotalEvaluates() == 1);

	rm->resetStatistics();

        BOOST_CHECK(r1->getMatchs() == 0);
        BOOST_CHECK(r1->getTotalEvaluates() == 0);

        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 0);
        
	BOOST_CHECK(r3->getMatchs() == 0);
        BOOST_CHECK(r3->getTotalEvaluates() == 0);

	BOOST_CHECK(r4->getMatchs() == 0);
        BOOST_CHECK(r4->getTotalEvaluates() == 0);
}

BOOST_FIXTURE_TEST_CASE(test22, StackLanTest) // Tests for release the caches on SMTP
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        smtp->increaseAllocatedMemory(1);

        pd->open("../pcapfiles/smtp.pcap");
        pd->run();

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 1);
        BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 0);
      
	// there is only one flow	
	auto flow = *flow_table_tcp->getFlowTable().begin();
 
        BOOST_CHECK(flow->getSMTPInfo() != nullptr);
       	SharedPointer<SMTPInfo> info = flow->getSMTPInfo();
	BOOST_CHECK(info != nullptr);

	{
		RedirectOutput r;
	
		flow->serialize(r.cout);
		flow->showFlowInfo(r.cout);
		r.cout << *(info.get());
		flow_table_tcp->showFlows(10);
		flow_table_tcp->showFlows(-1);
		flow_table_tcp->showFlows("smtp");
		flow_table_tcp->showFlows("SMTPProtocol", 10);
	}

	// Verify some information about the SMTPInfo object
	BOOST_CHECK(info->getTotalDataBytes() >= 20389);
	BOOST_CHECK(info->getTotalDataBlocks() == 1);
	BOOST_CHECK(info->isData() == false);
 
        BOOST_CHECK(flow->getHTTPInfo() == nullptr);
        BOOST_CHECK(flow->getSSLInfo() == nullptr);

        releaseCaches();

	smtp->decreaseAllocatedMemory(1);

        BOOST_CHECK(flow->layer7info == nullptr);
	
	// close the dispatcher here
        pd->close();
}

BOOST_FIXTURE_TEST_CASE(test23, StackLanTest) // Tests for release the caches and with ssl traffic 
{
	// The pcap contains 4 ssl flows with the same cert name
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        ssl->increaseAllocatedMemory(4);

        pd->open("../pcapfiles/amazon_4ssl_flows.pcap");
        pd->setPcapFilter("port 57077");
        pd->run();
        pd->close();

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 1);
        BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 0);

        // there is only one flow
        auto flow = *flow_table_tcp->getFlowTable().begin();
	SharedPointer<SSLInfo> info = flow->getSSLInfo();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);
	SharedPointer<StringCache> str = info->host_name;

	std::string cnname("images-na.ssl-images-amazon.com");
	BOOST_CHECK(cnname.compare(str->getName()) == 0);

	{
		RedirectOutput r;

		r.cout << *(info.get());
	}

	JsonFlow j;
	info->serialize(j);

#if defined(__FREEBSD__)
        std::ostringstream stream;

        stream << j.j["info"]["host"];
	std::string jvalue(stream.str());

	BOOST_CHECK (jvalue.compare(1, jvalue.length() - 2, cnname) == 0);
#else
	BOOST_CHECK (cnname.compare(j.j["info"]["host"]) == 0);
#endif
        releaseCaches();

        BOOST_CHECK(flow->getSSLInfo() == nullptr);
	// The str should be empty
	BOOST_CHECK(str->getNameSize() == 0);

	// Inject two flows 	
        pd->open("../pcapfiles/amazon_4ssl_flows.pcap");
        pd->setPcapFilter("port 57078 or port 57079");
	pd->run();
	pd->close();

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 3);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 3);
        BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 0);

        flow = *flow_table_tcp->getFlowTable().begin();
	BOOST_CHECK(flow->getSSLInfo() == nullptr);

	// Both flows points to ptr and now ptr contains the name
	BOOST_CHECK(cnname.compare(str->getName()) == 0);
	int process_flows = 0;
	for (auto &ff: flow_table_tcp->getFlowTable()) {
		if (ff != flow) { 
			BOOST_CHECK(ff->getSSLInfo() != nullptr);
			BOOST_CHECK(ff->getSSLInfo()->host_name != nullptr);
			BOOST_CHECK(ff->getSSLInfo()->host_name == str);
			BOOST_CHECK(cnname.compare(str->getName()) == 0);
			++process_flows;
		}
	}	
	BOOST_CHECK(process_flows == 2);
        
	releaseCaches();
	
	for (auto &ff: flow_table_tcp->getFlowTable()) {
		BOOST_CHECK(ff->getSSLInfo() == nullptr);
	}
	BOOST_CHECK(str->getNameSize() == 0);
       
	// Inject the last flow 
	pd->open("../pcapfiles/amazon_4ssl_flows.pcap");
        pd->setPcapFilter("port 57080");
	pd->run();
	pd->close();

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 4);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 4);
        BOOST_CHECK(flow_table_tcp->getTotalTimeoutFlows() == 0);

	BOOST_CHECK(cnname.compare(str->getName()) == 0);

	for (auto &ff: flow_table_tcp->getFlowTable()) {
		if (ff->getSourcePort() == 57080) { 
			BOOST_CHECK(ff->getSSLInfo() != nullptr);
			BOOST_CHECK(ff->getSSLInfo()->host_name != nullptr);
			BOOST_CHECK(ff->getSSLInfo()->host_name == str);
			BOOST_CHECK(cnname.compare(str->getName()) == 0);
		} else {
			BOOST_CHECK(ff->getSSLInfo() == nullptr);
		}
	}	
	flow_table_tcp->flush();
}

// Test the dynamic allocation
BOOST_FIXTURE_TEST_CASE(test24, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
	auto flowmgr = FlowManagerPtr(new FlowManager());
	auto flowcache1 = FlowCachePtr(new FlowCache());
	auto flowcache2 = FlowCachePtr(new FlowCache());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	// make dynamic allocation for both caches
	flowcache1->setDynamicAllocatedMemory(true);
	flowcache2->setDynamicAllocatedMemory(true);

	// Connect the flow manager and flow cache to their corresponding analyzer
	udp->setFlowManager(flowmgr);
	udp->setFlowCache(flowcache1);

	pd->open("../pcapfiles/4udppackets.pcap");
        pd->run();
        pd->close();
	
	//Checkers
        BOOST_CHECK(flowcache1->getTotalFlows() == 0);

	// The flows are created dynamically
	BOOST_CHECK(flowcache1->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache1->getTotalReleases() == 0);
        BOOST_CHECK(flowcache1->getTotalFails() == 0);
	BOOST_CHECK(flowmgr->getTotalFlows() == 1);

	// One flow on the cache
	flowcache2->createFlows(1);
	udp->setFlowCache(flowcache2);

        pd->open("../pcapfiles/4udppackets.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(flowcache2->getTotalFlows() == 1);
        BOOST_CHECK(flowcache2->getTotalAcquires() == 0);
        BOOST_CHECK(flowcache2->getTotalReleases() == 0);
        BOOST_CHECK(flowcache2->getTotalFails() == 0);
	BOOST_CHECK(flowmgr->getTotalFlows() == 1);

	// Add one flow on the cache
	flowcache2->createFlows(1);
	tcp->setFlowCache(flowcache2);
	tcp->setFlowManager(flowmgr);

        pd->open("../pcapfiles/sslflow.pcap");
        pd->run();
        pd->close();

        //Checkers
        BOOST_CHECK(flowcache2->getTotalFlows() == 1);
        BOOST_CHECK(flowcache2->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache2->getTotalReleases() == 0);
        BOOST_CHECK(flowcache2->getTotalFails() == 0);
        BOOST_CHECK(flowmgr->getTotalFlows() == 1);
}

// Test the system running out of memory std::bad_alloc on caches 
BOOST_FIXTURE_TEST_CASE(test25, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
	auto flowmgr = FlowManagerPtr(new FlowManager());
	auto flowcache_tcp = FlowCachePtr(new FlowCache());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	// make dynamic allocation for both caches
	flowcache_tcp->setDynamicAllocatedMemory(true);

        // This flag will generate a exception on the allocations check Cache_Imp.h
	flowcache_tcp->setGenerateBadAllocException(true);

	flowcache_tcp->createFlows(1);

	// Nothing can be created
	BOOST_CHECK(flowcache_tcp->getAllocatedMemory() == 0); // No memory available
        BOOST_CHECK(flowcache_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalAcquires() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalReleases() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalFails() == 0);
	// check values

	tcp->setFlowCache(flowcache_tcp);
	tcp->setFlowManager(flowmgr);

        pd->open("../pcapfiles/sslflow.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(flowcache_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalAcquires() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalReleases() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalFails() == 95); // Trying get memory :D
}

// Test the smtp with ssl 
BOOST_FIXTURE_TEST_CASE(test26, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
	auto flowmgr = FlowManagerPtr(new FlowManager());
	auto flowcache_tcp = FlowCachePtr(new FlowCache());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	// make dynamic allocation 
	flowcache_tcp->setDynamicAllocatedMemory(true);
	tcp->setDynamicAllocatedMemory(true);
	smtp->setDynamicAllocatedMemory(true);
	ssl->setDynamicAllocatedMemory(true);

	tcp->setFlowCache(flowcache_tcp);
	tcp->setFlowManager(flowmgr);

	// This pcap contains just one network flow
	// we inject the first 10 packets
	pd->setMaxPackets(9); 
        pd->open("../pcapfiles/smtp_starttls.pcap");
        pd->run();

        BOOST_CHECK(flowcache_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache_tcp->getTotalReleases() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalFails() == 0); 

	// Check the SMTPProtocol
	BOOST_CHECK(smtp->getTotalClientCommands() == 2);
	BOOST_CHECK(smtp->getTotalServerResponses() == 2);

	// Check the SSLProtocol
	BOOST_CHECK(ssl->getTotalHandshakes() == 0);
	BOOST_CHECK(ssl->getTotalAlerts() == 0);
	BOOST_CHECK(ssl->getTotalDatas() == 0); 
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 0);
	BOOST_CHECK(ssl->getTotalCertificates() == 0);

	// Check the flow
	Flow *flow = tcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getSMTPInfo() != nullptr);
	BOOST_CHECK(flow->getSSLInfo() == nullptr);

	auto info = flow->getSMTPInfo();
        
	BOOST_CHECK(info->isStartTLS() == true);

	JsonFlow j;
        info->serialize(j);

	// Inject the rest of the trace
	pd->setMaxPackets(20);
	pd->run();
	
	// Check the SMTPProtocol
	BOOST_CHECK(smtp->getTotalClientCommands() == 2);
	BOOST_CHECK(smtp->getTotalServerResponses() == 3);

	// Check the SSLProtocol
	BOOST_CHECK(ssl->getTotalHandshakes() == 3);
	BOOST_CHECK(ssl->getTotalAlerts() == 0);
	BOOST_CHECK(ssl->getTotalDatas() == 3); 
	BOOST_CHECK(ssl->getTotalClientHellos() == 1);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);

	// Check the Flow, now changes a ssl
	flow = tcp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getSMTPInfo() == nullptr);
	BOOST_CHECK(flow->getSSLInfo() != nullptr);
        
	pd->close();
}

// Test the imap with ssl 
BOOST_FIXTURE_TEST_CASE(test27, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto flowmgr = FlowManagerPtr(new FlowManager());
        auto flowcache_tcp = FlowCachePtr(new FlowCache());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        // make dynamic allocation 
        flowcache_tcp->setDynamicAllocatedMemory(true);
        tcp->setDynamicAllocatedMemory(true);
        imap->setDynamicAllocatedMemory(true);
        ssl->setDynamicAllocatedMemory(true);

        tcp->setFlowCache(flowcache_tcp);
        tcp->setFlowManager(flowmgr);

        // This pcap contains just one network flow
        // we inject the first 10 packets
        pd->setMaxPackets(10);
        pd->open("../pcapfiles/imap_starttls.pcap");
        pd->run();

        BOOST_CHECK(flowcache_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache_tcp->getTotalReleases() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalFails() == 0);

        // Check the IMAPProtocol
        BOOST_CHECK(imap->getTotalClientCommands() == 2);
        BOOST_CHECK(imap->getTotalServerResponses() == 2);

        // Check the SSLProtocol
        BOOST_CHECK(ssl->getTotalHandshakes() == 0);
        BOOST_CHECK(ssl->getTotalAlerts() == 0);
        BOOST_CHECK(ssl->getTotalDatas() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);

        // Check the flow
        Flow *flow = tcp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->getIMAPInfo() != nullptr);
        BOOST_CHECK(flow->getSSLInfo() == nullptr);

	auto info = flow->getIMAPInfo();

	BOOST_CHECK(info->isStartTLS() == true);

	JsonFlow j;
        info->serialize(j);

        // Inject just before finish the network flow
        pd->setMaxPackets(30);
        pd->run();

	// recheck the values
        BOOST_CHECK(flowcache_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache_tcp->getTotalReleases() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalFails() == 0);

        // Check the IMAPProtocol
        BOOST_CHECK(imap->getTotalClientCommands() == 2);
        BOOST_CHECK(imap->getTotalServerResponses() == 3);

        // Check the SSLProtocol
        BOOST_CHECK(ssl->getTotalHandshakes() == 3);
        BOOST_CHECK(ssl->getTotalAlerts() == 2);
        BOOST_CHECK(ssl->getTotalDatas() == 2);
        BOOST_CHECK(ssl->getTotalClientHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);

        // ReCheck the flow
        flow = tcp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->getIMAPInfo() == nullptr);
        BOOST_CHECK(flow->getSSLInfo() != nullptr);

	pd->close();
}

// Test the pop with ssl 
BOOST_FIXTURE_TEST_CASE(test28, StackLanTest)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto flowmgr = FlowManagerPtr(new FlowManager());
        auto flowcache_tcp = FlowCachePtr(new FlowCache());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        // make dynamic allocation 
        flowcache_tcp->setDynamicAllocatedMemory(true);
        tcp->setDynamicAllocatedMemory(true);
        pop->setDynamicAllocatedMemory(true);
        ssl->setDynamicAllocatedMemory(true);

        tcp->setFlowCache(flowcache_tcp);
        tcp->setFlowManager(flowmgr);

        // This pcap contains just one network flow
        // we inject the first 7 packets
        pd->setMaxPackets(7);
        pd->open("../pcapfiles/pop3_starttls.pcap");
        pd->run();

        BOOST_CHECK(flowcache_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache_tcp->getTotalReleases() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalFails() == 0);

        // Check the IMAPProtocol
        BOOST_CHECK(pop->getTotalClientCommands() == 1);
        BOOST_CHECK(pop->getTotalServerResponses() == 1);

        // Check the SSLProtocol
        BOOST_CHECK(ssl->getTotalHandshakes() == 0);
        BOOST_CHECK(ssl->getTotalAlerts() == 0);
        BOOST_CHECK(ssl->getTotalDatas() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);

        // Check the flow
        Flow *flow = tcp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->getPOPInfo() != nullptr);
        BOOST_CHECK(flow->getSSLInfo() == nullptr);

	auto info = flow->getPOPInfo();

	BOOST_CHECK(info->isStartTLS() == true);

	JsonFlow j;
	info->serialize(j);

        // Inject just before finish the network flow
        pd->setMaxPackets(30);
        pd->run();

	// Recheck all the values again
        BOOST_CHECK(flowcache_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache_tcp->getTotalReleases() == 0);
        BOOST_CHECK(flowcache_tcp->getTotalFails() == 0);

        // Check the IMAPProtocol
        BOOST_CHECK(pop->getTotalClientCommands() == 1);
        BOOST_CHECK(pop->getTotalServerResponses() == 2);

        // Check the SSLProtocol
        BOOST_CHECK(ssl->getTotalHandshakes() == 8);
        BOOST_CHECK(ssl->getTotalAlerts() == 1);
        BOOST_CHECK(ssl->getTotalDatas() == 4);
        BOOST_CHECK(ssl->getTotalClientHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 2);

        // Check the flow
        flow = tcp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->getPOPInfo() == nullptr);
        BOOST_CHECK(flow->getSSLInfo() != nullptr);

	pd->close();
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE (test_suite_stack_lan) // Test cases for real stacks StackLan 

BOOST_AUTO_TEST_CASE (test01)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
	auto stack = StackLanPtr(new StackLan());

	stack->setTotalTCPFlows(2);
	stack->enableFrequencyEngine(true);
	pd->setStack(stack);
	pd->open("../pcapfiles/two_http_flows_noending.pcap");
        pd->run();
        pd->close();

	FrequencyGroup<std::string> group_by_ip;

       	group_by_ip.setName("by destination IP");
	group_by_ip.agregateFlowsByDestinationAddress(stack->getTCPFlowManager().lock());
	group_by_ip.compute();

	BOOST_CHECK(group_by_ip.getReferenceFlows().size() == 2);
	BOOST_CHECK(group_by_ip.getTotalProcessFlows() == 2);
	BOOST_CHECK(group_by_ip.getTotalComputedFrequencies() == 2);

        FrequencyGroup<std::string> group_by_port;

	auto fm = stack->getTCPFlowManager().lock();

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(fm);
        group_by_port.compute();

	BOOST_CHECK(group_by_port.getTotalProcessFlows() == 0);
	BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 0);

	// Check the relaseCache functionality with the frequencies

	for (auto &flow: fm->getFlowTable()) {
		BOOST_CHECK(flow->frequencies != nullptr);
		BOOST_CHECK(flow->packet_frequencies != nullptr);
	} 
	fm->flush();
	stack->releaseCaches();

	BOOST_CHECK(fm->getTotalFlows() == 0);

	{
		RedirectOutput r;

		fm->showFlows();
		stack->setStatisticsLevel(5);
		stack->statistics(r.cout);
	}
	group_by_ip.reset();
}

BOOST_AUTO_TEST_CASE (test02)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
	auto learner = LearnerEnginePtr(new LearnerEngine());

        stack->setTotalTCPFlows(2);
        stack->enableFrequencyEngine(true);

	BOOST_CHECK(stack->isEnableFrequencyEngine() == true);
	BOOST_CHECK(stack->isEnableNIDSEngine() == false);

	pd->setStack(stack);
        pd->open("../pcapfiles/two_http_flows_noending.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 2);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

	// pass the flows to the Learner engine
	learner->agregateFlows(group_by_port.getReferenceFlows());	
	learner->compute();
	std::string header("^\\x47\\x45\\x54\\x20\\x2f");// a GET on hexa
	std::string reg(learner->getRegularExpression());

	BOOST_CHECK(header.compare(0, header.length(), reg, 0, header.length())== 0);

	stack->enableFrequencyEngine(false);
}

BOOST_AUTO_TEST_CASE (test03)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto learner = LearnerEnginePtr(new LearnerEngine());
	std::vector<WeakPointer<Flow>> flow_list;

	BOOST_CHECK(stack->getFlowsTimeout() == 180);

        stack->setTotalTCPFlows(2);
        stack->enableFrequencyEngine(true);
        pd->setStack(stack);
        pd->open("../pcapfiles/two_http_flows_noending.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 2);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        flow_list = group_by_port.getReferenceFlowsByKey("1443");

        // The flow_list should contains zero entries
        BOOST_CHECK(flow_list.size() == 0);

	flow_list = group_by_port.getReferenceFlowsByKey("80");

	// The flow_list should contains two entries
        BOOST_CHECK(flow_list.size() == 2);

        // pass the flows to the Learner engine
        learner->agregateFlows(flow_list);
        learner->compute();
        std::string header("^\\x47\\x45\\x54\\x20\\x2f");// a GET on hexa
        std::string reg(learner->getRegularExpression());

        BOOST_CHECK(header.compare(0, header.length(), reg, 0, header.length())== 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto learner = LearnerEnginePtr(new LearnerEngine());
        std::vector<WeakPointer<Flow>> flow_list;

        stack->setTotalTCPFlows(4);
        stack->enableFrequencyEngine(true);
        pd->setStack(stack);
        pd->open("../pcapfiles/tor_4flows.pcap");
        pd->run();
        pd->close();
 
        FrequencyGroup<std::string> group_by_port;
 
        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 4);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        flow_list = group_by_port.getReferenceFlowsByKey("80");

        // The flow_list should contains two entries
        BOOST_CHECK(flow_list.size() == 4);
 
        // pass the flows to the Learner engine
        learner->agregateFlows(flow_list);
        learner->compute();
        std::string header("^\\x16\\x03\\x01\\x00\\xd1\\x01\\x00\\x00\\xcd\\x03\\x01\\x52\\xc1\\xd5\\x86\\xd0\\xd3\\x8f\\x87\\xb8\\xf1\\x6e\\x0f\\xe1\\x59\\xff");// a SSL header on hexa
        std::string reg(learner->getRegularExpression());
       
        BOOST_CHECK(header.compare(0, header.length(), reg, 0, header.length())== 0);

	{
		RedirectOutput r;
		
		group_by_port.setLogLevel(1);
		r.cout << group_by_port;
	}
}

BOOST_AUTO_TEST_CASE (test05) // integrate the learner and the FrequencyGroups 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto learner = LearnerEnginePtr(new LearnerEngine());
        std::vector<WeakPointer<Flow>> flow_list;

        stack->setTotalTCPFlows(2);
        stack->enableFrequencyEngine(true);
        pd->setStack(stack);
        pd->open("../pcapfiles/two_http_flows_noending.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group;

        group.setName("by destination port");
        group.agregateFlowsByDestinationAddressAndPort(stack->getTCPFlowManager().lock());
        group.compute();

        BOOST_CHECK(group.getTotalProcessFlows() == 2);
        BOOST_CHECK(group.getTotalComputedFrequencies() == 2);

	auto it = group.begin();

	BOOST_CHECK(it != group.end());

	FrequencyGroupItemPtr fg = it->second;
	
	flow_list = fg->getReferenceFlows();
        BOOST_CHECK(flow_list.size() == 1);
	
	std::string cad_group("95.100.96.10:80");
	BOOST_CHECK(cad_group.compare(it->first) == 0);

        // pass the flows to the Learner engine
	learner->reset();
        learner->agregateFlows(flow_list);
        learner->compute();
        std::string header("^\\x47\\x45\\x54\\x20\\x2f\\x42");// a GET on hexa
        std::string reg(learner->getRegularExpression());

        BOOST_CHECK(header.compare(0, header.length(), reg, 0, header.length())== 0);

	++it;

	cad_group = "95.100.96.48:80";

	BOOST_CHECK(it != group.end());
	BOOST_CHECK(cad_group.compare(it->first) == 0);
	fg = it->second;
	
	flow_list = fg->getReferenceFlows();
        BOOST_CHECK(flow_list.size() == 1);

        learner->reset();
        learner->agregateFlows(flow_list);
        learner->compute();

	header = "^\\x47\\x45\\x54\\x20\\x2f\\x63";
	reg = learner->getRegularExpression();
	std::string regascii = learner->getAsciiExpression();	

	{
		RedirectOutput r;
		r.cout << *learner.get();
		learner->statistics(r.cout);
	}

        BOOST_CHECK(header.compare(0, header.length(), reg, 0, header.length())== 0);
	++it;
	BOOST_CHECK(it == group.end());
}

// Check the file format support for pcapng files
BOOST_AUTO_TEST_CASE (test06)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());

        stack->setTotalTCPFlows(1);
        stack->setTotalUDPFlows(2);
        pd->setStack(stack);

        pd->open("../pcapfiles/icq.pcapng");
        pd->run();
        pd->close();

	{
		RedirectOutput r;

		pd->statistics();
 		pd->showCurrentPayloadPacket(); // Ok
	}

        pd->open("../pcapfiles/4udppackets.pcap");
        pd->run();
        pd->close();

	{
		RedirectOutput r;
		pd->statistics(r.cout);
 		pd->showCurrentPayloadPacket(r.cout); // ok
	}

	auto flows_tcp = stack->getTCPFlowManager().lock();
	auto flows_udp = stack->getUDPFlowManager().lock();

	BOOST_CHECK(flows_tcp->getTotalFlows() == 1);
	BOOST_CHECK(flows_udp->getTotalFlows() == 1);

	auto flow = *flows_tcp->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getProtocol() == IPPROTO_TCP);
	
	flow = *flows_udp->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getProtocol() == IPPROTO_UDP);
}

// Test the IPset functionality 
BOOST_AUTO_TEST_CASE (test07)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());
	auto ipset_tcp = SharedPointer<IPSet>(new IPSet("IPSet on TCP"));
	auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

	ipset_tcp->addIPAddress("69.64.34.124");
	ipset_tcp->addIPAddress("69.64.34.125");

	ipset_mng->addIPSet(ipset_tcp);

	stack->setTCPIPSetManager(ipset_mng);
        stack->setTotalTCPFlows(1);
        pd->setStack(stack);

        pd->open("../pcapfiles/icq.pcapng");
        pd->run();
        pd->close();

	BOOST_CHECK(ipset_tcp->getTotalIPs() == 2);
	BOOST_CHECK(ipset_tcp->getTotalLookups() == 1);
	BOOST_CHECK(ipset_tcp->getTotalLookupsIn() == 1);
	BOOST_CHECK(ipset_tcp->getTotalLookupsOut() == 0);

        auto flows_tcp = stack->getTCPFlowManager().lock();

        BOOST_CHECK(flows_tcp->getTotalFlows() == 1);
	auto flow = *flows_tcp->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->getProtocol() == IPPROTO_TCP);

	uint32_t ipsrc = flow->getSourceAddress();
	uint32_t ipdst = flow->getDestinationAddress();

	{
		RedirectOutput r;
        
		stack->showFlows(5);
        	stack->showFlows();
        	stack->showFlows("tcp");
		stack->statistics();
		stack->statistics(5);
	}
}

// Test the IPset functionality
BOOST_AUTO_TEST_CASE (test08)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto ipset_tcp = SharedPointer<IPSet>(new IPSet("IPSet 1"));
	auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

	ipset_mng->addIPSet(ipset_tcp);
        ipset_tcp->addIPAddress("69.64.34.1");

        stack->setTCPIPSetManager(ipset_mng);
        stack->setTotalTCPFlows(1);
        pd->setStack(stack);

        pd->open("../pcapfiles/icq.pcapng");
        pd->run();
        pd->close();

        BOOST_CHECK(ipset_tcp->getTotalIPs() == 1);
        BOOST_CHECK(ipset_tcp->getTotalLookups() == 1);
        BOOST_CHECK(ipset_tcp->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset_tcp->getTotalLookupsOut() == 1);
}

#ifdef HAVE_BLOOMFILTER 
// Test the IPBloomSet functionality
BOOST_AUTO_TEST_CASE (test09)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto ipset_tcp = SharedPointer<IPBloomSet>(new IPBloomSet("IPBloomSet 1"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

        ipset_mng->addIPSet(ipset_tcp);
        ipset_tcp->addIPAddress("69.64.34.1");

        stack->setTCPIPSetManager(ipset_mng);
        stack->setTotalTCPFlows(1);
        pd->setStack(stack);

        pd->open("../pcapfiles/icq.pcapng");
        pd->run();
        pd->close();

        BOOST_CHECK(ipset_tcp->getTotalIPs() == 1);
        BOOST_CHECK(ipset_tcp->getTotalLookups() == 1);
        BOOST_CHECK(ipset_tcp->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset_tcp->getTotalLookupsOut() == 1);
}

BOOST_AUTO_TEST_CASE (test10)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto ipset_tcp = SharedPointer<IPBloomSet>(new IPBloomSet("IPBloomSet 1"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

        ipset_mng->addIPSet(ipset_tcp);

	for (int i = 1 ; i < 255; ++i) {
		std::stringstream ipstr;
		
		ipstr << "74.12.3." << i;
        	ipset_tcp->addIPAddress(ipstr.str());
	}

        stack->setTCPIPSetManager(ipset_mng);
        stack->setTotalTCPFlows(1);
        pd->setStack(stack);

        pd->open("../pcapfiles/icq.pcapng");
        pd->run();
        pd->close();

        BOOST_CHECK(ipset_tcp->getTotalIPs() == 254);
        BOOST_CHECK(ipset_tcp->getTotalLookups() == 1);
        BOOST_CHECK(ipset_tcp->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset_tcp->getTotalLookupsOut() == 1);
}

#endif // 

BOOST_AUTO_TEST_CASE (test11)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto learner = LearnerEnginePtr(new LearnerEngine());
        std::vector<WeakPointer<Flow>> flow_list;

        stack->setTotalTCPFlows(4);
        stack->enableFrequencyEngine(true);
        pd->setStack(stack);
        pd->open("../pcapfiles/amazon_4ssl_flows.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 4);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        flow_list = group_by_port.getReferenceFlowsByKey("443");

        // The flow_list should contains four entries
        BOOST_CHECK(flow_list.size() == 4);

        // pass the flows to the Learner engine
        learner->agregateFlows(flow_list);
        learner->compute();

	std::string header("^\\x16\\x03\\x01\\x00\\xe1\\x01\\x00\\x00\\xdd\\x03\\x03\\x53\\x17\\xc4\\x30.{28}\\x00\\x00");
        std::string reg(learner->getRegularExpression());

        BOOST_CHECK(header.compare(0, header.length(), reg, 0, header.length())== 0);
}

// Test the statistics method by passing the protocol name
BOOST_AUTO_TEST_CASE (test12)
{
        auto stack = NetworkStackPtr(new StackLan());

	stack->setStatisticsLevel(1);

	{
		RedirectOutput r;

		stack->statistics("EthernetProtocol");
		stack->statistics("EthernetNoExiste");
	}
}

BOOST_AUTO_TEST_CASE (test13) // Test the UDP regex 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("Netbios", "^.*FACACA.*$"));

	r_generic->setEvidence(true);
        // connect with the stack
        pd->setStack(stack);

        stack->setTotalUDPFlows(2);
        stack->enableLinkLayerTagging("vlan");

	stack->enableNIDSEngine(true);

        rm->addRegex(r_generic);
        stack->setUDPRegexManager(rm);

        pd->setEvidences(true);
        pd->open("../pcapfiles/flow_vlan_netbios.pcap");
        pd->run();
        pd->close();

	{
		RedirectOutput r;

        	pd->showCurrentPayloadPacket(r.cout);
                stack->setStatisticsLevel(5);
                stack->statistics(r.cout);
          	pd->statistics(r.cout);
	}

	BOOST_CHECK(r_generic->getMatchs() == 1);
	BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

        stack->setUDPRegexManager(nullptr);

	auto fm = stack->getUDPFlowManager().lock();
	fm->flush();

        // Enabling a unknow linklayer tag
        stack->enableLinkLayerTagging("pepe");
        BOOST_CHECK(stack->getLinkLayerTagging() == "");

	// A new file has been generated for the evidences
	BOOST_CHECK(pd->getEvidences() == true);

	std::string filename(pd->getEvidencesFilename());
	BOOST_CHECK(boost::filesystem::exists(filename) == true);

	// Remove the file generated
	boost::filesystem::remove(filename);
}

// Test the release cache funcionality
BOOST_AUTO_TEST_CASE (test14)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());

	// For exercise the getters
	int tcpf = stack->getTotalTCPFlows();
	int udpf = stack->getTotalUDPFlows();

        stack->setTotalTCPFlows(2);
        stack->setTotalUDPFlows(2);
        pd->setStack(stack);

        pd->open("../pcapfiles/accessgoogle.pcap");
        pd->run();
        pd->close();

	auto flows_tcp = stack->getTCPFlowManager().lock();
        BOOST_CHECK(flows_tcp->getTotalFlows() == 1);
	auto flow = *flows_tcp->getFlowTable().begin();
	BOOST_CHECK(flow  != nullptr);
	SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
	BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->ua != nullptr);
        BOOST_CHECK(info->uri != nullptr);
      
	{ 
		RedirectOutput r;
	
		r.cout  << *info.get();
	} 

        auto flows_udp = stack->getUDPFlowManager().lock();
        BOOST_CHECK(flows_udp->getTotalFlows() == 1);
	flow = *flows_udp->getFlowTable().begin();
        BOOST_CHECK(flow->getDNSInfo() != nullptr);

	flows_tcp->flush();
	flows_udp->flush();

	stack->releaseCaches();

        BOOST_CHECK(flows_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flows_udp->getTotalFlows() == 0);
}

// Test the chain of regex with the RegexManager
// To understand the values of the test, open the smtp.pcap file
BOOST_AUTO_TEST_CASE (test15)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto rmbase = RegexManagerPtr(new RegexManager());
        auto rm1 = SharedPointer<RegexManager>(new RegexManager());
        auto rm2 = SharedPointer<RegexManager>(new RegexManager());

        auto r1 = SharedPointer<Regex>(new Regex("r1", "^\\x26\\x01"));
        auto r2 = SharedPointer<Regex>(new Regex("r2", "^\\x26\\x01"));
        auto r3 = SharedPointer<Regex>(new Regex("r3", "^AUTH"));

	r3->setNextRegexManager(rm1);
        rmbase->addRegex(r1);
        rmbase->addRegex(r2);
        rmbase->addRegex(r3);

        auto r4 = SharedPointer<Regex>(new Regex("r4", "^\\x26\\x01"));
        auto r5 = SharedPointer<Regex>(new Regex("r5", "^MAIL FROM"));

	rm1->addRegex(r4);
	rm1->addRegex(r5);

	r5->setNextRegexManager(rm2);

        auto r6 = SharedPointer<Regex>(new Regex("r6", "^250 OK"));
        auto r7 = SharedPointer<Regex>(new Regex("r7", "^QUIT"));

	r7->setEvidence(true);
	r6->setNextRegex(r7);

	rm2->addRegex(r6);	
	
        stack->setTCPRegexManager(rmbase);

        stack->setTotalTCPFlows(8);
        stack->setTotalUDPFlows(8);
        pd->setStack(stack);

	stack->enableNIDSEngine(true);

        pd->open("../pcapfiles/smtp.pcap");
        pd->run();
        pd->close();

	BOOST_CHECK(r1->getMatchs() == 0);
	BOOST_CHECK(r1->getTotalEvaluates() == 4);
	BOOST_CHECK(r2->getMatchs() == 0);
	BOOST_CHECK(r2->getTotalEvaluates() == 4);
	BOOST_CHECK(r3->getMatchs() == 1);
	BOOST_CHECK(r3->getTotalEvaluates() == 4);

	BOOST_CHECK(r4->getMatchs() == 0);
	BOOST_CHECK(r4->getTotalEvaluates() == 6);
	BOOST_CHECK(r5->getMatchs() == 1);
	BOOST_CHECK(r5->getTotalEvaluates() == 6);

	BOOST_CHECK(r6->getMatchs() == 1);
	BOOST_CHECK(r6->getTotalEvaluates() == 1);
	BOOST_CHECK(r7->getMatchs() == 1);
	BOOST_CHECK(r7->getTotalEvaluates() == 21);
	
        auto flows_tcp = stack->getTCPFlowManager().lock();
        BOOST_CHECK(flows_tcp->getTotalFlows() == 1);
	auto flow = *flows_tcp->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->regex.lock() == r7);
        BOOST_CHECK(flow->regex_mng == rm2);
        
	stack->enableNIDSEngine(false);
}

// Test the functionality of the SSDPProtocol
BOOST_AUTO_TEST_CASE (test16)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
	auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());

	stack->setDomainNameManager(dm, "ssdp");
	stack->setDynamicAllocatedMemory("SSDPProtocol", true);

        stack->setTotalUDPFlows(5);
        pd->setStack(stack);
        pd->open("../pcapfiles/ssdp_flow.pcap");
        pd->run();
        pd->close();

        auto fm = stack->getUDPFlowManager().lock();
        BOOST_CHECK(fm->getTotalFlows() == 1);

	auto flow = *fm->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);
	auto info = flow->getSSDPInfo();
	BOOST_CHECK(info != nullptr);

	{ 
		RedirectOutput r;
		
		flow->serialize(r.cout);
		r.cout << *(info.get());
	}	

        stack->releaseCaches();
	stack->setDomainNameManager(nullptr, "ssdp");

        BOOST_CHECK(flow->layer7info == nullptr);
}

BOOST_AUTO_TEST_CASE (test17)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());
	auto dm = DomainNameManagerPtr(new DomainNameManager());

        pd->setStack(stack);

	stack->setDomainNameManager(dm, "POPProtocol");
	stack->setDynamicAllocatedMemory("POPProtocol", true);
        stack->setTotalTCPFlows(10);
	stack->increaseAllocatedMemory("POPProtocol", 1);

        pd->open("../pcapfiles/pop_flow.pcap");
        pd->run();

	auto fm = stack->getTCPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();

	SharedPointer<POPInfo> info = flow->getPOPInfo();
	BOOST_CHECK(info != nullptr);

	{ 
		RedirectOutput r;
		flow->serialize(r.cout);
		r.cout << *(info.get());
       		flow->showFlowInfo(r.cout);
	}

	stack->releaseCaches();
        
	BOOST_CHECK(flow->layer7info == nullptr);

	stack->setDomainNameManager(nullptr, "POPProtocol");
	
	stack->decreaseAllocatedMemory("POPProtocol", 1);
       
	{
		RedirectOutput r;	
	
		// For exercise the statistics
       		stack->setStatisticsLevel(5);
       		stack->statistics();
      		stack->showFlows(10); 
      		stack->showFlows(); 
      		stack->showFlows("pop", 10); 
	}

	auto tup = stack->getCurrentFlows();
	pd->close();
}

BOOST_AUTO_TEST_CASE (test18)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());
	auto dom = DomainNameManagerPtr(new DomainNameManager());
	auto dom_old = DomainNameManagerPtr(new DomainNameManager("old manager"));
	auto d1 = DomainNamePtr(new DomainName("domain1", "localhost"));
	auto us = SharedPointer<HTTPUriSet>(new HTTPUriSet());

	us->addURI("/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time");
	d1->setHTTPUriSet(us);

	dom->addDomainName(d1);	

        pd->setStack(stack);

	stack->setDomainNameManager(dom, "CoAPProtocol");

	stack->setDynamicAllocatedMemory("CoAPProtocol", true);
	stack->setTotalUDPFlows(10);
	stack->increaseAllocatedMemory("CoAPProtocol", 10);

        pd->open("../pcapfiles/ipv4_coap_big_uri.pcap");
        pd->run();
	auto tup = stack->getCurrentFlows(); // Just for exercise the code
        pd->close();

	stack->setDomainNameManager(dom_old, "CoAPProtocol");

	auto fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();

	BOOST_CHECK(flow != nullptr);
	auto info = flow->getCoAPInfo();
	BOOST_CHECK(info != nullptr);

	{
		RedirectOutput r;

		flow->serialize(r.cout);
		r.cout << *info.get();
		flow->showFlowInfo(r.cout);
		dom->statistics("domain1");
		dom_old->statistics("domain1");
		r.cout << *us.get();
	}

	JsonFlow j;
	info->serialize(j);	

	std::string host("localhost");
	std::string uri("/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time");

#if defined(__FREEBSD__)
        std::ostringstream stream;

        stream << j.j["info"]["host"];
        std::string jvalue(stream.str());

        BOOST_CHECK (jvalue.compare(1, jvalue.length() - 2, host) == 0);
#else
        BOOST_CHECK (host.compare(j.j["info"]["host"]) == 0);
	BOOST_CHECK(uri.compare(j.j["info"]["uri"]) == 0);
#endif


	BOOST_CHECK(info->matched_domain_name == d1);
	BOOST_CHECK(host.compare(info->host_name->getName()) == 0);	
	stack->decreaseAllocatedMemory("CoAPProtocol", 10);

	fm->flush();

	stack->setDynamicAllocatedMemory("CoAPProtocol", false);
	stack->decreaseAllocatedMemory("UDPProtocol", 10);
	BOOST_CHECK(stack->getTotalUDPFlows() == 0);

	stack->setDomainNameManager(nullptr, "CoAPProtocol");
	
	stack->releaseCache("CoAPProtocol");
}

// Test for exercise the modbus components
BOOST_AUTO_TEST_CASE (test19) 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());

        pd->setStack(stack);

        stack->setTotalTCPFlows(10);
	stack->increaseAllocatedMemory("ModbusProtocol", 5);

        pd->open("../pcapfiles/modbus_five_flows.pcap");
        pd->run();
        pd->close();

	auto fm = stack->getTCPFlowManager().lock();

	stack->releaseCaches();
        
	stack->decreaseAllocatedMemory("ModbusProtocol", 5);
	{
		RedirectOutput r;

		stack->statistics("ModbusProtocol", 5);
	}
}

BOOST_AUTO_TEST_CASE (test20) 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());
	auto dm = DomainNameManagerPtr(new DomainNameManager());

        pd->setStack(stack);

	stack->setDynamicAllocatedMemory(true);
        stack->setTotalTCPFlows(10);
	stack->increaseAllocatedMemory("IMAPProtocol", 1);
	stack->setDomainNameManager(dm, "IMAPProtocol");
	stack->setDomainNameManager(dm, "IMAPProtocol", false);

	pd->open("../pcapfiles/imap_flow.pcap");
        pd->run();
        pd->close();

	auto fm = stack->getTCPFlowManager().lock();

        bool called = false;

	// Check the relaseCache functionality 
       	for (auto &flow: fm->getFlowTable()) {
		SharedPointer<IMAPInfo> info = flow->getIMAPInfo();
		BOOST_CHECK(info != nullptr);
		
		{
			RedirectOutput r;

			flow->serialize(r.cout);
			r.cout << *(info.get());
			flow->showFlowInfo(r.cout);
		}
		// Check some of the values ?
		called = true;
	}
	BOOST_CHECK (called == true);	
        
	stack->releaseCaches();

        called = false;
        for (auto &flow: fm->getFlowTable()) {
                BOOST_CHECK(flow->getIMAPInfo() == nullptr);
		called = true;
	}
	BOOST_CHECK (called == true);	
	stack->decreaseAllocatedMemory("IMAPProtocol", 1);
	stack->setDomainNameManager(nullptr, "IMAPProtocol");
}

// Test the serialize of the netbios objects and the release of the flows from cache
BOOST_AUTO_TEST_CASE (test21) 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());

	stack->enableLinkLayerTagging("vlan");
        pd->setStack(stack);

        stack->setTotalUDPFlows(3);
	stack->increaseAllocatedMemory("NetbiosProtocol", 1);

        pd->open("../pcapfiles/flow_vlan_netbios.pcap");
        pd->run();
        pd->close();

	auto fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();

	BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(flow->getIMAPInfo() == nullptr);
        BOOST_CHECK(flow->getPOPInfo() == nullptr);
        BOOST_CHECK(flow->getSMTPInfo() == nullptr);
        BOOST_CHECK(flow->getNetbiosInfo() != nullptr);

	{
		RedirectOutput r;
	
		flow->serialize(r.cout);
		flow->showFlowInfo(r.cout);
	}

        stack->releaseCaches();

        BOOST_CHECK(flow->getNetbiosInfo() == nullptr);
	stack->decreaseAllocatedMemory("NetbiosProtocol", 1);
}       

BOOST_AUTO_TEST_CASE (test22) // Test the bitcoin elements
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());

        pd->setStack(stack);

        stack->setTotalTCPFlows(1);
	stack->increaseAllocatedMemory("BitcoinProtocol", 1);

        pd->open("../pcapfiles/bitcoin_flow.pcap");
        pd->run();

	auto fm = stack->getTCPFlowManager().lock();
	BOOST_CHECK(fm->getTotalFlows() == 1);
	auto flow = *fm->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);

       	std::filebuf fb;
       	fb.open ("/dev/null", std::ios::out);
       	std::ostream outp(&fb);

        BOOST_CHECK(flow->getIMAPInfo() == nullptr);
        BOOST_CHECK(flow->getPOPInfo() == nullptr);
        BOOST_CHECK(flow->getSMTPInfo() == nullptr);
        BOOST_CHECK(flow->getBitcoinInfo() != nullptr);

	SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();

	BOOST_CHECK(info->getTotalTransactions() == 0);
	BOOST_CHECK(info->getTotalBlocks() == 0);
	BOOST_CHECK(info->getTotalRejects() == 0);

	{
		RedirectOutput r;

		r.cout << *info.get();
		flow->serialize(r.cout);
		flow->showFlowInfo(r.cout);

		stack->setStatisticsLevel(5);	
		stack->statistics(r.cout);
	}

	JsonFlow j;
	info->serialize(j);

	BOOST_CHECK(j.j["info"]["tx"] == 0);
	BOOST_CHECK(j.j["info"]["blocks"] == 0);
	BOOST_CHECK(j.j["info"]["rejects"] == 0);

	fm->flush();

        stack->releaseCaches();

        BOOST_CHECK(flow->getBitcoinInfo() == nullptr);
	stack->decreaseAllocatedMemory("BitcoinProtocol", 10);
        
	pd->close();
}

BOOST_AUTO_TEST_CASE (test23) // Test the mqtt components
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());

        pd->setStack(stack);

        stack->setTotalTCPFlows(1);
	stack->increaseAllocatedMemory("MQTTProtocol", 1);

        pd->open("../pcapfiles/ipv4_mqtt.pcap");
        pd->run();
        pd->close();

	auto fm = stack->getTCPFlowManager().lock();
	BOOST_CHECK(fm->getTotalFlows() == 1);
	auto flow = *fm->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(flow->getIMAPInfo() == nullptr);
        BOOST_CHECK(flow->getPOPInfo() == nullptr);
        BOOST_CHECK(flow->getSMTPInfo() == nullptr);
        BOOST_CHECK(flow->getBitcoinInfo() == nullptr);

	SharedPointer<MQTTInfo> info = flow->getMQTTInfo();

	BOOST_CHECK(info != nullptr);

	{
		RedirectOutput r;

		r.cout << *info.get();
		flow->serialize(r.cout);
		flow->showFlowInfo(r.cout);
	}

	JsonFlow j;
	info->serialize(j);

#if !defined(__FREEBSD__)
        BOOST_CHECK (j.j["info"]["operation"] == 4);
        BOOST_CHECK(j.j["info"]["total_client"] == 8);
#endif

        stack->releaseCaches();

        BOOST_CHECK(flow->getMQTTInfo() == nullptr);
	stack->decreaseAllocatedMemory("MQTTProtocol", 10);
}

BOOST_AUTO_TEST_CASE (test24) // Test the HTTP components
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());

        pd->setStack(stack);

        stack->setTotalTCPFlows(1);
	stack->increaseAllocatedMemory("HTTPProtocol", 1);

	DomainNameManagerPtr dom = DomainNameManagerPtr(new DomainNameManager());
	auto d1 = DomainNamePtr(new DomainName("domain1", "google.com"));

	dom->addDomainName(d1);	

	stack->setDomainNameManager(dom, "HTTPProtocol");

        pd->setStack(stack);

        stack->setTotalTCPFlows(0);
        stack->setTotalUDPFlows(18);
        pd->open("../pcapfiles/accessgoogle.pcap");
        pd->run();
        pd->close();

	auto fm = stack->getTCPFlowManager().lock();
	BOOST_CHECK(fm->getTotalFlows() == 1);
	auto flow = *fm->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(flow->getIMAPInfo() == nullptr);
        BOOST_CHECK(flow->getPOPInfo() == nullptr);
        BOOST_CHECK(flow->getSMTPInfo() == nullptr);
        BOOST_CHECK(flow->getBitcoinInfo() == nullptr);

	auto info = flow->getHTTPInfo();

	std::string host("www.google.com");
	std::string ua("Mozilla/5.0 (X11; Linux x86_64; rv:10.0.12) Gecko/20100101 Firefox/10.0.12 Iceweasel/10.0.12");
	std::string ct("text/html");

	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name != nullptr);
	BOOST_CHECK(info->ct != nullptr);
	BOOST_CHECK(info->ua != nullptr);
	BOOST_CHECK(info->matched_domain_name == d1);

	BOOST_CHECK(host.compare(info->host_name->getName()) == 0);
	BOOST_CHECK(ua.compare(info->ua->getName()) == 0);
	BOOST_CHECK(ct.compare(info->ct->getName()) == 0);

	{
		RedirectOutput r;

		stack->showProtocolSummary(r.cout);
		r.cout << *info.get();
		flow->serialize(r.cout);
		flow->showFlowInfo(r.cout);
	}

	JsonFlow j;
	info->serialize(j);

#if defined(__FREEBSD__)
        std::ostringstream stream;

        stream << j.j["info"]["host"];
        std::string jvalue(stream.str());

        BOOST_CHECK (jvalue.compare(1, jvalue.length() - 2, host) == 0);
#else
        BOOST_CHECK (host.compare(j.j["info"]["host"]) == 0);
#endif

        stack->releaseCaches();

        BOOST_CHECK(flow->getHTTPInfo() == nullptr);
	stack->setDomainNameManager(nullptr, "HTTPProtocol");
	stack->decreaseAllocatedMemory("HTTPProtocol", 10);
}

BOOST_AUTO_TEST_CASE (test25) // Test the Uris matchs with regex 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());
	auto dom = DomainNameManagerPtr(new DomainNameManager());
	auto rm = RegexManagerPtr(new RegexManager());
	auto d = DomainNamePtr(new DomainName("Gafas", "google.com"));
	auto r = SharedPointer<Regex>(new Regex("3 uri matchs", "^.*(ant/tia.png)$"));

        pd->setStack(stack);

        stack->setTotalTCPFlows(2);
	stack->increaseAllocatedMemory("HTTPProtocol", 2);

	dom->addDomainName(d);	
	rm->addRegex(r);
	d->setHTTPUriRegexManager(rm);

	stack->setDomainNameManager(dom, "HTTPProtocol");

        pd->setStack(stack);

        pd->open("../pcapfiles/accessgoogle.pcap");
        pd->run();
        pd->close();

	BOOST_CHECK(r->getMatchs() == 1);
	BOOST_CHECK(r->getTotalEvaluates() == 2);
}

BOOST_AUTO_TEST_CASE (test26) // Test the RegexManager on DomainNames
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());
	auto dom = DomainNameManagerPtr(new DomainNameManager());
	auto rm = RegexManagerPtr(new RegexManager());
	auto d = DomainNamePtr(new DomainName("Gafas", "google.com"));
	auto r = SharedPointer<Regex>(new Regex("Somethiing in the payload", "^<HTML>.*$"));

	stack->setFlowsTimeout(200); // just for exercise the code
	
        pd->setStack(stack);

        stack->setTotalTCPFlows(2);
	stack->increaseAllocatedMemory("HTTPProtocol", 2);

	dom->addDomainName(d);
	d->setRegexManager(rm);
	rm->addRegex(r);

	stack->setDomainNameManager(dom, "HTTPProtocol");

        pd->setStack(stack);

        pd->open("../pcapfiles/accessgoogle.pcap");
        pd->run();
        pd->close();

	BOOST_CHECK(d->getMatchs() == 1);
	BOOST_CHECK(r->getMatchs() == 1);
	BOOST_CHECK(r->getTotalEvaluates() == 1);
	
	d->setRegexManager(nullptr);
}

BOOST_AUTO_TEST_CASE (test27) // Domain bans functionality on CoAP
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLan());
        auto dom = DomainNameManagerPtr(new DomainNameManager());
	auto d = DomainNamePtr(new DomainName("Not interested", "localhost"));

        dom->addDomainName(d);

        pd->setStack(stack);

        stack->setDomainNameManager(dom, "CoAPProtocol", false);

        stack->setDynamicAllocatedMemory("udp", true);
        stack->setDynamicAllocatedMemory("CoAPProtocol", true);

        pd->open("../pcapfiles/ipv4_coap_big_uri.pcap");
        pd->run();
        pd->close();

        auto fm = stack->getUDPFlowManager().lock();
        BOOST_CHECK(fm != nullptr);
        auto flow = *fm->getFlowTable().begin();

        BOOST_CHECK(flow != nullptr);
        auto info = flow->getCoAPInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name == nullptr);
}

BOOST_AUTO_TEST_CASE (test28) // Exercise the IPSetManager with UDP traffic 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
	auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());
	auto ipset = SharedPointer<IPSet>(new IPSet());

	ipset->addIPAddress("88.190.242.141");

	ipset_mng->addIPSet(ipset);

	stack->setUDPIPSetManager(ipset_mng);
	
	stack->setDynamicAllocatedMemory(true);

        pd->setStack(stack);

        pd->open("../pcapfiles/4udppackets.pcap");
        pd->run();
        pd->close();

	BOOST_CHECK(ipset->getTotalIPs() == 1);
	BOOST_CHECK(ipset->getTotalLookups() == 1);
	BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
	BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
}

BOOST_AUTO_TEST_CASE (test29) // mpls traffic with telnet and regex
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
	auto rm = RegexManagerPtr(new RegexManager());
	auto r1 = SharedPointer<Regex>(new Regex("Somethiing in the payload1", "^\\xff\\xfd.{7}$"));
	auto r2 = SharedPointer<Regex>(new Regex("Somethiing in the payload2", "^\\x0d\\x0a\\x0d\\x0aPassword.*$"));

        pd->setStack(stack);

	stack->setTCPRegexManager(rm);
	rm->addRegex(r1);

	r1->setNextRegex(r2);

	stack->setDynamicAllocatedMemory(true);
        stack->enableLinkLayerTagging("mpls");

        pd->open("../pcapfiles/mpls_icmp_tcp.pcap");
        pd->run();
        pd->close();

	BOOST_CHECK(r1->getMatchs() == 1);
	BOOST_CHECK(r1->getTotalEvaluates() == 2);

	BOOST_CHECK(r2->getMatchs() == 1);
	BOOST_CHECK(r2->getTotalEvaluates() == 5);

	{
		RedirectOutput r;

		// For exercise the statistics
                stack->setStatisticsLevel(5);
                stack->statistics(r.cout);
	}
}

BOOST_AUTO_TEST_CASE (test30) // SSDPprotocol with banned domains
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
	auto d = SharedPointer<DomainName>(new DomainName("bu", "239.255.255.250:1900"));

	dm->addDomainName(d);

        stack->setDomainNameManager(dm, "ssdp", false);
        stack->setDynamicAllocatedMemory(true);

        pd->setStack(stack);
        pd->open("../pcapfiles/ssdp_flow.pcap");
        pd->run();
        pd->close();

        auto fm = stack->getUDPFlowManager().lock();
        BOOST_CHECK(fm->getTotalFlows() == 1);

        auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
        auto info = flow->getSSDPInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->isBanned() == true);
	BOOST_CHECK(d->getMatchs() == 1);

	fm->flush();

        BOOST_CHECK(fm->getTotalFlows() == 0);

	stack->decreaseAllocatedMemory("ssdp", 10);
}

BOOST_AUTO_TEST_CASE(test31) // Tests for flush of the SMTP
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());

	stack->setDynamicAllocatedMemory(true);

        pd->setStack(stack);
        pd->open("../pcapfiles/smtp.pcap");
        pd->run();
        pd->close();

        auto fm = stack->getTCPFlowManager().lock();
        BOOST_CHECK(fm->getTotalFlows() == 1);

        auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
        auto info = flow->getSMTPInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->isBanned() == false);

	fm->flush();

        BOOST_CHECK(fm->getTotalFlows() == 0);
}

BOOST_AUTO_TEST_CASE(test32) // Tests for flush of the IMAP 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());

        stack->setDynamicAllocatedMemory(true);

        pd->setStack(stack);
        pd->open("../pcapfiles/imap_flow.pcap");
        pd->run();
        pd->close();

        auto fm = stack->getTCPFlowManager().lock();
        BOOST_CHECK(fm->getTotalFlows() == 1);

        auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
        auto info = flow->getIMAPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->isBanned() == false);

        fm->flush();

        BOOST_CHECK(fm->getTotalFlows() == 0);
}

BOOST_AUTO_TEST_CASE(test33) // Tests for flush of the POP
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());

        stack->setDynamicAllocatedMemory(true);

        pd->setStack(stack);
        pd->open("../pcapfiles/pop_flow.pcap");
        pd->run();
        pd->close();

        auto fm = stack->getTCPFlowManager().lock();
        BOOST_CHECK(fm->getTotalFlows() == 1);

        auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
        auto info = flow->getPOPInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->isBanned() == false);

        fm->flush();

        BOOST_CHECK(fm->getTotalFlows() == 0);
}

BOOST_AUTO_TEST_CASE(test34) // Tests for pppoe traffic
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());

        stack->enableLinkLayerTagging("pppoe");
        stack->setDynamicAllocatedMemory(true);

        pd->setStack(stack);
        pd->open("../pcapfiles/pppoe_tcp.pcap");
        pd->run();
        pd->close();

        auto fm = stack->getTCPFlowManager().lock();
        BOOST_CHECK(fm->getTotalFlows() == 1);

        auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);

        {
                RedirectOutput r;

                // For exercise the statistics
                stack->setStatisticsLevel(5);
                stack->statistics(r.cout);
        }
}

// Test the IPRadixTree functionality
BOOST_AUTO_TEST_CASE (test35)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto iprad = SharedPointer<IPRadixTree>(new IPRadixTree("IPRadixTree 1"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

        ipset_mng->addIPSet(iprad);
        iprad->addIPAddress("95.100.0.0/16");
        iprad->addIPAddress("63.100.12.0/24");
        iprad->addIPAddress("193.153.1.16");
        iprad->addIPAddress("193.153.1.26");
        iprad->addIPAddress("193.153.1.46");
        iprad->addIPAddress("192.168.0.0/24");
        iprad->addIPAddress("10.0.0.0/8");

        stack->setTCPIPSetManager(ipset_mng);
        stack->setTotalTCPFlows(2);
        pd->setStack(stack);

        pd->open("../pcapfiles/two_http_flows.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(iprad->getTotalLookups() == 2);
        BOOST_CHECK(iprad->getTotalLookupsIn() == 2);
        BOOST_CHECK(iprad->getTotalLookupsOut() == 0);

        {
                RedirectOutput r;

		r.cout << *iprad.get();
        }
}

BOOST_AUTO_TEST_CASE (test37) // Test the dcerpc component
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());

        stack->setDynamicAllocatedMemory(true);

        pd->setStack(stack);
        pd->open("../pcapfiles/dcerpc_traffic.pcapng");
        pd->run();
        pd->close();

        auto fm = stack->getTCPFlowManager().lock();
        BOOST_CHECK(fm->getTotalFlows() == 12);

        auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
        auto info = flow->getDCERPCInfo();
        BOOST_CHECK(info != nullptr);

	stack->releaseCaches();

        fm->flush();

        BOOST_CHECK(fm->getTotalFlows() == 0);
}

BOOST_AUTO_TEST_CASE (test38) // integrate the learner and the FrequencyGroups with other option 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto learner = LearnerEnginePtr(new LearnerEngine());
        std::vector<WeakPointer<Flow>> flow_list;

	stack->setDynamicAllocatedMemory(true);

        stack->enableFrequencyEngine(true);
        pd->setStack(stack);
        pd->open("../pcapfiles/4udppackets.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group;

        group.setName("by source adddress and port");
        group.agregateFlowsBySourceAddressAndPort(stack->getUDPFlowManager().lock());
        group.compute();

        BOOST_CHECK(group.getTotalProcessFlows() == 1);
        BOOST_CHECK(group.getTotalComputedFrequencies() == 1);

        auto it = group.begin();

        BOOST_CHECK(it != group.end());

        FrequencyGroupItemPtr fg = it->second;

        flow_list = fg->getReferenceFlows();
        BOOST_CHECK(flow_list.size() == 1);

        std::string cad_group("10.0.2.15:51413");
        BOOST_CHECK(cad_group.compare(it->first) == 0);

        // pass the flows to the Learner engine
        learner->reset();
        learner->agregateFlows(flow_list);
        learner->compute();
        std::string header("^\\x64\\x31\\x3a\\x61\\x64\\x32\\x3a\\x69");// a GET on hexa
        std::string reg(learner->getRegularExpression());

        BOOST_CHECK(header.compare(0, header.length(), reg, 0, header.length())== 0);
}

BOOST_AUTO_TEST_CASE (test39) // Test the Regexs on the SMTP traffic
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackLanPtr(new StackLan());
        auto rm = SharedPointer<RegexManager>(new RegexManager());
        auto r = SharedPointer<Regex>(new Regex("r1", "GCC"));

        auto dm = DomainNameManagerPtr(new DomainNameManager());
        auto d = DomainNamePtr(new DomainName("domain1", ".patriots.in"));

        dm->addDomainName(d);

        stack->setDynamicAllocatedMemory(true);

	d->setRegexManager(rm);

        rm->addRegex(r);

        stack->setDomainNameManager(dm, "SMTP");

        stack->setTotalTCPFlows(8);
        stack->setTotalUDPFlows(8);

        pd->setStack(stack);
        pd->open("../pcapfiles/smtp.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(d->getMatchs() == 1);
        BOOST_CHECK(r->getMatchs() == 1);
        BOOST_CHECK(r->getTotalEvaluates() == 3);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE (test_suite_stack_mobile) // Test cases for real stacks StackMobile

BOOST_AUTO_TEST_CASE (test01)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobile());

        pd->setStack(stack);

	int64_t a = stack->getAllocatedMemory();
	int64_t b = stack->getTotalAllocatedMemory();

	stack->setDynamicAllocatedMemory(true);

        stack->setTotalUDPFlows(10);
        stack->setTotalTCPFlows(10);
	
	// For exercise the getters
	int tcpf = stack->getTotalTCPFlows();
	int udpf = stack->getTotalUDPFlows();

	BOOST_CHECK(stack->isEnableFrequencyEngine() == false);
	BOOST_CHECK(stack->isEnableNIDSEngine() == false);

	stack->increaseAllocatedMemory("SIPProtocol", 10);

	pd->open("../pcapfiles/gprs_sip_flow.pcap");
        pd->run();

	{
		RedirectOutput r;

 		pd->showCurrentPayloadPacket(r.cout); // ok
	}

        pd->close();

	auto fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SIPInfo> info = flow->getSIPInfo();
	BOOST_CHECK(info != nullptr);

	{
		RedirectOutput r;
	
		stack->showProtocolSummary(r.cout);
		flow->showFlowInfo(r.cout);	
		flow->serialize(r.cout);
		r.cout << *(info.get());
	}

	stack->releaseCaches();
	fm->flush();

        BOOST_CHECK(flow->getSIPInfo() == nullptr);
	stack->decreaseAllocatedMemory("SIPProtocol", 100);

	{
		RedirectOutput r;
	
		// For exercise the statistics
		stack->setStatisticsLevel(5);
		stack->statistics();
		stack->showFlows(); 
		stack->showFlows(10); 
      		stack->showFlows("sip", 10000); 
      	}
 
	stack->setDynamicAllocatedMemory(false);
}

// Test the dispersion and the entrophy with sip traffic
BOOST_AUTO_TEST_CASE (test02)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobile());
        auto learner = LearnerEnginePtr(new LearnerEngine());

        stack->setTotalUDPFlows(8);
        stack->enableFrequencyEngine(true);

        pd->setStack(stack);
        pd->open("../pcapfiles/gprs_sip_flow.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getUDPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 1);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        auto fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->frequencies != nullptr);
        BOOST_CHECK(flow->packet_frequencies != nullptr);

        SharedPointer<Frequencies> fq = flow->frequencies;
        SharedPointer<PacketFrequencies> pf = flow->packet_frequencies;

	// The dispersion of non encrypted flows is lower than ascii protocols.
        BOOST_CHECK(fq->getEntropy() == 0);
        BOOST_CHECK(fq->getDispersion() > 74 and fq->getDispersion() < 76);
        BOOST_CHECK(pf->getEntropy() == 0);
        BOOST_CHECK(pf->getDispersion() > 73 and pf->getDispersion() < 76 );
	
	std::string cadf = fq->getFrequenciesString();
	std::string cadp = pf->getPacketFrequenciesString();

	{
		RedirectOutput r;

		// Exercise the print methods
		r.cout << *(fq.get()); 
		r.cout << *(pf.get());
       		flow->showFlowInfo(r.cout);
	}

	stack->enableFrequencyEngine(false);
}

// Test the IPSets and Regex functionality 
BOOST_AUTO_TEST_CASE (test03)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobile());
        auto i = SharedPointer<IPSet>(new IPSet("IPSet udp"));
        auto im = SharedPointer<IPSetManager>(new IPSetManager());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("SIP test", "^REGISTER.*$"));

	r_generic->setEvidence(true);

        im->addIPSet(i);
        i->addIPAddress("10.0.0.100");

	pd->setStack(stack);

	stack->enableNIDSEngine(true);

	rm->addRegex(r_generic);

	stack->setUDPIPSetManager(im);
	stack->setUDPRegexManager(rm);

	stack->setFlowsTimeout(200);
	BOOST_CHECK(stack->getFlowsTimeout() == 200);
        stack->setTotalUDPFlows(10);

        pd->open("../pcapfiles/gprs_sip_flow.pcap");
        pd->run();
        pd->close();
        
	FlowManagerPtr fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->ipset.lock() == i);
	BOOST_CHECK(flow->regex.lock() == r_generic);

	{
		RedirectOutput r;

        	stack->showFlows();
        	stack->showFlows("SIPProtocol");
  	} 

	stack->enableNIDSEngine(false);

        BOOST_CHECK(i->getTotalIPs() == 1);
        BOOST_CHECK(i->getTotalLookups() == 1); 
        BOOST_CHECK(i->getTotalLookupsIn() == 1);
        BOOST_CHECK(i->getTotalLookupsOut() == 0);
}

BOOST_AUTO_TEST_CASE (test04) // Test regex and ipsets with TCP traffic
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobile());
        auto ipset = SharedPointer<IPSet>(new IPSet("IPSet example"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("Regex test", "^.*6EUds.*$"));

        ipset_mng->addIPSet(ipset);
        ipset->addIPAddress("102.0.5.0");

	pd->setStack(stack);

	stack->enableNIDSEngine(true);

	rm->addRegex(r_generic);

	stack->setTCPIPSetManager(ipset_mng);
	stack->setTCPRegexManager(rm);

        stack->setTotalUDPFlows(10);
        stack->setTotalTCPFlows(10);

        pd->open("../pcapfiles/gprs_ftp.pcap");
        pd->run();
        
	FlowManagerPtr fm = stack->getTCPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->ipset.lock() == ipset);
	BOOST_CHECK(flow->regex.lock() == r_generic);

	stack->enableNIDSEngine(false);

        // The last computed flow is ftp over gprs
        auto tup = stack->getCurrentFlows();
        Flow *low_flow = std::get<0>(tup);
        Flow *high_flow = std::get<1>(tup);

        BOOST_CHECK(low_flow != nullptr); // is gtp encapsulation
        BOOST_CHECK(high_flow != nullptr);

        std::string l7proto_name_low("gprs");
        std::string l7proto_name_high("tcpgeneric");

        BOOST_CHECK(l7proto_name_low.compare(low_flow->getL7ShortProtocolName()) == 0);
        BOOST_CHECK(l7proto_name_high.compare(high_flow->getL7ShortProtocolName()) == 0);
        pd->close();
}

BOOST_AUTO_TEST_CASE (test05) // release flush functionality
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobile());

        pd->setStack(stack);

        stack->setTotalUDPFlows(10);

        pd->open("../pcapfiles/gprs_sip_flow.pcap");
        pd->run();
        pd->close();

        FlowManagerPtr fm = stack->getUDPFlowManager().lock();
        auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
      	BOOST_CHECK(fm->getTotalFlows() == 1); 
	fm->flush();
      	BOOST_CHECK(fm->getTotalFlows() == 0); 
}

BOOST_AUTO_TEST_CASE (test06) // run a file with no stack configured
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobile());

        stack->setDynamicAllocatedMemory(true);

        pd->open("../pcapfiles/gprs_sip_flow.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(pd->getTotalBytes() > 0);
        BOOST_CHECK(pd->getTotalPackets() > 0);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (test_suite_stack_lan6) // Test cases for real stacks StackIPv6

BOOST_AUTO_TEST_CASE (test01) // Test the TCP regex with IPv6 extension headers
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLanIPv6());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("Bad http", "^GET /bad.html"));

        pd->setStack(stack);

	stack->setFlowsTimeout(200);

	BOOST_CHECK(stack->getFlowsTimeout() == 200);

        stack->setTotalTCPFlows(1);
	
	// For exercise the getters
	int tcpf = stack->getTotalTCPFlows();
	int udpf = stack->getTotalUDPFlows();

	stack->enableNIDSEngine(true);

	BOOST_CHECK(stack->isEnableFrequencyEngine() == false);
	BOOST_CHECK(stack->isEnableNIDSEngine() == true);

        rm->addRegex(r_generic);
        stack->setTCPRegexManager(rm);

        pd->open("../pcapfiles/ipv6_ah.pcap");
        pd->run();

	{
		RedirectOutput r;

		pd->showCurrentPayloadPacket(r.cout); 
	}

        BOOST_CHECK(r_generic->getMatchs() == 1);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

	{
		RedirectOutput r;

		stack->showFlows(1000);
		stack->showFlows();
		stack->showFlows("TCPGenericProtocol");
		stack->showFlows("TCPGenericProtocol", 1000);
       	} 

        auto tup = stack->getCurrentFlows();
        Flow *low_flow = std::get<0>(tup);
        Flow *high_flow = std::get<1>(tup);

        BOOST_CHECK(low_flow != nullptr); 
        BOOST_CHECK(high_flow == nullptr);

        std::string l7proto_name_low("tcpgeneric");

        BOOST_CHECK(l7proto_name_low.compare(low_flow->getL7ShortProtocolName()) == 0);

	pd->close();
}

BOOST_AUTO_TEST_CASE (test02) // Test the DomainNames with DNS traffic
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLanIPv6());
	auto dom = DomainNameManagerPtr(new DomainNameManager());
	auto d1 = DomainNamePtr(new DomainName("domain1", "itojun.org"));
	auto d2 = DomainNamePtr(new DomainName("domain2", "yahoo.com"));

	dom->addDomainName("Another domain", "this.domain.dont.exists.com");
	dom->addDomainName(d1);	
	dom->addDomainName(d2);	

        pd->setStack(stack);

        stack->setTotalTCPFlows(0);
        stack->setTotalUDPFlows(18);
	stack->increaseAllocatedMemory("DNSProtocol", 18);

	stack->setDomainNameManager(dom, "DNSProtocol");
       	
	RedirectOutput r;
	
	r.cout << *d1.get(); // Execute the default print

        pd->open("../pcapfiles/ipv6_mix_traffic.pcap");
        pd->setPcapFilter("port 53 and not icmp6");
        pd->run();

	BOOST_CHECK(d1->getMatchs() == 3);
	BOOST_CHECK(d2->getMatchs() == 1);
        
	auto fm = stack->getUDPFlowManager().lock();

       	pd->showCurrentPayloadPacket(r.cout);

        pd->close();

        bool called = false;
        // Check the relaseCache functionality 
        for (auto &flow: fm->getFlowTable()) {
		SharedPointer<DNSInfo> info = flow->getDNSInfo();
		BOOST_CHECK(info != nullptr); 
		// Execute the code for serialize the flows
		flow->serialize(r.cout);
		flow->showFlowInfo(r.cout);
                called = true;
        }
	BOOST_CHECK(called == true);
	called = false;

       	stack->setStatisticsLevel(5);
       	stack->statistics(r.cout);

        stack->releaseCaches();

        for (auto &flow: fm->getFlowTable()) {
                BOOST_CHECK(flow->layer7info == nullptr);
                called = true;
        }
	BOOST_CHECK(called == true);

	stack->decreaseAllocatedMemory("DNSProtocol", 100);

	// For exercise the statistics
       	stack->setStatisticsLevel(5);
       	stack->statistics(r.cout);
      	stack->showFlows(r.cout); 
      	dom->statistics(r.cout);
       	r.cout << *dom.get();	
}

BOOST_AUTO_TEST_CASE (test03) // Test the frequency engine on IPv6
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLanIPv6());

        pd->setStack(stack);

        stack->setTotalTCPFlows(1);

	stack->enableFrequencyEngine(true);

        pd->open("../pcapfiles/ipv6_ah.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 1);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        auto fm = stack->getTCPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();

        BOOST_CHECK(flow != nullptr);

        SharedPointer<Frequencies> fq = flow->frequencies;
        SharedPointer<PacketFrequencies> pf = flow->packet_frequencies;

	BOOST_CHECK(fq != nullptr);
	BOOST_CHECK(pf != nullptr);

	// The dispersion of non encrypted flows is lower than ascii protocols.
        BOOST_CHECK(fq->getEntropy() == 0);
        // BOOST_CHECK(fq->getDispersion() > 74 and fq->getDispersion() < 76);
	stack->releaseCaches();
	stack->enableFrequencyEngine(false);

	// Just for hit the code :)
	group_by_port.reset();
	group_by_port.agregateFlowsBySourcePort(fm);
	group_by_port.agregateFlowsBySourceAddress(fm);
	group_by_port.agregateFlowsBySourceAddressAndPort(fm);
}

BOOST_AUTO_TEST_CASE (test04) // Test the IPSets on TCP
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLanIPv6());
        auto ipset_tcp = SharedPointer<IPSet>(new IPSet("IPSet 1"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

        ipset_mng->addIPSet(ipset_tcp);
        ipset_tcp->addIPAddress("192.168.2.14");
        ipset_tcp->addIPAddress("2001:db8:1::1");

	pd->setStack(stack);

	stack->setTCPIPSetManager(ipset_mng);

        stack->setTotalTCPFlows(1);

        pd->open("../pcapfiles/ipv6_ah.pcap");
        pd->run();
        
	auto fm = stack->getTCPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->ipset.lock() == ipset_tcp);

	auto tup = stack->getCurrentFlows();
        pd->close();
	fm->flush();
}

BOOST_AUTO_TEST_CASE (test05) // Tests the IPSets and REgex on UDP
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLanIPv6());
        auto ipset_udp = SharedPointer<IPSet>(new IPSet("IPSet udp"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("RIP test", "^.*\\x00\\x00\\x20\\x04$"));

        ipset_mng->addIPSet(ipset_udp);
        ipset_udp->addIPAddress("ff02::9");

	pd->setStack(stack);

	stack->enableNIDSEngine(true);

	rm->addRegex(r_generic);

	stack->setUDPIPSetManager(ipset_mng);
	stack->setUDPRegexManager(rm);

        stack->setTotalUDPFlows(1);

        pd->open("../pcapfiles/ipv6_mix_traffic.pcap");
        pd->setPcapFilter("port 521"); // There is a poor RIP flow
        pd->run();
        
	FlowManagerPtr fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->ipset.lock() == ipset_udp);
	BOOST_CHECK(flow->regex.lock() == r_generic);
	stack->enableNIDSEngine(false);

	struct in6_addr *ipsrc = flow->getSourceAddress6();
	struct in6_addr *ipdst = flow->getDestinationAddress6();

        auto tup = stack->getCurrentFlows();
        Flow *low_flow = std::get<0>(tup);
        Flow *high_flow = std::get<1>(tup);

        BOOST_CHECK(low_flow != nullptr);
        BOOST_CHECK(high_flow == nullptr);

        std::string l7proto_name_low("udpgeneric");

        BOOST_CHECK(l7proto_name_low.compare(low_flow->getL7ShortProtocolName()) == 0);

        pd->close();
}

BOOST_AUTO_TEST_CASE (test06) 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLanIPv6());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r = SharedPointer<Regex>(new Regex("PNG File", "^\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a.*$"));
	auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
	auto d = SharedPointer<DomainName>(new DomainName("Music domain", ".us.listen.com"));	

	pd->setStack(stack);

	rm->addRegex(r);
	dm->addDomainName(d);

	d->setRegexManager(rm);

	stack->setDynamicAllocatedMemory(true);
	stack->setDomainNameManager(dm, "HTTPProtocol");

        //So the flows from listen.com will be analise the regexmanager attached 

        pd->open("../pcapfiles/http_over_ipv6.pcap");
        pd->run();
        pd->close();

	BOOST_CHECK(d->getMatchs() == 1);
	BOOST_CHECK(r->getMatchs() == 1);
}

// Complex example with a regex that links with more regexs on the http responses
// similar as test06 but with more detectin complexity
BOOST_AUTO_TEST_CASE (test07)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLanIPv6());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r1 = SharedPointer<Regex>(new Regex("PNG File", "^\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a.*$"));
        auto r2 = SharedPointer<Regex>(new Regex("PNG File", "^\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a.*$"));
        auto r3 = SharedPointer<Regex>(new Regex("PNG File", "^\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a.*$"));
        auto r4 = SharedPointer<Regex>(new Regex("PNG File", "^\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a.*$"));

        auto r1end = SharedPointer<Regex>(new Regex("PNG File end", "^.*\\x49\\x45\\x4e\\x44\\xae\\x42\\x60\\x82$"));
        auto r2end = SharedPointer<Regex>(new Regex("PNG File end", "^.*\\x49\\x45\\x4e\\x44\\xae\\x42\\x60\\x82$"));
        auto r3end = SharedPointer<Regex>(new Regex("PNG File end", "^.*\\x49\\x45\\x4e\\x44\\xae\\x42\\x60\\x82$"));
        auto r4end = SharedPointer<Regex>(new Regex("PNG File end", "^.*\\x49\\x45\\x4e\\x44\\xae\\x42\\x60\\x82$"));

        auto dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto d = SharedPointer<DomainName>(new DomainName("Music domain", ".us.listen.com"));

        pd->setStack(stack);

	r1->setNextRegex(r1end);
	r1end->setNextRegex(r2);

	r2->setNextRegex(r2end);
	r2end->setNextRegex(r3);

	r3->setNextRegex(r3end);
	r3end->setNextRegex(r4);

	r4->setNextRegex(r4end);

        rm->addRegex(r1);
        dm->addDomainName(d);

        d->setRegexManager(rm);

        stack->setDynamicAllocatedMemory(true);
        stack->setDomainNameManager(dm, "HTTPProtocol");

        //So the flows from listen.com will be analise the regexmanager attached

        pd->open("../pcapfiles/http_over_ipv6.pcap");
        pd->run();
        pd->close();

        BOOST_CHECK(d->getMatchs() == 1);
        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r2->getMatchs() == 1);
        BOOST_CHECK(r3->getMatchs() == 1);
        BOOST_CHECK(r4->getMatchs() == 1);
        BOOST_CHECK(r1end->getMatchs() == 1);
        BOOST_CHECK(r2end->getMatchs() == 1);
        BOOST_CHECK(r3end->getMatchs() == 1);
        BOOST_CHECK(r4end->getMatchs() == 1);

        dm->resetStatistics();
	rm->resetStatistics();
        
	BOOST_CHECK(d->getMatchs() == 0);
        BOOST_CHECK(r1->getMatchs() == 0);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r3->getMatchs() == 0);
        BOOST_CHECK(r4->getMatchs() == 0);
        BOOST_CHECK(r1end->getMatchs() == 0);
        BOOST_CHECK(r2end->getMatchs() == 0);
        BOOST_CHECK(r3end->getMatchs() == 0);
        BOOST_CHECK(r4end->getMatchs() == 0);
}

BOOST_AUTO_TEST_CASE (test08) // Test the IPSets on DNS traffic
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackLanIPv6());
        auto ipset_udp = SharedPointer<IPSet>(new IPSet("IPSet 1"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

        ipset_mng->addIPSet(ipset_udp);
        ipset_udp->addIPAddress("2001:abcd::1");

        pd->setStack(stack);

        stack->setUDPIPSetManager(ipset_mng);

        stack->setTotalUDPFlows(1);

        pd->open("../pcapfiles/ipv6_google_dns.pcap");
        pd->run();

        auto fm = stack->getUDPFlowManager().lock();
        auto flow = *fm->getFlowTable().begin();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->ipset.lock() == ipset_udp);

        pd->close();
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (test_suite_stack_virtual) // Test cases for real stacks StackVirtual

BOOST_AUTO_TEST_CASE (test01)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackVirtual());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("Bin directory", "^bin$"));

        pd->setStack(stack);

        stack->setTotalUDPFlows(32);
        stack->setTotalTCPFlows(1);

	// For exercise the getters
	int tcpf = stack->getTotalTCPFlows();
	int udpf = stack->getTotalUDPFlows();

	BOOST_CHECK(stack->isEnableFrequencyEngine() == false);
	BOOST_CHECK(stack->isEnableNIDSEngine() == false);

	rm->addRegex(r_generic);
        stack->setTCPRegexManager(rm);

        pd->open("../pcapfiles/gre_ssh.pcap");
        pd->run();

	{
		RedirectOutput r;
	
		// Just print one flow because is gre encapsulation
        	pd->showCurrentPayloadPacket(r.cout);
		
		stack->showFlows(5);
		stack->showFlows();
		stack->showFlows("TCPGenericProtocol");
	}
 
	auto tup = stack->getCurrentFlows();
        BOOST_CHECK(r_generic->getMatchs() == 0);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 75);
        pd->close();
}

BOOST_AUTO_TEST_CASE (test02)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackVirtual());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r_generic = SharedPointer<Regex>(new Regex("Bin directory", "^bin$"));
	auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());
	auto ipset = SharedPointer<IPSet>(new IPSet());

        pd->setStack(stack);

        stack->setTotalUDPFlows(32);
        stack->setTotalTCPFlows(1);

        rm->addRegex(r_generic);
        stack->setTCPRegexManager(rm);
       
	ipset_mng->addIPSet(ipset);
	ipset->addIPAddress("192.168.1.100");

	stack->setTCPIPSetManager(ipset_mng);
	
        pd->open("../pcapfiles/vxlan_ftp.pcap");
        pd->run();

	{
		RedirectOutput r;

		// print two flows because is vxlan 
		pd->showCurrentPayloadPacket(r.cout); // ok

		stack->setStatisticsLevel(5);
		stack->statistics(r.cout);
		stack->showFlows(r.cout); 
	}

        BOOST_CHECK(r_generic->getMatchs() == 1);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

       	BOOST_CHECK(ipset->getTotalIPs() == 1);
       	BOOST_CHECK(ipset->getTotalLookups() == 1);
       	BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
       	BOOST_CHECK(ipset->getTotalLookupsOut() == 0);

        // The last computed flow is ftp over vxlan 
        auto tup = stack->getCurrentFlows();
        Flow *low_flow = std::get<0>(tup);
        Flow *high_flow = std::get<1>(tup);

        BOOST_CHECK(low_flow != nullptr); // is vxlan encapsulation
        BOOST_CHECK(high_flow != nullptr);

        std::string l7proto_name_low("vxlan");
        std::string l7proto_name_high("tcpgeneric");

        BOOST_CHECK(l7proto_name_low.compare(low_flow->getL7ShortProtocolName()) == 0);
        BOOST_CHECK(l7proto_name_high.compare(high_flow->getL7ShortProtocolName()) == 0);

        pd->close();
}

// Test the dispersion and entropy of encrypted flows on the freq engine 
BOOST_AUTO_TEST_CASE (test03)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = StackVirtualPtr(new StackVirtual());
        auto learner = LearnerEnginePtr(new LearnerEngine());

        stack->setTotalTCPFlows(4);
        stack->enableFrequencyEngine(true);

        pd->setStack(stack);
        pd->open("../pcapfiles/gre_ssh.pcap");
        pd->run();
	auto tup = stack->getCurrentFlows();
        pd->close();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 1); 
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        auto fm = stack->getTCPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();

	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->frequencies != nullptr);
        BOOST_CHECK(flow->packet_frequencies != nullptr);

        // Verify the frequencies values
	SharedPointer<Frequencies> fq = flow->frequencies;
	SharedPointer<PacketFrequencies> pf = flow->packet_frequencies;

	BOOST_CHECK(fq->getEntropy() == 0);
	BOOST_CHECK(fq->getDispersion() > 250);
	BOOST_CHECK(pf->getEntropy() == 0);
	BOOST_CHECK(pf->getDispersion() > 250);
     
	// Some crazy checks
	Frequencies f = *fq.get();

	BOOST_CHECK(f[0] == 190); 
	BOOST_CHECK(f[1] == 33); 
	BOOST_CHECK(f[2] == 22); 
	BOOST_CHECK(f[3] == 26); 
	BOOST_CHECK(f[4] == 25); 
	BOOST_CHECK(f[5] == 30); 
	BOOST_CHECK(f[6] == 21); 
	BOOST_CHECK(f[7] == 29); 
	BOOST_CHECK(f[8] == 14); 
	BOOST_CHECK(f[9] == 23); 

	BOOST_CHECK(f[246] == 23);
	BOOST_CHECK(f[247] == 19);
	BOOST_CHECK(f[248] == 27);
	BOOST_CHECK(f[249] == 14);
	BOOST_CHECK(f[250] == 25);
	BOOST_CHECK(f[251] == 27);
	BOOST_CHECK(f[252] == 28);
	BOOST_CHECK(f[253] == 15);
	BOOST_CHECK(f[254] == 26);
	BOOST_CHECK(f[255] == 17);
 
	stack->enableFrequencyEngine(false);
}

BOOST_AUTO_TEST_CASE (test04)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackVirtual());
	auto system = SystemPtr(new System());
	auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());
	auto ipset = SharedPointer<IPSet>(new IPSet());

        pd->setStack(stack);

        stack->setTotalUDPFlows(32);
	
	ipset_mng->addIPSet(ipset);
	ipset->addIPAddress("255.255.255.255");

	stack->setUDPIPSetManager(ipset_mng);

        pd->open("../pcapfiles/gre_dhcp.pcap");
        pd->run();

	RedirectOutput r;

	// Just print one flow because is gre encapsulation
        pd->showCurrentPayloadPacket(r.cout); // OK

        pd->close();
        
	auto fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<DHCPInfo> info = flow->getDHCPInfo();
	BOOST_CHECK(info != nullptr);

	flow->showFlowInfo(r.cout);	
	flow->serialize(r.cout);
	r.cout << *info.get();
	system->statistics(r.cout);
      	stack->showFlows(); 
      	stack->showFlows(1); 
      	stack->showFlows("DHCPProcotol", 10000); 

	// Exercise the system class
	std::string temp = system->getOSName();
	temp = system->getNodeName();
	temp = system->getReleaseName();
	temp = system->getVersionName();
	temp = system->getMachineName();

	std::string name("PAQUITO");
	BOOST_CHECK(name.compare(info->host_name->getName()) == 0);

	stack->releaseCaches();

	info = flow->getDHCPInfo();
	BOOST_CHECK(info == nullptr);

       	BOOST_CHECK(ipset->getTotalIPs() == 1);
       	BOOST_CHECK(ipset->getTotalLookups() == 1);
       	BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
       	BOOST_CHECK(ipset->getTotalLookupsOut() == 0);

	stack->decreaseAllocatedMemory("DHCPProtocol", 10);
}

BOOST_AUTO_TEST_CASE (test05)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackVirtual());
        auto rm = RegexManagerPtr(new RegexManager());
        auto re = SharedPointer<Regex>(new Regex("example", "PAQUITO"));

	rm->addRegex(re);

	stack->setFlowsTimeout(5);
	BOOST_CHECK(stack->getFlowsTimeout() == 5);
	stack->setUDPRegexManager(rm);
        pd->setStack(stack);

	stack->enableNIDSEngine(true);
        stack->setTotalUDPFlows(32);

        pd->open("../pcapfiles/gre_dhcp.pcap");
        pd->run();
        
	auto fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->regex.lock() == re);

	stack->enableNIDSEngine(false);

        // The last computed flow is dhcp over gre
        auto tup = stack->getCurrentFlows();
        Flow *low_flow = std::get<0>(tup);
        Flow *high_flow = std::get<1>(tup);

        BOOST_CHECK(low_flow == nullptr); // is gre encapsulation
        BOOST_CHECK(high_flow != nullptr);

        std::string l7proto_name_high("udpgeneric");

        BOOST_CHECK(l7proto_name_high.compare(high_flow->getL7ShortProtocolName()) == 0);

        pd->close();
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (test_suite_stack_openflow) // Test cases for real stacks StackOpenFlow

BOOST_AUTO_TEST_CASE (test01)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackOpenFlow());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r = SharedPointer<Regex>(new Regex("a signature", "^\\x26\\x01"));
        auto ipset_tcp = SharedPointer<IPSet>(new IPSet("IPSet 1"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

        ipset_mng->addIPSet(ipset_tcp);
        ipset_tcp->addIPAddress("192.168.2.14");

	stack->enableNIDSEngine(true);

	BOOST_CHECK(stack->isEnableFrequencyEngine() == false);
	BOOST_CHECK(stack->isEnableNIDSEngine() == true);

        stack->setTCPIPSetManager(ipset_mng);

        rm->addRegex(r);
        stack->setTCPRegexManager(rm);

	stack->setFlowsTimeout(200);
	BOOST_CHECK(stack->getFlowsTimeout() == 200);
        stack->setTotalTCPFlows(8);
        stack->setTotalUDPFlows(8);
        pd->setStack(stack);
	
	// For exercise the getters
	int tcpf = stack->getTotalTCPFlows();
	int udpf = stack->getTotalUDPFlows();

	// For exercise the statistics and outputs
	RedirectOutput ro;

	ro.cout << *ipset_tcp.get();
	ro.cout << *ipset_mng.get();

        pd->open("../pcapfiles/openflow.pcap");
        pd->run();
	pd->showCurrentPayloadPacket(ro.cout); // Two tcp flows
        pd->close();

        auto flows_tcp = stack->getTCPFlowManager().lock();
        BOOST_CHECK(flows_tcp->getTotalFlows() == 1);
	auto flow = *flows_tcp->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);

        BOOST_CHECK(flow->regex.lock() == r);
        BOOST_CHECK(flow->ipset.lock() == ipset_tcp);

        auto flows_udp = stack->getUDPFlowManager().lock();
        BOOST_CHECK(flows_udp->getTotalFlows() == 1);
	flow = *flows_udp->getFlowTable().begin();

	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::UDP_BOGUS_HEADER);

	{
		RedirectOutput rr;

       		stack->setStatisticsLevel(5);
       		stack->statistics(rr.cout);
      		stack->showFlows(); 
      		stack->showFlows("TCPGenericProcotol", 1000); 
      		rr.cout << *rm.get();
	}

	stack->enableNIDSEngine(false);

	{ 
		RedirectOutput rr;

		stack->showFlows(55);
		stack->showFlows();
		stack->showFlows("SIPProtocol");
   	} 
}

BOOST_AUTO_TEST_CASE (test02) // frequencies on openflow
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackOpenFlow());

        stack->setTotalTCPFlows(8);
        stack->setTotalUDPFlows(8);
        pd->setStack(stack);

	stack->enableFrequencyEngine(true);

        pd->open("../pcapfiles/openflow.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getUDPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 1); 
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        FlowManagerPtr fm = stack->getUDPFlowManager().lock();
	auto flow = *fm->getFlowTable().begin();
        
	BOOST_CHECK(flow != nullptr);
        // Verify the frequencies values
	SharedPointer<Frequencies> fq = flow->frequencies;
	SharedPointer<PacketFrequencies> pf = flow->packet_frequencies;

	BOOST_CHECK(fq->getEntropy() == 0);
	BOOST_CHECK(fq->getDispersion() > 90);
	BOOST_CHECK(pf->getEntropy() == 0);
	BOOST_CHECK(pf->getDispersion() >= 90);
	
	stack->enableFrequencyEngine(false);
}

BOOST_AUTO_TEST_CASE (test03) // Tests ipsets and regex on UDP traffic
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackOpenFlow());
        auto rm = RegexManagerPtr(new RegexManager());
        auto re = SharedPointer<Regex>(new Regex("a signature", "^.*NOTIFY.*$"));
        auto ipset = SharedPointer<IPSet>(new IPSet("IPSet 1"));
        auto ipset_mng = SharedPointer<IPSetManager>(new IPSetManager());

        ipset_mng->addIPSet(ipset);
        ipset->addIPAddress("239.255.255.250");

	stack->enableNIDSEngine(true);
        stack->setUDPIPSetManager(ipset_mng);

        rm->addRegex(re);
        stack->setUDPRegexManager(rm);

        stack->setTotalTCPFlows(8);
        stack->setTotalUDPFlows(8);
        pd->setStack(stack);
	
        pd->open("../pcapfiles/openflow.pcap");
        pd->run();

        auto fm = stack->getUDPFlowManager().lock();
        BOOST_CHECK(fm->getTotalFlows() == 1);
	auto flow = *fm->getFlowTable().begin();
	BOOST_CHECK(flow != nullptr);

	std::string l7proto("udpgeneric");

	BOOST_CHECK(l7proto.compare(flow->getL7ShortProtocolName()) == 0);
        BOOST_CHECK(flow->regex.lock() == re);
        BOOST_CHECK(flow->ipset.lock() == ipset);

	// The last computed flow is ssh over openflow
	auto tup = stack->getCurrentFlows();
	Flow *low_flow = std::get<0>(tup);
	Flow *high_flow = std::get<1>(tup);

	BOOST_CHECK(low_flow != nullptr);
	BOOST_CHECK(high_flow != nullptr);

	std::string l7proto_name_high("tcpgeneric");
	std::string l7proto_name_low("openflow");

	BOOST_CHECK(l7proto_name_high.compare(high_flow->getL7ShortProtocolName()) == 0);
	BOOST_CHECK(l7proto_name_low.compare(low_flow->getL7ShortProtocolName()) == 0);
	
	stack->enableNIDSEngine(false);

	pd->close();
}

BOOST_AUTO_TEST_CASE (test04) 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackOpenFlow());

	stack->setDynamicAllocatedMemory(true);
        pd->setStack(stack);

        pd->open("../pcapfiles/openflow_dns.pcap");
        pd->run();

	// The last computed flow is dns over openflow
	auto tup = stack->getCurrentFlows();
	Flow *low_flow = std::get<0>(tup);
	Flow *high_flow = std::get<1>(tup);

	BOOST_CHECK(low_flow != nullptr);
	BOOST_CHECK(high_flow != nullptr);

	std::string l7proto_name_high("dns");
	std::string l7proto_name_low("openflow");

	BOOST_CHECK(l7proto_name_high.compare(high_flow->getL7ShortProtocolName()) == 0);
	BOOST_CHECK(l7proto_name_low.compare(low_flow->getL7ShortProtocolName()) == 0);
	
	pd->close();
}

BOOST_AUTO_TEST_CASE (test05) // try to run something that do not exists
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackOpenFlow());

        stack->setDynamicAllocatedMemory(true);
        pd->setStack(stack);

        pd->open("../pcapfiles/this_file_dont_exists.pcap");
        pd->run();
        pd->close();

	BOOST_CHECK(pd->getTotalBytes() == 0);
	BOOST_CHECK(pd->getTotalPackets() == 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE (test_suite_stack_mobile6) // Test cases for real stacks StackMobileIPv6

BOOST_AUTO_TEST_CASE (test01)
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobileIPv6());

	stack->setFlowsTimeout(100);
	BOOST_CHECK(stack->getFlowsTimeout() == 100);

        stack->setDynamicAllocatedMemory(true);
        pd->setStack(stack);

        pd->open("../pcapfiles/gprs_ip6_udp.pcap");
        pd->run();

        auto tup = stack->getCurrentFlows();
        Flow *low_flow = std::get<0>(tup);
        Flow *high_flow = std::get<1>(tup);

        BOOST_CHECK(low_flow != nullptr);
        BOOST_CHECK(high_flow != nullptr);

        std::string l7proto_name_high("sip");
        std::string l7proto_name_low("gprs");

        BOOST_CHECK(l7proto_name_high.compare(high_flow->getL7ShortProtocolName()) == 0);
        BOOST_CHECK(l7proto_name_low.compare(low_flow->getL7ShortProtocolName()) == 0);
 
        BOOST_CHECK(stack->isEnableFrequencyEngine() == false);
        BOOST_CHECK(stack->isEnableNIDSEngine() == false);

        pd->close();

        {
                RedirectOutput rr;

                stack->setStatisticsLevel(5);
                stack->statistics(rr.cout);
                stack->showFlows();
                stack->showFlows("udpgeneric", 10);
        }
}

BOOST_AUTO_TEST_CASE (test02) // Test the regex component on UDP
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobileIPv6());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r = SharedPointer<Regex>(new Regex("a signature", "^MESSAGE"));

        stack->enableNIDSEngine(true);

        BOOST_CHECK(stack->isEnableFrequencyEngine() == false);
        BOOST_CHECK(stack->isEnableNIDSEngine() == true);

        rm->addRegex(r);
        stack->setUDPRegexManager(rm);

        stack->setDynamicAllocatedMemory(true);
        pd->setStack(stack);

        pd->open("../pcapfiles/gprs_ip6_udp.pcap");
        pd->run();
        pd->close();

	stack->enableNIDSEngine(false);

	auto flows_udp = stack->getUDPFlowManager().lock();
        BOOST_CHECK(flows_udp->getTotalFlows() == 1);
	auto flows_tcp = stack->getTCPFlowManager().lock();
        BOOST_CHECK(flows_tcp->getTotalFlows() == 0);

	BOOST_CHECK(r->getMatchs() == 1);
        BOOST_CHECK(r->getTotalEvaluates() == 3);
}

BOOST_AUTO_TEST_CASE (test03) // Test the regex component on TCP 
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobileIPv6());
        auto rm = RegexManagerPtr(new RegexManager());
        auto r = SharedPointer<Regex>(new Regex("a signature", "^REGISTER"));

        stack->enableNIDSEngine(true);

        BOOST_CHECK(stack->isEnableFrequencyEngine() == false);
        BOOST_CHECK(stack->isEnableNIDSEngine() == true);

        rm->addRegex(r);
        stack->setTCPRegexManager(rm);

        stack->setDynamicAllocatedMemory(true);
        pd->setStack(stack);

	pd->setMaxPackets(8); // Remove the FIN/ACK
        pd->open("../pcapfiles/gprs_ip6_tcp.pcap");
        pd->run();

        stack->enableNIDSEngine(false);

        auto flows_udp = stack->getUDPFlowManager().lock();
        BOOST_CHECK(flows_udp->getTotalFlows() == 0);
        auto flows_tcp = stack->getTCPFlowManager().lock();
        BOOST_CHECK(flows_tcp->getTotalFlows() == 1);

        BOOST_CHECK(r->getMatchs() == 1);
        BOOST_CHECK(r->getTotalEvaluates() == 1);

        auto tup = stack->getCurrentFlows();
        Flow *low_flow = std::get<0>(tup);
        Flow *high_flow = std::get<1>(tup);

        BOOST_CHECK(low_flow != nullptr);
        BOOST_CHECK(high_flow != nullptr);

        std::string l7proto_name_high("tcpgeneric");
        std::string l7proto_name_low("gprs");

        BOOST_CHECK(l7proto_name_high.compare(high_flow->getL7ShortProtocolName()) == 0);
        BOOST_CHECK(l7proto_name_low.compare(low_flow->getL7ShortProtocolName()) == 0);

	pd->close();
}

BOOST_AUTO_TEST_CASE (test04) // Test the ipsets
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobileIPv6());
        auto i_tcp = SharedPointer<IPSet>(new IPSet("IPSet generic"));
        auto i_udp = SharedPointer<IPSet>(new IPSet("IPSet generic"));
        auto im_tcp = SharedPointer<IPSetManager>(new IPSetManager());
        auto im_udp = SharedPointer<IPSetManager>(new IPSetManager());

        im_udp->addIPSet(i_udp);
        im_tcp->addIPSet(i_tcp);
        i_tcp->addIPAddress("fd00:183:1:1:1886:9040:8605:32b8");
        i_tcp->addIPAddress("fd01::183");
        i_udp->addIPAddress("fd00:183:1:1:1886:9040:8605:32ba");

        stack->setTCPIPSetManager(im_tcp);
        stack->setUDPIPSetManager(im_udp);

        stack->setDynamicAllocatedMemory(true);
        pd->setStack(stack);

        pd->open("../pcapfiles/gprs_ip6_tcp.pcap");
        pd->run();
        pd->close();

	// stack->statistics(5);

        BOOST_CHECK(i_tcp->getTotalIPs() == 2);
        BOOST_CHECK(i_tcp->getTotalLookups() == 1); 
        BOOST_CHECK(i_tcp->getTotalLookupsIn() == 1);
        BOOST_CHECK(i_tcp->getTotalLookupsOut() == 0);

        BOOST_CHECK(i_udp->getTotalIPs() == 1);
        BOOST_CHECK(i_udp->getTotalLookups() == 0); 
        BOOST_CHECK(i_udp->getTotalLookupsIn() == 0);
        BOOST_CHECK(i_udp->getTotalLookupsOut() == 0);
}

BOOST_AUTO_TEST_CASE (test05) // Test the frequencies on this stack
{
        auto pd = PacketDispatcherPtr(new PacketDispatcher());
        auto stack = NetworkStackPtr(new StackMobileIPv6());

        stack->setTotalTCPFlows(8);
        stack->setTotalUDPFlows(8);
        pd->setStack(stack);

	// For exercise the getters
	int tcpf = stack->getTotalTCPFlows();
	int udpf = stack->getTotalUDPFlows();

        stack->enableFrequencyEngine(true);

        pd->open("../pcapfiles/gprs_ip6_udp.pcap");
        pd->run();
        pd->close();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getUDPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 1);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        FlowManagerPtr fm = stack->getUDPFlowManager().lock();
        auto flow = *fm->getFlowTable().begin();

        BOOST_CHECK(flow != nullptr);
        // Verify the frequencies values
        SharedPointer<Frequencies> fq = flow->frequencies;
        SharedPointer<PacketFrequencies> pf = flow->packet_frequencies;

        BOOST_CHECK(fq->getEntropy() == 0);
        BOOST_CHECK(fq->getDispersion() > 90);
        BOOST_CHECK(pf->getEntropy() == 0);
        BOOST_CHECK(pf->getDispersion() >= 90);

        stack->enableFrequencyEngine(false);
}

BOOST_AUTO_TEST_SUITE_END()
