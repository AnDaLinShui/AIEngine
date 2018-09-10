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
#include "test_ssl.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE ssltest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(ssl_suite_static, StackSSLtest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet("../ssl/packets/packet01.pcap");

	inject(packet);

	// Check the results
	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalValidPackets() == 1);
	BOOST_CHECK(ip->getTotalBytes() == 245);
	BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

	// tcp
	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalBytes() == 225);
	BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

	// ssl
	BOOST_CHECK(ssl->getTotalPackets() == 1);
	BOOST_CHECK(ssl->getTotalValidPackets() == 1);
	BOOST_CHECK(ssl->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ssl->getTotalBytes() == 193);
	BOOST_CHECK(ssl->getTotalInvalidPackets() == 0);

	// all this counters are zero because there is no memory for ssl
	BOOST_CHECK(ssl->getTotalHandshakes() == 0);
	BOOST_CHECK(ssl->getTotalHandshakeFinishes() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);

	BOOST_CHECK(ssl->getTotalEvents() == 0);

	BOOST_CHECK(ssl->processPacket(packet) == true);

	// The name and issuer caches should be empty
	GenericMapType *host_c = ssl->getHostMap();
	GenericMapType *issuer_c = ssl->getIssuerMap();

	BOOST_CHECK(host_c->size() == 0);
	BOOST_CHECK(issuer_c->size() == 0);
}

BOOST_AUTO_TEST_CASE (test02)
{
        Packet packet1("../ssl/packets/packet01.pcap");

	ssl->increaseAllocatedMemory(2);

	inject(packet1);

	BOOST_CHECK(ssl->getTotalHandshakes() == 1);
        BOOST_CHECK(ssl->getTotalClientHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);
	BOOST_CHECK(ssl->getTotalHandshakeFinishes() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 1);

	GenericMapType *host_c = ssl->getHostMap();
	GenericMapType *issuer_c = ssl->getIssuerMap();

	BOOST_CHECK(host_c->size() == 1);
	BOOST_CHECK(issuer_c->size() == 0);

        Flow *flow1 = ssl->getCurrentFlow();
        BOOST_CHECK(flow1 != nullptr);
        SharedPointer<SSLInfo> info1 = flow1->getSSLInfo();
        BOOST_CHECK(info1 != nullptr);

	auto item = host_c->begin();
	
	BOOST_CHECK((*item).second.hits == 1);
	BOOST_CHECK((*item).second.sc == info1->host_name);
	BOOST_CHECK(info1->host_name.use_count() == 2);

        Packet packet2("../ssl/packets/packet02.pcap");

	inject(packet2);

        // Check the results
        BOOST_CHECK(ssl->getTotalClientHellos() == 2);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 2);
	BOOST_CHECK(ssl->getTotalEvents() == 0);

        Flow *flow2 = ssl->getCurrentFlow();
        BOOST_CHECK(flow2 != nullptr);
        SharedPointer<SSLInfo> info2 = flow2->getSSLInfo();
        BOOST_CHECK(info2 != nullptr);
	BOOST_CHECK(info1 != info2);
	BOOST_CHECK(info1->host_name != info2->host_name);

	BOOST_CHECK(host_c->size() == 2);
	BOOST_CHECK(issuer_c->size() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
	// Client hello ToR packet
        Packet packet("../ssl/packets/packet13.pcap");

        ssl->increaseAllocatedMemory(1);

	inject(packet);

        BOOST_CHECK(ssl->getTotalPackets() == 1);
        BOOST_CHECK(ssl->getTotalValidPackets() == 1);
        BOOST_CHECK(ssl->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ssl->getTotalBytes() == 923);
        BOOST_CHECK(ssl->getTotalInvalidPackets() == 0);

        // Check the results
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 1);
	BOOST_CHECK(ssl->getTotalHandshakeFinishes() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 4); // The packet contains 4 records, but we only process 3 types;

	// Issuer:www.tglpf5q7au.com
	Flow *flow = ssl->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->issuer != nullptr);

	std::string issuer("www.tglpf5q7au.com");

	BOOST_CHECK(issuer.compare(info->issuer->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
        Packet packet("../ssl/packets/packet01.pcap");

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        ssl->increaseAllocatedMemory(0);

        flow->packet = const_cast<Packet*>(&packet);
        ssl->processFlow(flow.get());

        BOOST_CHECK(flow->layer7info == nullptr);
}

BOOST_AUTO_TEST_CASE (test05)
{
        Packet packet1("../ssl/packets/packet01.pcap", 66);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        ssl->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet1);
        ssl->processFlow(flow.get());

        BOOST_CHECK(flow->layer7info != nullptr);
	std::string cad("0.drive.google.com");

	SharedPointer<SSLInfo> info = flow->getSSLInfo();
	BOOST_CHECK(info != nullptr);
	// The host is valid
        BOOST_CHECK(cad.compare(info->host_name->getName()) == 0);
	BOOST_CHECK(info->getHeartbeat() == false);
	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
	BOOST_CHECK(info->getCipher() == 0); // The client dont set the cipher
}

BOOST_AUTO_TEST_CASE (test06)
{
        Packet packet1("../ssl/packets/packet02.pcap", 54);

        auto flow = SharedPointer<Flow>(new Flow());

        ssl->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet1);
        ssl->processFlow(flow.get());

        std::string cad("atv-ps.amazon.com");

	SharedPointer<SSLInfo> info = flow->getSSLInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name != nullptr);
        // The host is valid
        BOOST_CHECK(cad.compare(info->host_name->getName()) == 0);
	BOOST_CHECK(info->getHeartbeat() == false);
	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
}

// Tor ssl case 
BOOST_AUTO_TEST_CASE (test07)
{
	// SSL client hello ToR
        Packet packet("../ssl/packets/packet03.pcap", 54);

        auto flow = SharedPointer<Flow>(new Flow());

        ssl->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        ssl->processFlow(flow.get());

        std::string cad("www.6k6fnxstu.com");

        // The host is valid
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
	BOOST_CHECK(info != nullptr);
        BOOST_CHECK(cad.compare(info->host_name->getName()) == 0);
	BOOST_CHECK(info->getHeartbeat() == false);
	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
}

BOOST_AUTO_TEST_CASE (test08)
{
        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("example",".drive.google.com"));

        Packet packet("../ssl/packets/packet01.pcap");

        ssl->increaseAllocatedMemory(1);
        ssl->setDomainNameManager(host_mng);
        host_mng->addDomainName(host_name);
        
	mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	BOOST_CHECK(host_name->getMatchs() == 1);

	BOOST_CHECK(ssl->getTotalAllowHosts() == 1);
	BOOST_CHECK(ssl->getTotalBanHosts() == 0);
	BOOST_CHECK(ssl->getTotalEvents() == 1);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
	BOOST_CHECK(info != nullptr);
	
	flow->setLabel("I like this");

	{
		RedirectOutput r;

        	flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
        	r.cout << *(info.get());
     	}
 
	JsonFlow j;
	info->serialize(j); 

	std::string protocol("SSLProtocol");
	BOOST_CHECK(protocol.compare(flow->getL7ProtocolName()) == 0);
	std::string label("I like this");
	BOOST_CHECK(label.compare(flow->getLabel()) == 0);

	// Force the cache
	ssl->releaseFlowInfo(flow);
 
	ssl->setDomainNameManager(nullptr);
}

BOOST_AUTO_TEST_CASE (test09)
{
        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("example",".paco.google.com"));

        Packet packet("../ssl/packets/packet01.pcap");

        ssl->increaseAllocatedMemory(1);
        ssl->setDomainNameManager(host_mng);
        host_mng->addDomainName(host_name);

	inject(packet);

        BOOST_CHECK(host_name->getMatchs() == 0);
}

BOOST_AUTO_TEST_CASE (test10)
{
        auto host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto host_name = SharedPointer<DomainName>(new DomainName("example",".google.com"));

        Packet packet("../ssl/packets/packet01.pcap");
        Packet packet1("../ssl/packets/packet03.pcap", 54);

        ssl->increaseAllocatedMemory(1);
        ssl->setDomainNameBanManager(host_mng);
        host_mng->addDomainName(host_name);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);

	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->isBanned() == true);
        BOOST_CHECK(info->host_name  == nullptr);
	
        BOOST_CHECK(host_name->getMatchs() == 1);

        BOOST_CHECK(ssl->getTotalAllowHosts() == 0);
        BOOST_CHECK(ssl->getTotalBanHosts() == 1);
	BOOST_CHECK(ssl->getTotalEvents() == 0);

        flow->packet = const_cast<Packet*>(&packet1);
	// Inject the same flow 
	ssl->processFlow(flow);

        BOOST_CHECK(info->isBanned() == true);
        BOOST_CHECK(info->host_name  == nullptr);
}

BOOST_AUTO_TEST_CASE (test11)
{
        Packet packet1("../ssl/packets/packet01.pcap");
        Packet packet2("../ssl/packets/packet03.pcap");

        ssl->increaseAllocatedMemory(2);

	inject(packet1);
	inject(packet2);

	auto fm = tcp->getFlowManager();

#if defined(STAND_ALONE)
        Cache<StringCache>::CachePtr c = ssl->getHostCache();

	BOOST_CHECK(c->getTotal() == 0);
	BOOST_CHECK(c->getTotalAcquires() == 2);
	BOOST_CHECK(c->getTotalReleases() == 0);
#endif
	for (auto &f: fm->getFlowTable()) {
		BOOST_CHECK(f->getSSLInfo() != nullptr);
	}
	ssl->releaseCache();

#if defined(STAND_ALONE)
	BOOST_CHECK(c->getTotal() == 2);
	BOOST_CHECK(c->getTotalAcquires() == 2);
	BOOST_CHECK(c->getTotalReleases() == 2);
#endif

	for (auto &f: fm->getFlowTable()) {
		BOOST_CHECK(f->layer7info == nullptr);
	}
}

// Renegotitaion header on the ssl hello
BOOST_AUTO_TEST_CASE (test12)
{
	Packet packet("../ssl/packets/packet14.pcap", 54);

        auto flow = SharedPointer<Flow>(new Flow());

        ssl->increaseAllocatedMemory(1);

        flow->packet = const_cast<Packet*>(&packet);
        ssl->processFlow(flow.get());

        std::string cad("ipv4_1-aaag0-c001.1.000001.xx.aaaavideo.net");

        // The host is valid
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
	BOOST_CHECK(info != nullptr);
        BOOST_CHECK(cad.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(info->getHeartbeat() == false);
}

// have a heartbeat header on the ssl hello, just at the end
BOOST_AUTO_TEST_CASE (test13)
{
	Packet packet("../ssl/packets/packet06.pcap");

        ssl->increaseAllocatedMemory(1);

	inject(packet);

        // Some TCP checks
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 275);
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

	// Check some TCP ports
	BOOST_CHECK(tcp->getSourcePort() == 49034);
	BOOST_CHECK(tcp->getDestinationPort() == 8080);

        std::string cad("www.gi7n35abj6dehjlg5g7.com");

        // The host is valid
	Flow *flow = ssl->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);

	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);

	SharedPointer<SSLInfo> info = flow->getSSLInfo();
	BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->host_name != nullptr);
        BOOST_CHECK(cad.compare(info->host_name->getName()) == 0);

	// This pcap have a heartbeat enable
        BOOST_CHECK(info->getHeartbeat() == true);
	
	CounterMap c = ssl->getCounters();

	// Set the alert just for execute the code
	info->setAlert(true);
	info->setAlertCode(10);

        JsonFlow j;
        info->serialize(j);
}

BOOST_AUTO_TEST_CASE (test14) // Corrupt hello length to verify anomaly
{
        Packet packet("../ssl/packets/packet01.pcap");

	// remove 16 bytes from the packet, enought for corruption
	packet.setPayloadLength(packet.getLength() - 16);

        ssl->increaseAllocatedMemory(1);

        inject(packet);

	Flow *flow = ssl->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
	BOOST_CHECK(info != nullptr);

	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SSL_BOGUS_HEADER);

        BOOST_CHECK(ssl->getTotalEvents() == 1);
        BOOST_CHECK(ssl->getTotalHandshakes() == 1);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 1);

	std::string anomaly_str("SSL bogus header");
	BOOST_CHECK(anomaly_str.compare(anomaly->getName(flow->getPacketAnomaly())) == 0);

	{
		RedirectOutput r;
        
		flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
        	r.cout << *(info.get());
	}
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ssl_suite_dynamic, StackSSLtest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet("../ssl/packets/packet01.pcap");

        ssl->increaseAllocatedMemory(0);

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

        inject(packet);

	Flow *flow = ssl->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);

	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);

        BOOST_CHECK(flow->layer7info != nullptr);
        BOOST_CHECK(flow->getSSLInfo() != nullptr);

        BOOST_CHECK(ssl->getTotalHandshakes() == 1);
        BOOST_CHECK(ssl->getTotalClientHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 1);
}

BOOST_AUTO_TEST_CASE (test02) // test the ssl alerts
{
        Packet packet("../ssl/packets/packet04.pcap", 66);

        auto flow = SharedPointer<Flow>(new Flow());

	flow->total_packets_l7 = 5;

        ssl->increaseAllocatedMemory(0);

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

        flow->packet = const_cast<Packet*>(&packet);
        ssl->processFlow(flow.get());

        BOOST_CHECK(flow->layer7info != nullptr);
        auto info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->isAlert() == true);
	BOOST_CHECK(info->getAlertCode() == 112); // Unrecognized Name
}

BOOST_AUTO_TEST_CASE (test03) // test 4 pdus in one packet
{
        Packet packet("../ssl/packets/packet05.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);

	// Check the cipher, in this case is C030 == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	BOOST_CHECK(info->getCipher() == 0xC030);

	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 1);
	BOOST_CHECK(ssl->getTotalServerKeyExchanges() == 1);
	BOOST_CHECK(ssl->getTotalRecords() == 4);
}

BOOST_AUTO_TEST_CASE (test04) // corrupt the certificate packet, is the third one
{
        Packet packet("../ssl/packets/packet05.pcap");

	// Change the size of the packet
	packet.setPayloadLength(packet.getLength() - 17);

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
	
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SSL_BOGUS_HEADER);

	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 3);
}

BOOST_AUTO_TEST_CASE (test05) // three messages on the packet 
{
        Packet packet("../ssl/packets/packet07.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
	
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::NONE);

	BOOST_CHECK(ssl->getTotalHandshakeFinishes() == 1);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 1);
	BOOST_CHECK(ssl->getTotalClientKeyExchanges() == 1);
	BOOST_CHECK(ssl->getTotalServerHellos() == 0);
	BOOST_CHECK(ssl->getTotalCertificates() == 0);
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 3);
}

BOOST_AUTO_TEST_CASE (test06) // three messages on the packet 
{
        Packet packet("../ssl/packets/packet08.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->getVersion() == TLS1_2_VERSION);

	BOOST_CHECK(ssl->getTotalHandshakes() == 2);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 1);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 0);
	BOOST_CHECK(ssl->getTotalCertificates() == 0);
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 3);
}

BOOST_AUTO_TEST_CASE (test07) // client hello to mtalk.google.com and server 
{
        Packet packet1("../ssl/packets/packet09.pcap");
        Packet packet2("../ssl/packets/packet10.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet1);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name != nullptr);

	BOOST_CHECK(info->getVersion() == TLS1_VERSION);

        std::string cad("mtalk.google.com");
        BOOST_CHECK(cad.compare(info->host_name->getName()) == 0);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(info->getCipher() == 0);

	BOOST_CHECK(ssl->getTotalHandshakes() == 1);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 1);
	BOOST_CHECK(ssl->getTotalServerHellos() == 0);
	BOOST_CHECK(ssl->getTotalCertificates() == 0);
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 1);
	
	inject(packet2);

	BOOST_CHECK(info->getCipher() == 0xCCA9); // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

	// 3 handshakes, server hello and the certificate (partially)	
	BOOST_CHECK(ssl->getTotalHandshakes() == 3);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 1);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 3);
}

BOOST_AUTO_TEST_CASE (test08) // server hello, cert and server done 
{
        Packet packet("../ssl/packets/packet11.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);
	BOOST_CHECK(info->getCipher() == 0x0005); // TLS_RSA_WITH_RC4_128_SHA

	BOOST_CHECK(ssl->getTotalHandshakes() == 3);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 1);
	BOOST_CHECK(ssl->getTotalRecords() == 3);
}

BOOST_AUTO_TEST_CASE (test09) // server hello, cert and cert request 
{
        Packet packet("../ssl/packets/packet12.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 1420); 
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // tcp
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 1400); 
        BOOST_CHECK(tcp->getTotalInvalidPackets() == 0);

        // ssl
        BOOST_CHECK(ssl->getTotalPackets() == 1);
        BOOST_CHECK(ssl->getTotalValidPackets() == 1);
        BOOST_CHECK(ssl->getTotalInvalidPackets() == 0);
        BOOST_CHECK(ssl->getTotalBytes() == 1380); 
        BOOST_CHECK(ssl->getTotalInvalidPackets() == 0);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);
	BOOST_CHECK(info->getCipher() == 0x002F); // TLS_RSA_WITH_AES_128_CBC_SHA

	BOOST_CHECK(ssl->getTotalHandshakes() == 3);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalCertificateRequests() == 0); // Corrupted
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 3);

	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::SSL_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test10) // client key exchange, cert verify 
{
	Packet packet("../ssl/packets/packet15.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(ssl->getTotalHandshakes() == 3);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 1);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 0);
	BOOST_CHECK(ssl->getTotalCertificates() == 0);
	BOOST_CHECK(ssl->getTotalCertificateRequests() == 0);
	BOOST_CHECK(ssl->getTotalCertificateVerifies() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 4);
}

BOOST_AUTO_TEST_CASE (test11) // Change cipher specs message 
{
	Packet packet("../ssl/packets/packet16.pcap", 66);

        auto flow = SharedPointer<Flow>(new Flow());
	
	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

        flow->packet = const_cast<Packet*>(&packet);
        ssl->processFlow(flow.get());

	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

	// The version should be set on previous packets not on a change cipher spec
	BOOST_CHECK(info->getVersion() == 0);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(ssl->getTotalHandshakes() == 0);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 1);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 0);
	BOOST_CHECK(ssl->getTotalCertificates() == 0);
	BOOST_CHECK(ssl->getTotalCertificateRequests() == 0);
	BOOST_CHECK(ssl->getTotalCertificateVerifies() == 0);
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 1);
}

BOOST_AUTO_TEST_CASE (test12) // Finish handshake
{
	Packet packet("../ssl/packets/packet17.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

	// The version should be set on previous packets not on a change cipher spec
	BOOST_CHECK(info->getVersion() == TLS1_2_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(ssl->getTotalHandshakes() == 1);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 0);
	BOOST_CHECK(ssl->getTotalCertificates() == 0);
	BOOST_CHECK(ssl->getTotalCertificateRequests() == 0);
	BOOST_CHECK(ssl->getTotalCertificateVerifies() == 0);
	BOOST_CHECK(ssl->getTotalServerDones() == 0);
	BOOST_CHECK(ssl->getTotalRecords() == 1);
}

BOOST_AUTO_TEST_CASE (test13) // split last record in another packet 
{
	Packet packet("../ssl/packets/packet18.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

	// The version should be set on previous packets not on a change cipher spec
	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(ssl->getTotalHandshakes() == 2);
	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalCertificateRequests() == 0);
}

BOOST_AUTO_TEST_CASE (test14) // Return the issuer from the cert
{
	Packet packet("../ssl/packets/packet19.pcap");

	// enable dynamic memory
	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	Flow *flow = ssl->getCurrentFlow();

	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->issuer != nullptr);

        std::string cad("Let's Encrypt Authority X3");

        BOOST_CHECK(cad.compare(info->issuer->getName()) == 0);

	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 1);
}

BOOST_AUTO_TEST_CASE (test15) // Return the issuer from the cert from google
{
	Packet packet("../ssl/packets/packet20.pcap");

	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	BOOST_CHECK(ssl->getTotalBytes() == 1430);

	Flow *flow = ssl->getCurrentFlow();
	
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->issuer != nullptr);

        std::string cad("Google Internet Authority");

        BOOST_CHECK(cad.compare(info->issuer->getName()) == 0);

	BOOST_CHECK(info->getVersion() == TLS1_1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 0); 

	{
		RedirectOutput r;

        	flow->serialize(r.cout);
        	flow->showFlowInfo(r.cout);
        	r.cout << *(info.get());
	}

        JsonFlow j;
        info->serialize(j);
}

BOOST_AUTO_TEST_CASE (test16) // Return the issuer from the cert 
{
	Packet packet("../ssl/packets/packet21.pcap");

	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	BOOST_CHECK(ssl->getTotalBytes() == 1460);

	Flow *flow = ssl->getCurrentFlow();
	
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->issuer != nullptr);

        std::string cad("Go Daddy Secure Certificate Authority - G2");

        BOOST_CHECK(cad.compare(info->issuer->getName()) == 0);

	BOOST_CHECK(info->getVersion() == TLS1_2_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 0); 
}

BOOST_AUTO_TEST_CASE (test17) // Tor certificate
{
	Packet packet("../ssl/packets/packet22.pcap");

	ssl->setDynamicAllocatedMemory(true);

	inject(packet);

	BOOST_CHECK(ssl->getTotalBytes() == 929);

	Flow *flow = ssl->getCurrentFlow();
	
	SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->issuer != nullptr);

        std::string cad("www.o2ihd54volj4icngap.com");

        BOOST_CHECK(cad.compare(info->issuer->getName()) == 0);

	BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

	BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
	BOOST_CHECK(ssl->getTotalClientHellos() == 0);
	BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalCertificates() == 1);
	BOOST_CHECK(ssl->getTotalServerDones() == 1); 
	BOOST_CHECK(ssl->getTotalRecords() == 4);
}

BOOST_AUTO_TEST_CASE (test18) // Two flows share the same issuer
{
	Packet packet1("../ssl/packets/packet21.pcap", 54);
	Packet packet2("../ssl/packets/packet21.pcap", 54);

       	auto flow1 = SharedPointer<Flow>(new Flow());
        auto flow2 = SharedPointer<Flow>(new Flow());

	flow1->setId(1); flow2->setId(2);
	// The flows are in the FlowManager
	flow_mng->addFlow(flow1);
	flow_mng->addFlow(flow2);

        ssl->setDynamicAllocatedMemory(true);

        flow1->packet = const_cast<Packet*>(&packet1);
        flow2->packet = const_cast<Packet*>(&packet2);

        ssl->processFlow(flow1.get());
        ssl->processFlow(flow2.get());

        BOOST_CHECK(ssl->getTotalBytes() == 1460 * 2);

        SharedPointer<SSLInfo> info1 = flow1->getSSLInfo();
        SharedPointer<SSLInfo> info2 = flow2->getSSLInfo();
        BOOST_CHECK(info1 != nullptr);
        BOOST_CHECK(info2 != nullptr);
        BOOST_CHECK(info1->issuer != nullptr);
        BOOST_CHECK(info1->issuer == info2->issuer);

        std::string cad("Go Daddy Secure Certificate Authority - G2");

        BOOST_CHECK(cad.compare(info1->issuer->getName()) == 0);

        GenericMapType *issuer_c = ssl->getIssuerMap();

        BOOST_CHECK(issuer_c->size() == 1);

	auto item = issuer_c->begin();

        BOOST_CHECK((*item).second.hits == 2);
        BOOST_CHECK((*item).second.sc == info1->issuer);
        BOOST_CHECK((*item).second.sc == info2->issuer);

	ssl->releaseCache();
       
	// Check the effect of release 
	BOOST_CHECK(issuer_c->size() == 0);
	BOOST_CHECK(info1->issuer == nullptr);
	BOOST_CHECK(info2->issuer == nullptr);
        BOOST_CHECK(flow1->getSSLInfo() == nullptr);
        BOOST_CHECK(flow2->getSSLInfo() == nullptr);

	// Inject again the two flows
        ssl->processFlow(flow1.get());
        ssl->processFlow(flow2.get());
        
	BOOST_CHECK(issuer_c->size() == 1);
}

BOOST_AUTO_TEST_CASE (test19)
{
        Packet packet("../ssl/packets/packet23.pcap");

        ssl->setDynamicAllocatedMemory(true);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 1234);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->issuer != nullptr);

        std::string issuer("Oracle canada, Inc.");

        BOOST_CHECK(issuer.compare(info->issuer->getName()) == 0);

        BOOST_CHECK(info->getVersion() == TLS1_2_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
        BOOST_CHECK(ssl->getTotalServerDones() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 1);
}

BOOST_AUTO_TEST_CASE (test20)
{
        Packet packet("../ssl/packets/packet24.pcap");

        ssl->setDynamicAllocatedMemory(true);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 1460);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

        std::string issuer("www.valuecommerce.ne.jp");

        BOOST_CHECK(info->issuer != nullptr);
        BOOST_CHECK(issuer.compare(info->issuer->getName()) == 0);

        BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
        BOOST_CHECK(ssl->getTotalServerDones() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 2);
}

BOOST_AUTO_TEST_CASE (test21)
{
        Packet packet("../ssl/packets/packet25.pcap");

        ssl->setDynamicAllocatedMemory(true);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 1460);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

        std::string issuer("www.highbeam.com");

        BOOST_CHECK(info->issuer != nullptr);
        BOOST_CHECK(issuer.compare(info->issuer->getName()) == 0);

        BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
        BOOST_CHECK(ssl->getTotalServerDones() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 1);
}

BOOST_AUTO_TEST_CASE (test22)
{
        Packet packet("../ssl/packets/packet28.pcap");

        ssl->setDynamicAllocatedMemory(true);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 709);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

        std::string issuer("localhost");

        BOOST_CHECK(info->issuer != nullptr);
        BOOST_CHECK(issuer.compare(info->issuer->getName()) == 0);

        BOOST_CHECK(info->getVersion() == TLS1_2_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);
	// Check the cipher, in this case is C030 == TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	BOOST_CHECK(info->getCipher() == 0xCCA9);

        BOOST_CHECK(ssl->getTotalHandshakes() == 4);
        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl->getTotalServerKeyExchanges() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
        BOOST_CHECK(ssl->getTotalCertificateRequests() == 0);
        BOOST_CHECK(ssl->getTotalCertificateVerifies() == 0);
        BOOST_CHECK(ssl->getTotalServerDones() == 1);
        BOOST_CHECK(ssl->getTotalRecords() == 4);
}

BOOST_AUTO_TEST_CASE (test23)
{
        Packet packet("../ssl/packets/packet29.pcap");

        ssl->setDynamicAllocatedMemory(true);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 686);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->issuer == nullptr);

        BOOST_CHECK(info->getVersion() == TLS1_3_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

        BOOST_CHECK(ssl->getTotalHandshakes() == 1);
        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerKeyExchanges() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);
        BOOST_CHECK(ssl->getTotalCertificateRequests() == 0);
        BOOST_CHECK(ssl->getTotalCertificateVerifies() == 0);
        BOOST_CHECK(ssl->getTotalServerDones() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 5);
	BOOST_CHECK(ssl->getTotalDatas() == 4); // 4 Encrypted pdus
}

BOOST_AUTO_TEST_CASE (test24)
{
        Packet packet("../ssl/packets/packet30.pcap");

        ssl->setDynamicAllocatedMemory(true);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 1448);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->issuer == nullptr);

        BOOST_CHECK(info->getVersion() == TLS1_2_VERSION);

        BOOST_CHECK(info->getHeartbeat() == false);
	BOOST_CHECK(info->getCipher() == 0xC028);

        BOOST_CHECK(ssl->getTotalHandshakes() == 2);
        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerKeyExchanges() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
        BOOST_CHECK(ssl->getTotalCertificateRequests() == 0);
        BOOST_CHECK(ssl->getTotalCertificateVerifies() == 0);
        BOOST_CHECK(ssl->getTotalServerDones() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 2);
        BOOST_CHECK(ssl->getTotalDatas() == 0); 
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ipv6_ssl_suite_static, StackIPv6SSLtest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet("../ssl/packets/packet26.pcap");

	ssl->increaseAllocatedMemory(1);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 70);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

        BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);
        BOOST_CHECK(ssl->getTotalServerDones() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 1);
}

BOOST_AUTO_TEST_CASE (test02)
{
        Packet packet("../ssl/packets/packet27.pcap");

	ssl->increaseAllocatedMemory(1);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 1220);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);

        std::string issuer("CA Cert Signing Authority");

        BOOST_CHECK(info->issuer != nullptr);
        BOOST_CHECK(issuer.compare(info->issuer->getName()) == 0);

        BOOST_CHECK(info->getVersion() == TLS1_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
        BOOST_CHECK(ssl->getTotalServerDones() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 2);
}

BOOST_AUTO_TEST_CASE (test03)
{
        Packet packet("../ssl/packets/packet31.pcap");

        ssl->increaseAllocatedMemory(1);

        inject(packet);

        BOOST_CHECK(ssl->getTotalBytes() == 2115);

        Flow *flow = ssl->getCurrentFlow();

        SharedPointer<SSLInfo> info = flow->getSSLInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host_name == nullptr);
        BOOST_CHECK(info->issuer != nullptr);

        std::string issuer("Lilawelt");

        BOOST_CHECK(issuer.compare(info->issuer->getName()) == 0);

        BOOST_CHECK(info->getVersion() == TLS1_2_VERSION);
        BOOST_CHECK(info->getHeartbeat() == false);

        BOOST_CHECK(ssl->getTotalHandshakes() == 4);
        BOOST_CHECK(ssl->getTotalChangeCipherSpecs() == 0);
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerKeyExchanges() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
        BOOST_CHECK(ssl->getTotalCertificateRequests() == 1);
        BOOST_CHECK(ssl->getTotalCertificateVerifies() == 0);
        BOOST_CHECK(ssl->getTotalServerDones() == 1);
        BOOST_CHECK(ssl->getTotalRecords() == 4);
        BOOST_CHECK(ssl->getTotalDatas() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
