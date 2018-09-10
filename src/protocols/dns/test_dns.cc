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
#include "test_dns.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE dnstest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(dns_test_suite, StackDNStest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet;

        BOOST_CHECK(dns->getTotalPackets() == 0);
        BOOST_CHECK(dns->getTotalBytes() == 0);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dns->getTotalAllowQueries() == 0);
	BOOST_CHECK(dns->getTotalBanQueries() == 0);
	BOOST_CHECK(dns->processPacket(packet) == true);
	
	CounterMap c = dns->getCounters();
}

BOOST_AUTO_TEST_CASE (test02)
{
        Packet packet("../dns/packets/packet01.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 56);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);
	BOOST_CHECK(ip->getPacketLength() == 56);

	BOOST_CHECK(udp->getLength() == 36);
        BOOST_CHECK(udp->getTotalPackets() == 1);
        BOOST_CHECK(udp->getTotalBytes() == 36);
        BOOST_CHECK(udp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(udp->getTotalValidPackets() == 1);
        // dns 
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 28);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dns->getTotalAllowQueries() == 1);
	BOOST_CHECK(dns->getTotalBanQueries() == 0);

	BOOST_CHECK(dns->getTotalQueries() == 1);
	BOOST_CHECK(dns->getTotalResponses() == 0);
	BOOST_CHECK(dns->getTotalQuestions() == 1);
	BOOST_CHECK(dns->getTotalAnswers() == 0);

	Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

	BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_A));	

	std::string domain("www.as.com");

	BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
}

// Test the ban functionality for avoid unwanted domains
BOOST_AUTO_TEST_CASE (test03)
{
        Packet packet("../dns/packets/packet01.pcap");

	auto host_ban_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
	auto host_name = SharedPointer<DomainName>(new DomainName("unwanted domain", ".com"));

	dns->setDomainNameBanManager(host_ban_mng);
	host_ban_mng->addDomainName(host_name);

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 56);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // dns
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 28);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dns->getTotalAllowQueries() == 0);
	BOOST_CHECK(dns->getTotalBanQueries() == 1);

	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

	Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
	SharedPointer<DNSInfo> info = flow->getDNSInfo();
        BOOST_CHECK(info->name == nullptr);
        BOOST_CHECK(info->isBanned() == true);
}

BOOST_AUTO_TEST_CASE (test04)
{
        Packet packet("../dns/packets/packet02.pcap");

	inject(packet);

	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SRV));
}

BOOST_AUTO_TEST_CASE (test05)
{
        Packet packet("../dns/packets/packet03.pcap");

	inject(packet);

	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SOA));
}

BOOST_AUTO_TEST_CASE (test06)
{
        Packet packet("../dns/packets/packet04.pcap");

	inject(packet);

	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 2);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SOA));

	std::string domain("bgskrot.ex");
	BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test07)
{
        Packet packet("../dns/packets/packet05.pcap");

	inject(packet);

	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_AAAA));

        std::string domain("ssl.google-analytics.com");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test08)
{
        Packet packet("../dns/packets/packet06.pcap");

	inject(packet);

        BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DNSKEY));

        std::string domain("<Root>");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test09)
{
        Packet packet("../dns/packets/packet07.pcap");

	inject(packet);

	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DNSKEY));

        std::string domain("ietf.org");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test10)
{
        Packet packet("../dns/packets/packet07.pcap");

	inject(packet);

	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

	Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);

	dns->releaseCache();
	
        BOOST_CHECK(flow->layer7info == nullptr);
	BOOST_CHECK(flow->getDNSInfo() == nullptr);
}

// Process query and response
BOOST_AUTO_TEST_CASE (test11)
{
        Packet packet1("../dns/packets/packet08.pcap");
        Packet packet2("../dns/packets/packet09.pcap");
        
	inject(packet1);
	
	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

	inject(packet2);
	
	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 1);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 7);

        Flow *flow = udp->getCurrentFlow();
	//show();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

	int i = std::distance((*dom.get()).begin(), (*dom.get()).end()); 
	BOOST_CHECK(i == 0);// There is no DomainNameManager so the IPs are not extracted
}

// Process query and response and IP address extraction
BOOST_AUTO_TEST_CASE (test12)
{
        Packet packet1("../dns/packets/packet08.pcap");
        Packet packet2("../dns/packets/packet09.pcap");

        auto dom_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        auto dom_name = SharedPointer<DomainName>(new DomainName("Youtube test", ".youtube.com"));

        dns->setDomainNameManager(dom_mng);
        dom_mng->addDomainName(dom_name);

	inject(packet1);
	inject(packet2);

	BOOST_CHECK(dns->getTotalEvents() == 1);

        Flow *flow = udp->getCurrentFlow();
        //show();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

	std::set<std::string> ips {
		{ "74.125.24.139" },	
		{ "74.125.24.138" },	
		{ "74.125.24.100" },	
		{ "74.125.24.101" },	
		{ "74.125.24.102" },	
		{ "74.125.24.113" },
                { "video-stats.l.google" }
	};
        int i = 0;
	std::set<std::string>::iterator it = ips.end();

        for (auto &ip: *dom) {
               	BOOST_CHECK( ips.find(ip) != it);
		++i; 
        }
        BOOST_CHECK( i == 7);
        
	dns->setDomainNameManager(nullptr);
}

BOOST_AUTO_TEST_CASE (test13)
{
        Packet packet1("../dns/packets/packet08.pcap");
        Packet packet2("../dns/packets/packet09.pcap");

	inject(packet1);

        Flow *flow = udp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getDNSInfo() != nullptr);

	dns->releaseCache();

	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getDNSInfo() == nullptr);

	inject(packet2);
	
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->getDNSInfo() != nullptr);
}

BOOST_AUTO_TEST_CASE (test14)
{
        Packet packet1("../dns/packets/packet12.pcap");
        Packet packet2("../dns/packets/packet13.pcap");

        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".google.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet1);
        inject(packet2);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

	BOOST_CHECK(dom->name != nullptr);
	//std::cout << dom->name->getName() << std::endl;
        std::string domain("ds95g6opkyh8s8ldq1xqrucrnlzbdrii8o6r1zvggtssutwdvtyh5an27ujrkt4.99b9vbsqmrsa9jjylcoglpeemtm3uahoomlisrs6oz4gntdlul1te.99b9vbsqm");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);

	BOOST_CHECK(dns->getTotalEvents() == 1);
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::DNS_LONG_NAME);
}

BOOST_AUTO_TEST_CASE (test15)
{
        Packet packet1("../dns/packets/packet10.pcap");
        Packet packet2("../dns/packets/packet11.pcap");

        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".adobe.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet1);
	
	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        inject(packet2);
	
	BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 1);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 6);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

	BOOST_CHECK(dns->getTotalEvents() == 1);

        std::set<std::string> items {
                { "wwwimages.wip4e.com" },
                { "wwwimages.adobe.com.edgesuite.net" },
                { "wwwimages.adobe.com.edgesuite.net.globalredir.akadns" },
		{ "a1953.x.akamaie.com.edgesuite.net.globalredir.akadns" },
                { "150.199.100.104" },
                { "150.199.100.101" }
        };
        int i = 0;
        std::set<std::string>::iterator it = items.end();

        for (auto &ip: *dom) {
                BOOST_CHECK( items.find(ip) != it);
                ++i;
        }
        BOOST_CHECK(i == 6);
}

BOOST_AUTO_TEST_CASE (test16)
{
        Packet packet("../dns/packets/packet14.pcap");

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_IXFR));
        std::string domain("etas.com");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test17) // malformed dns
{
        Packet packet("../dns/packets/packet14.pcap", 42);

	packet.setPayloadLength(8);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        dns->processFlow(flow.get());

        BOOST_CHECK(flow->layer7info == nullptr);

	BOOST_CHECK(dns->getTotalEvents() == 1);
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::DNS_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test18) // malformed query
{
        Packet packet("../dns/packets/packet08.pcap", 42);

	packet.setPayloadLength(packet.getLength() - 4);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        dns->processFlow(flow.get());

        SharedPointer<DNSInfo> info = flow->getDNSInfo();
	BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->name == nullptr);

	BOOST_CHECK(dns->getTotalEvents() == 1);
	BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::DNS_BOGUS_HEADER); 
}

BOOST_AUTO_TEST_CASE (test19) // name server 
{
        Packet packet("../dns/packets/packet15.pcap");

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> info = flow->getDNSInfo();

	BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_NS));
}

BOOST_AUTO_TEST_CASE (test20) // txt record to google
{
        Packet packet("../dns/packets/packet16.pcap");

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> info = flow->getDNSInfo();

	BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_TXT));
}

BOOST_AUTO_TEST_CASE (test21) // loc record to google
{
        Packet packet("../dns/packets/packet17.pcap");

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> info = flow->getDNSInfo();

	BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_LOC));
}

BOOST_AUTO_TEST_CASE (test22) // banned
{
        Packet packet("../dns/packets/packet08.pcap");

	packet.setPayloadLength(20);

        auto flow = SharedPointer<Flow>(new Flow());
	auto info = SharedPointer<DNSInfo>(new DNSInfo());

	flow->layer7info = info;

	info->setIsBanned(true);

        flow->packet = const_cast<Packet*>(&packet);
        dns->processFlow(flow.get());

	BOOST_CHECK(info->isBanned() == true);
}

BOOST_AUTO_TEST_CASE (test23)
{
        Packet packet("../dns/packets/packet18.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 54);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // dns 
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 26);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);
	BOOST_CHECK(dns->getTotalAllowQueries() == 1);
	BOOST_CHECK(dns->getTotalBanQueries() == 0);

	Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

	BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_CNAME));	

}

BOOST_AUTO_TEST_CASE (test24) // dns response with no respond block
{
        Packet packet("../dns/packets/packet19.pcap", 42);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        dns->processFlow(flow.get());

        // dns 
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 23);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);

	BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

	BOOST_CHECK(dom != nullptr);

	std::string name("<Root>");
	BOOST_CHECK(name.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test25) // Extract the information of a TXT record with 6 responses
{
        Packet packet("../dns/packets/packet20.pcap");

        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".cisco.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dns->getTotalEvents() == 1);

        std::set<std::string> items {
                { "docusign=95052c5f-a421-4594-9227-02ad2d86dfbe" },
                { "google-site-verification=K2w--6oeqrFjHfYtTsYyd2tFw7OQd6g5HJDC9UAI8Jk" },
                { "v=spf1 ip4:173.37.147.224/27 ip4:173.37.142.64/26 ip4:173.38.212.128/27 ip4:173.38.203.0/24"
		  " ip4:64.100.0.0/14 ip4:72.163.7.160/27 ip4:72.163.197.0/24 ip4:144.254.0.0/16 ip4:66.187.208.0/20 ip4:173.37.86.0/24"
		  " ip4:64.104.206.0/24 ip4:64.104.15.96/27 ip4:64.102.19.192/26 ip4:144.254.15.96/27"
		  " ip4:173.36.137.128/26 ip4:173.36.130.0/24 mx:res.cisco.com mx:sco.cisco.com ~all" },
                { "MS=ms65960035" },
                { "926723159-3188410" },
                { "docusign=5e18de8e-36d0-4a8e-8e88-b7803423fa2f" }
        };
        int i = 0;
        std::set<std::string>::iterator it = items.end();

	for (auto &item: *dom) {
                BOOST_CHECK(items.find(item) != it);
		++i;
	}
        BOOST_CHECK(i == 6);
}

BOOST_AUTO_TEST_CASE (test26) // Extract the information of a TXT record with 1 responses
{
        Packet packet("../dns/packets/packet21.pcap");

        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".facebook.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dns->getTotalEvents() == 1);

	// Facebook spf record
	std::string txt_record("v=spf1 ip4:69.63.179.25 ip4:69.63.178.128/25 ip4:69.63.184.0/25 "
		"ip4:66.220.144.128/25 ip4:66.220.155.0/24 ip4:69.171.232.0/24 i"
		"p4:66.220.157.0/25 ip4:69.171.244.0/24 mx -all");
	
	auto item = (*dom).begin();

	BOOST_CHECK(txt_record.compare(*item) == 0);
}

BOOST_AUTO_TEST_CASE (test27) // Corrupted awnser block 
{
        Packet packet("../dns/packets/packet21.pcap");

	packet.setPayloadLength(packet.getLength() - 1);

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dns->getTotalEvents() == 0);
        BOOST_CHECK(udp->getTotalEvents() == 1);
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::UDP_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test28) // Corrupted length of TXT block 
{
        Packet packet("../dns/packets/packet21.pcap");
        uint8_t buffer[1500];
        std::memcpy(&buffer, packet.getPayload(), packet.getLength());

	// Corrupt the length of the txt record
        buffer[87] = 0x0f;
        buffer[88] = 0xff;
        Packet packet_mod(&buffer[0], packet.getLength());

        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".facebook.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet_mod);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
       
	BOOST_CHECK(dns->getTotalEvents() == 2); // one of the anomaly and the other the match
        BOOST_CHECK(udp->getTotalEvents() == 0);
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::DNS_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test29) // Corrupted the data length of TXT block 
{
        Packet packet("../dns/packets/packet21.pcap");
        uint8_t buffer[1500];
        std::memcpy(&buffer, packet.getPayload(), packet.getLength());

        // Corrupt the data length of the second txt record
       	buffer[217] = 0xff; 
	Packet packet_mod(&buffer[0], packet.getLength());

        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".facebook.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet_mod);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dns->getTotalEvents() == 2); // one of the anomaly and the other the match
        BOOST_CHECK(udp->getTotalEvents() == 0);
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::DNS_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test30) // Extract the information of a TXT record with 2 responses
{
        Packet packet("../dns/packets/packet22.pcap");

        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".twitter.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dns->getTotalEvents() == 1);

        std::set<std::string> items {
                { "google-site-verification=h6dJIv0HXjLOkGAotLAWEzvoi9SxqP4vjpx98vrCvvQ" },
                { "v=spf1 ip4:199.16.156.0/22 ip4:199.59.148.0/22 ip4:8.25.194.0/23 ip4:8.25.196.0/23 "
		  "ip4:204.92.114.203 ip4:204.92.114.204/31 ip4:23.21.83.90 include:_spf.google.com"
		  " include:_thirdparty.twitter.com -all"}
        };
        int i = 0;
        std::set<std::string>::iterator it = items.end();

        for (auto &item: *dom) {
                BOOST_CHECK(items.find(item) != it);
                ++i;
        }
        BOOST_CHECK(i == 2);
}

BOOST_AUTO_TEST_CASE (test31) // DNS query with no data, bogus
{
        Packet packet("../dns/packets/packet23.pcap");

        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".twitter.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(udp->getTotalEvents() == 1);
        BOOST_CHECK(dns->getTotalEvents() == 1);

        BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalAnswers() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);

        BOOST_CHECK(dom != nullptr);
	BOOST_CHECK(dom->name == nullptr);
}

BOOST_AUTO_TEST_CASE (test32) // DNS response with no data, bogus
{
        Packet packet("../dns/packets/packet24.pcap");

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dns->getTotalQueries() == 0);
        BOOST_CHECK(dns->getTotalResponses() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 4); // There is original 4 answers
        BOOST_CHECK(dns->getTotalQuestions() == 1);

        BOOST_CHECK(dom != nullptr);
	BOOST_CHECK(dom->name == nullptr);
        
	BOOST_CHECK(dns->getTotalEvents() == 1); // anomaly DNS_BOGUS_HEADER 
        BOOST_CHECK(udp->getTotalEvents() == 1);
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::UDP_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test33) // DNS query with no data, bogus
{
        Packet packet("../dns/packets/packet25.pcap");

        inject(packet);

        Flow *flow = udp->getCurrentFlow();
        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalAnswers() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);

        BOOST_CHECK(dom != nullptr);
	BOOST_CHECK(dom->name == nullptr);
        
	BOOST_CHECK(dns->getTotalEvents() == 1); // anomaly DNS_BOGUS_HEADER 
        BOOST_CHECK(udp->getTotalEvents() == 1);
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::UDP_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test34) // DNS query with no data, bogus
{
        Packet packet("../dns/packets/packet24.pcap", 42);

        auto flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        dns->processFlow(flow.get());

        BOOST_CHECK(flow != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

        BOOST_CHECK(dns->getTotalQueries() == 0);
        BOOST_CHECK(dns->getTotalResponses() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 4);
        BOOST_CHECK(dns->getTotalQuestions() == 1);

        BOOST_CHECK(dom != nullptr);
        BOOST_CHECK(dom->name == nullptr);

        BOOST_CHECK(dns->getTotalEvents() == 1); // anomaly DNS_BOGUS_HEADER 
        BOOST_CHECK(udp->getTotalEvents() == 0);
        BOOST_CHECK(flow->getPacketAnomaly() == PacketAnomalyType::DNS_BOGUS_HEADER);
}

BOOST_AUTO_TEST_CASE (test35)
{
        Packet packet("../dns/packets/packet26.pcap");

	inject(packet);

        BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_ANY));
}

BOOST_AUTO_TEST_CASE (test36)
{
        Packet packet("../dns/packets/packet27.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 40);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // dns
        BOOST_CHECK(dns->getTotalPackets() == 0);
        BOOST_CHECK(dns->getTotalBytes() == 0);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 1);

        BOOST_CHECK(dns->getTotalQueries() == 0);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 0);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info == nullptr);
}

BOOST_AUTO_TEST_CASE (test37)
{
        Packet packet("../dns/packets/packet28.pcap");

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 48);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // dns
        BOOST_CHECK(dns->getTotalPackets() == 0);
        BOOST_CHECK(dns->getTotalBytes() == 0);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 1);

        BOOST_CHECK(dns->getTotalQueries() == 0);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 3228); // corrupted value
        BOOST_CHECK(dns->getTotalAnswers() == 40600); // corrupted value

        Flow *flow = udp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info == nullptr);
}

BOOST_AUTO_TEST_CASE (test38)
{
        Packet packet("../dns/packets/packet29.pcap");

	SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 243);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // dns
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 215);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);
        BOOST_CHECK(dns->getTotalValidPackets() == 1);

        BOOST_CHECK(dns->getTotalQueries() == 0);
        BOOST_CHECK(dns->getTotalResponses() == 1);
        BOOST_CHECK(dns->getTotalQuestions() == 1); // corrupted value
        BOOST_CHECK(dns->getTotalAnswers() == 5); // corrupted value

        Flow *flow = udp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> info = flow->getDNSInfo();

	BOOST_CHECK(info->matched_domain_name == dom_name);
        //BOOST_CHECK(dns->getTotalEvents() == 1);

        std::set<std::string> items {
                { "1.1.1.100" }
        };
        std::set<std::string>::iterator it = items.end();
        int i = 0;
        for (auto &item: *info) {
                BOOST_CHECK(items.find(item) != it);
                ++i;
        }
        BOOST_CHECK(i == 1);
}

BOOST_AUTO_TEST_CASE (test39)
{
        Packet packet("../dns/packets/packet30.pcap");

        inject(packet);

        BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DS));

        std::string domain("ietf.org");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test40)
{
        Packet packet("../dns/packets/packet31.pcap");

        inject(packet);

        BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();
        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SSHFP));

        std::string domain("monadic.cynic.net");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test41)
{
        Packet packet("../dns/packets/packet29.pcap");

	SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", ".com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 243);
        BOOST_CHECK(ip->getTotalInvalidPackets() == 0);

        // dns
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 215);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);
        BOOST_CHECK(dns->getTotalValidPackets() == 1);

        BOOST_CHECK(dns->getTotalQueries() == 0);
        BOOST_CHECK(dns->getTotalResponses() == 1);
        BOOST_CHECK(dns->getTotalQuestions() == 1); // corrupted value
        BOOST_CHECK(dns->getTotalAnswers() == 5); // corrupted value

        Flow *flow = udp->getCurrentFlow();
	BOOST_CHECK(flow != nullptr);
	BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> info = flow->getDNSInfo();

	BOOST_CHECK(info->matched_domain_name == dom_name);
        //BOOST_CHECK(dns->getTotalEvents() == 1);

        std::set<std::string> items {
                { "1.1.1.100" }
        };
        std::set<std::string>::iterator it = items.end();
        int i = 0;
        for (auto &item: *info) {
                BOOST_CHECK(items.find(item) != it);
                ++i;
        }
        BOOST_CHECK(i == 1);
}

/* Just used for check the speed of push_back against emplace_back
BOOST_AUTO_TEST_CASE (test15)
{
        SharedPointer<DNSInfo> dom = SharedPointer<DNSInfo>(new DNSInfo());

        std::vector<std::string> items {
                { "wwwimages.wip4" },
                { "wwwimages.adobe.com.edgesuite.net" },
                { "wwwimages.adobe.com.edgesuite.net.globalredir.akadns" },
                { "a1953.x.akamai" },
                { "150.199.100.104" },
                { "150.199.100.101" }
        };

	for (int j = 0 ; j < 2000000; ++j ) {
	 	for (int i = 0; i < 6; ++i) {
			dom->addIPAddress(items[i].c_str());
		}
	}
}
*/

BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(ipv6_dns_test_suite, StackIPv6DNStest)

BOOST_AUTO_TEST_CASE (test01)
{
        Packet packet("../dns/packets/packet32.pcap");

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 97 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(udp->getTotalPackets() == 1);
        BOOST_CHECK(udp->getTotalBytes() == 89 + 8);
        BOOST_CHECK(udp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(udp->getTotalValidPackets() == 1);
        // dns 
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 89);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);
        BOOST_CHECK(dns->getTotalAllowQueries() == 1);
        BOOST_CHECK(dns->getTotalBanQueries() == 0);

        BOOST_CHECK(dns->getTotalQueries() == 1);
        BOOST_CHECK(dns->getTotalResponses() == 0);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 0);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> dom = flow->getDNSInfo();

	BOOST_CHECK(dom->name != nullptr);

        BOOST_CHECK(dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_PTR));

        std::string query("a.e.9.6.7.0.e.f.f.f.7.9.0.6.2.0.1.0.0.0.0.0.0.0.7.0.5.0.e.f.f.3.ip6.int");

        BOOST_CHECK(query.compare(dom->name->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test02)
{
        Packet packet("../dns/packets/packet33.pcap");
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("test", "google.com"));

        dns->setDomainNameManager(dm);
        dm->addDomainName(dom_name);

        inject(packet);

        // Check the results
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidPackets() == 1);
        BOOST_CHECK(ip6->getTotalBytes() == 68 + 40);
        BOOST_CHECK(ip6->getTotalInvalidPackets() == 0);

        BOOST_CHECK(udp->getTotalPackets() == 1);
        BOOST_CHECK(udp->getTotalBytes() == 60 + 8);
        BOOST_CHECK(udp->getTotalInvalidPackets() == 0);
        BOOST_CHECK(udp->getTotalValidPackets() == 1);
        // dns 
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 60);
        BOOST_CHECK(dns->getTotalInvalidPackets() == 0);
        BOOST_CHECK(dns->getTotalAllowQueries() == 0);
        BOOST_CHECK(dns->getTotalBanQueries() == 0);

        BOOST_CHECK(dns->getTotalQueries() == 0);
        BOOST_CHECK(dns->getTotalResponses() == 1);
        BOOST_CHECK(dns->getTotalQuestions() == 1);
        BOOST_CHECK(dns->getTotalAnswers() == 1);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->layer7info != nullptr);
        SharedPointer<DNSInfo> info = flow->getDNSInfo();

        BOOST_CHECK(info->name != nullptr);

        BOOST_CHECK(info->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_AAAA));

        std::string query("www.google.com");

        BOOST_CHECK(query.compare(info->name->getName()) == 0);

        BOOST_CHECK(info->matched_domain_name == dom_name);

        std::set<std::string> items {
                { "2a00:1450:4001:80f::1011" }
        };
        std::set<std::string>::iterator it = items.end();
        int i = 0;
        for (auto &item: *info) {
                BOOST_CHECK(items.find(item) != it);
                ++i;
        }
        BOOST_CHECK(i == 1);
}

BOOST_AUTO_TEST_SUITE_END( )
