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
#include "test_ipset.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE ipsettest
#endif

#include <boost/test/unit_test.hpp>

#ifdef HAVE_BLOOMFILTER
using namespace boost::bloom_filters;
#endif

using namespace aiengine;

BOOST_AUTO_TEST_SUITE (test_suite_ipset_1)

BOOST_AUTO_TEST_CASE (test01)
{
	auto ipset = IPSetPtr(new IPSet());

	BOOST_CHECK(ipset->getTotalIPs() == 0);
	BOOST_CHECK(ipset->getTotalLookups() == 0);
	
	BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
	BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
	BOOST_CHECK(ipset->getFalsePositiveRate() == 0);
	BOOST_CHECK(ipset->getTotalBytes() == 0);
}

BOOST_AUTO_TEST_CASE (test02)
{
        auto ipset = IPSetPtr(new IPSet());
	IPAddress addr;

        BOOST_CHECK(ipset->getTotalIPs() == 0);
        BOOST_CHECK(ipset->getTotalLookups() == 0);

	ipset->addIPAddress("192.168.1.1");
	
	BOOST_CHECK(ipset->getTotalBytes() == 4);
	ipset->addIPAddress("this is not an ip 192.168.1.1");

        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
	BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
	BOOST_CHECK(ipset->getTotalLookupsOut() == 0);

	addr.setDestinationAddress(inet_addr("192.168.1.2"));

	BOOST_CHECK(ipset->lookupIPAddress(addr) == false);
        BOOST_CHECK(ipset->getTotalLookups() == 1);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 1);

	addr.setDestinationAddress(inet_addr("192.168.1.1"));

	BOOST_CHECK(ipset->lookupIPAddress(addr) == true);
        BOOST_CHECK(ipset->getTotalLookups() == 2);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 1);

	ipset->clear();

        BOOST_CHECK(ipset->getTotalIPs() == 0);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
	BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
	BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
}

BOOST_AUTO_TEST_CASE (test03)
{
        auto ipset1 = IPSetPtr(new IPSet("one ipset"));
        auto ipset2 = IPSetPtr(new IPSet("second ipset"));
	auto ipmng = IPSetManagerPtr(new IPSetManager());
	IPAddress addr;

        ipset1->addIPAddress("192.168.1.1");

	ipmng->addIPSet(ipset1);
	ipmng->addIPSet(ipset2);

	addr.setDestinationAddress(inet_addr("192.168.1.1"));
	BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
	BOOST_CHECK(ipmng->getMatchedIPSet() == ipset1);

	// ipmng->statistics("one ipset");

	BOOST_CHECK(ipmng->getTotalSets() == 2);
	ipmng->removeIPSet("one ipset");

	BOOST_CHECK(ipmng->lookupIPAddress(addr) == false);
	BOOST_CHECK(ipmng->getMatchedIPSet() == nullptr);
	
	BOOST_CHECK(ipmng->getTotalSets() == 1);

	{ 
		RedirectOutput r;

		ipmng->statistics("one ipset");
		ipmng->statistics("second ipset");
    	} 
}

BOOST_AUTO_TEST_CASE (test04)
{
        auto ipset1 = IPSetPtr(new IPSet());
        auto ipset2 = SharedPointer<IPSet>(new IPSet());
        auto ipmng = IPSetManagerPtr(new IPSetManager());
	IPAddress addr;

        ipset1->addIPAddress("192.168.1.1");
        ipset2->addIPAddress("10.1.1.1");
        ipset2->addIPAddress("10.1.1.2");
        ipset2->addIPAddress("10.1.1.21234");

        BOOST_CHECK(ipset1->getTotalIPs() == 1);
        BOOST_CHECK(ipset2->getTotalIPs() == 2);

	ipmng->addIPSet(ipset1);
        ipmng->addIPSet(ipset2);

	addr.setDestinationAddress(inet_addr("192.168.1.2"));
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == false);
        BOOST_CHECK(ipmng->getMatchedIPSet() == nullptr);
        
	addr.setDestinationAddress(inet_addr("192.168.1.1"));
	BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset1);

        BOOST_CHECK(ipset1->getTotalLookups() == 2);
        BOOST_CHECK(ipset1->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset1->getTotalLookupsOut() == 1);	
	BOOST_CHECK(ipset2->getTotalLookups() == 1);
        BOOST_CHECK(ipset2->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset2->getTotalLookupsOut() == 1);	
	
	addr.setDestinationAddress(inet_addr("10.1.1.2"));
	BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset2);
        
	BOOST_CHECK(ipset1->getTotalLookups() == 3);
        BOOST_CHECK(ipset1->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset1->getTotalLookupsOut() == 2);	
	BOOST_CHECK(ipset2->getTotalLookups() == 2);
        BOOST_CHECK(ipset2->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset2->getTotalLookupsOut() == 1);	
}

// Remove some ipsets
BOOST_AUTO_TEST_CASE (test05)
{
        auto ipset1 = SharedPointer<IPSet>(new IPSet());
        auto ipset2 = SharedPointer<IPSet>(new IPSet());
        auto ipset3 = SharedPointer<IPSet>(new IPSet());
        IPSetManagerPtr ipmng = IPSetManagerPtr(new IPSetManager());
	IPAddress addr;

        ipset1->addIPAddress("192.168.1.1");
        ipset2->addIPAddress("10.1.1.1");
        ipset2->addIPAddress("10.1.1.2");
        ipset3->addIPAddress("10.1.100.1");

        ipmng->addIPSet(ipset1);
        ipmng->addIPSet(ipset2);
        ipmng->addIPSet(ipset3);

	addr.setDestinationAddress(inet_addr("10.1.1.2"));
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset2);

	ipmng->removeIPSet(ipset2);

        BOOST_CHECK(ipmng->lookupIPAddress(addr) == false);
        BOOST_CHECK(ipmng->getMatchedIPSet() == nullptr);
}

BOOST_AUTO_TEST_CASE (test06)
{
        auto ipset = SharedPointer<IPSet>(new IPSet());
        auto ipmng = IPSetManagerPtr(new IPSetManager());
	IPAddress addr;

        ipset->addIPAddress("192.168.1.1");
        ipset->addIPAddress("10.1.1.1");
        ipset->addIPAddress("10.1.1.2");
        ipset->addIPAddress("10.1.100.1");

        ipmng->addIPSet(ipset);

	addr.setDestinationAddress(inet_addr("10.1.1.2"));
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset);

        ipset->removeIPAddress("192.168.1.1");

	addr.setDestinationAddress(inet_addr("192.168.1.1"));
        BOOST_CHECK(ipmng->lookupIPAddress("192.168.1.1") == false);
        BOOST_CHECK(ipmng->getMatchedIPSet() == nullptr);
}

BOOST_AUTO_TEST_CASE (test07)
{
        auto ipset = SharedPointer<IPSet>(new IPSet());
        auto ipmng = IPSetManagerPtr(new IPSetManager());

        ipset->addIPAddress("2000:aaaa:bbbb::7");
        ipset->addIPAddress("2000:aaaa:bbbb::8");

#if defined(__FREEBSD__)
	BOOST_CHECK(ipset->getTotalBytes() == 22 * 2);
#else	
	BOOST_CHECK(ipset->getTotalBytes() == 17 * 2);
#endif 
	ipmng->addIPSet(ipset);

        BOOST_CHECK(ipmng->lookupIPAddress("2000:aaaa:bbbb::7") == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset);

        ipset->removeIPAddress("2000:aaaa:bbbb::7");

        BOOST_CHECK(ipmng->lookupIPAddress("2000:aaaa:bbbb::7") == false);
        BOOST_CHECK(ipmng->getMatchedIPSet() == nullptr);

	IPAddress addr;

	struct sockaddr_in6 sa;
	char str[INET6_ADDRSTRLEN];

	inet_pton(AF_INET6, "2000:aaaa:bbbb:cccc::1245", &(sa.sin6_addr));
	addr.setDestinationAddress6(&(sa.sin6_addr));

        BOOST_CHECK(ipmng->lookupIPAddress(addr) == false);
        BOOST_CHECK(ipmng->getMatchedIPSet() == nullptr);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(test_suite_ipset_2, StackTCPIPSetTest)

BOOST_AUTO_TEST_CASE (test01)
{
	Packet packet("../protocols/ssl/packets/packet02.pcap");

        auto ipset = SharedPointer<IPSet>(new IPSet("new ipset"));
	auto ipset_mng = IPSetManagerPtr(new IPSetManager());

	ipset_mng->addIPSet(ipset);
	ipset->addIPAddress("72.21.211.223");

	tcp->setIPSetManager(ipset_mng);

	inject(packet);

        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 1);

        BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);

	tcp->setIPSetManager(SharedPointer<IPSetManager>(new IPSetManager()));	
	tcp->setIPSetManager(nullptr);
	BOOST_CHECK(tcp->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_CASE (test02)
{
	Packet packet("../protocols/ssl/packets/packet02.pcap");

	auto ipset_mng = IPSetManagerPtr(new IPSetManager());
        auto ipset = IPSetPtr(new IPSet("new ipset"));

	ipset_mng->addIPSet(ipset);
        ipset->addIPAddress("72.21.211.3");

        tcp->setIPSetManager(ipset_mng);
	
	inject(packet);

        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 1);

        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 1);

	ipset_mng->resetStatistics();
}

// Test the addition of a RegexManager on the IPSet functionality with TCP traffic
BOOST_AUTO_TEST_CASE (test03)
{
	Packet packet("../protocols/ssl/packets/packet02.pcap");

	auto rmng = RegexManagerPtr(new RegexManager());
	auto r = SharedPointer<Regex>(new Regex("ssl regex", "^\x16\x03.*$"));
        auto ipset_mng = IPSetManagerPtr(new IPSetManager());
        auto ipset = IPSetPtr(new IPSet("new ipset"));

	rmng->addRegex(r);

        ipset_mng->addIPSet(ipset);
        ipset->addIPAddress("72.21.211.223");

	ipset->setRegexManager(rmng);

        tcp->setIPSetManager(ipset_mng);

	inject(packet);

        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 1);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);

	// Checks on the Regex that should match
	BOOST_CHECK(r->getMatchs() == 1);

	ipset->setRegexManager(nullptr);
}


// Test the addition of a RegexManager on the IPSet functionality on UDP traffic
BOOST_AUTO_TEST_CASE (test04)
{
	Packet packet("../protocols/dns/packets/packet34.pcap");
//        Packet packet(reinterpret_cast <uint8_t*> (raw_packet_ethernet_ip_udp_dns), raw_packet_ethernet_ip_udp_dns_length);

        auto rmng = RegexManagerPtr(new RegexManager());
        auto r = SharedPointer<Regex>(new Regex("other regex", "^\\x84.*$"));

        rmng->addRegex(r);

        auto ipset_mng = IPSetManagerPtr(new IPSetManager());
        auto ipset = IPSetPtr(new IPSet("new ipset"));

        ipset_mng->addIPSet(ipset);
        ipset->addIPAddress("80.58.61.250");

        ipset->setRegexManager(rmng);

        udp->setIPSetManager(ipset_mng);

	inject(packet);

        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 1);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);

        // Checks on the Regex that should match
        BOOST_CHECK(r->getMatchs() == 1);
	BOOST_CHECK(udp->getTotalEvents() == 1);
}

BOOST_AUTO_TEST_SUITE_END( )

#ifdef HAVE_BLOOMFILTER

BOOST_AUTO_TEST_SUITE (testipset_bloom)

// Unit test for test the boost bloom filter
BOOST_AUTO_TEST_CASE (test01)
{
	static const size_t INSERT_MAX = 5000;
	static const size_t CONTAINS_MAX = 10000;
	static const size_t NUM_BITS = 8192;

	basic_bloom_filter<int, NUM_BITS> bloom;
	size_t collisions = 0;

	for (int i = 0; i < INSERT_MAX; ++i) {
		bloom.insert(i);
	}

	for (int i = INSERT_MAX; i < CONTAINS_MAX; ++i) {
		if (bloom.probably_contains(i)) ++collisions;
	}

	BOOST_CHECK( collisions == 1808);
}

BOOST_AUTO_TEST_CASE (test02)
{
        auto ipset = SharedPointer<IPBloomSet>(new IPBloomSet());

        BOOST_CHECK(ipset->getTotalIPs() == 0);
        BOOST_CHECK(ipset->getTotalLookups() == 0);

        ipset->addIPAddress("192.168.1.1");
        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
}

// Testing C class network
BOOST_AUTO_TEST_CASE (test03)
{
        auto ipset = SharedPointer<IPBloomSet>(new IPBloomSet());

        BOOST_CHECK(ipset->getTotalIPs() == 0);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
        BOOST_CHECK(ipset->getFalsePositiveRate() == 0);

	for (int i = 0; i < 255 ; ++i) {
		std::stringstream ipstr;

		ipstr << "192.168.0." << i;
        	ipset->addIPAddress(ipstr.str());
	}
        BOOST_CHECK(ipset->getTotalIPs() == 255);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
        BOOST_CHECK(ipset->getFalsePositiveRate() == 0);

        for (int i = 0; i < 255 ; ++i) {
                std::stringstream ipstr;

                ipstr << "192.168.1." << i;
                ipset->lookupIPAddress(ipstr.str());
        }

        BOOST_CHECK(ipset->getTotalLookups() == 255);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 255);
        BOOST_CHECK(ipset->getFalsePositiveRate() == 0);

        ipset->clear();

        BOOST_CHECK(ipset->getTotalIPs() == 0);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
}

// Testing B class network
BOOST_AUTO_TEST_CASE (test04)
{
        auto ipset = SharedPointer<IPBloomSet>(new IPBloomSet());

        BOOST_CHECK(ipset->getTotalIPs() == 0);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
        BOOST_CHECK(ipset->getFalsePositiveRate() == 0);

        for (int i = 0; i < 255 ; ++i) {
        	for (int j = 0; j < 255 ; ++j) {
                	std::stringstream ipstr;

                	ipstr << "192.168." << i << "." << j;
                	ipset->addIPAddress(ipstr.str());
		}
        }
        BOOST_CHECK(ipset->getTotalIPs() == 255 * 255);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
        BOOST_CHECK(ipset->getFalsePositiveRate() == 1); // With the default bloom value

        for (int i = 0; i < 255 ; ++i) {
                std::stringstream ipstr;

                ipstr << "192.167.1." << i;
                ipset->lookupIPAddress(ipstr.str());
        }

        BOOST_CHECK(ipset->getTotalLookups() == 255);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 2); // The false positives
        BOOST_CHECK(ipset->getTotalLookupsOut() == 253);
        BOOST_CHECK(ipset->getFalsePositiveRate() == 1);
}

// Testing B class network
BOOST_AUTO_TEST_CASE (test05)
{
        auto ipset = SharedPointer<IPBloomSet>(new IPBloomSet());

	// Resize the bloom filter in order to remove the FPs
	ipset->resize(4194304 * 2); // 2MB size

        for (int i = 0; i < 255 ; ++i) {
                for (int j = 0; j < 255 ; ++j) {
                        std::stringstream ipstr;

                        ipstr << "192.168." << i << "." << j;
                        ipset->addIPAddress(ipstr.str());
                }
        }

        BOOST_CHECK(ipset->getTotalIPs() == 255 * 255);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
        BOOST_CHECK(ipset->getFalsePositiveRate() == 1); 

        for (int i = 0; i < 255 ; ++i) {
                std::stringstream ipstr;

                ipstr << "192.167.1." << i;
                ipset->lookupIPAddress(ipstr.str());
        }

        BOOST_CHECK(ipset->getTotalLookups() == 255);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0); // The false positives
        BOOST_CHECK(ipset->getTotalLookupsOut() == 255);
        BOOST_CHECK(ipset->getFalsePositiveRate() == 1);
}

BOOST_AUTO_TEST_SUITE_END( )

#endif // HAVE_BLOOMFILTER

BOOST_AUTO_TEST_SUITE (test_radix_tree)

BOOST_AUTO_TEST_CASE (test01)
{
        auto iprad = IPRadixTreePtr(new IPRadixTree());
	IPAddress addr;

        BOOST_CHECK(iprad->getTotalIPs() == 0);
        BOOST_CHECK(iprad->getTotalLookups() == 0);
        BOOST_CHECK(iprad->getTotalLookupsIn() == 0);
        BOOST_CHECK(iprad->getTotalLookupsOut() == 0);
        BOOST_CHECK(iprad->getFalsePositiveRate() == 0);
	BOOST_CHECK(iprad->getTotalBytes() == 0);
	
	iprad->addIPAddress("192.168.0.1/33");
        BOOST_CHECK(iprad->getTotalIPs() == 0);
        BOOST_CHECK(iprad->getTotalNetworks() == 0);

	iprad->removeIPAddress("192.168.0.1/33");
        BOOST_CHECK(iprad->getTotalIPs() == 0);
        BOOST_CHECK(iprad->getTotalNetworks() == 0);

	addr.setDestinationAddress(inet_addr("172.168.1.1"));	
	BOOST_CHECK(iprad->lookupIPAddress(addr) == false);
	BOOST_CHECK(iprad->lookupIPAddress("this can not work") == false);
}

BOOST_AUTO_TEST_CASE (test02)
{
        auto iprad = IPRadixTreePtr(new IPRadixTree());
	IPAddress addr;

	iprad->addIPAddress("192.168.0.1/not valid");
	iprad->addIPAddress("I dont know");
	iprad->addIPAddress("192.168.0.1");
	iprad->addIPAddress("192.168.0.2");
	iprad->addIPAddress("196.168.0.1");
	iprad->addIPAddress("192.168.100.0/24");

	addr.setDestinationAddress(inet_addr("10.0.0.1"));	
	BOOST_CHECK(iprad->lookupIPAddress(addr) == false);

	addr.setDestinationAddress(inet_addr("192.0.0.1"));	
	BOOST_CHECK(iprad->lookupIPAddress(addr) == false);
	
	addr.setDestinationAddress(inet_addr("192.168.0.1"));	
	BOOST_CHECK(iprad->lookupIPAddress(addr) == true);

	addr.setDestinationAddress(inet_addr("192.168.100.1"));	
	BOOST_CHECK(iprad->lookupIPAddress(addr) == true);

	addr.setDestinationAddress(inet_addr("192.168.100.255"));	
	BOOST_CHECK(iprad->lookupIPAddress(addr) == true);
       
	BOOST_CHECK(iprad->getTotalIPs() == 3);
        BOOST_CHECK(iprad->getTotalNetworks() == 1);
        BOOST_CHECK(iprad->getTotalLookups() == 5);
        BOOST_CHECK(iprad->getTotalLookupsIn() == 3);
        BOOST_CHECK(iprad->getTotalLookupsOut() == 2);
        BOOST_CHECK(iprad->getFalsePositiveRate() == 0);
	
	iprad->removeIPAddress("196.168.0.1");
	BOOST_CHECK(iprad->getTotalIPs() == 2);

	iprad->removeIPAddress("192.168.200.0/24");
	BOOST_CHECK(iprad->getTotalIPs() == 2);
	
	iprad->removeIPAddress("192.168.100.0/24");
	BOOST_CHECK(iprad->getTotalIPs() == 2);

	// Clear all the internal structs
        iprad->clear();

        BOOST_CHECK(iprad->getTotalIPs() == 0);
        BOOST_CHECK(iprad->getTotalLookups() == 0);
        BOOST_CHECK(iprad->getTotalLookupsIn() == 0);
        BOOST_CHECK(iprad->getTotalLookupsOut() == 0);
        BOOST_CHECK(iprad->getTotalNetworks() == 0);
	
	BOOST_CHECK(iprad->lookupIPAddress("192.168.1.1") == false);
	
	iprad->removeIPAddress("196.168.0.1");
	BOOST_CHECK(iprad->getTotalIPs() == 0);

	iprad->addIPAddress("100.68.0.1");
	iprad->addIPAddress("100.68.0.2");
	iprad->addIPAddress("100.68.0.3");
	iprad->addIPAddress("100.68.0.4");
	
	BOOST_CHECK(iprad->getTotalIPs() == 4);

	iprad->addIPAddress("100.1.0.0/24");
        BOOST_CHECK(iprad->getTotalNetworks() == 1);
	BOOST_CHECK(iprad->getTotalIPs() == 4);

	BOOST_CHECK(iprad->lookupIPAddress("192.168.1.1") == false);
	BOOST_CHECK(iprad->lookupIPAddress("100.68.0.7") == false);
	BOOST_CHECK(iprad->lookupIPAddress("100.68.0.4") == true);
	BOOST_CHECK(iprad->lookupIPAddress("100.1.0.100") == true);
}

BOOST_AUTO_TEST_CASE (test03)
{
        auto iprad = IPRadixTreePtr(new IPRadixTree());
        auto ipmng = IPSetManagerPtr(new IPSetManager());
	IPAddress addr;

        iprad->addIPAddress("192.168.1.1");
        iprad->addIPAddress("192.168.200.12/16");

        ipmng->addIPSet(iprad);

	addr.setDestinationAddress(inet_addr("192.168.1.1"));	
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);

	addr.setDestinationAddress(inet_addr("192.167.200.12"));	
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == false);

	addr.setDestinationAddress(inet_addr("192.168.22.12"));	
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
	
	BOOST_CHECK(ipmng->getMatchedIPSet() == iprad);
        
	iprad->removeIPAddress("192.168.1.1");
        iprad->removeIPAddress("192.168.200.12/16");

	BOOST_CHECK(iprad->getTotalIPs() == 0);
	addr.setDestinationAddress(inet_addr("192.168.99.12"));	
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == false);

	{
		RedirectOutput r;
        
		ipmng->statistics();
        	iprad->statistics();
 	} 
}

BOOST_AUTO_TEST_CASE (test04)
{
        auto iprad = IPRadixTreePtr(new IPRadixTree("a radix tree"));
        auto ipset = IPSetPtr(new IPSet("new ipset"));
        auto ipmng = IPSetManagerPtr(new IPSetManager());
	IPAddress addr;

        iprad->addIPAddress("192.168.1.1");
        iprad->addIPAddress("192.168.200.12/24");
	BOOST_CHECK(iprad->getTotalBytes() == sizeof(IPRadixEntry) * 2);       
 
	ipset->addIPAddress("192.168.1.100");

        ipmng->addIPSet(iprad);
        ipmng->addIPSet(ipset);

	addr.setDestinationAddress(inet_addr("192.168.1.1"));	
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
	BOOST_CHECK(ipmng->getMatchedIPSet() == iprad);

	addr.setDestinationAddress(inet_addr("192.168.1.100"));	
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
	BOOST_CHECK(ipmng->getMatchedIPSet() == ipset);
}

BOOST_AUTO_TEST_CASE (test05) // generate a big tree
{
        auto iprad = IPRadixTreePtr(new IPRadixTree("a radix tree"));
        auto ipmng = IPSetManagerPtr(new IPSetManager());
        IPAddress addr;

        iprad->addIPAddress("10.22.0.0/16");
        iprad->addIPAddress("10.33.0.0/16");
        iprad->addIPAddress("10.44.0.0/16");
        iprad->addIPAddress("10.44.10.0/24");
        iprad->addIPAddress("10.44.11.0/24");
        iprad->addIPAddress("10.44.10.128");
        iprad->addIPAddress("10.44.10.129");
        iprad->addIPAddress("10.44.10.100/30");
        iprad->addIPAddress("10.44.10.200/30");
        iprad->addIPAddress("10.33.10.200/31");
        iprad->addIPAddress("10.33.10.10/31");
        iprad->addIPAddress("10.33.10.10/16");
        iprad->addIPAddress("10.33.10.201");
        iprad->addIPAddress("10.33.10.202");

        iprad->addIPAddress("192.168.0.0/16");
        iprad->addIPAddress("192.168.1.0/16");
        iprad->addIPAddress("192.168.2.0/16");
        iprad->addIPAddress("192.168.2.0/24");
        iprad->addIPAddress("192.168.2.100/32");


	iprad->addIPAddress("63.12.245.1");
	iprad->addIPAddress("63.12.245.0/24");
	iprad->addIPAddress("63.12.0.0/16");
	iprad->addIPAddress("63.12.245.1/8");
	
	iprad->addIPAddress("0.0.0.0");
	/*
        ipset2->addIPAddress("192.168.1.100");

        ipmng->addIPSet(ipset1);
        ipmng->addIPSet(ipset2);

        addr.setDestinationAddress(inet_addr("192.168.1.1"));
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset1);

        addr.setDestinationAddress(inet_addr("192.168.1.100"));
        BOOST_CHECK(ipmng->lookupIPAddress(addr) == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset2);
	*/
}

BOOST_AUTO_TEST_SUITE_END( )
