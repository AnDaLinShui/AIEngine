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
#include <string>
#include "FlowCache.h"
#include "FlowManager.h"
#include "IPAddress.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE_TEST
#define BOOST_TEST_MODULE flowtest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_AUTO_TEST_SUITE (flowcache_test_suite_static) 

BOOST_AUTO_TEST_CASE (test01)
{
	FlowCache *fc = new FlowCache(); 
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);

	fc->createFlows(1000);
	BOOST_CHECK(fc->getTotalFlows() == 1000);
	fc->destroyFlows(10000);
	BOOST_CHECK(fc->getTotalFlows() == 0);
	delete fc;	
}

BOOST_AUTO_TEST_CASE (test02)
{
        FlowCache *fc = new FlowCache();
        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

        fc->createFlows(2);

        BOOST_CHECK(fc->getTotalFlows() == 2);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	auto f1 = fc->acquireFlow();
	auto f2 = fc->acquireFlow();
	auto f3 = fc->acquireFlow();

        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 2);
        BOOST_CHECK(fc->getTotalFails() == 1);
	BOOST_CHECK(fc->getCurrentUseMemory() == (2 * FlowCache::flowSize));
	BOOST_CHECK(f1 !=  nullptr);
	BOOST_CHECK(f2 !=  nullptr);
	BOOST_CHECK(f3 ==  nullptr);

	fc->releaseFlow(f2);
	fc->releaseFlow(f1);
        
	BOOST_CHECK(fc->getTotalFlows() == 2);
        BOOST_CHECK(fc->getTotalReleases() == 2);

	BOOST_CHECK(fc->getTotalAcquires() == 2);
        BOOST_CHECK(fc->getTotalFails() == 1);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	delete fc;
}

BOOST_AUTO_TEST_CASE (test03)
{
        FlowCache *fc = new FlowCache();

	auto f1 = SharedPointer<Flow>(new Flow());
	auto f2 = SharedPointer<Flow>(new Flow());
	auto f3 = SharedPointer<Flow>(new Flow());

        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	fc->releaseFlow(f1);

	BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(fc->getTotalFlows() == 1);
        BOOST_CHECK(fc->getTotalReleases() == 1);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);

	auto f4 = fc->acquireFlow();

	BOOST_CHECK(f1 == f4);

	delete fc;
}

BOOST_AUTO_TEST_CASE (test04)
{
	FlowCache *fc = new FlowCache(); 
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	fc->createFlows(10);
	BOOST_CHECK(fc->getTotalFlows() == 10);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	fc->destroyFlows(9);

	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	fc->destroyFlows(9);

	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);

	fc->createFlows(1);

	BOOST_CHECK(fc->getTotalFlows() == 1);

	auto f1 = fc->acquireFlow();

	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == FlowCache::flowSize);

	auto f2 = fc->acquireFlow();

	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 1);
	BOOST_CHECK(fc->getCurrentUseMemory() == FlowCache::flowSize);
	BOOST_CHECK(f2 == nullptr);

	fc->releaseFlow(f1);
	fc->destroyFlows(1);	
	delete fc;
}

BOOST_AUTO_TEST_CASE (test05)
{
        FlowCache *fc = new FlowCache();
        fc->createFlows(10);

	auto f1 = fc->acquireFlow();
	auto f2 = fc->acquireFlow();
	auto f3 = fc->acquireFlow();
	
	BOOST_CHECK(fc->getCurrentUseMemory() == 3 * FlowCache::flowSize);
	BOOST_CHECK(fc->getTotalFlows() == 7);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 3);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(f2 != f1);
	BOOST_CHECK(f1 != f3);
	
	fc->releaseFlow(f1);
	fc->releaseFlow(f2);
	fc->releaseFlow(f3);
	BOOST_CHECK(fc->getTotalReleases() == 3);
	BOOST_CHECK(fc->getTotalFlows() == 10);

	fc->destroyFlows(fc->getTotalFlows());
	delete fc;
}

BOOST_AUTO_TEST_CASE (test06)
{
        FlowCache *fc = new FlowCache();
        fc->createFlows(1);

        auto f1 = fc->acquireFlow();

	BOOST_CHECK(fc->getTotalFlows() == 0);

	f1->setId(10);
	f1->total_bytes = 10;
	f1->total_packets = 10;

        fc->releaseFlow(f1);
	BOOST_CHECK(fc->getTotalFlows() == 1);
        BOOST_CHECK(fc->getTotalReleases() == 1);

	auto f2 = fc->acquireFlow();
        fc->destroyFlows(fc->getTotalFlows());
        delete fc;
}

BOOST_AUTO_TEST_CASE (test07)
{
        FlowCache *fc = new FlowCache();
        fc->createFlows(1);

        auto f1 = fc->acquireFlow();

	f1->setFiveTuple(inet_addr("192.168.1.1"), 2345, IPPROTO_TCP, inet_addr("54.12.5.1"), 80);

	std::ostringstream os;
	f1->serialize(os);

	JsonFlow j;

	j.j = nlohmann::json::parse(os.str());

	BOOST_CHECK(j.j["bytes"] == 0);
	BOOST_CHECK(j.j["ip"]["dst"] == "54.12.5.1");
	BOOST_CHECK(j.j["ip"]["src"] == "192.168.1.1");
	BOOST_CHECK(j.j["port"]["dst"] == 80);
	BOOST_CHECK(j.j["port"]["src"] == 2345);

        fc->releaseFlow(f1);
        BOOST_CHECK(fc->getTotalFlows() == 1);
        BOOST_CHECK(fc->getTotalReleases() == 1);

        fc->destroyFlows(fc->getTotalFlows());
        delete fc;
}

BOOST_AUTO_TEST_CASE (test08) // Simulate bad_alloc on the system 
{
        FlowCache *fc = new FlowCache();

	fc->setDynamicAllocatedMemory(true);

	// This flag will generate a exception on the allocations check Cache_Imp.h
	fc->setGenerateBadAllocException(true);

	fc->createFlows(1);
	BOOST_CHECK(fc->getTotalFlows() == 0);

	auto flow = fc->acquireFlow();
	BOOST_CHECK(flow == nullptr);
	
	fc->setGenerateBadAllocException(false);
	delete fc;
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowcache_dynamic) 

BOOST_AUTO_TEST_CASE (test01)
{
        FlowCache *fc = new FlowCache();

	fc->setDynamicAllocatedMemory(true);
	BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

        fc->createFlows(2);

        BOOST_CHECK(fc->getTotalFlows() == 2);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	auto f1 = fc->acquireFlow();
	auto f2 = fc->acquireFlow();
	auto f3 = fc->acquireFlow();

        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 3);
        BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == (3 * FlowCache::flowSize));
	BOOST_CHECK(f1 !=  nullptr);
	BOOST_CHECK(f2 !=  nullptr);
	BOOST_CHECK(f3 !=  nullptr);

	fc->releaseFlow(f2);
	fc->releaseFlow(f1);
        
	BOOST_CHECK(fc->getTotalFlows() == 2);
        BOOST_CHECK(fc->getTotalReleases() == 2);

	BOOST_CHECK(fc->getTotalAcquires() == 3);
        BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == FlowCache::flowSize);

	delete fc;
}

BOOST_AUTO_TEST_CASE (test02)
{
	FlowCache *fc = new FlowCache(); 
	fc->setDynamicAllocatedMemory(true);
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	fc->createFlows(10);
	BOOST_CHECK(fc->getTotalFlows() == 10);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	fc->destroyFlows(9);

	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);

	fc->destroyFlows(9);

	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);

	fc->createFlows(1);

	BOOST_CHECK(fc->getTotalFlows() == 1);

	auto f1 = fc->acquireFlow();

	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == FlowCache::flowSize);

	auto f2 = fc->acquireFlow();

	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 2);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(fc->getCurrentUseMemory() == FlowCache::flowSize * 2);
	BOOST_CHECK(f2 != nullptr);

	fc->releaseFlow(f1);
	fc->destroyFlows(1);	
	delete fc;
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowmanager) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test01)
{
        FlowManager *fm = new FlowManager();
        auto f1 = SharedPointer<Flow>(new Flow());
        auto f2 = SharedPointer<Flow>(new Flow());
	IPAddress addr;

	addr.setSourceAddress(inet_addr("192.168.1.1"));
	addr.setDestinationAddress(inet_addr("192.168.1.255"));

        unsigned long h1 = addr.getHash(2, IPPROTO_UDP, 5);
        unsigned long h2 = addr.getHash(5, IPPROTO_UDP, 2);
        unsigned long hfail = addr.getHash(10, IPPROTO_UDP, 10); // for fails

	f2->setId(h1);
        f1->setId(hfail);
        fm->addFlow(f1);
	fm->addFlow(f2);

        BOOST_CHECK(fm->getTotalFlows() == 2);

	BOOST_CHECK(fm->getAllocatedMemory() == 2 * FlowCache::flowSize);
	fm->removeFlow(f2);
	BOOST_CHECK(fm->getAllocatedMemory() == FlowCache::flowSize);

        delete fm;
}

// Test the lookups of the flows
BOOST_AUTO_TEST_CASE (test02)
{
	FlowManager *fm = new FlowManager();
	auto f1 = SharedPointer<Flow>(new Flow());

	IPAddress addr;

	addr.setSourceAddress(inet_addr("192.168.1.1"));
	addr.setDestinationAddress(inet_addr("192.168.1.255"));

        unsigned long h1 = addr.getHash(137, IPPROTO_UDP, 137);
        unsigned long h2 = addr.getHash(137, IPPROTO_UDP, 137);
        unsigned long hfail = addr.getHash(10, IPPROTO_UDP, 10); // for fails

	f1->setId(h1);
	fm->addFlow(f1);
	BOOST_CHECK(fm->getTotalFlows() == 1);

	auto f2 = fm->findFlow(hfail, h2);
	BOOST_CHECK(f1 == f2);
	BOOST_CHECK(f1.get() == f2.get());

	auto f3 = fm->findFlow(hfail, hfail);
	BOOST_CHECK(f3.get() == 0);
	BOOST_CHECK(fm->getTotalFlows() == 1);

	delete fm;
}

// Test lookups
BOOST_AUTO_TEST_CASE (test03)
{
        FlowManager *fm = new FlowManager();
        auto f1 = SharedPointer<Flow>(new Flow());

        IPAddress addr1;

        addr1.setSourceAddress(inet_addr("192.168.1.1"));
        addr1.setDestinationAddress(inet_addr("192.168.1.2"));

        unsigned long h1 = addr1.getHash(137, IPPROTO_UDP, 137);
        unsigned long h2 = addr1.getHash(137, IPPROTO_UDP, 137);

        f1->setId(h1);
        fm->addFlow(f1);
        BOOST_CHECK(fm->getTotalFlows() == 1);

	// The same conversation but other direction
        IPAddress addr2;

	// 5tuple 192.168.1.2:137:17:192.168.1.1:137
        addr2.setSourceAddress(inet_addr("192.168.1.2"));
        addr2.setDestinationAddress(inet_addr("192.168.1.1"));

        h1 = addr1.getHash(137, IPPROTO_UDP, 137);
        h2 = addr1.getHash(137, IPPROTO_UDP, 137);

        auto f2 = fm->findFlow(h1, h2);
        BOOST_CHECK(f1 == f2);
        BOOST_CHECK(f1.get() == f2.get());

	// Different conversation, different port same ips
	
	// 5tuple 192.168.1.2:138:17:192.168.1.1:138
        h1 = addr1.getHash(138, IPPROTO_UDP, 138);
        h2 = addr1.getHash(138, IPPROTO_UDP, 138);

        auto f3 = fm->findFlow(h1, h2);
        BOOST_CHECK(f3 != f2);
        BOOST_CHECK(f3 == nullptr) ;

        delete fm;
}

// Test lookups
BOOST_AUTO_TEST_CASE (test04)
{
        FlowManager *fm = new FlowManager();
        auto f1 = SharedPointer<Flow>(new Flow());

        IPAddress addr1;

	// Inject 5tuple 83.156.1.2:800:6:172.100.31.196:80
        uint32_t ipsrc = inet_addr("83.156.1.2");
        uint32_t ipdst = inet_addr("172.100.31.196");
        addr1.setSourceAddress(ipsrc);
        addr1.setDestinationAddress(ipdst);

        uint16_t portsrc = 800;
        uint16_t portdst = 80;
        uint16_t proto = IPPROTO_TCP;

        unsigned long h1 = addr1.getHash(portsrc, proto, portdst);
        unsigned long h2 = addr1.getHash(portdst, proto, portsrc);

        f1->setId(h1);
        fm->addFlow(f1);

	// Inject 5tuple 172.100.31.196:80:6:83.156.1.2:800
        IPAddress addr2;

        addr2.setSourceAddress(ipdst);
        addr2.setDestinationAddress(ipsrc);

        h1 = addr2.getHash(portdst, proto, portsrc);
        h2 = addr2.getHash(portsrc, proto, portdst);

        auto f2 = fm->findFlow(h1, h2);
        BOOST_CHECK(f1 == f2);

	delete fm;
}

// Test looups and removes
BOOST_AUTO_TEST_CASE (test05)
{
        FlowManager *fm = new FlowManager();
        auto f1 = SharedPointer<Flow>(new Flow());

        IPAddress addr;

        addr.setSourceAddress(inet_addr("192.156.1.2"));
        addr.setDestinationAddress(inet_addr("10.10.1.1"));

        unsigned long h1 = addr.getHash(137, IPPROTO_UDP, 5000);
        unsigned long h2 = addr.getHash(137, IPPROTO_UDP, 5000);
        unsigned long hfail = 10^10^10^10^10; // for fails

        f1->setId(h1);
    
	BOOST_CHECK(f1.use_count() == 1); 
	fm->addFlow(f1);
	BOOST_CHECK(f1.use_count() == 2); 
        BOOST_CHECK(fm->getTotalFlows() == 1);

        f1 = fm->findFlow(hfail, h2);

	fm->removeFlow(f1);
        BOOST_CHECK(fm->getTotalFlows() == 0);

        delete fm;
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowcache_static_and_flowmanager) 

BOOST_AUTO_TEST_CASE (test01)
{
	FlowCache *fc = new FlowCache(); 
	FlowManager *fm = new FlowManager();

        IPAddress addr;

        addr.setSourceAddress(inet_addr("192.156.1.2"));
        addr.setDestinationAddress(inet_addr("10.10.1.1"));

        unsigned long h1 = addr.getHash(137, IPPROTO_UDP, 5000);
        unsigned long h2 = addr.getHash(137, IPPROTO_UDP, 5000);
        unsigned long hfail = addr.getHash(138, IPPROTO_UDP, 5000); // for fails

	fc->createFlows(10);
	auto f1 = fc->acquireFlow();

	BOOST_CHECK(f1.use_count() == 1); // one is the cache and the other f1
        BOOST_CHECK(fm->getTotalFlows() == 0);
        
	f1->setId(h1);

	fm->addFlow(f1);
        BOOST_CHECK(fm->getTotalFlows() == 1);
	auto f2 = fm->findFlow(h1, hfail);
	BOOST_CHECK(f2.get() == f1.get());
	fm->removeFlow(f1);
        BOOST_CHECK(fm->getTotalFlows() == 0);

	delete fm;
	delete fc;
}

BOOST_AUTO_TEST_CASE (test02)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
	std::vector<SharedPointer<Flow>> v;
	
        fc->createFlows(64);

	for (int i = 0; i < 66; ++i) {
        	auto f1 = fc->acquireFlow();
		if (f1) {
        		IPAddress addr;

        		addr.setSourceAddress(inet_addr("192.156.1.2"));
        		addr.setDestinationAddress(inet_addr("10.10.1.1"));

        		unsigned long h1 = addr.getHash(137, IPPROTO_TCP, i);
        		unsigned long h2 = addr.getHash(i, IPPROTO_TCP, 137);

        		f1->setId(h1);

        		fm->addFlow(f1);
        		BOOST_CHECK(fm->getTotalFlows() == i + 1);
		}
	}

	BOOST_CHECK(fm->getTotalFlows() == 64);
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 64);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalFails() == 2);

	for (int i = 0; i < 64; ++i) {
        	IPAddress addr;

        	addr.setSourceAddress(inet_addr("192.156.1.2"));
        	addr.setDestinationAddress(inet_addr("10.10.1.1"));

        	unsigned long h1 = addr.getHash(137, IPPROTO_TCP, i);
        	unsigned long h2 = addr.getHash(i, IPPROTO_TCP, 137);

		auto f1 = fm->findFlow(h1, h2);
		if (f1) {
			fm->removeFlow(f1);
			v.push_back(f1);
		}
	}

	BOOST_CHECK(fm->getTotalFlows() == 0);

	for (auto value: v) {
		fc->releaseFlow(value);
	}

	BOOST_CHECK(fc->getTotalReleases() == 64);
}

BOOST_AUTO_TEST_CASE (test03)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        std::vector<SharedPointer<Flow>> v;

        fc->createFlows(254);

        for (int i = 0; i < 254; ++i) {
                auto f1 = fc->acquireFlow();
                if (f1) {
        		IPAddress addr;

			uint32_t ipsrc = inet_addr("83.156.1.2");
			uint32_t ipdst = inet_addr("172.100.31.196");
        		addr.setSourceAddress(ipsrc);
        		addr.setDestinationAddress(ipdst);

			uint16_t portsrc = 800 + i;
			uint16_t portdst = 80;
			uint16_t proto = IPPROTO_TCP;

	      		unsigned long h1 = addr.getHash(portsrc, proto, portdst);
        		unsigned long h2 = addr.getHash(portdst, proto, portsrc);

                        f1->setId(h1);
			f1->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);

                        fm->addFlow(f1);
			f1->total_packets = 1;
                        BOOST_CHECK(fm->getTotalFlows() == i + 1);
                }
        }

        BOOST_CHECK(fm->getTotalFlows() == 254);
        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 254);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);

	// Now the second packet of the flow arrives
        for (int i = 0; i < 254; ++i) {
        	IPAddress addr;
		uint32_t ipsrc = inet_addr("172.100.31.196");
                uint32_t ipdst = inet_addr("83.156.1.2"); 

        	addr.setSourceAddress(ipsrc);
        	addr.setDestinationAddress(ipdst);

                uint16_t portsrc = 80;
                uint16_t portdst = 800 + i;
                uint16_t proto = IPPROTO_TCP;
                        
	      	unsigned long h1 = addr.getHash(portsrc, proto, portdst);
        	unsigned long h2 = addr.getHash(portdst, proto, portsrc);

		auto f1 = fm->findFlow(h1, h2);	
		BOOST_CHECK(f1 != nullptr);
		// The flow only have one packet
		BOOST_CHECK(f1->total_packets == 1);
		++f1->total_packets;
        }
        BOOST_CHECK(fm->getTotalFlows() == 254);
        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 254);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE (test04)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        std::vector<SharedPointer<Flow>> v;

        fc->createFlows(254);

        for (int i = 0; i < 254; ++i) {
                auto f1 = fc->acquireFlow();

                if (f1) {
			std::ostringstream os;
			IPAddress addr;
	
			os << "10.253." << i << "1";	
			std::string ipsrc_str = "192.168.1.1";	
			uint32_t ipsrc = inet_addr(ipsrc_str.c_str());
                        uint32_t ipdst = inet_addr(os.str().c_str());
                        uint16_t portsrc = 1200 + i;
                        uint16_t portdst = 8080;
                        uint16_t proto = IPPROTO_TCP;

        		addr.setSourceAddress(ipsrc);
        		addr.setDestinationAddress(ipdst);

	      		unsigned long h1 = addr.getHash(portsrc, proto, portdst);
        		unsigned long h2 = addr.getHash(portdst, proto, portsrc);

                        f1->setId(h1);
                        f1->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);

                        fm->addFlow(f1);
                        f1->total_packets = 1;
                        BOOST_CHECK(fm->getTotalFlows() == i+1);
                }
        }
        // Now the second packet of the flow arrives
        for (int i = 0; i < 254; ++i) {
		std::ostringstream os;
		IPAddress addr;

                os << "10.253." << i << "1";
                std::string ipsrc_str = "192.168.1.1";
                uint32_t ipdst = inet_addr(ipsrc_str.c_str());
                uint32_t ipsrc = inet_addr(os.str().c_str());
                uint16_t portdst = 1200 + i;
                uint16_t portsrc = 8080;
                uint16_t proto = IPPROTO_TCP;

        	addr.setSourceAddress(ipdst);
        	addr.setDestinationAddress(ipsrc);

	      	unsigned long h1 = addr.getHash(portsrc, proto, portdst);
        	unsigned long h2 = addr.getHash(portdst, proto, portsrc);

                auto f1 = fm->findFlow(h1, h2);
		BOOST_CHECK(f1 != nullptr);
                // The flow only have one packet
                BOOST_CHECK(f1->total_packets == 1);
                ++f1->total_packets;
        }
}

BOOST_AUTO_TEST_CASE (test05)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());

	fm->setFlowCache(fc);

        fc->createFlows(4);
        for (int i = 0; i < 4; ++i) {
                auto f = fc->acquireFlow();
                if (f) {
			IPAddress addr;
                        std::ostringstream os;

                        os << "10.253." << i << "1";
                        std::string ipsrc_str = "192.168.1.1";
                        
			uint32_t ipsrc = inet_addr(ipsrc_str.c_str());
                        uint32_t ipdst = inet_addr(os.str().c_str());

        		addr.setSourceAddress(ipdst);
        		addr.setDestinationAddress(ipsrc);

                        uint16_t portsrc = 1200 + i;
                        uint16_t portdst = 8080;
                        uint16_t proto = IPPROTO_TCP;

	      		unsigned long h1 = addr.getHash(portsrc, proto, portdst);
        		unsigned long h2 = addr.getHash(portdst, proto, portsrc);

                        f->setId(h1);
                        f->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);

                        fm->addFlow(f);
                        f->total_packets = 1;
                        BOOST_CHECK(fm->getTotalFlows() == i + 1);
                }
        }
        BOOST_CHECK(fm->getTotalFlows() == 4);
        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 4);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);

	// the user from cmd execute the command
	fm->flush();	
        
	BOOST_CHECK(fm->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalFlows() == 4);
        BOOST_CHECK(fc->getTotalAcquires() == 4);
        BOOST_CHECK(fc->getTotalReleases() == 4);
        BOOST_CHECK(fc->getTotalFails() == 0);
}

// This test tries all the combination of ports that a tuple of ips can have in order to find hash problems
BOOST_AUTO_TEST_CASE (test06)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());

        fm->setFlowCache(fc);
        fc->createFlows(65536);

        for (int i = 1; i < 65536; ++i) {
                auto f = fc->acquireFlow();
                if (f) {
                        IPAddress addr;
                        std::ostringstream os;

                        os << "10.253." << i << "1";
                        std::string ipsrc_str = "192.168.1.1";

                        uint32_t ipsrc = inet_addr(ipsrc_str.c_str());
                        uint32_t ipdst = inet_addr(os.str().c_str());

                        addr.setSourceAddress(ipdst);
                        addr.setDestinationAddress(ipsrc);

                        uint16_t portsrc = i;
                        uint16_t portdst = 80;
                        uint16_t proto = IPPROTO_TCP;

                        unsigned long h1 = addr.getHash(portsrc, proto, portdst);
                        unsigned long h2 = addr.getHash(portdst, proto, portsrc);

                        f->setId(h1);
                        f->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);

                        fm->addFlow(f);
                        f->total_packets = 1;
                        BOOST_CHECK(fm->getTotalFlows() == i);
                }
        }
	BOOST_CHECK(fm->getTotalFlows() == 65536 - 1);
        BOOST_CHECK(fc->getTotalFlows() == 1);
        BOOST_CHECK(fc->getTotalAcquires() == 65536 - 1);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowcache_dynamic_and_flowmanager) 

BOOST_AUTO_TEST_CASE (test01)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
	std::vector<SharedPointer<Flow>> v;

	fc->setDynamicAllocatedMemory(true);

        fc->createFlows(64);

	for (int i = 0; i < 66; ++i) {
        	auto f1 = fc->acquireFlow();
		if (f1) {
        		IPAddress addr;

        		addr.setSourceAddress(inet_addr("192.156.1.2"));
        		addr.setDestinationAddress(inet_addr("10.10.1.1"));

        		unsigned long h1 = addr.getHash(137, IPPROTO_TCP, i);
        		unsigned long h2 = addr.getHash(i, IPPROTO_TCP, 137);

        		f1->setId(h1);

        		fm->addFlow(f1);
        		BOOST_CHECK(fm->getTotalFlows() == i+1);
		}
	}

	BOOST_CHECK(fm->getTotalFlows() == 66);
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 66);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);

	for (int i = 0; i < 64; ++i) {
        	IPAddress addr;

        	addr.setSourceAddress(inet_addr("192.156.1.2"));
        	addr.setDestinationAddress(inet_addr("10.10.1.1"));

        	unsigned long h1 = addr.getHash(137, IPPROTO_TCP, i);
        	unsigned long h2 = addr.getHash(i, IPPROTO_TCP, 137);

		auto f1 = fm->findFlow(h1, h2);
		if (f1) {
			fm->removeFlow(f1);
			v.push_back(f1);
		}
	}

	BOOST_CHECK(fm->getTotalFlows() == 2);

	for (auto value: v) {
		fc->releaseFlow(value);
	}

	BOOST_CHECK(fc->getTotalReleases() == 64);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowmanager_time_release_flow) // test for manage the time with releasing the flows 

BOOST_AUTO_TEST_CASE (test01)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow());
        auto f2 = SharedPointer<Flow>(new Flow());
	IPAddress addr;

	uint32_t ipsrc = inet_addr("56.125.100.2");
        uint32_t ipdst = inet_addr("213.200.11.87");
        uint16_t portsrc = 1000;
        uint16_t portdst = 80;
        uint16_t proto = IPPROTO_TCP;

       	addr.setSourceAddress(ipsrc);
       	addr.setDestinationAddress(ipdst);
    	
	unsigned long h = addr.getHash(portsrc, proto, portdst);

        f1->setId(h);
	f1->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);

	// other flow
	ipsrc = inet_addr("56.125.100.247");
       	addr.setSourceAddress(ipsrc);
	h = addr.getHash(portsrc, proto, portdst);

	f2->setId(h);
	f1->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);

        f1->setArriveTime(0);
        f2->setArriveTime(0);

        fm->addFlow(f1);
        fm->addFlow(f2);
	
	// fm->showFlowsByTime();
	
	fm->updateFlowTime(f1, 200);
	fm->updateFlowTime(f2, 2);

	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

        // Update the time of the flows
        fm->updateTimers(200);

        BOOST_CHECK(fm->getTotalFlows() == 1);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);
	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 1);
}

BOOST_AUTO_TEST_CASE (test02)
{
  	FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
	auto f1 = SharedPointer<Flow>(new Flow(1));
	auto f2 = SharedPointer<Flow>(new Flow(2));
	auto f3 = SharedPointer<Flow>(new Flow(3));

	f1->setArriveTime(0);
	f2->setArriveTime(0);
	f3->setArriveTime(0);

	f1->setLastPacketTime(1);
	f2->setLastPacketTime(2);
	f3->setLastPacketTime(200);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
 
	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);
	BOOST_CHECK(f3.use_count() == 2);

	BOOST_CHECK(fm->getTotalFlows() == 3);
	BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);	

	fm->updateFlowTime(f1, 1);
	fm->updateFlowTime(f2, 2);
	fm->updateFlowTime(f3, 200);

	// Update the time of the flows
	fm->updateTimers(200);

	BOOST_CHECK(fm->getTotalFlows() == 1);
	BOOST_CHECK(fm->getTotalTimeoutFlows() == 2);	
	
	BOOST_CHECK(f1.use_count() == 1);
	BOOST_CHECK(f2.use_count() == 1);
	BOOST_CHECK(f3.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test03)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow(1));
        auto f2 = SharedPointer<Flow>(new Flow(2));
        auto f3 = SharedPointer<Flow>(new Flow(3));
        auto f4 = SharedPointer<Flow>(new Flow(5));

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);
        f4->setArriveTime(0);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
        fm->addFlow(f4);

        //fm->showFlowsByTime();
	
        fm->updateFlowTime(f1, 1);
        fm->updateFlowTime(f2, 200);
        fm->updateFlowTime(f4, 210);
        fm->updateFlowTime(f3, 2);

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);
        BOOST_CHECK(f4.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 4);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

        // Update the time of the flows
	// Two flows will be removed due to the timeout f2 and f4
        fm->updateTimers(220);

        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 2);
        BOOST_CHECK(f1.use_count() == 1);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 1);
        BOOST_CHECK(f4.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test04)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow(1));
        auto f2 = SharedPointer<Flow>(new Flow(2));
        auto f3 = SharedPointer<Flow>(new Flow(3));
        auto f4 = SharedPointer<Flow>(new Flow(4));
        auto f5 = SharedPointer<Flow>(new Flow(4999));

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);
        f4->setArriveTime(0);
        f5->setArriveTime(0);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
        fm->addFlow(f4);
        fm->addFlow(f5);

	// The flows are not sorted on the multi_index
	f1->setLastPacketTime(150);
	f2->setLastPacketTime(110);
	f3->setLastPacketTime(12); // comatose flow
	f4->setLastPacketTime(17); // comatose flow
	f5->setLastPacketTime(140);
        
	// Just update three flows 
        fm->updateFlowTime(f1, 151);
        fm->updateFlowTime(f2, 110);
        fm->updateFlowTime(f5, 141);

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);
        BOOST_CHECK(f4.use_count() == 2);
        BOOST_CHECK(f5.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 5);

        fm->updateTimers(200);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 1);
        BOOST_CHECK(f4.use_count() == 1);
        BOOST_CHECK(f5.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test05)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
	FlowCachePtr fc = FlowCachePtr(new FlowCache());
        auto f1 = SharedPointer<Flow>(new Flow(1));
        auto f2 = SharedPointer<Flow>(new Flow(22));
        auto f3 = SharedPointer<Flow>(new Flow(3));
        auto f4 = SharedPointer<Flow>(new Flow(444));
        auto f5 = SharedPointer<Flow>(new Flow(7));

	fm->setFlowCache(fc);

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);
        f4->setArriveTime(0);
        f5->setArriveTime(0);

        BOOST_CHECK(f1.use_count() == 1);
        BOOST_CHECK(f2.use_count() == 1);
        BOOST_CHECK(f3.use_count() == 1);
        BOOST_CHECK(f4.use_count() == 1);
        BOOST_CHECK(f5.use_count() == 1);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
        fm->addFlow(f4);
        fm->addFlow(f5);

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);
        BOOST_CHECK(f4.use_count() == 2);
        BOOST_CHECK(f5.use_count() == 2);

        // The flows are not sorted on the multi_index
        f1->setLastPacketTime(150);
        f2->setLastPacketTime(110);
        f3->setLastPacketTime(12); // comatose flow
        f4->setLastPacketTime(17); // comatose flow
        f5->setLastPacketTime(140);

        // Just update two flows
        fm->updateFlowTime(f1, 151);
        fm->updateFlowTime(f2, 110);

	// remove two flows
	fm->removeFlow(f3);
	fm->removeFlow(f5);

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 1);
        BOOST_CHECK(f4.use_count() == 2);
        BOOST_CHECK(f5.use_count() == 1);

        BOOST_CHECK(fm->getTotalFlows() == 3);

        fm->updateTimers(200);

        BOOST_CHECK(fc->getTotalFlows() == 1);
        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 1);
        BOOST_CHECK(f4.use_count() == 2);
        BOOST_CHECK(f5.use_count() == 1);
}

BOOST_AUTO_TEST_CASE (test06)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow(1));
        auto f2 = SharedPointer<Flow>(new Flow(2));
        auto f3 = SharedPointer<Flow>(new Flow(3));

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);

        f1->setLastPacketTime(10);
        f2->setLastPacketTime(200);
        f3->setLastPacketTime(300);

	fm->setTimeout(120);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);

	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);
	BOOST_CHECK(f3.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

        // Update the time of the flows
        fm->updateTimers(301);

	// flow1 should not exist on the fm
	auto fout = fm->findFlow(1, 0x0fffeaf);

        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);
	BOOST_CHECK(f1.use_count() == 1);
	BOOST_CHECK(f2.use_count() == 2);
	BOOST_CHECK(f3.use_count() == 2);
	BOOST_CHECK(fout.use_count() == 0);
	BOOST_CHECK(fout == nullptr);
}

BOOST_AUTO_TEST_CASE (test07)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow(1));
        auto f2 = SharedPointer<Flow>(new Flow(2042));
        auto f3 = SharedPointer<Flow>(new Flow(7));

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);

        f1->setLastPacketTime(100);
        f2->setLastPacketTime(20);
        f3->setLastPacketTime(300);
	
	fm->setTimeout(210);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

        // Update the time of the flows
        fm->updateTimers(301);

        auto fout = fm->findFlow(2042, 0);

        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);
        BOOST_CHECK(fout.use_count() == 0);
        BOOST_CHECK(fout == nullptr);
}

// Test the flow manager and the flow cache timeouts
BOOST_AUTO_TEST_CASE (test08)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        FlowCachePtr fc = FlowCachePtr(new FlowCache());

        fc->createFlows(64);

        for (int i = 0; i < 66; ++i) {
                auto f = fc->acquireFlow();
                if (f) {
        		IPAddress addr;

        		uint32_t ipsrc = inet_addr("192.168.100.102");
        		uint32_t ipdst = inet_addr("213.2.1.8");
        		uint16_t portsrc = 2;
        		uint16_t portdst = i;
        		uint16_t proto = IPPROTO_TCP;

        		addr.setSourceAddress(ipsrc);
        		addr.setDestinationAddress(ipdst);

        		unsigned long h1 = addr.getHash(portsrc, proto, portdst);
        		unsigned long h2 = addr.getHash(portdst, proto, portsrc);

                        f->setId(h1);
			f->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);
			f->setArriveTime(0);

                        fm->addFlow(f);
                        BOOST_CHECK(fm->getTotalFlows() == i+1);
                }
        }
      
	// 64 flows should exists on the FlowManager 
	BOOST_CHECK(fm->getTotalFlows() == 64);

	fm->setFlowCache(fc);
	fm->setTimeout(50);

	// Update the time of 33 flows
        for (int i = 0; i < 33; ++i) {
        	IPAddress addr;

        	uint32_t ipsrc = inet_addr("192.168.100.102");
        	uint32_t ipdst = inet_addr("213.2.1.8");
        	uint16_t portsrc = 2;
        	uint16_t portdst = i;
        	uint16_t proto = IPPROTO_TCP;

        	addr.setSourceAddress(ipsrc);
        	addr.setDestinationAddress(ipdst);

        	unsigned long h1 = addr.getHash(portsrc, proto, portdst);
        	unsigned long h2 = addr.getHash(portdst, proto, portsrc);

                auto f = fm->findFlow(h1, h2);
		if (f) {
			fm->updateFlowTime(f, 50);
		}
	}

	fm->updateTimers(80);

        BOOST_CHECK(fm->getTotalFlows() == 33);
	BOOST_CHECK(fm->getTotalProcessFlows() == 64);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 31);
        BOOST_CHECK(fc->getTotalFlows() == 31);
        BOOST_CHECK(fc->getTotalAcquires() == 64);
        BOOST_CHECK(fc->getTotalReleases() == 31);
        BOOST_CHECK(fc->getTotalFails() == 2);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowmanager_time_no_release_flow) // test for manage the time with releasing the flows 

BOOST_AUTO_TEST_CASE (test01)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow());
        auto f2 = SharedPointer<Flow>(new Flow());
	IPAddress addr;

	uint32_t ipsrc = inet_addr("56.125.100.2");
        uint32_t ipdst = inet_addr("213.200.11.87");
        uint16_t portsrc = 1000;
        uint16_t portdst = 80;
        uint16_t proto = IPPROTO_TCP;

       	addr.setSourceAddress(ipsrc);
       	addr.setDestinationAddress(ipdst);
    	
	unsigned long h = addr.getHash(portsrc, proto, portdst);

        f1->setId(h);
	f1->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);

	// other flow
	ipsrc = inet_addr("56.125.100.247");
       	addr.setSourceAddress(ipsrc);
	h = addr.getHash(portsrc, proto, portdst);

	f2->setId(h);
	f1->setFiveTuple(ipsrc, portsrc, proto, ipdst, portdst);

        f1->setArriveTime(0);
        f2->setArriveTime(0);

        fm->addFlow(f1);
        fm->addFlow(f2);
	
	// Tell the flow manager not to release the flows
	fm->setReleaseFlows(false); 
	
	fm->updateFlowTime(f1, 200);
	fm->updateFlowTime(f2, 2);

	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

        // Update the time of the flows
        fm->updateTimers(200);

        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);
	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test02)
{
  	FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
	auto f1 = SharedPointer<Flow>(new Flow(1));
	auto f2 = SharedPointer<Flow>(new Flow(2));
	auto f3 = SharedPointer<Flow>(new Flow(3));

	f1->setArriveTime(0);
	f2->setArriveTime(0);
	f3->setArriveTime(0);

	f1->setLastPacketTime(1);
	f2->setLastPacketTime(2);
	f3->setLastPacketTime(200);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
 
	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);
	BOOST_CHECK(f3.use_count() == 2);

	BOOST_CHECK(fm->getTotalFlows() == 3);
	BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);	

	fm->updateFlowTime(f1, 1);
	fm->updateFlowTime(f2, 2);
	fm->updateFlowTime(f3, 200);

	// dont release the network flows
	fm->setReleaseFlows(false);

	// Update the time of the flows
	fm->updateTimers(200);

	BOOST_CHECK(fm->getTotalFlows() == 3);
	BOOST_CHECK(fm->getTotalTimeoutFlows() == 2);	

	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);
	BOOST_CHECK(f3.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test03)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow(1));
        auto f2 = SharedPointer<Flow>(new Flow(2));
        auto f3 = SharedPointer<Flow>(new Flow(3));
        auto f4 = SharedPointer<Flow>(new Flow(5));

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);
        f4->setArriveTime(0);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
        fm->addFlow(f4);

        //fm->showFlowsByTime();
	
        fm->updateFlowTime(f1, 1);
        fm->updateFlowTime(f2, 200);
        fm->updateFlowTime(f4, 210);
        fm->updateFlowTime(f3, 2);

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);
        BOOST_CHECK(f4.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 4);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

	// Dont release the flows
	fm->setReleaseFlows(false);

        // Update the time of the flows
        fm->updateTimers(220);

        BOOST_CHECK(fm->getTotalFlows() == 4);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 2);
        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);
        BOOST_CHECK(f4.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test04)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow(1));
        auto f2 = SharedPointer<Flow>(new Flow(2));
        auto f3 = SharedPointer<Flow>(new Flow(3));

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);

        f1->setLastPacketTime(10);
        f2->setLastPacketTime(200);
        f3->setLastPacketTime(300);

        fm->setTimeout(120);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

	fm->setReleaseFlows(false);

        // Update the time of the flows
        fm->updateTimers(301);

        // flow1 should not exist on the fm
        auto fout = fm->findFlow(1, 0x0fffeaf);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);
        BOOST_CHECK(f1.use_count() == 4);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);
        BOOST_CHECK(fout.use_count() == 4);
        BOOST_CHECK(fout == f1);
}

BOOST_AUTO_TEST_CASE (test05)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        auto f1 = SharedPointer<Flow>(new Flow(1));
        auto f2 = SharedPointer<Flow>(new Flow(2042));
        auto f3 = SharedPointer<Flow>(new Flow(7));

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);

        f1->setLastPacketTime(100);
        f2->setLastPacketTime(20);
        f3->setLastPacketTime(300);

        fm->setTimeout(210);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

	fm->setReleaseFlows(false);

        // Update the time of the flows
        fm->updateTimers(301);

        auto fout = fm->findFlow(2042, 0);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);
        BOOST_CHECK(fout.use_count() == 4);
        BOOST_CHECK(fout == f2);
}

BOOST_AUTO_TEST_SUITE_END( )
